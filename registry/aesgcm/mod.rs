//! AES-128-GCM and AES-256-GCM (FIPS 197, NIST SP 800-38D) as TLS 1.3
//! uses them: a 16- or 32-byte key, a 12-byte nonce and a 16-byte tag,
//! sealed and opened in place.
//!
//! A SealingKey and an OpeningKey number their own nonces, as TLS 1.3
//! does (RFC 9846 5.3): the n-th record's nonce is the IV XOR n, n
//! big-endian in its last eight bytes, so that no nonce seals twice
//! under the key; after 2^64 - 1 records the key is Exhausted. A
//! direction of a connection has one of each, both sides from the same
//! key and IV:
//!
//! ```text
//! let mut sealing = SealingKey::new(&key, &iv);
//! let tag = sealing.seal(&header, &mut record)?;      // number 0, 1, ...
//! send(&header, &record, tag.bytes());
//! let mut opening = OpeningKey::new(&key, &iv);       // the peer's
//! opening.open(&header, &mut record, &tag)?;          // Err(Forged)
//! ```
//!
//! AesGcm, the key alone, takes a nonce of the caller's, by
//! seal_with_nonce and open_with_nonce: a nonce sealed twice under one
//! key gives away the XOR of both plaintexts and lets anyone forge a
//! tag, which is why their names say so. Each key's schedule and hash
//! key are wiped when it is dropped.
//!
//! CTR and GHASH run on the CPU's instructions through sys::aes where it
//! has them. The portable code is constant-time: AES is bitsliced, four
//! blocks at once in eight 64-bit words with the S-box as a circuit, and
//! GHASH multiplies with integer products whose carries fall into holes
//! between the bits; neither indexes memory by a secret. Both follow
//! BearSSL's aes_ct64 and ghash_ctmul64 (Thomas Pornin, MIT licence).

mod sys;

use sys as hw;

pub const KEY_LEN: usize = 16;
/// AES-256's key.
pub const KEY256_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// What one nonce may cover: the 32-bit counter starts at 2, so 2^32 - 2
/// blocks.
const DATA_MAX: u64 = ((1 << 32) - 2) * 16;
/// The AAD's length in bits must fit in 64.
const AAD_MAX: u64 = u64::MAX / 8;
/// Every fourth bit: the bitsliced key's lanes and bmul64's slices.
const M0: u64 = 0x1111_1111_1111_1111;
/// AES-256's round keys; AES-128's 11 are the last of as many places.
const ROUND_KEYS: usize = 15;

/// What went wrong. Only Exhausted ends a key; after TooLong a shorter
/// record goes on, and after Forged the next record (a stream that had a
/// forgery in it is broken, and its owner ends it).
#[cfg_attr(any(test, fuzzing), derive(Debug))]
#[cfg_attr(test, derive(PartialEq))]
pub enum Error {
    /// The data or the AAD is past GCM's limit; nothing was changed and
    /// no number taken.
    TooLong,
    /// The tag does not match; data is still the ciphertext. An
    /// OpeningKey took the record's number.
    Forged,
    /// The key numbered 2^64 - 1 records: it takes no more, and nothing
    /// was changed.
    Exhausted,
}

/// A tag that authenticates a sealed record: to be sent beside it.
#[must_use]
#[cfg_attr(any(test, fuzzing), derive(Debug, PartialEq))]
pub struct Tag([u8; TAG_LEN]);

impl Tag {
    /// The tag's bytes, to send.
    pub fn bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }

    /// The tag's bytes, by value: a record's buffer takes them where it
    /// would take a copy.
    pub fn into_bytes(self) -> [u8; TAG_LEN] {
        self.0
    }
}

/// A key and IV that seal records numbered 0, 1, ... in turn, each
/// under the IV XOR its number: the sending half of a direction.
pub struct SealingKey {
    key: AesGcm,
    iv: [u8; NONCE_LEN],
    next: u64,
}

/// A key and IV that open records numbered 0, 1, ... in turn, as the
/// peer's SealingKey sealed them: the receiving half.
pub struct OpeningKey {
    key: AesGcm,
    iv: [u8; NONCE_LEN],
    next: u64,
}

/// One key, expanded once: round keys and the hash key H in both forms.
pub struct AesGcm {
    /// The round keys as bytes, aligned for the instructions, from
    /// rk.first on.
    rk: hw::RoundKeys,
    /// The same, bitsliced and compressed: one bit of each nibble, which
    /// the portable code spreads to the nibble (spread_key) for its four
    /// blocks, a quarter of the size.
    sk: [[u64; 2]; ROUND_KEYS],
    /// H as two big-endian words, for the portable GHASH.
    h: [u64; 2],
    /// H to H^8 as the instructions' GHASH takes them.
    htbl: hw::Table,
    /// Whether to try the instructions; tests turn them off.
    hw: bool,
}

impl AesGcm {
    /// AES-128-GCM.
    pub fn new(key: &[u8; KEY_LEN]) -> AesGcm {
        AesGcm::with(key, hw::available())
    }

    /// AES-256-GCM.
    pub fn new256(key: &[u8; KEY256_LEN]) -> AesGcm {
        AesGcm::with(key, hw::available())
    }

    /// A key of 16 or 32 bytes: AES-128's 11 round keys go in the last 11
    /// places, so the last rounds take theirs from the same place for both.
    fn with(key: &[u8], hw: bool) -> AesGcm {
        let first = if key.len() == KEY256_LEN {
            0
        } else {
            hw::AES128_FIRST
        };
        let mut w = [[0; 4]; ROUND_KEYS];
        expand(key, w.get_mut(first..).unwrap_or_default());
        let mut g = AesGcm {
            rk: hw::RoundKeys {
                keys: [[0; 16]; ROUND_KEYS],
                first,
            },
            sk: [[0; 2]; ROUND_KEYS],
            h: [0; 2],
            htbl: [[0; 16]; 16],
            hw,
        };
        for ((rk, sk), k) in g.rk.keys.iter_mut().zip(&mut g.sk).zip(w) {
            *rk = block_bytes(k);
            *sk = bitslice_key(k);
        }
        hw::wipe_u32(w.as_flattened_mut());
        let mut h = [0; 16];
        g.ctr(&[0; 16], 0, &mut h);
        let (hi, lo) = words(&h);
        g.h = [hi, lo];
        if !hw::ghash_key(&h, &mut g.htbl) {
            g.hw = false;
        }
        hw::wipe(&mut h);
        g
    }

    /// Encrypts data in place; the tag that authenticates it and aad.
    /// Dangerous: a nonce must never seal twice under one key, which
    /// SealingKey makes sure of; this does not.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<Tag, Error> {
        check(aad, data)?;
        let block = iv(nonce);
        let mut y = [0; 16];
        self.ghash(&mut y, aad);
        self.encrypt(&block, data, &mut y);
        Ok(Tag(self.finish(&block, y, aad.len(), data.len())))
    }

    /// Decrypts data in place when tag authenticates it and aad; a
    /// forgery leaves the ciphertext, and no plaintext, in data. The
    /// nonce is the caller's, to match seal_with_nonce's: OpeningKey
    /// numbers them.
    pub fn open_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        check(aad, data)?;
        let block = iv(nonce);
        let mut y = [0; 16];
        self.ghash(&mut y, aad);
        let decrypted = self.decrypt(&block, data, &mut y);
        if !same(&self.finish(&block, y, aad.len(), data.len()), tag) {
            if decrypted {
                // CTR again puts the ciphertext back.
                self.ctr(&block, 2, data);
            }
            return Err(Error::Forged);
        }
        if !decrypted {
            self.ctr(&block, 2, data);
        }
        Ok(())
    }

    /// CTR over data from counter 2, and y continued over the ciphertext:
    /// one pass on the instructions, two in the portable code.
    fn encrypt(&self, block: &[u8; 16], data: &mut [u8], y: &mut [u8; 16]) {
        let (blocks, tail) = data.as_chunks_mut::<16>();
        // The counter after the whole blocks, mod 2^32 as GCM's inc32.
        let c = 2u32.wrapping_add(low32(blocks.len() as u64));
        if self.hw && hw::seal(&self.rk, &self.htbl, block, 2, blocks, y) {
            self.ctr(block, c, tail);
            self.ghash(y, tail);
            return;
        }
        self.ctr(block, 2, data);
        self.ghash(y, data);
    }

    /// y continued over the ciphertext in data; on the instructions, in
    /// the same pass, data decrypted, and then true.
    #[must_use]
    fn decrypt(&self, block: &[u8; 16], data: &mut [u8], y: &mut [u8; 16]) -> bool {
        let (blocks, tail) = data.as_chunks_mut::<16>();
        let c = 2u32.wrapping_add(low32(blocks.len() as u64));
        if self.hw && hw::open(&self.rk, &self.htbl, block, 2, blocks, y) {
            self.ghash(y, tail);
            self.ctr(block, c, tail);
            return true;
        }
        self.ghash(y, data);
        false
    }

    /// The tag: y continued over the lengths in bits, masked with E(K, J0).
    fn finish(&self, block: &[u8; 16], mut y: [u8; 16], alen: usize, n: usize) -> [u8; 16] {
        let bits = (u128::from(alen as u64 * 8) << 64) | u128::from(n as u64 * 8);
        self.ghash_blocks(&mut y, &[bits.to_be_bytes()]);
        self.ctr(block, 1, &mut y);
        y
    }

    /// GHASH over bytes, the last block padded with zeros.
    fn ghash(&self, y: &mut [u8; 16], bytes: &[u8]) {
        let (blocks, tail) = bytes.as_chunks::<16>();
        self.ghash_blocks(y, blocks);
        if !tail.is_empty() {
            // y ^ (tail padded with zeros), times H: the zero block adds
            // nothing, and the tail is never copied.
            for (d, s) in y.iter_mut().zip(tail) {
                *d ^= s;
            }
            self.ghash_blocks(y, &[[0; 16]]);
        }
    }

    fn ghash_blocks(&self, y: &mut [u8; 16], blocks: &[[u8; 16]]) {
        if self.hw && hw::ghash(&self.htbl, y, blocks) {
            return;
        }
        let [h1, h0] = self.h;
        let (h1r, h0r) = (rev64(h1), rev64(h0));
        let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
        let (mut y1, mut y0) = words(y);
        for b in blocks {
            let (b1, b0) = words(b);
            y1 ^= b1;
            y0 ^= b0;
            let (y1r, y0r) = (rev64(y1), rev64(y0));
            let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);
            let z0 = bmul64(y0, h0);
            let z1 = bmul64(y1, h1);
            let z2 = bmul64(y2, h2) ^ z0 ^ z1;
            let z0h = bmul64(y0r, h0r);
            let z1h = bmul64(y1r, h1r);
            let z2h = bmul64(y2r, h2r) ^ z0h ^ z1h;
            let (z0h, z1h, z2h) = (rev64(z0h) >> 1, rev64(z1h) >> 1, rev64(z2h) >> 1);
            // The 256-bit product, shifted left one for GCM's bit order.
            let (v0, v1, v2, v3) = (z0, z0h ^ z2, z1 ^ z2h, z1h);
            let v3 = (v3 << 1) | (v2 >> 63);
            let v2 = (v2 << 1) | (v1 >> 63);
            let v1 = (v1 << 1) | (v0 >> 63);
            let v0 = v0 << 1;
            let v2 = v2 ^ v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
            let v1 = v1 ^ (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
            y1 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
            y0 = v2 ^ (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        }
        *y = ((u128::from(y1) << 64) | u128::from(y0)).to_be_bytes();
    }

    /// CTR in place from counter ctr of block.
    fn ctr(&self, block: &[u8; 16], ctr: u32, data: &mut [u8]) {
        if self.hw && hw::ctr(&self.rk, block, ctr, data) {
            return;
        }
        let mut sk = [[0; 8]; ROUND_KEYS];
        for (d, k) in sk.iter_mut().zip(&self.sk).skip(self.rk.first) {
            *d = spread_key(*k);
        }
        let [n0, n1, n2, _] = block_words(block);
        let (quads, tail) = data.as_chunks_mut::<64>();
        let mut c = ctr;
        for q in quads {
            let ks = self.keystream(&sk, [n0, n1, n2], c);
            c = c.wrapping_add(4);
            for (d, k) in q.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
        if !tail.is_empty() {
            let ks = self.keystream(&sk, [n0, n1, n2], c);
            for (d, k) in tail.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
    }

    /// Four blocks of key stream, counters c to c + 3, under the round
    /// keys sk spread out.
    fn keystream(&self, sk: &[[u64; 8]; ROUND_KEYS], n: [u32; 3], c: u32) -> [u8; 64] {
        let [n0, n1, n2] = n;
        let mut q = [0; 8];
        let (lo, hi) = q.split_at_mut(4);
        for ((a, b), i) in lo.iter_mut().zip(hi.iter_mut()).zip(0..) {
            let w3 = u32::from_le_bytes(c.wrapping_add(i).to_be_bytes());
            (*a, *b) = interleave_in([n0, n1, n2, w3]);
        }
        ortho(&mut q);
        encrypt(sk, self.rk.first, &mut q);
        ortho(&mut q);
        let mut out = [0; 64];
        let (q03, q47) = q.split_at(4);
        for ((o, a), b) in out.as_chunks_mut::<16>().0.iter_mut().zip(q03).zip(q47) {
            *o = block_bytes(interleave_out(*a, *b));
        }
        out
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        hw::wipe(self.rk.keys.as_flattened_mut());
        hw::wipe_u64(self.sk.as_flattened_mut());
        hw::wipe_u64(&mut self.h);
        hw::wipe(self.htbl.as_flattened_mut());
    }
}

impl SealingKey {
    /// AES-128-GCM under key, nonces from iv.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> SealingKey {
        SealingKey {
            key: AesGcm::new(key),
            iv: *iv,
            next: 0,
        }
    }

    /// AES-256-GCM under key, nonces from iv.
    pub fn new256(key: &[u8; KEY256_LEN], iv: &[u8; NONCE_LEN]) -> SealingKey {
        SealingKey {
            key: AesGcm::new256(key),
            iv: *iv,
            next: 0,
        }
    }

    /// Encrypts data in place under the next number; the tag that
    /// authenticates it and aad. An error takes no number.
    pub fn seal(&mut self, aad: &[u8], data: &mut [u8]) -> Result<Tag, Error> {
        let (nonce, after) = numbered(&self.iv, self.next)?;
        let tag = self.key.seal_with_nonce(&nonce, aad, data)?;
        self.next = after;
        Ok(tag)
    }

    /// The number the next record takes: how many were sealed.
    pub fn sequence(&self) -> u64 {
        self.next
    }

    /// Sets the number the next record takes. Less safe: a number sealed
    /// again seals two records under one nonce. Only for records that
    /// were sealed and then dropped before any byte of them left, whose
    /// numbers the next records take instead, as TLS does when it fails
    /// with records still unsent.
    pub fn set_sequence_less_safe(&mut self, next: u64) {
        self.next = next;
    }
}

impl OpeningKey {
    /// AES-128-GCM under key, nonces from iv.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> OpeningKey {
        OpeningKey {
            key: AesGcm::new(key),
            iv: *iv,
            next: 0,
        }
    }

    /// AES-256-GCM under key, nonces from iv.
    pub fn new256(key: &[u8; KEY256_LEN], iv: &[u8; NONCE_LEN]) -> OpeningKey {
        OpeningKey {
            key: AesGcm::new256(key),
            iv: *iv,
            next: 0,
        }
    }

    /// Decrypts data in place, under the next number, when tag
    /// authenticates it and aad. Forged takes the number and leaves the
    /// ciphertext; TooLong and Exhausted take none.
    pub fn open(&mut self, aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        let (nonce, after) = numbered(&self.iv, self.next)?;
        check(aad, data)?;
        self.next = after;
        self.key.open_with_nonce(&nonce, aad, data, tag)
    }

    /// The number the next record takes: how many were opened.
    pub fn sequence(&self) -> u64 {
        self.next
    }

    /// Sets the number the next record takes, as a test reaches the
    /// limit without 2^64 records.
    #[cfg(any(test, fuzzing))]
    pub fn set_sequence_for_tests(&mut self, next: u64) {
        self.next = next;
    }
}

/// The nonce of record number n, the IV XOR n big-endian in its last
/// eight bytes (RFC 9846 5.3), and the number after it; Exhausted at
/// the last, which is never used, so that the count never wraps.
fn numbered(iv: &[u8; NONCE_LEN], n: u64) -> Result<([u8; NONCE_LEN], u64), Error> {
    let after = n.checked_add(1).ok_or(Error::Exhausted)?;
    let mut nonce = *iv;
    for (byte, number) in nonce.iter_mut().skip(4).zip(n.to_be_bytes()) {
        *byte ^= number;
    }
    Ok((nonce, after))
}

/// GCM's limits on one record.
fn check(aad: &[u8], data: &[u8]) -> Result<(), Error> {
    if data.len() as u64 > DATA_MAX || aad.len() as u64 > AAD_MAX {
        return Err(Error::TooLong);
    }
    Ok(())
}

/// The nonce with four zero bytes for the counter.
fn iv(nonce: &[u8; NONCE_LEN]) -> [u8; 16] {
    let [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11] = *nonce;
    [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, 0, 0, 0, 0]
}

/// Equal tags, in a time that does not depend on where they differ.
fn same(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let d = a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(d) == 0
}

/// A block as two big-endian words, high first.
fn words(b: &[u8; 16]) -> (u64, u64) {
    let [
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        a6,
        a7,
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
    ] = *b;
    (
        u64::from_be_bytes([a0, a1, a2, a3, a4, a5, a6, a7]),
        u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
    )
}

/// A block as four little-endian words, the order the bitslicing takes.
fn block_words(b: &[u8; 16]) -> [u32; 4] {
    let mut w = [0; 4];
    for (d, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *d = u32::from_le_bytes(*c);
    }
    w
}

fn block_bytes(w: [u32; 4]) -> [u8; 16] {
    let [w0, w1, w2, w3] = w.map(u128::from);
    ((w3 << 96) | (w2 << 64) | (w1 << 32) | w0).to_le_bytes()
}

/// The low half of x.
fn low32(x: u64) -> u32 {
    let [a, b, c, d, ..] = x.to_le_bytes();
    // The high half is zero or not wanted, as each caller says.
    u32::from_le_bytes([a, b, c, d])
}

/// x with its bits in reverse order.
fn rev64(x: u64) -> u64 {
    x.reverse_bits()
}

/// The 64x64 carry-less product, low 64 bits: four integer products of
/// every fourth bit, whose carries land in the three bits between.
fn bmul64(x: u64, y: u64) -> u64 {
    const M1: u64 = M0 << 1;
    const M2: u64 = M0 << 2;
    const M3: u64 = M0 << 3;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// The key schedule (FIPS 197 5.2) of a 16- or 32-byte key into rk, 11
/// or 15 round keys of little-endian words: Nk words of the key, then
/// each word the one Nk before XORed with the one before, transformed
/// at each multiple of Nk and, for AES-256, halfway too. SubWord goes
/// through the circuit, not a table.
fn expand(key: &[u8], rk: &mut [[u32; 4]]) {
    let w = rk.as_flattened_mut();
    let (words, _) = key.as_chunks::<4>();
    let nk = words.len();
    for (d, c) in w.iter_mut().zip(words) {
        *d = u32::from_le_bytes(*c);
    }
    let mut rcon = 1;
    for i in nk..w.len() {
        let Some((done, [next, ..])) = w.split_at_mut_checked(i) else {
            break;
        };
        let (Some(&back), Some(&prev)) = (done.get(i - nk), done.last()) else {
            break;
        };
        let t = if i % nk == 0 {
            let t = sub_word(prev.rotate_right(8)) ^ rcon;
            rcon = (rcon << 1) ^ ((rcon >> 7) * 0x11b);
            t
        } else if nk > 6 && i % nk == 4 {
            sub_word(prev)
        } else {
            prev
        };
        *next = back ^ t;
    }
}

/// S applied to each byte of x.
fn sub_word(x: u32) -> u32 {
    let mut q = [u64::from(x), 0, 0, 0, 0, 0, 0, 0];
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    // The high half holds S(0) of the zero padding.
    low32(q[0])
}

/// A round key in the bitsliced form, the same in all four blocks, and
/// so one bit of each nibble: those bits, which spread_key spreads.
fn bitslice_key(k: [u32; 4]) -> [u64; 2] {
    let (a, b) = interleave_in(k);
    let mut q = [a, a, a, a, b, b, b, b];
    ortho(&mut q);
    let [q0, q1, q2, q3, q4, q5, q6, q7] = q;
    let c0 = (q0 & M0) | (q1 & (M0 << 1)) | (q2 & (M0 << 2)) | (q3 & (M0 << 3));
    let c1 = (q4 & M0) | (q5 & (M0 << 1)) | (q6 & (M0 << 2)) | (q7 & (M0 << 3));
    [c0, c1]
}

/// The round key for four blocks from bitslice_key's bits.
fn spread_key(c: [u64; 2]) -> [u64; 8] {
    let [c0, c1] = c;
    // Each bit fills its nibble: x * 15 with one bit in four set.
    [
        (c0 & M0) * 15,
        ((c0 >> 1) & M0) * 15,
        ((c0 >> 2) & M0) * 15,
        ((c0 >> 3) & M0) * 15,
        (c1 & M0) * 15,
        ((c1 >> 1) & M0) * 15,
        ((c1 >> 2) & M0) * 15,
        ((c1 >> 3) & M0) * 15,
    ]
}

/// Spreads the 16-bit halves of a word to every other byte of two words.
fn interleave_in(w: [u32; 4]) -> (u64, u64) {
    let [x0, x1, x2, x3] = w.map(|x| {
        let x = u64::from(x);
        let x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
        (x | (x << 8)) & 0x00FF_00FF_00FF_00FF
    });
    (x0 | (x2 << 8), x1 | (x3 << 8))
}

fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    const M: u64 = 0x00FF_00FF_00FF_00FF;
    [q0 & M, q1 & M, (q0 >> 8) & M, (q1 >> 8) & M].map(|x| {
        let x = (x | (x >> 8)) & 0x0000_FFFF_0000_FFFF;
        // The high half is masked out above.
        low32((x | (x >> 16)) & 0xFFFF_FFFF)
    })
}

/// Swaps bits of x and y under masks: the transposition to and from the
/// bitsliced form, its own inverse.
fn ortho(q: &mut [u64; 8]) {
    fn swap(x: u64, y: u64, cl: u64, s: u32) -> (u64, u64) {
        let ch = !cl;
        ((x & cl) | ((y & cl) << s), ((x & ch) >> s) | (y & ch))
    }
    const C2: u64 = 0x5555_5555_5555_5555;
    const C4: u64 = 0x3333_3333_3333_3333;
    const C8: u64 = 0x0F0F_0F0F_0F0F_0F0F;
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let (q0, q1) = swap(q0, q1, C2, 1);
    let (q2, q3) = swap(q2, q3, C2, 1);
    let (q4, q5) = swap(q4, q5, C2, 1);
    let (q6, q7) = swap(q6, q7, C2, 1);
    let (q0, q2) = swap(q0, q2, C4, 2);
    let (q1, q3) = swap(q1, q3, C4, 2);
    let (q4, q6) = swap(q4, q6, C4, 2);
    let (q5, q7) = swap(q5, q7, C4, 2);
    let (q0, q4) = swap(q0, q4, C8, 4);
    let (q1, q5) = swap(q1, q5, C8, 4);
    let (q2, q6) = swap(q2, q6, C8, 4);
    let (q3, q7) = swap(q3, q7, C8, 4);
    *q = [q0, q1, q2, q3, q4, q5, q6, q7];
}

/// Ten or fourteen rounds on four bitsliced blocks, the round keys from
/// sk[first] on.
fn encrypt(sk: &[[u64; 8]; ROUND_KEYS], first: usize, q: &mut [u64; 8]) {
    let [keys @ .., last] = sk;
    let mut keys = keys.iter().skip(first);
    if let Some(k) = keys.next() {
        add_round_key(q, k);
    }
    for k in keys {
        sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, k);
    }
    sbox(q);
    shift_rows(q);
    add_round_key(q, last);
}

fn add_round_key(q: &mut [u64; 8], k: &[u64; 8]) {
    for (x, y) in q.iter_mut().zip(k) {
        *x ^= y;
    }
}

fn shift_rows(q: &mut [u64; 8]) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_FFFF)
            | ((v & 0x0000_0000_FFF0_0000) >> 4)
            | ((v & 0x0000_0000_000F_0000) << 12)
            | ((v & 0x0000_FF00_0000_0000) >> 8)
            | ((v & 0x0000_00FF_0000_0000) << 8)
            | ((v & 0xF000_0000_0000_0000) >> 12)
            | ((v & 0x0FFF_0000_0000_0000) << 4);
    }
}

fn mix_columns(q: &mut [u64; 8]) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let [r0, r1, r2, r3, r4, r5, r6, r7] = q.map(|x| x.rotate_right(16));
    let rot = |x: u64| x.rotate_right(32);
    *q = [
        q7 ^ r7 ^ r0 ^ rot(q0 ^ r0),
        q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rot(q1 ^ r1),
        q1 ^ r1 ^ r2 ^ rot(q2 ^ r2),
        q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rot(q3 ^ r3),
        q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rot(q4 ^ r4),
        q4 ^ r4 ^ r5 ^ rot(q5 ^ r5),
        q5 ^ r5 ^ r6 ^ rot(q6 ^ r6),
        q6 ^ r6 ^ r7 ^ rot(q7 ^ r7),
    ];
}

/// The S-box as Boyar and Peralta's circuit of 113 gates
/// (eprint.iacr.org/2009/191); x0 is the high bit, q[7].
fn sbox(q: &mut [u64; 8]) {
    let [x7, x6, x5, x4, x3, x2, x1, x0] = *q;

    // The top linear layer.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // The nonlinear middle: inversion in GF(2^4)^2.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // The bottom linear layer, with the affine constant 0x63.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

/// Any bytes as a record: the instructions and the portable code agree,
/// it opens to what was sealed, and a flipped bit does not open.
#[cfg(fuzzing)]
pub fn fuzz_seal_open(input: &[u8]) {
    let Some((&split, rest)) = input.split_first() else {
        return;
    };
    let (aad, msg) = rest.split_at(usize::from(split).min(rest.len()));
    let key = [0x42; KEY_LEN];
    let nonce = [0x24; NONCE_LEN];
    let (fast, slow) = (AesGcm::new(&key), AesGcm::with(&key, false));
    // rr: escape(copy): the record is sealed in place, twice.
    let mut a = msg.to_vec();
    // rr: escape(copy): the record is sealed in place, twice.
    let mut b = msg.to_vec();
    let ta = fast.seal_with_nonce(&nonce, aad, &mut a).unwrap();
    let tb = slow.seal_with_nonce(&nonce, aad, &mut b).unwrap();
    assert_eq!(a, b);
    assert_eq!(ta, tb);
    if let Some(x) = b.first_mut() {
        *x ^= 1;
        let forged = slow.open_with_nonce(&nonce, aad, &mut b, ta.bytes());
        assert!(matches!(forged, Err(Error::Forged)));
    }
    fast.open_with_nonce(&nonce, aad, &mut a, ta.bytes())
        .unwrap();
    assert_eq!(a, msg);
}

#[cfg(test)]
mod tests {
    use super::{AesGcm, Error, OpeningKey, SealingKey, hw};
    use alloc::vec::Vec;
    use test::Bencher;

    fn unhex(s: &str) -> Vec<u8> {
        let d = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            _ => c - b'a' + 10,
        };
        let mut v = Vec::new();
        for p in s.as_bytes().chunks(2) {
            v.push((d(p[0]) << 4) | d(p[1]));
        }
        v
    }

    /// The instructions where the CPU has them, and the portable code,
    /// for a key of 16 or 32 bytes.
    fn both(k: &str) -> [AesGcm; 2] {
        let key = unhex(k);
        assert!(matches!(key.len(), 16 | 32));
        [
            AesGcm::with(&key, hw::available()),
            AesGcm::with(&key, false),
        ]
    }

    /// Seals pt, checks ct and tag, then opens it back.
    fn vector(g: &AesGcm, nonce: &str, aad: &str, pt: &str, ct: &str, tag: &str) {
        let nonce: [u8; 12] = unhex(nonce).try_into().unwrap();
        let aad = unhex(aad);
        let mut data = unhex(pt);
        let t = g.seal_with_nonce(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data, unhex(ct));
        assert_eq!(t.bytes()[..], unhex(tag)[..]);
        g.open_with_nonce(&nonce, &aad, &mut data, t.bytes())
            .unwrap();
        assert_eq!(data, unhex(pt));
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    fn apple_silicon_has_the_instructions() {
        assert!(hw::available());
        assert!(AesGcm::new(&[0; 16]).hw);
        assert!(AesGcm::new256(&[0; 32]).hw);
    }

    /// FIPS 197 appendices C.1 and C.3, through the counter: E(K, P) is
    /// the key stream of the counter block P.
    #[test]
    fn fips197() {
        let key128 = "000102030405060708090a0b0c0d0e0f";
        let key256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        for (k, c) in [
            (key128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (key256, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            for g in both(k) {
                let p: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
                    .try_into()
                    .unwrap();
                let counter = u32::from_be_bytes(p[12..].try_into().unwrap());
                let mut block = p;
                block[12..].fill(0);
                let mut out = [0; 16];
                g.ctr(&block, counter, &mut out);
                assert_eq!(out[..], unhex(c)[..]);
            }
        }
    }

    /// FIPS 197 A.3's AES-256 key expansion: the last round key.
    #[test]
    fn key_expansion_256() {
        let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let g = AesGcm::with(&key, false);
        assert_eq!(g.rk.first, 0);
        assert_eq!(
            g.rk.keys[14][..],
            unhex("fe4890d1e6188d0b046df344706c631e")[..]
        );
        let short = AesGcm::with(&key[..16], false);
        assert_eq!(short.rk.first, hw::AES128_FIRST);
    }

    /// McGrew and Viega's test cases 1 to 4, and 13 to 16 of AES-256.
    #[test]
    fn gcm_spec() {
        let z = "00000000000000000000000000000000";
        let n = "000000000000000000000000";
        for g in both(z) {
            vector(&g, n, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
            let ct = "0388dace60b6a392f328c2b971b2fe78";
            vector(&g, n, "", z, ct, "ab6e47d42cec13bdf53a67b21257bddf");
        }
        let pt = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                  1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let ct = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                  21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let pt4 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let ct4 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                   21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let nonce = "cafebabefacedbaddecaf888";
        let aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        for g in both("feffe9928665731c6d6a8f9467308308") {
            vector(&g, nonce, "", pt, ct, "4d5c2af327cd64a62cf35abd2ba6fab4");
            vector(&g, nonce, aad, pt4, ct4, "5bc94fbc3221a5db94fae95ae7121a47");
        }
        let z256 = "0000000000000000000000000000000000000000000000000000000000000000";
        for g in both(z256) {
            vector(&g, n, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b");
            let zeros = "cea7403d4d606b6e074ec5d3baf39d18";
            vector(&g, n, "", z, zeros, "d0d1c8a799996bf0265b98b5d48ab919");
        }
        let ct15 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let ct16 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        for g in both("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308") {
            vector(&g, nonce, "", pt, ct15, "b094dac5d93471bdec1a502270e3cc6c");
            vector(
                &g,
                nonce,
                aad,
                pt4,
                ct16,
                "76fc6ece0f4e1768cddf8853bb2d551b",
            );
        }
    }

    /// A 12-byte nonce with AAD and a partial block: NIST's GCM validation
    /// vectors (gcmEncryptExtIV128 and 256, IVlen 96, PTlen 408, AADlen
    /// 160, Count 0), and one with AAD alone (PTlen 0, AADlen 128, Count
    /// 0).
    #[test]
    fn nist_cavp() {
        for g in both("fe47fcce5fc32665d2ae399e4eec72ba") {
            vector(
                &g,
                "5adb9609dbaeb58cbd6e7275",
                "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
                "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60\
                 e743f1b840382c4bccaf3bafb4ca8429bea063",
                "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf539304373\
                 6365253ddbc5db8778371495da76d269e5db3e",
                "291ef1982e4defedaa2249f898556b47",
            );
        }
        for g in both("77be63708971c4e240d1cb79e8d77feb") {
            vector(
                &g,
                "e0e00f19fed7ba0136a797f3",
                "7a43ec1d9c0a5a78a0b16533a6213cab",
                "",
                "",
                "209fcc8d3675ed938e9c7166709dd946",
            );
        }
        for g in both("24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f") {
            vector(
                &g,
                "9ff18563b978ec281b3f2794",
                "adb5ec720ccf9898500028bf34afccbcaca126ef",
                "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86\
                 757accb158bd9abb3868fdc0d0b074b5f01b2c",
                "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b0614\
                 5dae82057ad55994cf59ad7f67c0fa5e85fab8",
                "bc95c532fecc594c36d1550286a7a3f0",
            );
        }
        for g in both("78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223") {
            vector(
                &g,
                "d79cf22d504cc793c3fb6c8a",
                "b96baa8c1c75a671bfb2d08d06be5f36",
                "",
                "",
                "3e5d486aa2e30b22e040b85723a06e76",
            );
        }
    }

    /// The 8 fields of a case's line, split at spaces.
    fn fields(line: &str) -> [&str; 8] {
        let mut out = [""; 8];
        let mut words = line.split(' ');
        for slot in &mut out {
            *slot = words.next().unwrap();
        }
        assert!(words.next().is_none(), "{line}");
        out
    }

    /// Wycheproof's aes_gcm_test, the cases of a 128- or 256-bit key, a
    /// 96-bit nonce and a 128-bit tag (aesgcm-wycheproof.py), on both paths: a
    /// valid one seals to its ciphertext and tag and opens back; an
    /// invalid one is refused and leaves the ciphertext.
    #[test]
    fn wycheproof() {
        let field = |text: &str| if text == "-" { Vec::new() } else { unhex(text) };
        let mut cases = 0;
        for line in include_str!("aesgcm-wycheproof.txt").lines() {
            if line.starts_with('#') {
                continue;
            }
            let [id, valid, k, nonce, aad, pt, ct, tag] = fields(line);
            let nonce: [u8; 12] = unhex(nonce).try_into().unwrap();
            let tag: [u8; 16] = unhex(tag).try_into().unwrap();
            let aad = field(aad);
            for g in both(k) {
                if valid == "1" {
                    let mut data = field(pt);
                    let sealed = g.seal_with_nonce(&nonce, &aad, &mut data).unwrap();
                    assert_eq!((data, *sealed.bytes()), (field(ct), tag), "tcId {id}");
                }
                let mut data = field(ct);
                let opened = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
                assert_eq!(opened.is_ok(), valid == "1", "tcId {id}");
                let expected = if valid == "1" { field(pt) } else { field(ct) };
                assert_eq!(data, expected, "tcId {id}");
            }
            cases += 1;
        }
        assert_eq!(cases, 133);
    }

    /// A changed tag, ciphertext, AAD or nonce is refused, and the data is
    /// left the ciphertext it came as.
    #[test]
    fn rejects_forgeries() {
        let nonce = [7; 12];
        let mut aad = [0xfe, 0xed, 0xfa, 0xce];
        for g in both("feffe9928665731c6d6a8f9467308308") {
            let mut data = [0x5a; 300];
            let mut tag = *g.seal_with_nonce(&nonce, &aad, &mut data).unwrap().bytes();
            let ct = data;
            tag[3] ^= 1;
            let bad_tag = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_tag, Err(Error::Forged)));
            tag[3] ^= 1;
            data[57] ^= 0x80;
            let bad_ct = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_ct, Err(Error::Forged)));
            data[57] ^= 0x80;
            assert_eq!(data, ct);
            aad[0] ^= 1;
            let bad_aad = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_aad, Err(Error::Forged)));
            aad[0] ^= 1;
            let bad_nonce = g.open_with_nonce(&[8; 12], &aad, &mut data, &tag);
            assert!(matches!(bad_nonce, Err(Error::Forged)));
            assert_eq!(data, ct);
            g.open_with_nonce(&nonce, &aad, &mut data, &tag).unwrap();
            assert_eq!(data, [0x5a; 300]);
        }
    }

    /// The instructions and the portable code agree on every length to
    /// past three eight-block turns, at every alignment, with AAD of each
    /// length to past two blocks.
    #[test]
    fn paths_agree() {
        paths_agree_key(&[0x5a; 16]);
        paths_agree_key(&[0x5a; 32]);
    }

    fn paths_agree_key(k: &[u8]) {
        let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
        let mut aad = [0; 41];
        for (i, a) in aad.iter_mut().enumerate() {
            *a = u8::try_from(i).unwrap();
        }
        let mut buf = [0u8; 800];
        let mut x = 3u8;
        for b in &mut buf {
            *b = x;
            x = x.wrapping_add(7);
        }
        let mut other = buf;
        for n in 0..400 {
            let at = n % 17;
            let aad = &aad[..n % 41];
            let nonce = [u8::try_from(n % 256).unwrap(); 12];
            let a = &mut buf[at..at + n];
            let b = &mut other[at + 1..at + 1 + n];
            b.copy_from_slice(a);
            let ta = fast.seal_with_nonce(&nonce, aad, a).unwrap();
            let tb = slow.seal_with_nonce(&nonce, aad, b).unwrap();
            assert_eq!(a, b, "length {n}");
            assert_eq!(ta, tb, "length {n}");
            slow.open_with_nonce(&nonce, aad, a, ta.bytes()).unwrap();
            fast.open_with_nonce(&nonce, aad, b, tb.bytes()).unwrap();
            assert_eq!(a, b);
        }
    }

    /// The 32-bit counter wraps the same way on both paths, and only the
    /// counter: block 6 of a run from 2^32 - 6 is counter 0.
    #[test]
    fn counter_wraps() {
        for k in [&[0x11; 16][..], &[0x11; 32]] {
            let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
            let mut block = [0x33; 16];
            block[12..].fill(0);
            let mut a = [0; 200];
            let mut b = [0; 200];
            fast.ctr(&block, u32::MAX - 5, &mut a);
            slow.ctr(&block, u32::MAX - 5, &mut b);
            assert_eq!(a, b);
            let mut c = [0; 16];
            slow.ctr(&block, 0, &mut c);
            assert_eq!(a[96..112], c);
        }
    }

    /// CTR alone, as tag masks and a refused open use it, agrees on every
    /// length: whole groups of four blocks, the blocks after, a part.
    #[test]
    fn ctr_paths_agree() {
        for k in [&[0x77; 16][..], &[0x77; 32]] {
            let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
            let block = [
                0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0, 0, 0,
            ];
            for n in 0..200 {
                let mut a = [0; 200];
                let mut b = [0; 200];
                fast.ctr(&block, 2, &mut a[..n]);
                slow.ctr(&block, 2, &mut b[..n]);
                assert_eq!(a, b, "length {n}");
            }
        }
    }

    /// The one-pass seal and open wrap the 32-bit counter as CTR does, and
    /// agree with the portable CTR and GHASH: two eight-block turns and
    /// five blocks after.
    #[test]
    fn stitched_counter_wraps() {
        if !hw::available() {
            return;
        }
        for k in [&[0x11; 16][..], &[0x11; 32]] {
            stitched_counter_wraps_key(k);
        }
    }

    fn stitched_counter_wraps_key(k: &[u8]) {
        let [fast, slow] = [AesGcm::with(k, true), AesGcm::with(k, false)];
        let mut block = [0x33; 16];
        block[12..].fill(0);
        let start = u32::MAX - 9;
        let mut a = [[0x5a; 16]; 21];
        let mut b = a;
        let (mut ya, mut yb, mut yo) = ([1; 16], [1; 16], [1; 16]);
        assert!(hw::seal(
            &fast.rk, &fast.htbl, &block, start, &mut a, &mut ya
        ));
        slow.ctr(&block, start, b.as_flattened_mut());
        slow.ghash(&mut yb, b.as_flattened());
        assert_eq!(a, b);
        assert_eq!(ya, yb);
        assert!(hw::open(
            &fast.rk, &fast.htbl, &block, start, &mut a, &mut yo
        ));
        assert_eq!(yo, yb);
        assert_eq!(a, [[0x5a; 16]; 21]);
    }

    /// A whole TLS record, past the strides many times, agrees as well.
    #[test]
    fn long_records() {
        long_record(&[0x42; 16]);
        long_record(&[0x42; 32]);
    }

    fn long_record(k: &[u8]) {
        let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
        let mut a = Vec::new();
        a.resize(16384 + 5, 0x91);
        // rr: escape(copy): the same record, sealed by the other path.
        let mut b = a.clone();
        let aad = [0x17; 13];
        let ta = fast.seal_with_nonce(&[1; 12], &aad, &mut a).unwrap();
        let tb = slow.seal_with_nonce(&[1; 12], &aad, &mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(ta, tb);
    }

    /// As TLS uses the keys: one side seals records in turn and the other
    /// opens them, each under the next number; a record opened out of
    /// turn, or twice, is Forged; TooLong takes no number; Exhausted at
    /// the last number, on both sides.
    #[test]
    fn numbered_loop() {
        let iv = [0xa0; 12];
        numbered(
            SealingKey::new(&[0x3c; 16], &iv),
            OpeningKey::new(&[0x3c; 16], &iv),
            &iv,
        );
        numbered(
            SealingKey::new256(&[0x3c; 32], &iv),
            OpeningKey::new256(&[0x3c; 32], &iv),
            &iv,
        );
        let mut sealing = SealingKey::new(&[1; 16], &[2; 12]);
        let mut opening = OpeningKey::new(&[1; 16], &[2; 12]);
        sealing.set_sequence_less_safe(u64::MAX - 1);
        opening.set_sequence_for_tests(u64::MAX - 1);
        let mut data = [9; 20];
        let tag = sealing.seal(&[], &mut data).unwrap();
        assert_eq!(opening.open(&[], &mut data, tag.bytes()), Ok(()));
        assert_eq!(data, [9; 20]);
        assert_eq!(sealing.seal(&[], &mut data), Err(Error::Exhausted));
        assert_eq!(data, [9; 20]);
        assert_eq!(
            opening.open(&[], &mut data, tag.bytes()),
            Err(Error::Exhausted)
        );
        assert_eq!(sealing.sequence(), u64::MAX);
        assert_eq!(opening.sequence(), u64::MAX);
    }

    /// Five records sealed in turn, and opened by the other side.
    fn numbered(mut sealing: SealingKey, mut opening: OpeningKey, iv: &[u8; 12]) {
        let mut records = Vec::new();
        for n in 0..5_u8 {
            let mut data = [n; 33];
            let tag = sealing.seal(&[n], &mut data).unwrap();
            records.push((data, tag));
        }
        assert_eq!(sealing.sequence(), 5);
        // Number n is the IV XOR n: what seal_with_nonce gives.
        let mut nonce = *iv;
        nonce[11] ^= 3;
        let mut third = [3; 33];
        let again = sealing
            .key
            .seal_with_nonce(&nonce, &[3], &mut third)
            .unwrap();
        assert_eq!((third, &again), (records[3].0, &records[3].1));
        // Out of turn: record 1 under number 0.
        let mut early = records[1].0;
        let forged = opening.open(&[1], &mut early, records[1].1.bytes());
        assert_eq!(forged, Err(Error::Forged));
        assert_eq!(early, records[1].0);
        assert_eq!(opening.sequence(), 1);
        for (n, (data, tag)) in records.iter_mut().enumerate().skip(1) {
            let n = u8::try_from(n).unwrap();
            assert_eq!(opening.open(&[n], data, tag.bytes()), Ok(()));
            assert_eq!(*data, [n; 33]);
        }
        assert_eq!(opening.sequence(), 5);
    }

    /// One TLS record of 16 KiB with its 5-byte header as AAD.
    fn seal_record(b: &mut Bencher, g: &AesGcm) {
        let mut record = Vec::new();
        record.resize(16384, 0x17);
        let aad = [0x17, 3, 3, 0x40, 0x11];
        b.iter(|| g.seal_with_nonce(&[9; 12], &aad, &mut record).unwrap());
    }

    #[bench]
    fn seal_16k(b: &mut Bencher) {
        seal_record(b, &AesGcm::new(&[7; 16]));
    }

    #[bench]
    fn seal_16k_256(b: &mut Bencher) {
        seal_record(b, &AesGcm::new256(&[7; 32]));
    }

    /// The portable code, which a CPU without the instructions takes.
    #[bench]
    fn seal_16k_portable(b: &mut Bencher) {
        seal_record(b, &AesGcm::with(&[7; 16], false));
    }

    /// A record sealed and opened again, as one side of a connection
    /// sends and the other receives it, each key numbering its nonces.
    #[bench]
    fn seal_open_16k(b: &mut Bencher) {
        let mut sealing = SealingKey::new(&[7; 16], &[9; 12]);
        let mut opening = OpeningKey::new(&[7; 16], &[9; 12]);
        let mut record = Vec::new();
        record.resize(16384, 0x17);
        let aad = [0x17, 3, 3, 0x40, 0x11];
        b.iter(|| {
            let tag = sealing.seal(&aad, &mut record).unwrap();
            opening.open(&aad, &mut record, tag.bytes()).unwrap();
        });
    }
}
