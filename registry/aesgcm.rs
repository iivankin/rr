//! AES-128-GCM (FIPS 197, NIST SP 800-38D) as TLS 1.3 uses it: a 16-byte
//! key, a 12-byte nonce and a 16-byte tag, sealed and opened in place.
//!
//! CTR and GHASH run on the CPU's instructions through sys::aes where it
//! has them. The portable code is constant-time: AES is bitsliced, four
//! blocks at once in eight 64-bit words with the S-box as a circuit, and
//! GHASH multiplies with integer products whose carries fall into holes
//! between the bits; neither indexes memory by a secret. Both follow
//! BearSSL's aes_ct64 and ghash_ctmul64 (Thomas Pornin, MIT licence).

use crate::sys::aes as hw;

pub const KEY_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// What one nonce may cover: the 32-bit counter starts at 2, so 2^32 - 2
/// blocks.
const DATA_MAX: u64 = ((1 << 32) - 2) * 16;
/// The AAD's length in bits must fit in 64.
const AAD_MAX: u64 = u64::MAX / 8;
/// Every fourth bit: the bitsliced key's lanes and bmul64's slices.
const M0: u64 = 0x1111_1111_1111_1111;

#[cfg_attr(any(test, fuzzing), derive(Debug))]
pub enum Error {
    /// The data or the AAD is past GCM's limit; nothing was changed.
    TooLong,
    /// The tag does not match; data is still the ciphertext.
    Forged,
}

/// One key, expanded once: round keys and the hash key H in both forms.
pub struct AesGcm {
    /// The round keys as bytes, for the instructions.
    rk: [u8; 176],
    /// The same, bitsliced for four blocks of the portable code.
    sk: [[u64; 8]; 11],
    /// H as two big-endian words, for the portable GHASH.
    h: [u64; 2],
    /// H to H^8 as the instructions' GHASH takes them.
    htbl: hw::Table,
    /// Whether to try the instructions; tests turn them off.
    hw: bool,
}

impl AesGcm {
    pub fn new(key: &[u8; KEY_LEN]) -> AesGcm {
        AesGcm::with(key, hw::available())
    }

    fn with(key: &[u8; KEY_LEN], hw: bool) -> AesGcm {
        let w = expand(key);
        let mut g = AesGcm {
            rk: [0; 176],
            sk: [[0; 8]; 11],
            h: [0; 2],
            htbl: [[0; 16]; 16],
            hw,
        };
        for ((rk, sk), k) in
            g.rk.as_chunks_mut::<16>()
                .0
                .iter_mut()
                .zip(&mut g.sk)
                .zip(w)
        {
            *rk = block_bytes(k);
            *sk = bitslice_key(k);
        }
        let mut h = [0; 16];
        g.ctr(&[0; 16], 0, &mut h);
        let (hi, lo) = words(&h);
        g.h = [hi, lo];
        if !hw::ghash_key(&h, &mut g.htbl) {
            g.hw = false;
        }
        g
    }

    /// Encrypts data in place; the tag that authenticates it and aad.
    /// A nonce must never seal twice under one key.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Error> {
        check(aad, data)?;
        let block = iv(nonce);
        let mut y = [0; 16];
        self.ghash(&mut y, aad);
        self.encrypt(&block, data, &mut y);
        Ok(self.finish(&block, y, aad.len(), data.len()))
    }

    /// Decrypts data in place when tag authenticates it and aad; a
    /// forgery leaves the ciphertext, and no plaintext, in data.
    pub fn open(
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
        let [n0, n1, n2, _] = block_words(block);
        let (quads, tail) = data.as_chunks_mut::<64>();
        let mut c = ctr;
        for q in quads {
            let ks = self.keystream([n0, n1, n2], c);
            c = c.wrapping_add(4);
            for (d, k) in q.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
        if !tail.is_empty() {
            let ks = self.keystream([n0, n1, n2], c);
            for (d, k) in tail.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
    }

    /// Four blocks of key stream, counters c to c + 3.
    fn keystream(&self, n: [u32; 3], c: u32) -> [u8; 64] {
        let [n0, n1, n2] = n;
        let mut q = [0; 8];
        let (lo, hi) = q.split_at_mut(4);
        for ((a, b), i) in lo.iter_mut().zip(hi.iter_mut()).zip(0..) {
            let w3 = u32::from_le_bytes(c.wrapping_add(i).to_be_bytes());
            (*a, *b) = interleave_in([n0, n1, n2, w3]);
        }
        ortho(&mut q);
        encrypt(&self.sk, &mut q);
        ortho(&mut q);
        let mut out = [0; 64];
        let (q03, q47) = q.split_at(4);
        for ((o, a), b) in out.as_chunks_mut::<16>().0.iter_mut().zip(q03).zip(q47) {
            *o = block_bytes(interleave_out(*a, *b));
        }
        out
    }
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

/// The AES-128 key schedule (FIPS 197 5.2) as eleven round keys of
/// little-endian words; SubWord goes through the circuit, not a table.
fn expand(key: &[u8; KEY_LEN]) -> [[u32; 4]; 11] {
    let mut rk = [[0; 4]; 11];
    let mut k = block_words(key);
    let mut rcon = 1;
    for r in &mut rk {
        *r = k;
        let [_, _, _, last] = k;
        let t = sub_word(last.rotate_right(8)) ^ rcon;
        let [k0, k1, k2, k3] = k;
        let k0 = k0 ^ t;
        let k1 = k1 ^ k0;
        let k2 = k2 ^ k1;
        k = [k0, k1, k2, k3 ^ k2];
        rcon = (rcon << 1) ^ ((rcon >> 7) * 0x11b);
    }
    rk
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

/// A round key in the bitsliced form, the same in all four blocks.
fn bitslice_key(k: [u32; 4]) -> [u64; 8] {
    let (a, b) = interleave_in(k);
    let mut q = [a, a, a, a, b, b, b, b];
    ortho(&mut q);
    let [q0, q1, q2, q3, q4, q5, q6, q7] = q;
    let c0 = (q0 & M0) | (q1 & (M0 << 1)) | (q2 & (M0 << 2)) | (q3 & (M0 << 3));
    let c1 = (q4 & M0) | (q5 & (M0 << 1)) | (q6 & (M0 << 2)) | (q7 & (M0 << 3));
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

/// Ten rounds on four bitsliced blocks.
fn encrypt(sk: &[[u64; 8]; 11], q: &mut [u64; 8]) {
    let [first, middle @ .., last] = sk;
    add_round_key(q, first);
    for k in middle {
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
    let ta = fast.seal(&nonce, aad, &mut a).unwrap();
    let tb = slow.seal(&nonce, aad, &mut b).unwrap();
    assert_eq!(a, b);
    assert_eq!(ta, tb);
    if let Some(x) = b.first_mut() {
        *x ^= 1;
        let forged = slow.open(&nonce, aad, &mut b, &ta);
        assert!(matches!(forged, Err(Error::Forged)));
    }
    fast.open(&nonce, aad, &mut a, &ta).unwrap();
    assert_eq!(a, msg);
}

#[cfg(test)]
mod tests {
    use super::{AesGcm, Error, hw};
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

    fn key(s: &str) -> [u8; 16] {
        unhex(s).try_into().unwrap()
    }

    /// The instructions where the CPU has them, and the portable code.
    fn both(k: &str) -> [AesGcm; 2] {
        [AesGcm::new(&key(k)), AesGcm::with(&key(k), false)]
    }

    /// Seals pt, checks ct and tag, then opens it back.
    fn vector(g: &AesGcm, nonce: &str, aad: &str, pt: &str, ct: &str, tag: &str) {
        let nonce: [u8; 12] = unhex(nonce).try_into().unwrap();
        let aad = unhex(aad);
        let mut data = unhex(pt);
        let t = g.seal(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data, unhex(ct));
        assert_eq!(t[..], unhex(tag)[..]);
        g.open(&nonce, &aad, &mut data, &t).unwrap();
        assert_eq!(data, unhex(pt));
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    fn apple_silicon_has_the_instructions() {
        assert!(hw::available());
        assert!(AesGcm::new(&[0; 16]).hw);
    }

    /// FIPS 197 appendix C.1, through the counter: E(K, P) is the key
    /// stream of the counter block P.
    #[test]
    fn fips197() {
        for g in both("000102030405060708090a0b0c0d0e0f") {
            let p: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
                .try_into()
                .unwrap();
            let c = u32::from_be_bytes(p[12..].try_into().unwrap());
            let mut block = p;
            block[12..].fill(0);
            let mut out = [0; 16];
            g.ctr(&block, c, &mut out);
            assert_eq!(out[..], unhex("69c4e0d86a7b0430d8cdb78070b4c55a")[..]);
        }
    }

    /// McGrew and Viega's test cases 1 to 4.
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
    }

    /// A 12-byte nonce with AAD and a partial block: NIST's GCM validation
    /// vectors (gcmEncryptExtIV128, IVlen 96, PTlen 408, AADlen 160,
    /// Count 0), and one with AAD alone (PTlen 0, AADlen 128, Count 0).
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
    }

    /// A changed tag, ciphertext, AAD or nonce is refused, and the data is
    /// left the ciphertext it came as.
    #[test]
    fn rejects_forgeries() {
        let nonce = [7; 12];
        let mut aad = [0xfe, 0xed, 0xfa, 0xce];
        for g in both("feffe9928665731c6d6a8f9467308308") {
            let mut data = [0x5a; 300];
            let mut tag = g.seal(&nonce, &aad, &mut data).unwrap();
            let ct = data;
            tag[3] ^= 1;
            let bad_tag = g.open(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_tag, Err(Error::Forged)));
            tag[3] ^= 1;
            data[57] ^= 0x80;
            let bad_ct = g.open(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_ct, Err(Error::Forged)));
            data[57] ^= 0x80;
            assert_eq!(data, ct);
            aad[0] ^= 1;
            let bad_aad = g.open(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_aad, Err(Error::Forged)));
            aad[0] ^= 1;
            let bad_nonce = g.open(&[8; 12], &aad, &mut data, &tag);
            assert!(matches!(bad_nonce, Err(Error::Forged)));
            assert_eq!(data, ct);
            g.open(&nonce, &aad, &mut data, &tag).unwrap();
            assert_eq!(data, [0x5a; 300]);
        }
    }

    /// The instructions and the portable code agree on every length to
    /// past three eight-block turns, at every alignment, with AAD of each
    /// length to past two blocks.
    #[test]
    fn paths_agree() {
        let k = [0x5a; 16];
        let [fast, slow] = [AesGcm::new(&k), AesGcm::with(&k, false)];
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
            let ta = fast.seal(&nonce, aad, a).unwrap();
            let tb = slow.seal(&nonce, aad, b).unwrap();
            assert_eq!(a, b, "length {n}");
            assert_eq!(ta, tb, "length {n}");
            slow.open(&nonce, aad, a, &ta).unwrap();
            fast.open(&nonce, aad, b, &tb).unwrap();
            assert_eq!(a, b);
        }
    }

    /// The 32-bit counter wraps the same way on both paths, and only the
    /// counter: block 6 of a run from 2^32 - 6 is counter 0.
    #[test]
    fn counter_wraps() {
        let k = [0x11; 16];
        let [fast, slow] = [AesGcm::new(&k), AesGcm::with(&k, false)];
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

    /// CTR alone, as tag masks and a refused open use it, agrees on every
    /// length: whole groups of four blocks, the blocks after, a part.
    #[test]
    fn ctr_paths_agree() {
        let k = [0x77; 16];
        let [fast, slow] = [AesGcm::new(&k), AesGcm::with(&k, false)];
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

    /// The one-pass seal and open wrap the 32-bit counter as CTR does, and
    /// agree with the portable CTR and GHASH: two eight-block turns and
    /// five blocks after.
    #[test]
    fn stitched_counter_wraps() {
        if !hw::available() {
            return;
        }
        let k = [0x11; 16];
        let [fast, slow] = [AesGcm::new(&k), AesGcm::with(&k, false)];
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
        let k = [0x42; 16];
        let [fast, slow] = [AesGcm::new(&k), AesGcm::with(&k, false)];
        let mut a = Vec::new();
        a.resize(16384 + 5, 0x91);
        // rr: escape(copy): the same record, sealed by the other path.
        let mut b = a.clone();
        let aad = [0x17; 13];
        let ta = fast.seal(&[1; 12], &aad, &mut a).unwrap();
        let tb = slow.seal(&[1; 12], &aad, &mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(ta, tb);
    }

    /// One TLS record of 16 KiB with its 5-byte header as AAD.
    #[bench]
    fn seal_16k(b: &mut Bencher) {
        let g = AesGcm::new(&[7; 16]);
        let mut record = Vec::new();
        record.resize(16384, 0x17);
        let aad = [0x17, 3, 3, 0x40, 0x11];
        b.iter(|| g.seal(&[9; 12], &aad, &mut record).unwrap());
    }
}
