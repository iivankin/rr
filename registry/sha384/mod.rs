//! SHA-384 (FIPS 180-4: SHA-512's rounds from other initial values, cut
//! to 48 bytes), HMAC-SHA384 (RFC 2104) and HKDF-SHA384 (RFC 5869).
//! Whole blocks are compressed straight from the caller's input; only a
//! part block waits in the state. The rounds run on SHA512 instructions
//! where sys finds them, as portable code elsewhere.

mod sys;

/// The bytes of a digest.
pub const DIGEST_BYTES: usize = 48;
/// The bytes of one block the compression takes.
pub const BLOCK_BYTES: usize = 128;
/// The most bytes hkdf_expand writes: its counter is one byte.
pub const EXPAND_BYTES_MAX: usize = 255 * DIGEST_BYTES;
/// The bytes the padding gives the message's length in bits.
const LENGTH_BYTES: usize = 16;

const INITIAL: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// The round constants, which sys loads too.
pub const ROUND: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// A hash in progress: the chaining state and the part block not yet
/// compressed.
#[derive(Clone)]
pub struct Sha384 {
    state: [u64; 8],
    block: [u8; BLOCK_BYTES],
    /// The bytes of block that hold message; always under BLOCK_BYTES.
    buffered: usize,
    /// The message's bytes so far.
    length: u64,
}

impl Sha384 {
    pub fn new() -> Self {
        Self {
            state: INITIAL,
            block: [0; BLOCK_BYTES],
            buffered: 0,
            length: 0,
        }
    }

    /// Adds data to the message; any split of it gives the same digest.
    #[cfg_attr(rr, rr::hot)]
    pub fn update(&mut self, data: &[u8]) {
        // 2^64 bytes take centuries to hash; the count wraps there.
        self.length = self.length.wrapping_add(data.len() as u64);
        let mut rest = data;
        if self.buffered > 0 {
            let taken = (BLOCK_BYTES - self.buffered).min(rest.len());
            let (head, tail) = rest.split_at(taken);
            let end = self.buffered + taken;
            // rr: escape(copy, panic): a part block waits for the rest of
            // it, and taken is at most what is free there.
            self.block[self.buffered..end].copy_from_slice(head);
            self.buffered = end;
            if end < BLOCK_BYTES {
                return;
            }
            compress(&mut self.state, core::slice::from_ref(&self.block));
            rest = tail;
        }
        let (blocks, tail) = rest.as_chunks::<BLOCK_BYTES>();
        compress(&mut self.state, blocks);
        // rr: escape(copy, panic): the part block must outlive the caller's
        // buffer; as_chunks leaves fewer than BLOCK_BYTES.
        self.block[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// The digest of the message. It takes the hash, which padding ends.
    pub fn finish(mut self) -> [u8; DIGEST_BYTES] {
        assert!(self.buffered < BLOCK_BYTES);
        // rr: escape(panic): buffered is under BLOCK_BYTES after update.
        self.block[self.buffered] = 0x80;
        // rr: escape(panic): buffered + 1 is at most BLOCK_BYTES.
        self.block[self.buffered + 1..].fill(0);
        if self.buffered >= BLOCK_BYTES - LENGTH_BYTES {
            compress(&mut self.state, core::slice::from_ref(&self.block));
            self.block = [0; BLOCK_BYTES];
        }
        let bits = (u128::from(self.length) << 3).to_be_bytes();
        for (byte, length) in self.block.iter_mut().rev().zip(bits.iter().rev()) {
            *byte = *length;
        }
        compress(&mut self.state, core::slice::from_ref(&self.block));
        let mut digest = [0; DIGEST_BYTES];
        for (bytes, word) in digest.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        digest
    }
}

/// The digest of data in one call.
pub fn digest(data: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hash = Sha384::new();
    hash.update(data);
    hash.finish()
}

/// HMAC-SHA384 in progress: both hashes keyed, so that one keyed value
/// can be cloned for each message under the same key.
#[derive(Clone)]
pub struct Hmac384 {
    inner: Sha384,
    outer: Sha384,
}

impl Hmac384 {
    pub fn new(key: &[u8]) -> Self {
        // A key longer than a block is hashed first, as RFC 2104 says.
        let hashed;
        let key = if key.len() > BLOCK_BYTES {
            hashed = digest(key);
            &hashed[..]
        } else {
            key
        };
        let mut pad = [0x36; BLOCK_BYTES];
        for (byte, secret) in pad.iter_mut().zip(key) {
            *byte ^= secret;
        }
        let mut inner = Sha384::new();
        inner.update(&pad);
        for byte in &mut pad {
            *byte ^= 0x36 ^ 0x5c;
        }
        let mut outer = Sha384::new();
        outer.update(&pad);
        Self { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(mut self) -> [u8; DIGEST_BYTES] {
        let inner = self.inner.finish();
        self.outer.update(&inner);
        self.outer.finish()
    }
}

/// HKDF-Extract: the pseudorandom key from salt and input keying
/// material. An empty salt stands for a block of zeros, as HMAC pads it.
pub fn hkdf_extract(salt: &[u8], input: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hmac = Hmac384::new(salt);
    hmac.update(input);
    hmac.finish()
}

/// HKDF-Expand: fills out from the pseudorandom key and info. False,
/// and out untouched, when out is longer than EXPAND_BYTES_MAX.
#[must_use]
pub fn hkdf_expand(key: &[u8; DIGEST_BYTES], info: &[u8], out: &mut [u8]) -> bool {
    if out.len() > EXPAND_BYTES_MAX {
        return false;
    }
    let keyed = Hmac384::new(key);
    let mut previous = [0; DIGEST_BYTES];
    for (counter, chunk) in (1..=u8::MAX).zip(out.chunks_mut(DIGEST_BYTES)) {
        // rr: escape(copy): each block starts from the keyed hashes, which
        // spares compressing the two key blocks again.
        let mut hmac = keyed.clone();
        if counter > 1 {
            hmac.update(&previous);
        }
        hmac.update(info);
        hmac.update(&[counter]);
        previous = hmac.finish();
        // rr: escape(panic): chunks_mut gives at most DIGEST_BYTES.
        chunk.copy_from_slice(&previous[..chunk.len()]);
    }
    true
}

fn compress(state: &mut [u64; 8], blocks: &[[u8; BLOCK_BYTES]]) {
    if sys::compress(state, blocks) {
        return;
    }
    for block in blocks {
        let mut schedule = [0_u64; 80];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
            *word = u64::from_be_bytes(*bytes);
        }
        for at in 16..schedule.len() {
            // rr: escape(panic): at runs 16..80, so at - 16 to at are in the
            // 80-word schedule.
            let early = schedule[at - 15];
            // rr: escape(panic): as above.
            let late = schedule[at - 2];
            // rr: escape(panic): as above.
            let sum = schedule[at - 16].wrapping_add(schedule[at - 7]);
            let small0 = early.rotate_right(1) ^ early.rotate_right(8) ^ (early >> 7);
            let small1 = late.rotate_right(19) ^ late.rotate_right(61) ^ (late >> 6);
            // rr: escape(panic): as above.
            schedule[at] = sum.wrapping_add(small0).wrapping_add(small1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (word, constant) in schedule.iter().zip(&ROUND) {
            let big1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(*word);
            let big0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(big0).wrapping_add(majority);
        }
        for (word, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(add);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_BYTES, DIGEST_BYTES, EXPAND_BYTES_MAX, Hmac384, Sha384, digest, hkdf_expand,
        hkdf_extract,
    };
    use alloc::vec::Vec;
    use test::Bencher;

    fn hex(text: &str) -> Vec<u8> {
        let nibble = |c: u8| char::from(c).to_digit(16).unwrap();
        let mut bytes = Vec::new();
        for pair in text.as_bytes().as_chunks::<2>().0 {
            let [high, low] = *pair;
            bytes.push(u8::try_from((nibble(high) << 4) | nibble(low)).unwrap());
        }
        bytes
    }

    /// Bytes start, start + 1 and on, as RFC 5869's case 2 has them.
    fn counting(start: u8) -> [u8; 80] {
        let mut bytes = [start; 80];
        for (byte, step) in bytes.iter_mut().zip(0..) {
            *byte = byte.wrapping_add(step);
        }
        bytes
    }

    /// FIPS 180-4's examples and the million a's, whole and in pieces.
    #[test]
    fn fips_vectors() {
        let mut million = Vec::new();
        million.resize(1_000_000, b'a');
        for (data, expected) in [
            (
                &b""[..],
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
                 4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                b"abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
                 1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05ab\
                 fe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2\
                 2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
            ),
            (
                &million[..],
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852\
                 7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
            ),
        ] {
            let expected = hex(expected);
            assert_eq!(digest(data)[..], expected[..]);
            let mut hash = Sha384::new();
            for piece in data.chunks(997) {
                hash.update(piece);
            }
            assert_eq!(hash.finish()[..], expected[..]);
        }
    }

    /// Every length over two blocks, split everywhere, gives the digest
    /// of one update: the part block and the padding at each offset.
    #[test]
    fn splits_agree() {
        let mut data = [0_u8; 2 * BLOCK_BYTES + 1];
        let mut byte = 1_u8;
        for slot in &mut data {
            byte = byte.wrapping_mul(73).wrapping_add(19);
            *slot = byte;
        }
        for length in 0..=data.len() {
            let data = &data[..length];
            let whole = digest(data);
            for split in 0..=length {
                let (head, tail) = data.split_at(split);
                let mut hash = Sha384::new();
                hash.update(head);
                hash.update(&[]);
                hash.update(tail);
                assert_eq!(hash.finish(), whole);
            }
        }
    }

    /// RFC 4231's cases 1 to 7: short, long and hashed keys, and case 5
    /// cut to 128 bits.
    #[test]
    fn hmac_vectors() {
        let key4 = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        for (key, data, expected) in [
            (
                &[0x0b; 20][..],
                &b"Hi There"[..],
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6\
                 82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47\
                 e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9feb\
                 e83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            ),
            (
                &key4,
                &[0xcd; 50],
                "3e8a69b7783c25851933ab6290af6ca77a9981480850009c\
                 c5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            ),
            (
                &[0x0c; 20],
                b"Test With Truncation",
                "3abf34c3503b2a23a46efc619baef897",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f\
                 3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a \
                  larger than block-size data. The key needs to be hashed \
                  before being used by the HMAC algorithm.",
                "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9a\
                 dccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            ),
        ] {
            let expected = hex(expected);
            let mut hmac = Hmac384::new(key);
            hmac.update(data);
            assert_eq!(hmac.finish()[..expected.len()], expected[..]);
        }
    }

    /// RFC 5869's three inputs under SHA-384, whose results Python's
    /// hmac and hashlib gave: one and two output blocks, a long salt and
    /// info, and none at all.
    #[test]
    fn hkdf_vectors() {
        let short = [0x0b; 22];
        let (long, long_salt, long_info) = (counting(0x00), counting(0x60), counting(0xb0));
        for (input, salt, info, key, expected) in [
            (
                &short[..],
                &hex("000102030405060708090a0b0c")[..],
                &hex("f0f1f2f3f4f5f6f7f8f9")[..],
                "704b39990779ce1dc548052c7dc39f303570dd13fb39f7ac\
                 c564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade",
                "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7\
                 48b6457763e4f0204fc5",
            ),
            (
                &long,
                &long_salt,
                &long_info,
                "b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c\
                 901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb",
                "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649ee\
                 bf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6\
                 f4c09c5500dca24a56222fea53d8967a8b2e",
            ),
            (
                &short,
                b"",
                b"",
                "10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cb\
                 c8e45b40068f8f0ba57cdb598af9dfa6963a96899af047e5",
                "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daa\
                 cc1cea5670415b52849c",
            ),
        ] {
            let derived = hkdf_extract(salt, input);
            assert_eq!(derived[..], hex(key)[..]);
            let expected = hex(expected);
            let mut out = [0; 82];
            let out = &mut out[..expected.len()];
            assert!(hkdf_expand(&derived, info, out));
            assert_eq!(out[..], expected[..]);
        }
    }

    /// An output past 255 blocks is refused before any byte is written;
    /// one at the limit is filled.
    #[test]
    fn hkdf_expand_limit() {
        let key = [0x42; DIGEST_BYTES];
        let mut out = [0xa5; EXPAND_BYTES_MAX + 1];
        assert!(!hkdf_expand(&key, b"", &mut out));
        assert!(out.iter().all(|byte| *byte == 0xa5));
        assert!(hkdf_expand(&key, b"", &mut out[..EXPAND_BYTES_MAX]));
        assert_eq!(out[EXPAND_BYTES_MAX], 0xa5);
        let mut first = [0; DIGEST_BYTES];
        assert!(hkdf_expand(&key, b"", &mut first));
        assert_eq!(out[..DIGEST_BYTES], first);
    }

    /// One 16 KiB buffer, as a file or a record is hashed.
    #[bench]
    fn digest_16k(b: &mut Bencher) {
        let data = [0x5a; 16 * 1024];
        b.iter(|| digest(&data));
    }
}
