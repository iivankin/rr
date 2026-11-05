//! SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC
//! 5869). Whole blocks are compressed straight from the caller's input;
//! only a part block waits in the state. The CPU's SHA instructions run
//! where crate::sys::sha256 finds them, the portable rounds elsewhere.

/// The bytes of a digest.
pub const DIGEST_BYTES: usize = 32;
/// The bytes of one block the compression takes.
pub const BLOCK_BYTES: usize = 64;
/// The most bytes hkdf_expand writes: its counter is one byte.
pub const EXPAND_BYTES_MAX: usize = 255 * DIGEST_BYTES;
/// The bytes the padding gives the message's length in bits.
const LENGTH_BYTES: usize = 8;

const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// The round constants, which crate::sys::sha256 loads too.
pub const ROUND: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A hash in progress: the chaining state and the part block not yet
/// compressed.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK_BYTES],
    /// The bytes of block that hold message; always under BLOCK_BYTES.
    buffered: usize,
    /// The message's bytes so far.
    length: u64,
}

impl Sha256 {
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
        self.absorb(data, compress);
    }

    /// The digest of the message. It takes the hash, which padding ends.
    pub fn finish(self) -> [u8; DIGEST_BYTES] {
        self.pad(compress)
    }

    /// update with the compression given: the tests run both on each.
    fn absorb(&mut self, data: &[u8], compress: impl Fn(&mut [u32; 8], &[[u8; BLOCK_BYTES]])) {
        // A message of 2^61 bytes, past what SHA-256 is defined for, takes
        // decades to hash; the count wraps there as other hashes' do.
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
        if !blocks.is_empty() {
            compress(&mut self.state, blocks);
        }
        // rr: escape(copy, panic): the part block must outlive the caller's
        // buffer; as_chunks leaves fewer than BLOCK_BYTES.
        self.block[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// finish with the compression given.
    fn pad(mut self, compress: impl Fn(&mut [u32; 8], &[[u8; BLOCK_BYTES]])) -> [u8; DIGEST_BYTES] {
        assert!(self.buffered < BLOCK_BYTES);
        // rr: escape(panic): buffered is under BLOCK_BYTES after absorb.
        self.block[self.buffered] = 0x80;
        // rr: escape(panic): buffered + 1 is at most BLOCK_BYTES.
        self.block[self.buffered + 1..].fill(0);
        if self.buffered >= BLOCK_BYTES - LENGTH_BYTES {
            compress(&mut self.state, core::slice::from_ref(&self.block));
            self.block = [0; BLOCK_BYTES];
        }
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        for (byte, length) in self.block.iter_mut().rev().zip(bits.iter().rev()) {
            *byte = *length;
        }
        compress(&mut self.state, core::slice::from_ref(&self.block));
        let mut digest = [0; DIGEST_BYTES];
        for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        digest
    }
}

/// The digest of data in one call.
pub fn digest(data: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut hash = Sha256::new();
    hash.update(data);
    hash.finish()
}

/// HMAC-SHA256 in progress: both hashes keyed, so that one keyed value
/// can be cloned for each message under the same key.
#[derive(Clone)]
pub struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
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
        let mut inner = Sha256::new();
        inner.update(&pad);
        for byte in &mut pad {
            *byte ^= 0x36 ^ 0x5c;
        }
        let mut outer = Sha256::new();
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
    let mut hmac = Hmac::new(salt);
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
    let keyed = Hmac::new(key);
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

/// The hardware's compression, or the portable rounds without it.
fn compress(state: &mut [u32; 8], blocks: &[[u8; BLOCK_BYTES]]) {
    if !crate::sys::sha256::compress(state, blocks) {
        compress_portable(state, blocks);
    }
}

fn compress_portable(state: &mut [u32; 8], blocks: &[[u8; BLOCK_BYTES]]) {
    for block in blocks {
        let mut schedule = [0_u32; 64];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for at in 16..schedule.len() {
            // rr: escape(panic): at runs 16..64, so at - 16 to at are in the
            // 64-word schedule.
            let early = schedule[at - 15];
            // rr: escape(panic): as above.
            let late = schedule[at - 2];
            // rr: escape(panic): as above.
            let sum = schedule[at - 16].wrapping_add(schedule[at - 7]);
            let small0 = early.rotate_right(7) ^ early.rotate_right(18) ^ (early >> 3);
            let small1 = late.rotate_right(17) ^ late.rotate_right(19) ^ (late >> 10);
            // rr: escape(panic): as above.
            schedule[at] = sum.wrapping_add(small0).wrapping_add(small1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (word, constant) in schedule.iter().zip(&ROUND) {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(*word);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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
        BLOCK_BYTES, DIGEST_BYTES, EXPAND_BYTES_MAX, Hmac, Sha256, compress_portable, digest,
        hkdf_expand, hkdf_extract,
    };
    use alloc::vec::Vec;
    use test::Bencher;

    fn hex(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for pair in text.as_bytes().chunks(2) {
            let pair = core::str::from_utf8(pair).unwrap();
            bytes.push(u8::from_str_radix(pair, 16).unwrap());
        }
        bytes
    }

    /// The digest by the portable rounds alone, data split at split.
    fn portable(data: &[u8], split: usize) -> [u8; DIGEST_BYTES] {
        let (head, tail) = data.split_at(split);
        let mut hash = Sha256::new();
        hash.absorb(head, compress_portable);
        hash.absorb(tail, compress_portable);
        hash.pad(compress_portable)
    }

    /// Bytes 0, 1, 2 and on from start, as RFC 5869's case 2 has them.
    fn counting(start: u8) -> [u8; 80] {
        let mut bytes = [0; 80];
        for (byte, value) in bytes.iter_mut().zip(start..=u8::MAX) {
            *byte = value;
        }
        bytes
    }

    /// FIPS 180-4's examples and the million a's, through the selected
    /// compression and through the portable one, whole and split.
    #[test]
    fn fips_vectors() {
        let mut million = Vec::new();
        million.resize(1_000_000, b'a');
        for (data, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
            (
                &million[..],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ] {
            let expected = hex(expected);
            assert_eq!(digest(data)[..], expected[..]);
            assert_eq!(portable(data, data.len() / 3)[..], expected[..]);
            let mut hash = Sha256::new();
            for piece in data.chunks(997) {
                hash.update(piece);
            }
            assert_eq!(hash.finish()[..], expected[..]);
        }
    }

    /// The selected compression and the portable one agree on every
    /// length over three blocks and every split of it, so the padding
    /// and the part block are crossed at each offset by both.
    #[test]
    fn hardware_matches_portable() {
        let mut data = [0_u8; 3 * BLOCK_BYTES + 1];
        let mut byte = 1_u8;
        for slot in &mut data {
            byte = byte.wrapping_mul(73).wrapping_add(19);
            *slot = byte;
        }
        for length in 0..=data.len() {
            let data = &data[..length];
            let whole = portable(data, 0);
            for split in 0..=length {
                let (head, tail) = data.split_at(split);
                let mut hash = Sha256::new();
                hash.update(head);
                hash.update(tail);
                assert_eq!(hash.finish(), whole);
                assert_eq!(portable(data, split), whole);
            }
        }
        // Many blocks at once, from states that are not the initial one.
        let blocks = data.as_chunks::<BLOCK_BYTES>().0;
        for seed in [0, 1, 0x1234_5678, u32::MAX] {
            let mut expected = [seed; 8];
            compress_portable(&mut expected, blocks);
            let mut state = [seed; 8];
            if crate::sys::sha256::compress(&mut state, blocks) {
                assert_eq!(state, expected);
            }
        }
    }

    /// Every arm64 Mac has the instructions: the test above compared them.
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    fn hardware_runs_on_apple_silicon() {
        let mut state = [0; 8];
        assert!(crate::sys::sha256::compress(
            &mut state,
            &[[0; BLOCK_BYTES]]
        ));
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
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                &key4,
                &[0xcd; 50],
                "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            ),
            (
                &[0x0c; 20],
                b"Test With Truncation",
                "a3b6167473100ee06e0c796c2955552b",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a \
                  larger than block-size data. The key needs to be hashed \
                  before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ] {
            let expected = hex(expected);
            let mut hmac = Hmac::new(key);
            hmac.update(data);
            assert_eq!(hmac.finish()[..expected.len()], expected[..]);
        }
    }

    /// RFC 5869's cases 1 to 3: two and three output blocks, a long salt
    /// and info, and none at all.
    #[test]
    fn hkdf_vectors() {
        let short = [0x0b; 22];
        let (long, long_salt, long_info) = (counting(0x00), counting(0x60), counting(0xb0));
        for (input, salt, info, key, expected) in [
            (
                &short[..],
                &hex("000102030405060708090a0b0c")[..],
                &hex("f0f1f2f3f4f5f6f7f8f9")[..],
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                &long,
                &long_salt,
                &long_info,
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                &short,
                b"",
                b"",
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
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
