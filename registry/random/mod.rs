//! The system's randomness, as Go's crypto/rand and BoringSSL take it:
//! arc4random_buf on macOS, getrandom(2) on Linux, ProcessPrng on
//! Windows (sys.rs says why each). It never fails: a system that cannot
//! give randomness stops the program, as Go 1.24's Read and BoringSSL's
//! RAND_bytes do, rather than hand out bytes that are not random.
//!
//! A key is made from a Seed32 or a Seed64, which only seed32 and
//! seed64 make from the system (and for_tests in a test): a constant, a
//! counter or a test array cannot stand in for one where a key is made.
//! A seed is not Copy, Clone or Debug, is used once (the key takes it by
//! value, and into_bytes uses it up), and is wiped when dropped.
//!
//! The intended use:
//!
//! ```text
//! let secret = x25519::Secret::new(random::seed32());
//! let key = mlkem::DecapsulationKey::generate(random::seed64());
//! let mut nonce = [0; 12];
//! random::fill(&mut nonce);
//! ```

mod sys;

/// Bytes of a Seed32.
pub const SEED32_BYTES: usize = 32;
/// Bytes of a Seed64.
pub const SEED64_BYTES: usize = 64;

/// 32 bytes of the system's randomness, for one key.
pub struct Seed32 {
    bytes: [u8; SEED32_BYTES],
}

/// 64 bytes of the system's randomness, for one key.
pub struct Seed64 {
    bytes: [u8; SEED64_BYTES],
}

/// Fills out with the system's randomness.
pub fn fill(out: &mut [u8]) {
    sys::fill(out);
}

/// A new Seed32 from the system.
#[must_use]
pub fn seed32() -> Seed32 {
    let mut bytes = [0; SEED32_BYTES];
    sys::fill(&mut bytes);
    Seed32 { bytes }
}

/// A new Seed64 from the system.
#[must_use]
pub fn seed64() -> Seed64 {
    let mut bytes = [0; SEED64_BYTES];
    sys::fill(&mut bytes);
    Seed64 { bytes }
}

/// Overwrites a secret with zeros, by writes the compiler keeps though
/// nothing reads the bytes after them.
pub fn wipe(bytes: &mut [u8]) {
    sys::wipe(bytes);
}

/// wipe for 16-bit words, as a key's polynomials are.
pub fn wipe_u16(words: &mut [u16]) {
    sys::wipe_u16(words);
}

impl Seed32 {
    /// The bytes, for the key that takes the seed, which is used up:
    /// the key keeps them and wipes them.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SEED32_BYTES] {
        self.bytes
    }

    /// Given bytes as a seed: a standard's test vector. Only tests and
    /// fuzz targets have it.
    #[cfg(any(test, fuzzing))]
    pub fn for_tests(bytes: [u8; SEED32_BYTES]) -> Seed32 {
        Seed32 { bytes }
    }
}

impl Seed64 {
    /// The bytes, for the key that takes the seed, which is used up:
    /// the key keeps them and wipes them.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SEED64_BYTES] {
        self.bytes
    }

    /// Given bytes as a seed: a standard's test vector. Only tests and
    /// fuzz targets have it.
    #[cfg(any(test, fuzzing))]
    pub fn for_tests(bytes: [u8; SEED64_BYTES]) -> Seed64 {
        Seed64 { bytes }
    }
}

impl Drop for Seed32 {
    fn drop(&mut self) {
        sys::wipe(&mut self.bytes);
    }
}

impl Drop for Seed64 {
    fn drop(&mut self) {
        sys::wipe(&mut self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::{SEED32_BYTES, fill, seed32, seed64, wipe, wipe_u16};
    use alloc::vec::Vec;
    use test::Bencher;

    /// Bits set in bytes.
    fn ones(bytes: &[u8]) -> u32 {
        bytes.iter().map(|byte| byte.count_ones()).sum()
    }

    /// As a program uses it: seeds and buffers of every size from 0 to a
    /// megabyte (past getrandom's 32 MiB - 1 a call is not needed to show
    /// the loop: any short read goes round it), each different from the
    /// last and about half ones.
    #[test]
    fn fills() {
        let mut last = Vec::new();
        let mut buffer = Vec::new();
        for length in [0, 1, 7, 32, 255, 256, 257, 4096, 1 << 20] {
            buffer.clear();
            buffer.resize(length, 0);
            fill(&mut buffer);
            if length >= 32 {
                assert_ne!(buffer, last, "{length}");
                let bits = u32::try_from(8 * length).unwrap();
                let set = ones(&buffer);
                // Eight standard deviations of a fair coin's count.
                let spread = 4 * bits.isqrt() + 8;
                assert!(set.abs_diff(bits / 2) < spread, "{length}: {set} of {bits}");
            }
            core::mem::swap(&mut last, &mut buffer);
        }
        // A fill that covers part of a buffer leaves the rest.
        let mut part = [0; 64];
        fill(&mut part[..32]);
        assert_eq!(part[32..], [0; 32]);
    }

    /// Two seeds are never the same, and a seed is all its bytes.
    #[test]
    fn seeds() {
        let (a, b) = (seed32().into_bytes(), seed32().into_bytes());
        assert_ne!(a, b);
        assert_ne!(a, [0; SEED32_BYTES]);
        let (c, d) = (seed64().into_bytes(), seed64().into_bytes());
        assert_ne!(c, d);
        assert!(ones(&c) > 128);
    }

    #[test]
    fn wipes() {
        let mut bytes = [0xa5; 100];
        wipe(&mut bytes[1..]);
        assert_eq!(bytes[0], 0xa5);
        assert_eq!(bytes[1..], [0; 99]);
        let mut words = [0xa5a5; 9];
        wipe_u16(&mut words);
        assert_eq!(words, [0; 9]);
    }

    /// One seed for a key, from the system.
    #[bench]
    fn one_seed32(b: &mut Bencher) {
        b.iter(seed32);
    }
}
