//! RSA signature verification (RFC 8017): RSASSA-PKCS1-v1_5, which
//! certificates use, and RSASSA-PSS with MGF1 and a salt as long as the
//! hash, which TLS 1.3's CertificateVerify uses (RFC 9846 4.3.3); with
//! SHA-256, SHA-384 or SHA-512, as the Web PKI allows.
//!
//! The key, the digest and the signature are public, so the arithmetic
//! is not constant time; what an attacker controls is bounded instead:
//! moduli of 2048 to 8192 bits, as webpki takes them for TLS servers
//! (ring_algs.rs) and Go's TLS does, and exponents of at most 33 bits,
//! as BoringSSL allows, so one verification costs at most 33 squarings
//! of 8192 bits. Numbers are little-endian 64-bit limbs, multiplied in
//! the Montgomery domain.
//!
//! The arithmetic has a file for each width of modulus, with numbers of
//! its own limbs: bits2048.rs, bits3072.rs, bits4096.rs and bits8192.rs
//! hold moduli of up to 32, 48, 64 and 128 limbs, the sizes keys have,
//! and a verification takes the narrowest that holds its key. rr has no
//! const generics, and numbers as wide as 8192 bits for every key would
//! zero and copy limbs a 2048-bit key does not use. A modulus narrower
//! than its file's width, as one of 2049 bits in bits3072.rs, works on
//! the limbs it has, with R = 2^(64 limbs). registry/rsa/rsa-gen.py in
//! rr's repository writes the four from one template.
//!
//! What is verified is a digest that names its hash (digest::Digest),
//! never bytes of any length, and PSS's MGF1 takes the same hash. The
//! answer is a Result that says which part is wrong:
//!
//! ```text
//! let digest = sha256::digest(message);
//! rsa::verify_pss(modulus, exponent, &Digest::Sha256(&digest), signature)?;
//! ```

use crate::base::digest::Digest;
use crate::base::sha256;
use crate::base::sha384;

mod bits2048;
mod bits3072;
mod bits4096;
mod bits8192;

/// Why a signature does not verify.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// The key is out of bounds: a modulus of 2048 to 8192 bits, odd, and
    /// an odd exponent from 3 to 2^33 - 1.
    Key,
    /// The signature is not a number below the modulus, of its length.
    Encoding,
    /// The signature is not one of the digest under the key.
    Signature,
}

/// The hash a signature covers; PSS's MGF1 uses the same.
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

const MODULUS_BITS_MIN: usize = 2048;
const MODULUS_BITS_MAX: usize = 8192;
const EXPONENT_BITS_MAX: u32 = 33;
const BYTES_MAX: usize = MODULUS_BITS_MAX / 8;

/// DER of DigestInfo's SEQUENCE { AlgorithmIdentifier, OCTET STRING }
/// up to the digest (RFC 8017 9.2, note 1).
const SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_PREFIX: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_PREFIX: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// A public key, checked: an odd modulus of MODULUS_BITS_MIN to
/// MODULUS_BITS_MAX bits and an odd exponent from 3 to 2^33 - 1.
struct Key<'a> {
    /// The modulus's big-endian bytes, the first not zero.
    modulus: &'a [u8],
    bits: usize,
    e: u64,
}

/// The encoded message a signature must give: of a digest of the hash.
enum Encoding<'a> {
    Pkcs1(&'a Hash, &'a [u8]),
    Pss(&'a Hash, &'a [u8]),
}

impl Hash {
    /// The hash a digest names, and its bytes.
    fn of<'a>(digest: &Digest<'a>) -> (Hash, &'a [u8]) {
        match *digest {
            Digest::Sha256(bytes) => (Hash::Sha256, bytes),
            Digest::Sha384(bytes) => (Hash::Sha384, bytes),
            Digest::Sha512(bytes) => (Hash::Sha512, bytes),
        }
    }

    fn len(&self) -> usize {
        match self {
            Hash::Sha256 => sha256::DIGEST_BYTES,
            Hash::Sha384 => sha384::SHA384_BYTES,
            Hash::Sha512 => sha384::SHA512_BYTES,
        }
    }

    /// The digest of the parts one after another, in the first len()
    /// bytes.
    fn digest(&self, parts: &[&[u8]]) -> [u8; sha384::SHA512_BYTES] {
        let mut out = [0; sha384::SHA512_BYTES];
        match self {
            Hash::Sha256 => {
                let mut hash = sha256::Sha256::new();
                for part in parts {
                    hash.update(part);
                }
                for (byte, digest) in out.iter_mut().zip(hash.finish()) {
                    *byte = digest;
                }
            }
            Hash::Sha384 => {
                let mut hash = sha384::Sha384::new();
                for part in parts {
                    hash.update(part);
                }
                for (byte, digest) in out.iter_mut().zip(hash.finish()) {
                    *byte = digest;
                }
            }
            Hash::Sha512 => {
                let mut hash = sha384::Sha512::new();
                for part in parts {
                    hash.update(part);
                }
                out = hash.finish();
            }
        }
        out
    }
}

/// Ok when signature is an RSASSA-PKCS1-v1_5 signature of digest under
/// the key (modulus, exponent), both big-endian. The whole encoded
/// message is compared: 00 01 FF..FF 00 DigestInfo digest.
pub fn verify_pkcs1(
    modulus: &[u8],
    exponent: &[u8],
    digest: &Digest<'_>,
    signature: &[u8],
) -> Result<(), Error> {
    let key = Key::new(modulus, exponent).ok_or(Error::Key)?;
    let (hash, bytes) = Hash::of(digest);
    key.verify(signature, &Encoding::Pkcs1(&hash, bytes))
}

/// Ok when signature is an RSASSA-PSS signature of digest under the key
/// (modulus, exponent), with MGF1 of the digest's hash and a salt of its
/// length (RFC 8017 9.1.2).
pub fn verify_pss(
    modulus: &[u8],
    exponent: &[u8],
    digest: &Digest<'_>,
    signature: &[u8],
) -> Result<(), Error> {
    let key = Key::new(modulus, exponent).ok_or(Error::Key)?;
    let (hash, bytes) = Hash::of(digest);
    key.verify(signature, &Encoding::Pss(&hash, bytes))
}

impl Encoding<'_> {
    /// Whether em, signature^e mod m as the modulus's bytes, is this
    /// encoding under a modulus of bits.
    #[must_use]
    fn matches(&self, em: &mut [u8], bits: usize) -> bool {
        match self {
            Encoding::Pkcs1(hash, digest) => pkcs1_matches(em, hash, digest),
            Encoding::Pss(hash, digest) => pss_matches(em, bits, hash, digest),
        }
    }
}

/// Whether em is 00 01 FF..FF 00 DigestInfo digest.
fn pkcs1_matches(em: &[u8], hash: &Hash, digest: &[u8]) -> bool {
    let prefix = match hash {
        Hash::Sha256 => &SHA256_PREFIX,
        Hash::Sha384 => &SHA384_PREFIX,
        Hash::Sha512 => &SHA512_PREFIX,
    };
    // A 2048-bit key leaves 256 - 3 - 19 - 64 bytes of padding at least.
    let Some(padding) = em.len().checked_sub(3 + prefix.len() + digest.len()) else {
        return false;
    };
    let Some(([0, 1], rest)) = em.split_first_chunk::<2>() else {
        return false;
    };
    let (ones, rest) = rest.split_at(padding.min(rest.len()));
    let Some(([0], rest)) = rest.split_first_chunk::<1>() else {
        return false;
    };
    let (info, rest) = rest.split_at(prefix.len().min(rest.len()));
    ones.iter().all(|byte| *byte == 0xff) && info == prefix && rest == digest
}

/// Whether em, under a modulus of bits, is a PSS encoding of digest
/// with MGF1 of hash and a salt of the hash's length (RFC 8017 9.1.2).
#[must_use]
fn pss_matches(em: &mut [u8], bits: usize, hash: &Hash, digest: &[u8]) -> bool {
    let length = hash.len();
    // EM has emBits = modBits - 1 bits. When those fill whole bytes the
    // integer's first byte, one more, must be zero.
    let em_bits = bits - 1;
    let em = match em {
        [0, rest @ ..] if em_bits.is_multiple_of(8) => rest,
        [_, ..] if em_bits.is_multiple_of(8) => return false,
        [..] => em,
    };
    // The bits above emBits in the first byte are zero, and stay out of
    // the comparison after the mask.
    let top = 0xff_u8 >> (8 * em.len() - em_bits);
    let Some((last, rest)) = em.split_last_mut() else {
        return false;
    };
    if *last != 0xbc {
        return false;
    }
    let Some(db_length) = rest.len().checked_sub(length) else {
        return false;
    };
    let (db, h) = rest.split_at_mut(db_length);
    let Some(first) = db.first() else {
        return false;
    };
    if *first & !top != 0 {
        return false;
    }
    mgf1_xor(hash, h, db);
    if let Some(byte) = db.first_mut() {
        *byte &= top;
    }
    // DB = 00..00 01 salt.
    let Some(zeros) = db.len().checked_sub(length + 1) else {
        return false;
    };
    let (padding, tail) = db.split_at(zeros);
    let Some((1, salt)) = tail.split_first().map(|(one, salt)| (*one, salt)) else {
        return false;
    };
    if padding.iter().any(|byte| *byte != 0) {
        return false;
    }
    let expected = hash.digest(&[&[0; 8], digest, salt]);
    expected.get(..length) == Some(&*h)
}

/// db ^= MGF1(seed) (RFC 8017 B.2.1): the hash of seed and a 32-bit
/// counter, block by block. db is under 1024 bytes, so the counter is
/// too.
fn mgf1_xor(hash: &Hash, seed: &[u8], db: &mut [u8]) {
    for (counter, chunk) in (0_u32..).zip(db.chunks_mut(hash.len())) {
        let mask = hash.digest(&[seed, &counter.to_be_bytes()]);
        for (byte, bits) in chunk.iter_mut().zip(mask) {
            *byte ^= bits;
        }
    }
}

impl<'a> Key<'a> {
    /// The key from its big-endian integers, leading zeros allowed; None
    /// outside the bounds the type states.
    fn new(modulus: &'a [u8], exponent: &[u8]) -> Option<Key<'a>> {
        let modulus = strip(modulus);
        let exponent = strip(exponent);
        if modulus.len() > BYTES_MAX || exponent.len() > 8 {
            return None;
        }
        let e = exponent
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
        if e < 3 || e & 1 == 0 || e >> EXPONENT_BITS_MAX != 0 {
            return None;
        }
        let (first, last) = (modulus.first()?, modulus.last()?);
        let bits = 8 * modulus.len() - first.leading_zeros() as usize;
        if !(MODULUS_BITS_MIN..=MODULUS_BITS_MAX).contains(&bits) || last & 1 == 0 {
            return None;
        }
        Some(Key { modulus, bits, e })
    }

    /// Ok when signature^e mod m is the encoding, in the arithmetic of
    /// the narrowest width that holds the modulus.
    fn verify(&self, signature: &[u8], encoding: &Encoding<'_>) -> Result<(), Error> {
        let limbs = self.modulus.len().div_ceil(8);
        if limbs <= bits2048::LIMBS {
            bits2048::verify(self, signature, encoding)
        } else if limbs <= bits3072::LIMBS {
            bits3072::verify(self, signature, encoding)
        } else if limbs <= bits4096::LIMBS {
            bits4096::verify(self, signature, encoding)
        } else {
            bits8192::verify(self, signature, encoding)
        }
    }
}

/// -m^-1 mod 2^64 of an odd m's low limb, by Newton's iteration for
/// m^-1: each step doubles the bits that are right, from 3 (m m = 1 mod
/// 8 for odd m) to 96.
fn negative_inverse(low: u64) -> u64 {
    let mut inverse = low;
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2_u64.wrapping_sub(low.wrapping_mul(inverse)));
    }
    inverse.wrapping_neg()
}

/// A sum of products of two limbs, three words: a column of at most
/// 256 of them, two for each limb of 8192 bits, under 2^136, with what
/// the column below carries in, stays below 2^137, so top never wraps.
struct Column {
    low: u128,
    top: u64,
}

impl Column {
    fn new() -> Column {
        Column { low: 0, top: 0 }
    }

    /// The products of each first limb with the second's from its end:
    /// these here, other into sum. All four have one length.
    #[inline(always)]
    fn add_both(&mut self, these: (&[u64], &[u64]), sum: &mut Column, other: (&[u64], &[u64])) {
        let pairs = these.0.iter().zip(these.1.iter().rev());
        let others = other.0.iter().zip(other.1.iter().rev());
        for ((x, y), (p, q)) in pairs.zip(others) {
            self.add(*x, *y);
            sum.add(*p, *q);
        }
    }

    #[inline(always)]
    fn add(&mut self, x: u64, y: u64) {
        let product = u128::from(x).wrapping_mul(u128::from(y));
        let (sum, carry) = self.low.overflowing_add(product);
        self.low = sum;
        self.top = self.top.wrapping_add(u64::from(carry));
    }

    #[inline(always)]
    fn add_column(&mut self, other: &Column) {
        let (sum, carry) = self.low.overflowing_add(other.low);
        self.low = sum;
        self.top = self
            .top
            .wrapping_add(other.top)
            .wrapping_add(u64::from(carry));
    }

    /// The low word.
    #[inline(always)]
    fn word(&self) -> u64 {
        // rr: escape(cast): the low 64 bits; shift moves the rest down.
        self.low as u64
    }

    /// Down one word, for the next column.
    #[inline(always)]
    fn shift(&mut self) {
        self.low = (self.low >> 64) | (u128::from(self.top) << 64);
        self.top = 0;
    }
}

/// Without leading zero bytes.
fn strip(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    bytes.get(zeros..).unwrap_or_default()
}

/// Big-endian bytes into little-endian limbs; the caller bounds the
/// bytes by the limbs.
fn load(bytes: &[u8], limbs: &mut [u64]) {
    for (limb, chunk) in limbs.iter_mut().zip(bytes.rchunks(8)) {
        *limb = chunk
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
    }
}

/// Whether a < b, for limbs of the same count.
fn below(a: &[u64], b: &[u64]) -> bool {
    a.iter().rev().lt(b.iter().rev())
}

// The limb arithmetic below wraps instead of checking: each sum and
// product is bounded in its comment, and the checks would cost a large
// part of the verification's time.

/// a = a - b, dropping the borrow: the callers know a + 2^(64n) > b.
fn subtract(a: &mut [u64], b: &[u64]) {
    let mut borrow = false;
    for (word, y) in a.iter_mut().zip(b) {
        let x = *word;
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        *word = d;
        borrow = b1 | b2;
    }
}

/// out = a 2^shift, for shift below 64 and a that fits after it.
fn shift_left(a: &[u64], shift: u32, out: &mut [u64]) {
    let mut below_word = 0;
    for (word, x) in out.iter_mut().zip(a) {
        *word = low((((u128::from(*x) << 64) | u128::from(below_word)) << shift) >> 64);
        below_word = *x;
    }
}

/// out = a / 2^shift, for shift below 64 and a multiple of 2^shift.
fn shift_right(a: &[u64], shift: u32, out: &mut [u64]) {
    let mut above = 0;
    for (word, x) in out.iter_mut().zip(a).rev() {
        *word = low(((u128::from(above) << 64) | u128::from(*x)) >> shift);
        above = *x;
    }
}

/// The low 64 bits.
fn low(x: u128) -> u64 {
    // rr: escape(cast): callers take the high bits apart, or know them 0.
    x as u64
}

/// Any bytes as a key, a digest and a signature: both verifications
/// answer without a panic, on keys of any size the input gives them.
#[cfg(fuzzing)]
pub fn fuzz_verify(input: &[u8]) {
    let Some((&[choice, split], rest)) = input.split_first_chunk::<2>() else {
        return;
    };
    let hash = match choice % 3 {
        0 => Hash::Sha256,
        1 => Hash::Sha384,
        _ => Hash::Sha512,
    };
    let (exponent, rest) = rest.split_at(usize::from(choice / 3).min(rest.len()));
    let (digest, rest) = rest.split_at(hash.len().min(rest.len()));
    let modulus_length = rest.len() / 2 + usize::from(split % 3);
    let (modulus, signature) = rest.split_at(modulus_length.min(rest.len()));
    let Some(digest) = fuzz_digest(&hash, digest) else {
        return;
    };
    // rr: escape(discard): any answer will do; a panic is the failure.
    let _: Result<(), Error> = verify_pkcs1(modulus, exponent, &digest, signature);
    // rr: escape(discard): as above.
    let _: Result<(), Error> = verify_pss(modulus, exponent, &digest, signature);
}

/// bytes as a digest of hash, if they are its length.
#[cfg(fuzzing)]
fn fuzz_digest<'a>(hash: &Hash, bytes: &'a [u8]) -> Option<Digest<'a>> {
    Some(match hash {
        Hash::Sha256 => Digest::Sha256(bytes.try_into().ok()?),
        Hash::Sha384 => Digest::Sha384(bytes.try_into().ok()?),
        Hash::Sha512 => Digest::Sha512(bytes.try_into().ok()?),
    })
}

/// Any bytes as a signature under one 2048-bit key: the decoding of
/// the encoded message after the exponentiation answers without a panic.
#[cfg(fuzzing)]
pub fn fuzz_signature(input: &[u8]) {
    let mut modulus = [0xff; 256];
    modulus[255] = 0xfd;
    let mut signature = [0; 256];
    for (byte, given) in signature.iter_mut().skip(1).zip(input) {
        *byte = *given;
    }
    let bytes = [0x5a; 64];
    for hash in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
        let Some(digest) = fuzz_digest(&hash, bytes.get(..hash.len()).unwrap_or_default()) else {
            return;
        };
        for exponent in [&[3][..], &[1, 0, 1]] {
            // rr: escape(discard): any answer will do; a panic is the
            // failure.
            let _: Result<(), Error> = verify_pkcs1(&modulus, exponent, &digest, &signature);
            // rr: escape(discard): as above.
            let _: Result<(), Error> = verify_pss(&modulus, exponent, &digest, &signature);
            // rr: escape(discard): as above.
            let _: Result<(), Error> = verify_pss(&modulus, exponent, &digest, input);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Encoding, Error, Hash, Key, bits2048, bits3072, bits4096, bits8192};
    use crate::base::digest::Digest;
    use alloc::vec::Vec;
    use test::Bencher;

    /// bytes as a digest of hash, or None when they are not its length.
    fn digest<'a>(hash: &Hash, bytes: &'a [u8]) -> Option<Digest<'a>> {
        Some(match hash {
            Hash::Sha256 => Digest::Sha256(bytes.try_into().ok()?),
            Hash::Sha384 => Digest::Sha384(bytes.try_into().ok()?),
            Hash::Sha512 => Digest::Sha512(bytes.try_into().ok()?),
        })
    }

    /// Whether signature verifies under PKCS #1 for the digest of hash in
    /// bytes, which a length not the hash's never does.
    fn verify_pkcs1(m: &[u8], e: &[u8], hash: &Hash, bytes: &[u8], signature: &[u8]) -> bool {
        digest(hash, bytes).is_some_and(|d| super::verify_pkcs1(m, e, &d, signature).is_ok())
    }

    /// verify_pkcs1 for PSS.
    fn verify_pss(m: &[u8], e: &[u8], hash: &Hash, bytes: &[u8], signature: &[u8]) -> bool {
        digest(hash, bytes).is_some_and(|d| super::verify_pss(m, e, &d, signature).is_ok())
    }

    fn hex(text: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut digits = text.bytes().map(|c| char::from(c).to_digit(16).unwrap());
        while let (Some(high), Some(low)) = (digits.next(), digits.next()) {
            bytes.push(u8::try_from(high * 16 + low).unwrap());
        }
        bytes
    }

    /// Wycheproof's 2048-bit key of rsa_signature_2048_sha256 and
    /// rsa_pss_2048_sha256_mgf1_32, with its leading zero.
    const MODULUS: &str = "00a2b451a07d0aa5f96e455671513550514a8a5b462ebef717094fa1fee82224e637\
        f9746d3f7cafd31878d80325b6ef5a1700f65903b469429e89d6eac8845097b5ab393189db92512ed8a7711a\
        1253facd20f79c15e8247f3d3e42e46e48c98e254a2fe9765313a03eff8f17e1a029397a1fa26a8dce26f490\
        ed81299615d9814c22da610428e09c7d9658594266f5c021d0fceca08d945a12be82de4d1ece6b4c03145b5d\
        3495d4ed5411eb878daf05fd7afc3e09ada0f1126422f590975a1969816f48698bcbba1b4d9cae79d460d8f9\
        f85e7975005d9bc22c4e5ac0f7c1a45d12569a62807d3b9a02e5a530e773066f453d1f5b4c2e9cf7820283f7\
        42b9d5";
    /// SHA-256 of the empty message, which both files' case 1 signs.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// rsa_signature_2048_sha256 case 1.
    const PKCS1: &str = "840f5dac53106dd1f9c57219224cf51289290c42f20466875ba8e830ac5690e541536f\
        cc8ab03b731f82bf66d83f194e7e180b3963ec7a2f3f7904a7ce49aed47da4d4b79421eaf937d301b3e69616\
        9297b797c32c076a12be4de0b58e003c5123051a84a10c62f8dac2f42a8640008eb3c7cccd6760ff5b51b689\
        763922582845f048fb8150e5a7a6ca2eccc7bdc85349ad5b26c52137a79fa3fe5c29ab5cd7615013219c1941\
        b6708e9c3c23feff5febaf0c8ebca5750b54e3e6e99a3e876b396f27860b7f3ec4e9191703c6332d944f6f69\
        751167680c79c4f6b57f1cc8755d24b6ec158ccdbacdb23107a33cb6b332516c13274d1f9dccc21dced869e4\
        86";
    /// rsa_pss_2048_sha256_mgf1_32 case 1.
    const PSS: &str = "4f01e0c12b08625ecac89a69231906edf826380f37c959a96690d046316d68ffce9d5c47\
        1694fcebfc6b45534864689256e4fc81c78e583f675d0c94b449647451e81beff01a11a516d5e5ce3f1a9104\
        37cb8a3a5096b19fb15f4524a35b23d89cdba12cf5b71aac1047b28c562df7c5542c34ce23a182cf7e0e2319\
        34b17294799d44877a1d68ef1b8f073619b7618e6b7c22db20030d98cf591ffc3d4da5f58613ecd5ecfc3b40\
        a1d02f40891ca43695cd4c088b05a8054c89c595a47e274816f35384226f74459ee63e25a1bfc03c36049055\
        2ec38343f8ace502f065303b00bc0ec320711b211fde92e57feb9013c3609342495ec0d7cabdec21e54acc38";

    /// Wycheproof's PKCS #1 and PSS cases (rsa-wycheproof.py), with the
    /// digest of each message: valid ones verify, and the rest do not,
    /// among them a DigestInfo without its NULL, which some accept, and
    /// PSS signatures of another salt length or MGF1 hash.
    #[test]
    fn wycheproof() {
        let mut keys = Vec::new();
        let (mut pkcs1, mut pss) = (0, 0);
        for line in include_str!("rsa-wycheproof.txt").lines() {
            if line.starts_with('#') {
                continue;
            }
            let mut fields = [""; 7];
            let mut words = line.split(' ');
            for (slot, word) in fields.iter_mut().zip(&mut words) {
                *slot = word;
            }
            assert!(words.next().is_none(), "{line}");
            match fields {
                ["key", _, modulus, exponent, "", "", ""] => {
                    keys.push((hex(modulus), hex(exponent)))
                }
                [kind, bits, key, id, valid, digest, signature] => {
                    let hash = match bits {
                        "256" => Hash::Sha256,
                        "384" => Hash::Sha384,
                        _ => Hash::Sha512,
                    };
                    let (modulus, exponent) = &keys[key.parse::<usize>().unwrap()];
                    let signature = if signature == "-" {
                        Vec::new()
                    } else {
                        hex(signature)
                    };
                    let verify = if kind == "pkcs1" {
                        pkcs1 += 1;
                        verify_pkcs1
                    } else {
                        pss += 1;
                        verify_pss
                    };
                    let verified = verify(modulus, exponent, &hash, &hex(digest), &signature);
                    assert_eq!(verified, valid == "1", "{kind} {bits} tcId {id}");
                }
            }
        }
        assert_eq!((keys.len(), pkcs1, pss), (15, 326, 339));
    }

    /// A 2049-bit key with exponent 3, whose PSS encoding is a byte
    /// shorter than the modulus, and which signed "rr" by openssl 3.6:
    /// PSS with SHA-256 and PKCS #1 with SHA-384.
    #[test]
    fn odd_length_key() {
        let modulus = hex(
            "0171829bd120b4a4595cf7287bccbeb4b970b8711974b037438a329146a95e23c427043c1dcb8e\
             3b35e20830e96e8efe0b10de90020205039eb37095eb060b50cdf0e5cd8c2729c56ec2e85000852e\
             15df617fe5a260c90c7b3aa79ba728e72840ef897cc7135f5e332e06f905864e634a1f7997427ed2\
             644afcaaedab9f868d0dfbd3050500e842629bb65b7f1b0f108dc70994c9bc96c14d9bd17810c113\
             ece118cfe1915f6889055694c234afb2f460c6c5ebbb9b8f26878743fd844f1eabe0ef24eb4d26ed\
             2bc51948d1c73ad4e23566087fbf3a0aaf98633696a992be97d242fbc3febe56f90946cf4020fd87\
             8f1e294ace3c2c8333ab727ea7336f91a82b",
        );
        let pss = hex(
            "015e6a9fbb309b738043636f1a00661e4a2ad58e1cde2cbb4312562c06cd982a4bd2ff9ccb3c76\
             6fc50a37bf9979c56b55347af9f03e1b80d29c43c9f7cc4d4533a5196c975091d3ec7ca6b3f9139a\
             e38ed779b4aa53df2deb1826ebb3e856bd3d100138f1bd9973bf1d4ea2a95347c996e04cf3776c26\
             434fbb3ed96eddccdff25d9409729bf27f897a1a8a518bfd5b01dae60839acefc8eef7593addf669\
             9d3d6f347bdf7246d455f1641e3950bf9e4a75ed0b889357e10abe435d8a08a8f67cb914241d232c\
             923177b1c7ecc1934cf21956024c9b14815fa818d26e1056b67095d6b865175242b232bd009ac328\
             7d96e08d505118e9a651b8254a691079dd5e",
        );
        let pkcs1 = hex(
            "00e645abac1f61a70dc580b94296728bde2b7952c59db2d110586bff4fe171a77ebb9ad3808736\
             74e804bbd1defceaa242569d685727b714406d5a82826dccbb1345df449d22c5ff3f819e4d3be5f6\
             106c0dc7d7c3bac1755dd8de7a0fe66c96e0a3c39802c6d7aebd8e617cedfd7c1d6a1499af7ab09f\
             2a00c713e865e231e6e1288aa04bb62f3a1b319ca13c12b0bcdfa3ebb07330a4813521d26b6e2351\
             e9ef58c25914ad43c70d666119d770e777d7ae9bc969ca1dc84834127a6add8b376d0338ff862aac\
             c916405219e14f170cfda7d9c5311f2cfb6f259afcb0dcb4de7fdf758a5bee96483667f4203464d4\
             6fd6b2c4e48232e84cff211890313ba21372",
        );
        let sha256 = hex("597c28c381ef1feee61f3e9677a628b4cbd41cfb2539c8938062e1df2a882d39");
        let sha384 = hex(
            "6042949091f181d21bb7fd6c3389877cd1d8f2f32c4a97a4717f7b248d57f6dc\
             4c22d777121c05672112a8eb1c6142a6",
        );
        assert!(verify_pss(&modulus, &[3], &Hash::Sha256, &sha256, &pss));
        assert!(verify_pkcs1(&modulus, &[3], &Hash::Sha384, &sha384, &pkcs1));
        assert!(!verify_pkcs1(&modulus, &[3], &Hash::Sha256, &sha256, &pss));
        assert!(!verify_pss(&modulus, &[3], &Hash::Sha384, &sha384, &pkcs1));
        assert!(!verify_pss(
            &modulus,
            &[1, 0, 1],
            &Hash::Sha256,
            &sha256,
            &pss
        ));
        assert!(!verify_pss(
            &modulus,
            &[3],
            &Hash::Sha256,
            &sha256,
            &pss[1..]
        ));
    }

    /// The valid cases with one thing changed at a time.
    #[test]
    fn rejects() {
        let (modulus, e, empty) = (hex(MODULUS), [1, 0, 1], hex(EMPTY));
        let mut longer = Vec::new();
        for (verify, good) in [verify_pkcs1, verify_pss].into_iter().zip([PKCS1, PSS]) {
            let signature = hex(good);
            assert!(verify(&modulus, &e, &Hash::Sha256, &empty, &signature));
            // Leading zeros of the key's integers are no part of them.
            assert!(verify(
                &modulus[1..],
                &[0, 1, 0, 1],
                &Hash::Sha256,
                &empty,
                &signature
            ));
            let mut digest = hex(EMPTY);
            digest[0] ^= 0x80;
            assert!(!verify(&modulus, &e, &Hash::Sha256, &digest, &signature));
            assert!(!verify(
                &modulus,
                &e,
                &Hash::Sha256,
                &empty[..31],
                &signature
            ));
            assert!(!verify(&modulus, &e, &Hash::Sha384, &empty, &signature));
            for exponent in [&[1, 0, 3][..], &[1], &[2], &[], &[1, 0, 0]] {
                assert!(!verify(
                    &modulus,
                    exponent,
                    &Hash::Sha256,
                    &empty,
                    &signature
                ));
            }
            let mut changed = hex(good);
            changed[255] ^= 1;
            assert!(!verify(&modulus, &e, &Hash::Sha256, &empty, &changed));
            // The signature is the modulus's length, and below it.
            longer.clear();
            longer.push(0);
            longer.extend_from_slice(&signature);
            assert!(!verify(&modulus, &e, &Hash::Sha256, &empty, &longer));
            assert!(!verify(
                &modulus,
                &e,
                &Hash::Sha256,
                &empty,
                &signature[1..]
            ));
            assert!(!verify(&modulus, &e, &Hash::Sha256, &empty, &modulus[1..]));
            assert!(!verify(&modulus, &e, &Hash::Sha256, &empty, &[0xff; 256]));
            assert!(!verify(&modulus, &e, &Hash::Sha256, &empty, &[]));
        }
    }

    /// An 8192-bit key, exponent 65537, made and used by openssl 3.6:
    /// genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:8192, then dgst
    /// -sign over "rr RSA-8192 test vector\n", with SHA-256 and PKCS #1,
    /// and with SHA-384 and PSS (-sigopt rsa_padding_mode:pss
    /// rsa_pss_saltlen:digest rsa_mgf1_md:sha384). It is x509's test
    /// rsa8192root.
    const MODULUS_8192: &str = "d32aeb666756a20e0fb6f3f73b6492cb47a261bcbceed02843ad99264ce99a977afa54fa73566e07\
        be627c6b74c54fe32d02b9587905b8002ae03ecf2d61f4a73151c0c69b90a260df8a9b46b245d1f8\
        68e87f6394d13c5ec6067daa52dc254c374a83f3ff2e428804f086b9435a4006d549027f0bab268b\
        f79e5fddc85f321a7b81adefdd8d796d2c7f07e4b9f9ac3ffbfd218713007efcbb38dd1688310df2\
        915b1cebdc7688c80e33ccae7bb0b2dac069a5f1894dc18f108f51db96598ecb69c3f2f6476aa240\
        03d6127a0295ba535bdc971b5a3c6a3f623bacca5daeaafff11fc4cb8e581a00a1b6c19c9e07203f\
        0da8fbccf7c1811fc03001d04dcb33d6115d5011e440dd09f5f67ad795003e9777152f7ff8b63c19\
        75872fd0a0d92ff7d16c09cefb7bc819c8f3e4a1a097c745e3a9d264cc35b2966c949bf8dca2ac9a\
        5643b4b1bd3d3c25d443234243b11beac048efb49aab1f1cad8ddeb9668e2f8f31e6a6da05579d65\
        7999f5e4052318007d615c29db5df51d178593eaf819f3c0efa1f2fc07eb085a47761de493f46f25\
        98a0ce6a90e4832f6453dd467d45bcce9f0c35f568be706d1bcb335da49bee16a6f8496a2bccb78f\
        aca99529344385ebc777d9bf0f6801b712f0418c1ebca5719fcdb6aba271b035d0d3b797abab601e\
        8fe88f7477df57f51ba9716813c003ec23b7234be42375b9c310ece4d6bdf703b6b99d503f8e675c\
        863c1df0cf3046e0f49e506c0eca4a87b25c57ef1bb374fa4e735368da792fce01c640a6809d0aa4\
        0ebe7da0afcd86b59ae4808eaa9ee42fa61c90f866763f5f36606f02b99197fc5cb658352b83c3b3\
        f5d5461b8db02ce96fea940895678e91b7aeb2a207c0fc9ef8a4ce4757fb7654f50c99cb401bafcf\
        50d8d96b4fe26b83db7444365f9f72f263aa58375ca4752f129a1cb5ed629953e4178633de170984\
        10b472b41c0d79922894690d1f91da69d801aa7ba1af278400bcaa8927f5ea75ef32cd2d2431d758\
        356dda4bd0f61afc5115db3738e54a72eef159fdd2e6fcc2451750aa893ff09510880f65f5229e57\
        f2d0cf208ab9fbebe9cb807411fbc880a93bb2ba1d942fa489cac3ed827d65c5e09ad55e4d9ddab8\
        2fc02d716854d54483f54fc41d9a48b63153dce5a63a081e964b2ce76dbe6d5db2b0263b63997a41\
        3c0c2aaf739d52445a74702f487e0e098b74557fa139fb51badfede3aa7915b2f35b701493580163\
        be8ef3a27d1e4823a0e40d33a79727eb6f2f93c671997afde717e9900cac693d03d2670b88701631\
        f0e5fc83c95374b78b2e612cc5418dc89df2385dd85fc8397a8256bdab4c496b8a1da9463d28e5eb\
        d1a2528841d468005b6bf534ecc5fdbbd809de858aaabc8e31a13c97f32d92dc7f0eb9982eaf2caa\
        5cc5d6fa3a1eb4223a486cd3a2f68348ddcc7630d7ee3e67";
    /// Its PKCS #1 signature, with SHA-256.
    const PKCS1_8192: &str = "89b3c39ee896df8ac2b0de9bb8429a25aea6f17620b103760913ba23c480b2d56827eefc989095a0\
        3939ced6796162e83508c85925a438680c9fbc6e869a85b0d3e35d528a3d29c9cadd66e232311e8b\
        239be886d9d7a9cb84d3fbced59382d45e3328fbe2b755fbab404485c54b8f13fb9bf19c7ccb7348\
        b5af8e55d51191c0924b2b189141a92416e5ce0c548a0ea1fb1cb2e0da944285194734d8f14b219f\
        7b69f4080326ae255029e917da2fec2f959e6c51b1a896e17c62a1e538fd0dc124cb0f4187ec0795\
        9aff5f618b2e1c83ec80028bb20bf2c65ee8f57b2d5bdb1866093d678851edb92e74eb1dc55bfe12\
        aac01d6a7655c81db7ba589ee7807c1b64c849e7fc5cd02a84fbfe008227d3db35cb749dd94fc5a6\
        2798b6ec004b0836ff578e86738a1c46817b5315e63557643578d007b39f69ad0cb2e87ac0bfedec\
        3b6e489b4a5056fa660c947917b208f4d86eb60daec3db41ac3d1405ee28c3bab07158b4c5acda65\
        1c4aefccb8680d50261f5f853e9a8af16b8c03c6802e37d6f2c83b1d3521220419921910429e0b70\
        15e92a0fea6faea35d0749eddf81b433f9c9c1504adaf87babf02da7f0228d4c6e6da4dc7773ba65\
        a4440ef86510040175437ffac766e3b3b33bbb4621f63655d8fd83029048c53cdd06278dfd1c0a8a\
        f14c348d9b0a29ef675dcba6fcc2be6516abf0a199d5fc9bcebd50c48541d2f2dc29e0a0e74f6b69\
        1ff38cb976fbac6d7dd7318dbf73c31e66069eb0df0e23cd1ad9501583fa07610e9b43d3c052b414\
        6774098ed11fd19ebcc406627add7fdcda1cb1a9837bf4174dc8d64c64c359ad6d55bb0b0297a9b3\
        0a1f83e3dba7f740f92d8fad6ffdf0e211eedc3a1f520ccb11a2d446b0d81cd6ff136970f0d87ff2\
        f3dd2d90ab86098add5885d784c78e7e918eb4ebdfd8d5d8a648a17a92982d0bde224763055a30a1\
        570e99ff0e726d7da985e793126e0da6a4fb84dc48bd9f9ed3054363d2f5c2112c1f204691e321d5\
        7a252dbc96976fd7a3bf13f2beca14c21b513e392356073aa579521c1abe296d18f7e284407e85ae\
        b3a49cf8bae7ebd6279c2b97fb43d92f785330aa127ec5f76ae8bd776600dba92f37391e16725427\
        ca9a2308400e5f34d39b793acc9c6b44497848a91364b07a65a4160550dff418eff44e9716d6630b\
        393eaba7b84b88ba92c9b2ce1f698c11b468fb734876a4be7dd77e4efe82601d5a9e5c0de29853dc\
        82b4c1ab751521be8fde4097d8ad66bfbadfea3fb5bcd659c5042ca4221a27495f99c7601df1458f\
        e2df0b0a1a3e92688e3c2ac056a99c50d3c9b355922e084af17f412642dbed3f0fcbca3b56c8a8c9\
        633745bdc07456991c14c5eedddfd8d3c176d95dc5b51a113b3d5b261ec062fb642e64ad722927f0\
        35f983ff35a7f088fea4f11b50eaa3777753a7347a8e7923";
    /// Its PSS signature, with SHA-384.
    const PSS_8192: &str = "649170ab89e6ba3b40afaf714205e5bf07cf857d2d15b201c3da8fadc5a4d199f997b4ee99e7af88\
        735bfc05e7b22a25ec5f49513118e3842535496fec5259fb7123b4d769cd14448b0ebfd4fd280bf7\
        c843e2f09182fe6def413054831a08f1ddc191c5451800cb02f05bafc6d01bd3311259c874875916\
        5b719ff50567e561e79ac744b0fa9143b5f1daf2c56f9ccd237657d85a8798b36995c11df485b2a4\
        f7816d14e0aee94e8708bdbe43a2ba559f9c0d77a9409eb9dcfbcc0f44ff57bd5b15d159d56c98ad\
        28df2f8290af5c97f34ebb31344643bb78218c8535414030bbf521647273a3194bd6a983ac2b6057\
        aa7cebbb5ac16be9a298c33d42771d393d657363869a9932e0f455084452539709c3b09657f61095\
        f0e6be0448dec5cdf3b9ec6b7f81f00a47fa731035cfc1869f4c65937489109375d78d497d4976b5\
        9bd7f273020a5bd64144f7428d2b65ab050e27d271edd0bd4ea6f358ee91600f2bfa2cd684b03517\
        0eef7de46f604621b0fb38fa7e1aa1618ff44d4176baa31a65eeabf217215b50d697b1b07e827419\
        c91f80745700814e1fb7421d72b6db0e6f5ef79750ab925cea65d82191d094497521fd86a38e0440\
        feab76ec620c08707e5df7c66192326e3be497fa34e0e27dd5cee033d195e84f474090897776419b\
        bd224d271002fd12b6c62d0bfaeeb7a3ae7c1f7a7f8cac4031bd6bd6ce8974a085567cab4c4cdac8\
        c6acf9a630562986abd8870640625639e8eada715a119bb7206fa4677a71b71b2ad21bbafc45cae1\
        bd084f2187fa61d2469fe436ad17aa098fe66d26e865b8e91a921c5be6244ca54b1f0cba79592ccf\
        d525421ad8217aa43c08061aa010e35fc956f100c79cd04b7bf8025e11972dc38d2934a142479eaa\
        4dde8a8c76f8934dee4bd373d52c79a49226fea371e534cde817d71a1953d287a746c6012f2eb43f\
        f6e03e7243576f1e0d7cae3b6c1514b452fae481ba2c10f2cb6c1de0004d618603fd56be89b201cd\
        47a3ca03a3e9b0e6fa2a7e22a0b4c0930ab2a69e880bd824edc965a7cda9b9b4b542bfb63bd3d659\
        80c4e826146a4d78723d741c20a7c0342fb91cdf24747384e3da6c7725d9eafd13828dc3f1b7beb4\
        daae617a57ba6cb12c20c2929db1bda356aee2e49151dd77a3f8b8d50cbe211c8075cc4680d795fc\
        67c7c87c033550cf9ca68c3f1920e4266ae0d1140f0337abdaa1c3aec5d7254412cd568013d876b2\
        100b83d809c75efe4151b5ffa0dcc7fa84ca16c972b7c7f964ec5d88772e906ae4a4ce45882229e7\
        014b5bf007253aa90a3b44176bd7a007ed44a75ac838982f1e87eab3e71f6e46cd49d1a422fcb276\
        2bf7b2f10b81fd5589373263392f3bb41f6075f0825b8a65bee43ed102345176eb50b854d960a009\
        0143ed7e1de459ee5b9cc7ce54ba3b09fa37c167fb08ff04";
    /// SHA-256 of the message.
    const SHA256_8192: &str = "c5ff8eb61a0ba7fc9fc35f80753ba14cd65b9d7e180c3d9ef631e563f46c402b";
    /// SHA-384 of the message.
    const SHA384_8192: &str = "f0def41019e38082a9cd4dd079c3d8c277801d4a05b3016376e1d133c24f9d7e\
        c9540c96ad4f366c314134760d8260d1";

    /// The 8192-bit key's signatures verify, under their own hash and
    /// padding only.
    #[test]
    fn key_8192() {
        let (modulus, pkcs1, pss) = (hex(MODULUS_8192), hex(PKCS1_8192), hex(PSS_8192));
        let (sha256, sha384) = (hex(SHA256_8192), hex(SHA384_8192));
        let e = [1, 0, 1];
        assert!(verify_pkcs1(&modulus, &e, &Hash::Sha256, &sha256, &pkcs1));
        assert!(verify_pss(&modulus, &e, &Hash::Sha384, &sha384, &pss));
        assert!(!verify_pss(&modulus, &e, &Hash::Sha256, &sha256, &pkcs1));
        assert!(!verify_pkcs1(&modulus, &e, &Hash::Sha384, &sha384, &pss));
        let mut changed = pss;
        changed[1000] ^= 1;
        assert!(!verify_pss(&modulus, &e, &Hash::Sha384, &sha384, &changed));
    }

    /// Each width takes a modulus narrower than itself, on the limbs it
    /// has, as verify gives the narrowest: the 2048-bit key verifies in
    /// all four. A modulus wider than a width is not its.
    #[test]
    fn widths() {
        let verifies = [
            bits2048::verify,
            bits3072::verify,
            bits4096::verify,
            bits8192::verify,
        ];
        let (modulus, empty, signature) = (hex(MODULUS), hex(EMPTY), hex(PKCS1));
        let key = Key::new(&modulus, &[1, 0, 1]).unwrap();
        let encoding = Encoding::Pkcs1(&Hash::Sha256, &empty);
        for (width, verify) in verifies.iter().enumerate() {
            assert_eq!(verify(&key, &signature, &encoding), Ok(()), "{width}");
        }
        let (modulus_8192, digest_8192) = (hex(MODULUS_8192), hex(SHA256_8192));
        let (key_8192, signature_8192) = (
            Key::new(&modulus_8192, &[1, 0, 1]).unwrap(),
            hex(PKCS1_8192),
        );
        let encoding_8192 = Encoding::Pkcs1(&Hash::Sha256, &digest_8192);
        for (width, verify) in verifies.iter().enumerate() {
            let verified = verify(&key_8192, &signature_8192, &encoding_8192);
            assert_eq!(verified.is_ok(), width == 3, "{width}");
        }
    }

    /// Each failure says which part is wrong.
    #[test]
    fn errors() {
        let (modulus, empty, signature) = (hex(MODULUS), hex(EMPTY), hex(PSS));
        let digest: [u8; 32] = empty.try_into().unwrap();
        let good = Digest::Sha256(&digest);
        assert_eq!(
            super::verify_pss(&modulus, &[1, 0, 1], &good, &signature),
            Ok(())
        );
        let short = &modulus[..200];
        assert_eq!(
            super::verify_pss(short, &[1, 0, 1], &good, &signature),
            Err(Error::Key)
        );
        assert_eq!(
            super::verify_pss(&modulus, &[2], &good, &signature),
            Err(Error::Key)
        );
        let cut = &signature[1..];
        assert_eq!(
            super::verify_pss(&modulus, &[1, 0, 1], &good, cut),
            Err(Error::Encoding)
        );
        let above = [0xff; 256];
        assert_eq!(
            super::verify_pss(&modulus, &[1, 0, 1], &good, &above),
            Err(Error::Encoding)
        );
        let other = Digest::Sha256(&[0; 32]);
        let refused = super::verify_pss(&modulus, &[1, 0, 1], &other, &signature);
        assert_eq!(refused, Err(Error::Signature));
        let pkcs1 = super::verify_pkcs1(&modulus, &[1, 0, 1], &good, &signature);
        assert_eq!(pkcs1, Err(Error::Signature));
    }

    /// Moduli of 2048 to 8192 bits, odd; exponents odd, from 3 to 2^33 -
    /// 1. The numbers need not be keys: the bounds come first.
    #[test]
    fn key_bounds() {
        let mut modulus = [0xff; 1025];
        modulus[0] = 1;
        let e = [1, 0, 1];
        assert!(Key::new(&modulus[769..], &e).is_some());
        assert!(Key::new(&modulus[1..], &e).is_some());
        assert!(Key::new(&modulus, &e).is_none());
        assert!(Key::new(&modulus[770..], &e).is_none());
        modulus[769] = 0x7f;
        assert!(Key::new(&modulus[769..], &e).is_none());
        modulus[769] = 0x80;
        assert!(Key::new(&modulus[769..], &e).is_some());
        modulus[1024] = 0xfe;
        assert!(Key::new(&modulus[769..], &e).is_none());
        modulus[1024] = 0xff;
        assert!(Key::new(&[], &e).is_none());
        let modulus = &modulus[769..];
        for (exponent, valid) in [
            (&[3][..], true),
            (&[1, 0xff, 0xff, 0xff, 0xff], true),
            (&[0, 0, 0, 0, 0, 0, 0, 0, 3], true),
            (&[2, 0, 0, 0, 1], false),
            (&[1, 0, 0, 0, 0, 0, 0, 0, 1], false),
            (&[1], false),
            (&[4], false),
            (&[0], false),
        ] {
            assert_eq!(Key::new(modulus, exponent).is_some(), valid);
        }
    }

    /// One RSA-2048 PKCS #1 verification, as of a certificate.
    #[bench]
    fn verify_pkcs1_2048(b: &mut Bencher) {
        let (modulus, empty, signature) = (hex(MODULUS), hex(EMPTY), hex(PKCS1));
        b.iter(|| verify_pkcs1(&modulus, &[1, 0, 1], &Hash::Sha256, &empty, &signature));
    }

    /// One RSA-2048 PSS verification, as of a TLS 1.3 handshake.
    #[bench]
    fn verify_pss_2048(b: &mut Bencher) {
        let (modulus, empty, signature) = (hex(MODULUS), hex(EMPTY), hex(PSS));
        b.iter(|| verify_pss(&modulus, &[1, 0, 1], &Hash::Sha256, &empty, &signature));
    }

    /// The modulus, exponent, digest and signature of the first valid
    /// PKCS #1 case of Wycheproof's key at index.
    fn valid_case(index: usize) -> [Vec<u8>; 4] {
        let mut keys = 0;
        let mut key = [""; 7];
        for line in include_str!("rsa-wycheproof.txt").lines() {
            let mut fields = [""; 7];
            for (slot, word) in fields.iter_mut().zip(line.split(' ')) {
                *slot = word;
            }
            match fields {
                ["key", ..] => {
                    if keys == index {
                        key = fields;
                    }
                    keys += 1;
                }
                ["pkcs1", _, number, _, "1", digest, signature]
                    if number.parse::<usize>() == Ok(index) =>
                {
                    return [hex(key[2]), hex(key[3]), hex(digest), hex(signature)];
                }
                _ => {}
            }
        }
        panic!("no valid case of key {index}");
    }

    /// One RSA-3072 PKCS #1 verification, of Wycheproof's 3072-bit key.
    #[bench]
    fn verify_pkcs1_3072(b: &mut Bencher) {
        let [modulus, exponent, digest, signature] = valid_case(6);
        assert!(verify_pkcs1(
            &modulus,
            &exponent,
            &Hash::Sha256,
            &digest,
            &signature
        ));
        b.iter(|| verify_pkcs1(&modulus, &exponent, &Hash::Sha256, &digest, &signature));
    }

    /// One RSA-4096 PKCS #1 verification, of Wycheproof's 4096-bit key.
    #[bench]
    fn verify_pkcs1_4096(b: &mut Bencher) {
        let [modulus, exponent, digest, signature] = valid_case(11);
        assert!(verify_pkcs1(
            &modulus,
            &exponent,
            &Hash::Sha256,
            &digest,
            &signature
        ));
        b.iter(|| verify_pkcs1(&modulus, &exponent, &Hash::Sha256, &digest, &signature));
    }

    /// One RSA-8192 PKCS #1 verification.
    #[bench]
    fn verify_pkcs1_8192(b: &mut Bencher) {
        let (modulus, digest, signature) = (hex(MODULUS_8192), hex(SHA256_8192), hex(PKCS1_8192));
        b.iter(|| verify_pkcs1(&modulus, &[1, 0, 1], &Hash::Sha256, &digest, &signature));
    }

    /// One RSA-8192 PSS verification.
    #[bench]
    fn verify_pss_8192(b: &mut Bencher) {
        let (modulus, digest, signature) = (hex(MODULUS_8192), hex(SHA384_8192), hex(PSS_8192));
        b.iter(|| verify_pss(&modulus, &[1, 0, 1], &Hash::Sha384, &digest, &signature));
    }
}
