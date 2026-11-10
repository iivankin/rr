//! A digest that names its hash, SHA-256, SHA-384 or SHA-512, at its length:
//! what a signature verifier (ecdsa, rsa) takes instead of bytes of any
//! length.
//!
//! A digest that names the hash that made it, at that hash's length:
//! what ecdsa and rsa verify a signature of. A signature is of a
//! digest, and bytes of any length would let a message, or a digest cut
//! or of another hash, pass for one; here each is a variant of its own
//! size, so that only a digest of the hash the signature names fits.
//!
//! ```text
//! let digest = sha256::digest(message);
//! ecdsa::verify(&ecdsa::Curve::P256, key, &Digest::Sha256(&digest), signature)?;
//! ```

// rr: checked(0.5.2)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none

/// A digest of SHA-256, SHA-384 or SHA-512 (FIPS 180-4): 32, 48 and 64
/// bytes, as sha256::digest, sha384::digest384 and sha384::digest512
/// give them.
pub enum Digest<'a> {
    Sha256(&'a [u8; 32]),
    Sha384(&'a [u8; 48]),
    Sha512(&'a [u8; 64]),
}

impl Digest<'_> {
    /// The digest's bytes.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Digest::Sha256(bytes) => *bytes,
            Digest::Sha384(bytes) => *bytes,
            Digest::Sha512(bytes) => *bytes,
        }
    }
}

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    use super::Digest;

    /// Each variant is its hash's length.
    #[test]
    fn lengths() {
        let digests = [
            Digest::Sha256(&[1; 32]),
            Digest::Sha384(&[2; 48]),
            Digest::Sha512(&[3; 64]),
        ];
        for (digest, (length, byte)) in digests.iter().zip([(32, 1), (48, 2), (64, 3)]) {
            assert_eq!(digest.bytes().len(), length);
            assert!(digest.bytes().iter().all(|b| *b == byte));
        }
    }
}
// rr: end(tests = yes)
