//! ECDSA signature verification on P-256, P-384 and P-521 (FIPS 186-4,
//! SEC 1 4.1.4). Everything it reads is public: the key, the hash and the
//! signature. So the arithmetic is not constant time, but every length
//! an attacker picks is checked before it is used.
//!
//! Field elements are little-endian 64-bit limbs in Montgomery form,
//! multiplied and reduced (Montgomery) against each modulus as a
//! constant. Each curve has its own file, p256.rs, p384.rs and p521.rs,
//! with numbers of its own limbs, four, six and nine, which the compiler
//! unrolls: rr has no const generics, and numbers as wide as P-521's for
//! every curve would copy and loop over limbs the others do not use.
//! registry/ecdsa/ecdsa-gen.py in rr's repository writes the three from
//! one template. P-256's reduction is shifts of its special prime;
//! P-521's p = 2^521 - 1 reduces by adding the bits past 521 to those
//! below, with R = 1. Points are Jacobian; u1 G + u2 Q is one run of
//! doublings over both scalars in NAF, G's multiples a constant table.

mod p256;
mod p384;
mod p521;

/// The odd multiples P, 3P, ..., 15P of the key that a width-5 NAF
/// picks from.
const TABLE: usize = 8;

/// The curves this verifies on.
pub enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    /// Bytes of a coordinate and of a scalar.
    fn bytes(&self) -> usize {
        match self {
            Curve::P256 => p256::BYTES,
            Curve::P384 => p384::BYTES,
            Curve::P521 => p521::BYTES,
        }
    }
}

/// Whether signature, DER's Ecdsa-Sig-Value, signs hash under public,
/// an uncompressed point 04 || X || Y. The hash is cut to the order's
/// bits when longer (SEC 1 4.1.4 step 5), and may be of any length.
pub fn verify(curve: &Curve, public: &[u8], hash: &[u8], signature: &[u8]) -> bool {
    let Some((r, s)) = parse(signature, curve.bytes()) else {
        return false;
    };
    match curve {
        Curve::P256 => p256::verify(public, hash, r, s),
        Curve::P384 => p384::verify(public, hash, r, s),
        Curve::P521 => p521::verify(public, hash, r, s),
    }
}

/// r and s from DER's SEQUENCE of two INTEGERs, without their sign
/// byte; None unless the encoding is DER's one encoding of them (X.690
/// 8.3 and 10.1), each at most bytes long, with nothing after.
fn parse(signature: &[u8], bytes: usize) -> Option<(&[u8], &[u8])> {
    let (body, []) = element(signature, 0x30)? else {
        return None;
    };
    let (r, rest) = element(body, 0x02)?;
    let (s, []) = element(rest, 0x02)? else {
        return None;
    };
    Some((positive(r, bytes)?, positive(s, bytes)?))
}

/// The contents of the element of tag at the start of input, and what
/// follows it. Contents here are under 256 bytes: a length below 128 is
/// one byte, and one from 128 is 81 and a byte; any other form is either
/// not minimal or too long.
fn element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (length, rest) = match input {
        [found, length, rest @ ..] if *found == tag && *length < 0x80 => (*length, rest),
        [found, 0x81, length, rest @ ..] if *found == tag && *length >= 0x80 => (*length, rest),
        _ => return None,
    };
    rest.split_at_checked(usize::from(length))
}

/// A positive INTEGER's magnitude, at most bytes long: no sign bit set,
/// and a leading zero only where the next byte's top bit needs it.
fn positive(contents: &[u8], bytes: usize) -> Option<&[u8]> {
    let magnitude = match contents {
        [] => return None,
        [first, ..] if *first >= 0x80 => return None,
        [0, next, ..] if *next < 0x80 => return None,
        [0, rest @ ..] if !rest.is_empty() => rest,
        [..] => contents,
    };
    if magnitude.len() > bytes {
        return None;
    }
    Some(magnitude)
}

/// The width of a NAF whose odd multiples are entries many: 2^(width -
/// 2) of them.
const fn width(entries: usize) -> u32 {
    entries.trailing_zeros() + 2
}

/// a b + c + d as low and high words: at most (2^64 - 1)^2 + 2 (2^64 -
/// 1) = 2^128 - 1, so it never wraps.
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let wide = u128::from(a)
        .wrapping_mul(u128::from(b))
        .wrapping_add(u128::from(c))
        .wrapping_add(u128::from(d));
    // rr: escape(cast): the two halves of the 128-bit sum.
    (wide as u64, (wide >> 64) as u64)
}

/// Any bytes as a curve, a key, a hash and a signature: verify answers
/// without a panic, and a signature parse accepts is the DER encoding of
/// what it read.
#[cfg(fuzzing)]
pub fn fuzz_verify(input: &[u8]) {
    let Some((&choice, rest)) = input.split_first() else {
        return;
    };
    let curve = match choice % 3 {
        0 => Curve::P256,
        1 => Curve::P384,
        _ => Curve::P521,
    };
    let split = usize::from(choice / 3).min(rest.len());
    let (hash, rest) = rest.split_at(split);
    let half = rest.len() / 2;
    let (public, signature) = rest.split_at(half);
    verify(&curve, public, hash, signature);
    verify(&curve, &[], hash, rest);
    if let Some((r, s)) = parse(rest, curve.bytes()) {
        let mut encoded = alloc::vec::Vec::new();
        for integer in [r, s] {
            let sign = integer.first().is_some_and(|byte| *byte >= 0x80);
            encoded.push(2);
            encoded.push(u8::try_from(integer.len() + usize::from(sign)).unwrap());
            if sign {
                encoded.push(0);
            }
            encoded.extend_from_slice(integer);
        }
        let body = u8::try_from(encoded.len()).unwrap();
        let head: &[u8] = if body < 0x80 {
            &[0x30, body]
        } else {
            &[0x30, 0x81, body]
        };
        assert_eq!(rest.get(..head.len()), Some(head));
        assert_eq!(rest.get(head.len()..), Some(&encoded[..]));
    }
}

/// Hexadecimal text as bytes.
#[cfg(test)]
fn hex(text: &str) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec::Vec::new();
    let mut high = None;
    for c in text.bytes() {
        let digit = u8::try_from(char::from(c).to_digit(16).unwrap()).unwrap();
        match high.take() {
            None => high = Some(digit),
            Some(first) => bytes.push((first << 4) | digit),
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::{Curve, hex, verify};
    use alloc::vec::Vec;
    use test::Bencher;

    /// Wycheproof's P-256 key of its first ECDSA cases, and its first
    /// signature: SHA-256 of the empty message.
    const KEY256: &str = "0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5\
                          87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d";
    const EMPTY256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SIG256: &str = "3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d877\
                          0b34a02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2";

    /// Wycheproof's ECDSA cases with DER signatures (ecdsa-wycheproof.py):
    /// each curve under its own hash, every case, and a hash longer and
    /// shorter than the order. Valid ones verify, the rest do not.
    #[test]
    fn wycheproof() {
        let (mut keys, mut hashes) = (Vec::new(), Vec::new());
        let mut cases = [0; 3];
        for line in include_str!("ecdsa-wycheproof.txt").lines() {
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
                ["key", _, point, "", "", "", ""] => keys.push(hex(point)),
                ["hash", _, digest, "", "", "", ""] => hashes.push(hex(digest)),
                ["sig", bits, key, hash, id, valid, signature] => {
                    let (curve, count) = match bits {
                        "256" => (Curve::P256, &mut cases[0]),
                        "384" => (Curve::P384, &mut cases[1]),
                        _ => (Curve::P521, &mut cases[2]),
                    };
                    *count += 1;
                    let key = &keys[key.parse::<usize>().unwrap()];
                    let hash = &hashes[hash.parse::<usize>().unwrap()];
                    let signature = if signature == "-" {
                        Vec::new()
                    } else {
                        hex(signature)
                    };
                    let verified = verify(&curve, key, hash, &signature);
                    assert_eq!(verified, valid == "1", "{bits} tcId {id}");
                }
                _ => panic!("{line}"),
            }
        }
        assert_eq!(cases, [727, 666, 542]);
    }

    /// Wycheproof's first valid P-521 case: SHA-512 of the empty message,
    /// and a signature whose SEQUENCE is over 127 bytes, so of DER's long
    /// form of length.
    const KEY521: &str = "04012a908bfc5b70e17bdfae74294994808bf2a42dab59af8b0523a026d640a2a3d6\
                          d344520b62177e2cfa339ca42fb0883ec425904fbda2833a3b5b0a9a00811365d801\
                          2333d532f8f8eb1a623c378a3694651192bbda833e3b8d7b8f90b2bfc9b045f8a55e\
                          1b6a5fe1512c400c4bc9c86fd7c699d642f5cee9bb827c8b0abc0da01cef1e";
    const EMPTY512: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                            47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const SIG521: &str = "308188024201625d6115092a8e2ee21b9f8a425aa73814dec8b2335e86150ab4229f\
                          5a3421d2e6256d632c7a4365a1ee01dd2a936921bbb4551a512d1d4b5a56c314e4a0\
                          2534c5024201b792d23f2649862595451055777bda1b02dc6cc8fef23231e44b921b\
                          16155cd42257441d75a790371e91819f0a9b1fd0ebd02c90b5b774527746ed9bfe74\
                          3dbe2f";

    /// P-521's length and hash: the long form only where it is minimal,
    /// and a hash of 66 bytes or more cut to its leftmost 521 bits, so
    /// that the SHA-512 digest moved up by the bits past them verifies.
    #[test]
    fn p521() {
        let (key, hash, signature) = (hex(KEY521), hex(EMPTY512), hex(SIG521));
        assert!(verify(&Curve::P521, &key, &hash, &signature));
        assert!(!verify(&Curve::P384, &key, &hash, &signature));
        let body = &signature[3..];
        for bad in [
            der(&[0x30, 0x82, 0, 0x88], &[body]),
            der(&[0x30, 0x88], &[body]),
            der(&[0x30, 0x81, 0x89], &[body, &[0]]),
        ] {
            assert!(!verify(&Curve::P521, &key, &hash, &bad));
        }
        let mut moved = Vec::new();
        for length in [66, 67, 80] {
            // The digest times 2^(8 length - 521), in length bytes.
            let shift = 8 * length - 521;
            moved.clear();
            moved.resize(length, 0);
            let end = length - shift / 8;
            moved[end - hash.len()..end].copy_from_slice(&hash);
            let mut carry = 0;
            for byte in moved.iter_mut().rev() {
                let wide = (u16::from(*byte) << (shift % 8)) | carry;
                *byte = u8::try_from(wide & 0xff).unwrap();
                carry = wide >> 8;
            }
            assert!(verify(&Curve::P521, &key, &moved, &signature));
            moved[0] ^= 0x80;
            assert!(!verify(&Curve::P521, &key, &moved, &signature));
        }
    }

    /// The valid P-256 case with one thing changed at a time.
    #[test]
    fn rejects() {
        let (key, hash, signature) = (hex(KEY256), hex(EMPTY256), hex(SIG256));
        assert!(verify(&Curve::P256, &key, &hash, &signature));
        assert!(!verify(&Curve::P384, &key, &hash, &signature));
        let mut wrong = hex(EMPTY256);
        wrong[31] ^= 1;
        assert!(!verify(&Curve::P256, &key, &wrong, &signature));
        assert!(!verify(&Curve::P256, &key, &hash[..31], &signature));
        // Keys: off the curve, X = p, compressed, infinity, cut short.
        let mut off = hex(KEY256);
        off[64] ^= 1;
        let mut big = hex(KEY256);
        big[1..33].copy_from_slice(&hex(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        let mut compressed = hex(KEY256);
        compressed[0] = 3;
        for bad in [&off[..], &big, &compressed[..33], &[0], &key[..64], &[]] {
            assert!(!verify(&Curve::P256, bad, &hash, &signature));
        }
        // Signatures: r and s swapped; the same numbers in other BER
        // encodings; r or s of 0 or n; truncated and extended.
        let (r, s) = (&signature[4..37], &signature[39..]);
        let n = "00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        for bad in [
            der(&[0x30, 0x45], &[&[2, 0x20], s, &[2, 0x21], r]),
            der(&[0x30, 0x46], &[&[2, 0x21], r, &[2, 0x21, 0], s]),
            der(&[0x30, 0x44], &[&[2, 0x20], &r[1..], &[2, 0x20], s]),
            der(&[0x30, 0x81, 0x45], &[&[2, 0x21], r, &[2, 0x20], s]),
            der(&[0x30, 0x45], &[&[2, 0x81, 0x21], r, &[2, 0x20], s]),
            der(&[0x31, 0x45], &[&[2, 0x21], r, &[2, 0x20], s]),
            der(&[0x30, 0x45], &[&[3, 0x21], r, &[2, 0x20], s]),
            der(&[0x30, 0x46], &[&[2, 0x21], r, &[2, 0x20], s, &[0]]),
            der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], s, &[0]]),
            der(&[0x30, 0x44], &[&[2, 0x21], r, &[2, 0x20], &s[..31]]),
            der(&[0x30, 0x25], &[&[2, 1, 0], &[2, 0x20], s]),
            der(&[0x30, 0x26], &[&[2, 0x21], r, &[2, 1, 0]]),
            der(&[0x30, 0x46], &[&[2, 0x21], &hex(n), &[2, 0x20], s]),
            der(&[0x30, 0x46], &[&[2, 0x21], r, &[2, 0x21], &hex(n)]),
            der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], &s[..30]]),
            Vec::new(),
        ] {
            assert!(!verify(&Curve::P256, &key, &hash, &bad));
        }
        assert!(verify(
            &Curve::P256,
            &key,
            &hash,
            &der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], s])
        ));
    }

    fn der(head: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(head);
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    /// One P-256 verification, as of a certificate or a handshake.
    #[bench]
    fn verify_p256(b: &mut Bencher) {
        let (key, hash, signature) = (hex(KEY256), hex(EMPTY256), hex(SIG256));
        b.iter(|| verify(&Curve::P256, &key, &hash, &signature));
    }

    /// One P-521 verification.
    #[bench]
    fn verify_p521(b: &mut Bencher) {
        let (key, hash, signature) = (hex(KEY521), hex(EMPTY512), hex(SIG521));
        b.iter(|| verify(&Curve::P521, &key, &hash, &signature));
    }

    /// One P-384 verification.
    #[bench]
    fn verify_p384(b: &mut Bencher) {
        let key = hex(
            "0429bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61\
             ef182e155a54345a5e8e5e88f064e5bc9a525ab7f764dad3dae1468c2b419f3b62b9\
             ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3",
        );
        let hash = hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
        );
        let signature = hex(
            "3064023032401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9cd441\
             5dee29238afbd3b103c1e40ee5c9144aee0f02304326756fb2c4fd726360dd6479b5\
             849478c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aae6d4ddfeb753",
        );
        b.iter(|| verify(&Curve::P384, &key, &hash, &signature));
    }
}
