//! X25519 key agreement (RFC 7748). The field is five 51-bit limbs in
//! 64-bit words, multiplied through u128. The ladder is constant time:
//! the secret picks masks, never a branch, a loop count or an address.
//!
//! A Secret is made from random's seed, a PublicKey from the peer's
//! bytes, and agree gives a SharedSecret, which is only input to a key
//! derivation (HKDF-Extract), never a key. Secret and SharedSecret are
//! not Copy, Clone or Debug, and are wiped when dropped; P-256's are
//! ecdh's own types, so one cannot stand for the other.
//!
//! ```text
//! let secret = x25519::Secret::new(random::seed32());
//! send(secret.public_key().bytes());
//! let shared = secret.agree(&x25519::PublicKey::from_bytes(peer))?;  // Err(LowOrder)
//! let prk = sha256::hkdf_extract(salt, shared.kdf_input());
//! ```

use crate::base::random;
use core::num::Wrapping;

/// Bytes of a secret, a public key and a shared secret.
pub const KEY_BYTES: usize = 32;

/// What went wrong.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// The peer's key is a point of small order, whose shared secret is
    /// zero whatever the secret: TLS must abort (RFC 9846 7.4.2).
    LowOrder,
}

/// A secret scalar, from the system's randomness.
pub struct Secret {
    bytes: [u8; KEY_BYTES],
}

/// A public key: the u-coordinate of a point, as the peer sent it or
/// public_key made it. Every 32 bytes are one (RFC 7748 5).
pub struct PublicKey {
    bytes: [u8; KEY_BYTES],
}

/// The secret two keys agree on: input to a key derivation, not a key.
pub struct SharedSecret {
    bytes: [u8; KEY_BYTES],
}

/// A field element mod 2^255 - 19; limbs may run a few bits past 51.
type Fe = [u64; 5];

const MASK: u64 = (1 << 51) - 1;
const ONE: Fe = [1, 0, 0, 0, 0];
/// (486662 - 2) / 4, the curve constant of the doubling.
const A24: u64 = 121_665;

impl Secret {
    /// A secret from 32 random bytes; the ladder clamps them.
    pub fn new(seed: random::Seed32) -> Secret {
        Secret {
            bytes: seed.into_bytes(),
        }
    }

    /// The public key: the secret times the base point 9.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let mut base = [0; KEY_BYTES];
        base[0] = 9;
        PublicKey {
            bytes: ladder(&self.bytes, &base),
        }
    }

    /// The secret shared with peer; LowOrder when it is all zero, peer
    /// being a point of small order.
    #[cfg_attr(rr, rr::hot)]
    pub fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, Error> {
        let mut out = ladder(&self.bytes, &peer.bytes);
        // Fold every byte so the time does not depend on where one is set.
        let any = out.iter().fold(0, |acc, byte| acc | byte);
        if core::hint::black_box(any) == 0 {
            random::wipe(&mut out);
            return Err(Error::LowOrder);
        }
        Ok(SharedSecret { bytes: out })
    }
}

impl PublicKey {
    /// The peer's key as it came.
    pub fn from_bytes(bytes: &[u8; KEY_BYTES]) -> PublicKey {
        PublicKey { bytes: *bytes }
    }

    /// The key's bytes, to send.
    pub fn bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl SharedSecret {
    /// The secret as a key derivation's input keying material.
    pub fn kdf_input(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        random::wipe(&mut self.bytes);
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        random::wipe(&mut self.bytes);
    }
}

/// RFC 7748 section 5: the clamped scalar times the u-coordinate.
fn ladder(secret: &[u8; KEY_BYTES], point: &[u8; KEY_BYTES]) -> [u8; KEY_BYTES] {
    let [k0, k1, k2, k3] = load(secret);
    let k0 = k0 & !7;
    let k3 = (k3 & !(1 << 63)) | (1 << 62);
    let x1 = unpack(point);
    let mut x2 = ONE;
    let mut z2 = [0; 5];
    let mut x3 = x1;
    let mut z3 = ONE;
    let mut swap = 0;
    // Bit 255 is clamped away: the top word starts at bit 254.
    for (word, top) in [(k3, 63), (k2, 64), (k1, 64), (k0, 64)] {
        for shift in (0..top).rev() {
            let bit = (word >> shift) & 1;
            swap ^= bit;
            cswap(&mut x2, &mut x3, swap);
            cswap(&mut z2, &mut z3, swap);
            swap = bit;
            let a = add(&x2, &z2);
            let aa = sqr(&a);
            let b = sub(&x2, &z2);
            let bb = sqr(&b);
            let e = sub(&aa, &bb);
            let c = add(&x3, &z3);
            let d = sub(&x3, &z3);
            let da = mul(&d, &a);
            let cb = mul(&c, &b);
            x3 = sqr(&add(&da, &cb));
            z3 = mul(&x1, &sqr(&sub(&da, &cb)));
            x2 = mul(&aa, &bb);
            z2 = mul(&e, &add(&aa, &mul_small(&e, A24)));
        }
    }
    cswap(&mut x2, &mut x3, swap);
    cswap(&mut z2, &mut z3, swap);
    pack(&mul(&x2, &invert(&z2)))
}

/// Swaps p and q when b is 1 and leaves them when it is 0, by a mask.
fn cswap(p: &mut Fe, q: &mut Fe, b: u64) {
    let mask = 0_u64.wrapping_sub(b);
    for (x, y) in p.iter_mut().zip(q.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Four little-endian words.
fn load(bytes: &[u8; KEY_BYTES]) -> [u64; 4] {
    let mut out = [0; 4];
    for (word, chunk) in out.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*chunk);
    }
    out
}

/// RFC 7748 ignores the top bit of a u-coordinate; values of p and above
/// are taken as they are, and reduce in the arithmetic.
fn unpack(bytes: &[u8; KEY_BYTES]) -> Fe {
    let [w0, w1, w2, w3] = load(bytes);
    [
        w0 & MASK,
        ((w0 >> 51) | (w1 << 13)) & MASK,
        ((w1 >> 38) | (w2 << 26)) & MASK,
        ((w2 >> 25) | (w3 << 39)) & MASK,
        (w3 >> 12) & MASK,
    ]
}

/// The canonical encoding: fully reduced below p.
fn pack(n: &Fe) -> [u8; KEY_BYTES] {
    let mut t = *n;
    // Each round folds what passes 2^255 back times 19; after the
    // second the limbs are below 2^51, the third is margin.
    for _ in 0..3 {
        t[0] = t[0].wrapping_add(19 * carry(&mut t));
    }
    // t + 19 reaches 2^255 exactly when t >= p; that carry picks t - p.
    let mut r = t;
    r[0] += 19;
    let over = carry(&mut r);
    let mask = 0_u64.wrapping_sub(over);
    for (x, y) in t.iter_mut().zip(r) {
        *x = (*x & !mask) | (y & mask);
    }
    let [t0, t1, t2, t3, t4] = t;
    let words = [
        t0 | (t1 << 51),
        (t1 >> 13) | (t2 << 38),
        (t2 >> 26) | (t3 << 25),
        (t3 >> 39) | (t4 << 12),
    ];
    let mut out = [0; KEY_BYTES];
    for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        *chunk = word.to_le_bytes();
    }
    out
}

/// One carry pass through the limbs; returns what passes 2^255 for the
/// caller to fold back or to test.
#[must_use]
fn carry(t: &mut Fe) -> u64 {
    let mut c = 0;
    for x in t.iter_mut() {
        *x = x.wrapping_add(c);
        c = *x >> 51;
        *x &= MASK;
    }
    c
}

// The field arithmetic below wraps instead of checking: the bounds in
// each comment keep every sum and product inside its type, and an
// overflow check on each would cost the ladder 40% of its time.

/// Limbs below 2^54 give sums below 2^55.
fn add(a: &Fe, b: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = *a;
    let [b0, b1, b2, b3, b4] = *b;
    [
        a0.wrapping_add(b0),
        a1.wrapping_add(b1),
        a2.wrapping_add(b2),
        a3.wrapping_add(b3),
        a4.wrapping_add(b4),
    ]
}

/// a - b + 2p: never negative while b is a product, below 2^52.
fn sub(a: &Fe, b: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = *a;
    let [b0, b1, b2, b3, b4] = *b;
    let two = 2 * MASK;
    [
        a0.wrapping_add(two - 36).wrapping_sub(b0),
        a1.wrapping_add(two).wrapping_sub(b1),
        a2.wrapping_add(two).wrapping_sub(b2),
        a3.wrapping_add(two).wrapping_sub(b3),
        a4.wrapping_add(two).wrapping_sub(b4),
    ]
}

/// The limbs as wrapping 128-bit values, for the products.
fn wide(a: &Fe) -> [Wrapping<u128>; 5] {
    a.map(|x| Wrapping(u128::from(x)))
}

/// Products whose limbs reach past 2^255 come back times 19, as
/// 2^255 = 19 mod p. Inputs below 2^54, as add and sub give them (below
/// 2^53), keep the top column below 2^111, whose carry times 19 is below
/// 2^64 in reduce: at 2^55 it would not be, and the result would be wrong.
fn mul(f: &Fe, g: &Fe) -> Fe {
    let [f0, f1, f2, f3, f4] = wide(f);
    let [g0, g1, g2, g3, g4] = wide(g);
    let n = Wrapping(19);
    let [s1, s2, s3, s4] = [g1 * n, g2 * n, g3 * n, g4 * n];
    reduce([
        f0 * g0 + f1 * s4 + f2 * s3 + f3 * s2 + f4 * s1,
        f0 * g1 + f1 * g0 + f2 * s4 + f3 * s3 + f4 * s2,
        f0 * g2 + f1 * g1 + f2 * g0 + f3 * s4 + f4 * s3,
        f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * s4,
        f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0,
    ])
}

/// mul(a, a) with the symmetric products counted once: 15 instead of 25.
fn sqr(a: &Fe) -> Fe {
    let [a0, a1, a2, a3, a4] = wide(a);
    let two = Wrapping(2);
    let n = Wrapping(19);
    let (d0, d1) = (a0 * two, a1 * two);
    let (s3, s4) = (a3 * n, a4 * n);
    let (q0, q1, q2) = (a0 * a0, a1 * a1, a2 * a2);
    reduce([
        q0 + (a1 * s4 + a2 * s3) * two,
        d0 * a1 + a2 * s4 * two + a3 * s3,
        d0 * a2 + q1 + a3 * s4 * two,
        d0 * a3 + d1 * a2 + a4 * s4,
        d0 * a4 + d1 * a3 + q2,
    ])
}

/// A small constant k below 2^17 keeps each product below 2^72.
fn mul_small(a: &Fe, k: u64) -> Fe {
    let k = Wrapping(u128::from(k));
    reduce(wide(a).map(|x| x * k))
}

/// Carries the columns down to limbs below 2^51 + 2^13; what leaves the
/// top limb comes back into the bottom times 19.
fn reduce(h: [Wrapping<u128>; 5]) -> Fe {
    let [h0, h1, h2, h3, h4] = h.map(|x| x.0);
    let mask = u128::from(MASK);
    let h1 = h1.wrapping_add(h0 >> 51);
    let h2 = h2.wrapping_add(h1 >> 51);
    let h3 = h3.wrapping_add(h2 >> 51);
    let h4 = h4.wrapping_add(h3 >> 51);
    let h0 = (h0 & mask).wrapping_add((h4 >> 51).wrapping_mul(19));
    let o0 = low(h0);
    [
        o0 & MASK,
        (low(h1) & MASK).wrapping_add(o0 >> 51),
        low(h2) & MASK,
        low(h3) & MASK,
        low(h4) & MASK,
    ]
}

/// The low 64 bits.
fn low(x: u128) -> u64 {
    // rr: escape(cast): the high bits are carried out before the callers
    // use this, or masked off after it.
    x as u64
}

/// a^(n squarings).
fn sqrn(a: &Fe, n: u32) -> Fe {
    let mut t = sqr(a);
    for _ in 1..n {
        t = sqr(&t);
    }
    t
}

/// z^(p - 2) = z^-1 (0 for 0), by the usual chain of 254 squarings and
/// 11 products; the exponent is public.
fn invert(z: &Fe) -> Fe {
    let z2 = sqr(z);
    let z9 = mul(z, &sqrn(&z2, 2));
    let z11 = mul(&z2, &z9);
    let e5 = mul(&z9, &sqr(&z11));
    let e10 = mul(&sqrn(&e5, 5), &e5);
    let e20 = mul(&sqrn(&e10, 10), &e10);
    let e40 = mul(&sqrn(&e20, 20), &e20);
    let e50 = mul(&sqrn(&e40, 10), &e10);
    let e100 = mul(&sqrn(&e50, 50), &e50);
    let e200 = mul(&sqrn(&e100, 100), &e100);
    let e250 = mul(&sqrn(&e200, 50), &e50);
    mul(&sqrn(&e250, 5), &z11)
}

#[cfg(test)]
mod tests {
    use super::{Error, KEY_BYTES, PublicKey, Secret, ladder};
    use crate::base::random::Seed32;
    use test::Bencher;

    fn secret(bytes: [u8; KEY_BYTES]) -> Secret {
        Secret::new(Seed32::for_tests(bytes))
    }

    /// The shared secret of a secret and a peer's key, as bytes.
    fn shared(k: [u8; KEY_BYTES], peer: &[u8; KEY_BYTES]) -> Result<[u8; KEY_BYTES], Error> {
        let agreed = secret(k).agree(&PublicKey::from_bytes(peer))?;
        Ok(*agreed.kdf_input())
    }

    fn hex(s: &str) -> [u8; KEY_BYTES] {
        let mut out = [0; KEY_BYTES];
        for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
            let digit = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("not hex"),
            };
            *byte = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        out
    }

    /// RFC 7748 section 5.2: two scalars on two points.
    #[test]
    fn vectors() {
        let cases = [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];
        for (k, u, out) in cases {
            assert_eq!(shared(hex(k), &hex(u)), Ok(hex(out)));
        }
    }

    /// Section 5.2's iteration: k and u become the result and the old k.
    fn iterate(n: u32) -> [u8; KEY_BYTES] {
        let mut k = [0; KEY_BYTES];
        k[0] = 9;
        let mut u = k;
        for _ in 0..n {
            let r = ladder(&k, &u);
            u = k;
            k = r;
        }
        k
    }

    #[test]
    fn iterated() {
        assert_eq!(
            iterate(1),
            hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
        assert_eq!(
            iterate(1000),
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    /// Half a minute at -O: rr test always skips it; drop #[ignore] to run.
    #[test]
    #[ignore]
    fn iterated_million() {
        assert_eq!(
            iterate(1_000_000),
            hex("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424")
        );
    }

    /// Section 6.1: Alice and Bob reach one secret.
    #[test]
    fn alice_and_bob() {
        let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let alice_public = secret(alice).public_key();
        let bob_public = secret(bob).public_key();
        assert_eq!(
            *alice_public.bytes(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            *bob_public.bytes(),
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let agreed = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(shared(alice, bob_public.bytes()), Ok(agreed));
        assert_eq!(shared(bob, alice_public.bytes()), Ok(agreed));
    }

    /// Points of small order give the all-zero secret, which is refused.
    #[test]
    fn low_order() {
        let alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut one = [0; KEY_BYTES];
        one[0] = 1;
        let order8 = hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(shared(alice, &[0; KEY_BYTES]), Err(Error::LowOrder));
        assert_eq!(shared(alice, &one), Err(Error::LowOrder));
        assert_eq!(shared(alice, &order8), Err(Error::LowOrder));
    }

    /// The 4 fields of a case's line, split at spaces.
    fn fields(line: &str) -> [&str; 4] {
        let mut out = [""; 4];
        let mut words = line.split(' ');
        for slot in &mut out {
            *slot = words.next().unwrap();
        }
        assert!(words.next().is_none(), "{line}");
        out
    }

    /// Wycheproof's x25519_test, every case (x25519-wycheproof.py): the
    /// shared secret, twists and non-canonical points included, or None
    /// for the low-order points, whose secret is zero.
    #[test]
    fn wycheproof() {
        let mut cases = 0;
        for line in include_str!("x25519-wycheproof.txt").lines() {
            if line.starts_with('#') {
                continue;
            }
            let [id, key, peer, out] = fields(line);
            let out = hex(out);
            let expected = if out == [0; KEY_BYTES] {
                Err(Error::LowOrder)
            } else {
                Ok(out)
            };
            assert_eq!(shared(hex(key), &hex(peer)), expected, "tcId {id}");
            cases += 1;
        }
        assert_eq!(cases, 518);
    }

    /// As TLS uses it: each side's secret from the system, the public
    /// keys exchanged, one secret agreed on; a new secret agrees on
    /// another; the same secret agrees again on the same.
    #[test]
    fn exchange() {
        let (alice, bob) = (Secret::new(crate::base::random::seed32()), secret([7; 32]));
        let (to_bob, to_alice) = (alice.public_key(), bob.public_key());
        let ours = alice.agree(&to_alice).unwrap();
        let theirs = bob.agree(&to_bob).unwrap();
        assert_eq!(ours.kdf_input(), theirs.kdf_input());
        assert_eq!(
            alice.agree(&to_alice).unwrap().kdf_input(),
            ours.kdf_input()
        );
        let other = Secret::new(crate::base::random::seed32());
        assert_ne!(
            other.agree(&to_alice).unwrap().kdf_input(),
            ours.kdf_input()
        );
    }

    /// One key agreement.
    #[bench]
    fn one_shared(b: &mut Bencher) {
        let key = secret([42; KEY_BYTES]);
        let peer = secret([3; KEY_BYTES]).public_key();
        b.iter(|| core::hint::black_box(&key).agree(&peer));
    }
}
