//! P-256 (secp256r1) Diffie-Hellman, as TLS 1.3 uses it (RFC 9846
//! 4.3.8.2, 7.4.2): a secret scalar, its public point uncompressed, and
//! the x-coordinate shared with a peer's point.
//!
//! Constant time over the secret: the scalar is read four bits at a
//! time, each picking a multiple from a table by masks over every entry,
//! never a branch or an address; additions and doublings are the
//! complete formulas of Renes, Costello and Batina (eprint 2015/1060,
//! algorithms 4 and 6, for a = -3), as Go's crypto/internal/fips140/
//! nistec has them, which have no exception for the point at infinity
//! or for equal points. Field elements are four little-endian 64-bit
//! limbs in Montgomery form, multiplied by word-by-word Montgomery
//! reduction with masked final subtraction. The peer's point is public:
//! it is checked, and a refusal returns at once.
//!
//! A Secret is made from random's seed, a PublicKey is the peer's bytes
//! checked as a point, and agree gives a SharedSecret, which is only
//! input to a key derivation. Secret and SharedSecret are not Copy,
//! Clone or Debug, and are wiped when dropped; X25519's are x25519's
//! own types, so one cannot stand for the other.
//!
//! ```text
//! let secret = ecdh::Secret::new(random::seed64());
//! send(secret.public_key().bytes());
//! let peer = ecdh::PublicKey::parse(bytes)?;          // Err(Invalid)
//! let prk = sha256::hkdf_extract(salt, secret.agree(&peer).kdf_input());
//! ```

use crate::base::random;

/// Bytes of a secret scalar and of a shared secret.
pub const SECRET_BYTES: usize = 32;
/// Bytes of a public key: 4, then x and y (SEC 1 2.3.3, uncompressed).
pub const PUBLIC_BYTES: usize = 65;
/// Bytes of the shared secret: the x-coordinate.
pub const SHARED_BYTES: usize = 32;

/// A number below 2^256, little-endian words; in the field, Montgomery
/// form (times R = 2^256 mod p) and below p.
type Fe = [u64; 4];

/// p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P: Fe = [
    0xffffffffffffffff,
    0x00000000ffffffff,
    0,
    0xffffffff00000001,
];
/// The order n of the base point.
const N: Fe = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];
/// R^2 mod p, to bring a number into Montgomery form.
const RR: Fe = [
    0x0000000000000003,
    0xfffffffbffffffff,
    0xfffffffffffffffe,
    0x00000004fffffffd,
];
/// 1 in Montgomery form, R mod p.
const ONE: Fe = [
    0x0000000000000001,
    0xffffffff00000000,
    0xffffffffffffffff,
    0x00000000fffffffe,
];
/// The curve's b in Montgomery form.
const B: Fe = [
    0xd89cdf6229c4bddf,
    0xacf005cd78843090,
    0xe5a220abf7212ed6,
    0xdc30061d04874834,
];
/// The base point G, in Montgomery form.
const GX: Fe = [
    0x79e730d418a9143c,
    0x75ba95fc5fedb601,
    0x79fb732b77622510,
    0x18905f76a53755c6,
];
const GY: Fe = [
    0xddf25357ce95560a,
    0x8b4ab8e4ba19e45c,
    0xd2e88688dd21f325,
    0x8571ff1825885d85,
];
/// The table's multiples: 0 to 15 times the point, one per 4-bit window.
const TABLE: usize = 16;

/// A point in homogeneous projective coordinates (X / Z, Y / Z), in
/// Montgomery form; (0, 1, 0) is the point at infinity.
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

const INFINITY: Point = Point {
    x: [0; 4],
    y: ONE,
    z: [0; 4],
};

/// What went wrong.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// The peer's key is not an uncompressed point of the curve (65
    /// bytes, coordinates below p, on the curve), which TLS 1.3 must
    /// abort on (RFC 9846 4.3.8.2): compressed points are refused.
    Invalid,
}

/// A secret scalar in [1, n - 1], big-endian.
pub struct Secret {
    k: [u8; SECRET_BYTES],
}

/// A peer's public key, checked: a point of the curve, of order n.
pub struct PublicKey {
    bytes: [u8; PUBLIC_BYTES],
    point: Point,
}

/// The x-coordinate two keys agree on: input to a key derivation, not a
/// key.
pub struct SharedSecret {
    bytes: [u8; SHARED_BYTES],
}

impl Secret {
    /// A secret from 64 random bytes: the first 32, read big-endian, when
    /// they are in [1, n - 1]; else the second 32 (NIST SP 800-56A Rev. 3
    /// 5.6.1.2.2, key pairs by testing candidates, as Go's crypto/ecdh
    /// draws them); else, once in 2^64, the second less n, made odd, a
    /// number in [1, 2^256 - n]. Picked by masks: the time does not say
    /// which.
    pub fn new(seed: random::Seed64) -> Secret {
        let mut bytes = seed.into_bytes();
        let (first, second) = bytes.split_at(SECRET_BYTES);
        let (c1, c2) = (load(first), load(second));
        random::wipe(&mut bytes);
        let (m1, m2) = (valid(&c1).wrapping_neg(), valid(&c2).wrapping_neg());
        let (mut fallback, _) = sub_words(&c2, &N);
        fallback[0] |= 1;
        let mut k = [0; 4];
        for (((word, x), y), z) in k.iter_mut().zip(c1).zip(c2).zip(fallback) {
            *word = (x & m1) | (y & !m1 & m2) | (z & !m1 & !m2);
        }
        Secret { k: store(&k) }
    }

    /// The public key, uncompressed: 4, x and y.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let base = Point {
            x: GX,
            y: GY,
            z: ONE,
        };
        let point = multiply(&load(&self.k), &base);
        let Some((x, y)) = affine(&point) else {
            // rr: escape(panic): k is in [1, n - 1] and G of order n, so
            // k G is never the point at infinity.
            unreachable!();
        };
        let mut bytes = [0; PUBLIC_BYTES];
        bytes[0] = 4;
        bytes[1..33].copy_from_slice(&store(&x));
        bytes[33..].copy_from_slice(&store(&y));
        PublicKey { bytes, point }
    }

    /// The x-coordinate of the secret times peer.
    #[cfg_attr(rr, rr::hot)]
    #[must_use]
    pub fn agree(&self, peer: &PublicKey) -> SharedSecret {
        let product = multiply(&load(&self.k), &peer.point);
        let Some((x, _)) = affine(&product) else {
            // rr: escape(panic): k is in [1, n - 1] and a checked point's
            // order is n (the cofactor is 1): never the point at infinity.
            unreachable!();
        };
        SharedSecret { bytes: store(&x) }
    }

    /// The secret of a given scalar, for a standard's vectors; None
    /// outside [1, n - 1].
    #[cfg(test)]
    fn from_scalar(bytes: &[u8; SECRET_BYTES]) -> Option<Secret> {
        scalar(bytes)?;
        Some(Secret { k: *bytes })
    }
}

impl PublicKey {
    /// The peer's key: 4 || x || y with x and y below p, on the curve.
    pub fn parse(bytes: &[u8]) -> Result<PublicKey, Error> {
        let point = peer_point(bytes).ok_or(Error::Invalid)?;
        let Ok(bytes) = <[u8; PUBLIC_BYTES]>::try_from(bytes) else {
            return Err(Error::Invalid);
        };
        Ok(PublicKey { bytes, point })
    }

    /// The key's bytes, to send.
    pub fn bytes(&self) -> &[u8; PUBLIC_BYTES] {
        &self.bytes
    }
}

impl SharedSecret {
    /// The secret as a key derivation's input keying material.
    pub fn kdf_input(&self) -> &[u8; SHARED_BYTES] {
        &self.bytes
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        random::wipe(&mut self.k);
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        random::wipe(&mut self.bytes);
    }
}

/// 1 when k is in [1, n - 1], 0 when not, by arithmetic: the time does
/// not tell where a valid scalar differs from n.
fn valid(k: &Fe) -> u64 {
    let (_, below) = sub_words(k, &N);
    let any = k.iter().fold(0, |acc, word| acc | word);
    let nonzero = (any | any.wrapping_neg()) >> 63;
    below & nonzero
}

/// The scalar as 64-bit words, or None when it is 0 or at least n.
#[cfg(test)]
fn scalar(secret: &[u8; SECRET_BYTES]) -> Option<Fe> {
    let k = load(secret);
    if valid(&k) == 1 { Some(k) } else { None }
}

/// peer as a point, or None when it is not 4 || x || y with x and y below
/// p and y^2 = x^3 - 3x + b. A point of the curve is never the point at
/// infinity, and its order is n: P-256's cofactor is 1.
fn peer_point(peer: &[u8]) -> Option<Point> {
    let (&[tag], rest) = peer.split_first_chunk::<1>()?;
    let (x, y) = rest.split_first_chunk::<32>()?;
    let y: &[u8; 32] = y.try_into().ok()?;
    if tag != 4 {
        return None;
    }
    let x = field(x)?;
    let y = field(y)?;
    // x^3 - 3x + b = (x^2 - 3) x + b.
    let three = add(&add(&ONE, &ONE), &ONE);
    let right = add(&mul(&sub(&mul(&x, &x), &three), &x), &B);
    if mul(&y, &y) != right {
        return None;
    }
    Some(Point { x, y, z: ONE })
}

/// A coordinate in Montgomery form, or None when it is p or more.
fn field(bytes: &[u8; 32]) -> Option<Fe> {
    let a = load(bytes);
    let (_, below) = sub_words(&a, &P);
    if below == 1 { Some(mul(&a, &RR)) } else { None }
}

/// (x, y) of a point, plain, or None for the point at infinity. Z is
/// inverted by Fermat, an exponent that is public.
fn affine(point: &Point) -> Option<(Fe, Fe)> {
    let z = from_montgomery(&point.z);
    if z == [0; 4] {
        return None;
    }
    let inverse = invert(&point.z);
    Some((
        from_montgomery(&mul(&point.x, &inverse)),
        from_montgomery(&mul(&point.y, &inverse)),
    ))
}

/// k times point: k's 4-bit windows from the top, four doublings and
/// one addition of the window's multiple each.
fn multiply(k: &Fe, point: &Point) -> Point {
    // 0, 1, ..., 15 times point; the last addition, 16 times, is unused.
    let mut running = INFINITY;
    let table: [Point; TABLE] = core::array::from_fn(|_| {
        let next = add_points(&running, point);
        core::mem::replace(&mut running, next)
    });
    let mut acc = INFINITY;
    for word in k.iter().rev() {
        for shift in (0..64).step_by(4).rev() {
            for _ in 0..4 {
                acc = double(&acc);
            }
            acc = add_points(&acc, &select(&table, (word >> shift) & 15));
        }
    }
    acc
}

/// table[index], read by masking every entry in: the address does not
/// depend on index.
fn select(table: &[Point; TABLE], index: u64) -> Point {
    let mut out = Point {
        x: [0; 4],
        y: [0; 4],
        z: [0; 4],
    };
    for (entry, i) in table.iter().zip(0_u64..) {
        let d = i ^ index;
        // All ones when d is 0: then (d | -d) has its top bit clear.
        let mask = ((d | d.wrapping_neg()) >> 63).wrapping_sub(1);
        for (o, e) in [
            (&mut out.x, &entry.x),
            (&mut out.y, &entry.y),
            (&mut out.z, &entry.z),
        ] {
            for (a, b) in o.iter_mut().zip(e) {
                *a |= b & mask;
            }
        }
    }
    out
}

/// p1 + p2, complete: algorithm 4 of eprint 2015/1060, a = -3.
fn add_points(p1: &Point, p2: &Point) -> Point {
    let mut t0 = mul(&p1.x, &p2.x);
    let mut t1 = mul(&p1.y, &p2.y);
    let mut t2 = mul(&p1.z, &p2.z);
    let mut t3 = mul(&add(&p1.x, &p1.y), &add(&p2.x, &p2.y));
    t3 = sub(&t3, &add(&t0, &t1));
    let mut t4 = mul(&add(&p1.y, &p1.z), &add(&p2.y, &p2.z));
    t4 = sub(&t4, &add(&t1, &t2));
    let mut x3 = mul(&add(&p1.x, &p1.z), &add(&p2.x, &p2.z));
    let mut y3 = sub(&x3, &add(&t0, &t2));
    let mut z3 = mul(&B, &t2);
    x3 = sub(&y3, &z3);
    z3 = add(&x3, &x3);
    x3 = add(&x3, &z3);
    z3 = sub(&t1, &x3);
    x3 = add(&t1, &x3);
    y3 = mul(&B, &y3);
    t1 = add(&t2, &t2);
    t2 = add(&t1, &t2);
    y3 = sub(&sub(&y3, &t2), &t0);
    t1 = add(&y3, &y3);
    y3 = add(&t1, &y3);
    t1 = add(&t0, &t0);
    t0 = sub(&add(&t1, &t0), &t2);
    t1 = mul(&t4, &y3);
    t2 = mul(&t0, &y3);
    y3 = add(&mul(&x3, &z3), &t2);
    x3 = sub(&mul(&t3, &x3), &t1);
    z3 = add(&mul(&t4, &z3), &mul(&t3, &t0));
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// 2p, complete: algorithm 6 of eprint 2015/1060, a = -3.
fn double(p: &Point) -> Point {
    let mut t0 = mul(&p.x, &p.x);
    let t1 = mul(&p.y, &p.y);
    let mut t2 = mul(&p.z, &p.z);
    let mut t3 = mul(&p.x, &p.y);
    t3 = add(&t3, &t3);
    let mut z3 = mul(&p.x, &p.z);
    z3 = add(&z3, &z3);
    let mut y3 = sub(&mul(&B, &t2), &z3);
    let mut x3 = add(&y3, &y3);
    y3 = add(&x3, &y3);
    x3 = sub(&t1, &y3);
    y3 = add(&t1, &y3);
    y3 = mul(&x3, &y3);
    x3 = mul(&x3, &t3);
    t3 = add(&t2, &t2);
    t2 = add(&t2, &t3);
    z3 = sub(&sub(&mul(&B, &z3), &t2), &t0);
    t3 = add(&z3, &z3);
    z3 = add(&z3, &t3);
    t3 = add(&t0, &t0);
    t0 = sub(&add(&t3, &t0), &t2);
    t0 = mul(&t0, &z3);
    y3 = add(&y3, &t0);
    t0 = mul(&p.y, &p.z);
    t0 = add(&t0, &t0);
    z3 = mul(&t0, &z3);
    x3 = sub(&x3, &z3);
    z3 = mul(&t0, &t1);
    z3 = add(&z3, &z3);
    z3 = add(&z3, &z3);
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// 32 big-endian bytes, the first of bytes, as four little-endian limbs.
fn load(bytes: &[u8]) -> Fe {
    let mut out = [0; 4];
    for (word, chunk) in out.iter_mut().rev().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*chunk);
    }
    out
}

/// The limbs as 32 big-endian bytes.
fn store(a: &Fe) -> [u8; 32] {
    let mut out = [0; 32];
    for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(a.iter().rev()) {
        *chunk = word.to_be_bytes();
    }
    out
}

/// a + b * c + d as low and high words; never overflows 128 bits.
fn mac(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let t = u128::from(a) + u128::from(b) * u128::from(c) + u128::from(d);
    // rr: escape(cast): the low word, the high one shifted down.
    (t as u64, (t >> 64) as u64)
}

/// a - b over four words, and 1 when it borrowed (a < b).
fn sub_words(a: &Fe, b: &Fe) -> (Fe, u64) {
    let mut out = [0; 4];
    let mut borrow = false;
    for ((o, &x), &y) in out.iter_mut().zip(a).zip(b) {
        let (d, b1) = x.overflowing_sub(y);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        *o = d;
        borrow = b1 | b2;
    }
    (out, u64::from(borrow))
}

/// t + 2^256 top, below 2p, reduced below p: p is taken off unless that
/// borrows past top, picked by a mask.
fn reduce_once(t: &Fe, top: u64) -> Fe {
    let (r, borrow) = sub_words(t, &P);
    // Keep t only when t < p: no top word and a borrow.
    let keep = (top ^ 1) & borrow;
    let mask = keep.wrapping_neg();
    let mut out = [0; 4];
    for ((o, &x), &y) in out.iter_mut().zip(t).zip(&r) {
        *o = (x & mask) | (y & !mask);
    }
    out
}

/// a + b mod p.
fn add(a: &Fe, b: &Fe) -> Fe {
    let mut sum = [0; 4];
    let mut carry = false;
    for ((s, &x), &y) in sum.iter_mut().zip(a).zip(b) {
        let (t, c1) = x.overflowing_add(y);
        let (t, c2) = t.overflowing_add(u64::from(carry));
        *s = t;
        carry = c1 | c2;
    }
    reduce_once(&sum, u64::from(carry))
}

/// a - b mod p: p is added back when it borrowed, by a mask.
fn sub(a: &Fe, b: &Fe) -> Fe {
    let (d, borrow) = sub_words(a, b);
    let mask = borrow.wrapping_neg();
    let mut out = [0; 4];
    let mut carry = false;
    for ((o, &x), &m) in out.iter_mut().zip(&d).zip(&P) {
        let (t, c1) = x.overflowing_add(m & mask);
        let (t, c2) = t.overflowing_add(u64::from(carry));
        *o = t;
        carry = c1 | c2;
    }
    out
}

/// a b R^-1 mod p, for a and b below p: one word of a at a time, then
/// t + m p with m = t mod 2^64 (-p^-1 mod 2^64 is 1), shifted down a
/// word. t stays below 2p, so 2^256 top is one bit.
fn mul(a: &Fe, b: &Fe) -> Fe {
    let mut t = [0; 4];
    let mut top = 0_u64;
    for &word in a {
        let mut carry = 0;
        for (x, &y) in t.iter_mut().zip(b) {
            (*x, carry) = mac(*x, word, y, carry);
        }
        let (t4, over) = top.overflowing_add(carry);
        let m = t[0];
        let (_, mut c) = mac(t[0], m, P[0], 0);
        let mut next = [0; 4];
        for ((n, &x), &q) in next.iter_mut().zip(&t[1..]).zip(&P[1..]) {
            (*n, c) = mac(x, m, q, c);
        }
        let (s, o) = t4.overflowing_add(c);
        next[3] = s;
        top = u64::from(over) + u64::from(o);
        t = next;
    }
    reduce_once(&t, top)
}

/// Out of Montgomery form: a R^-1, below p.
fn from_montgomery(a: &Fe) -> Fe {
    mul(a, &[1, 0, 0, 0])
}

/// a^(p - 2) = a^-1 (0 for 0): squarings and products by the public
/// exponent's bits, from the top.
fn invert(a: &Fe) -> Fe {
    let (exponent, _) = sub_words(&P, &[2, 0, 0, 0]);
    let mut r = ONE;
    for word in exponent.iter().rev() {
        for shift in (0..64).rev() {
            r = mul(&r, &r);
            if (word >> shift) & 1 == 1 {
                r = mul(&r, a);
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::{Error, N, PUBLIC_BYTES, PublicKey, SECRET_BYTES, Secret, store};
    use crate::base::random::{self, Seed64};
    use test::Bencher;

    /// The public key of a scalar, or None outside [1, n - 1].
    fn public_key(k: &[u8; SECRET_BYTES]) -> Option<[u8; PUBLIC_BYTES]> {
        Some(*Secret::from_scalar(k)?.public_key().bytes())
    }

    /// The secret a scalar shares with peer's bytes, or None when the
    /// scalar or the point is refused.
    fn shared(k: &[u8; SECRET_BYTES], peer: &[u8]) -> Option<[u8; 32]> {
        let peer = PublicKey::parse(peer).ok()?;
        Some(*Secret::from_scalar(k)?.agree(&peer).kdf_input())
    }

    /// Cases of ecdh-wycheproof.txt: Wycheproof's and NIST CAVP's.
    const VECTORS: &str = include_str!("ecdh-wycheproof.txt");
    /// Room for the longest point of the file, a P-521 one.
    const HEX_MAX: usize = 160;

    /// text, hex ("-" for nothing), into out; the bytes written.
    fn hex<'a>(text: &str, out: &'a mut [u8; HEX_MAX]) -> &'a [u8] {
        let digit = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not hex"),
        };
        let text = if text == "-" { "" } else { text };
        let pairs = text.as_bytes().as_chunks::<2>().0;
        for (byte, &[h, l]) in out.iter_mut().zip(pairs) {
            *byte = (digit(h) << 4) | digit(l);
        }
        out.get(..pairs.len()).expect("a value of the file fits")
    }

    /// 32 bytes of hex: a scalar, a coordinate, a shared secret.
    fn bytes32(text: &str) -> [u8; 32] {
        let mut buffer = [0; HEX_MAX];
        hex(text, &mut buffer).try_into().expect("32 bytes")
    }

    /// A public key's 65 bytes of hex.
    fn point(text: &str) -> [u8; PUBLIC_BYTES] {
        let mut buffer = [0; HEX_MAX];
        hex(text, &mut buffer).try_into().expect("65 bytes")
    }

    /// Every case: a valid one gives its secret, an invalid one None, an
    /// acceptable one (a compressed point) either; CAVP's also give the
    /// private key's public key.
    #[test]
    fn vectors() {
        let mut count = 0;
        let mut peer = [0; HEX_MAX];
        for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
            let mut fields = line.split(' ');
            let mut field = || fields.next().expect("a field");
            let (id, result, private, theirs, expected) =
                (field(), field(), field(), field(), field());
            let secret = bytes32(private);
            let got = shared(&secret, hex(theirs, &mut peer));
            let want = (expected != "-").then(|| bytes32(expected));
            match result {
                "v" => assert_eq!(got, want, "{id}"),
                "i" => assert_eq!(got, None, "{id}"),
                _ => assert!(got.is_none() || got == want, "{id}"),
            }
            if let Some(public) = fields.next() {
                assert_eq!(public_key(&secret), Some(point(public)), "{id}");
            }
            count += 1;
        }
        assert_eq!(count, 355 + 17 + 25);
    }

    /// RFC 5903 8.1: both public keys and the one shared value.
    #[test]
    fn rfc5903() {
        let i = bytes32("c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433");
        let r = bytes32("c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53");
        let gi = public_key(&i).expect("a valid scalar");
        let gr = public_key(&r).expect("a valid scalar");
        let want = point(
            "04dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180\
             5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3",
        );
        assert_eq!(gi, want);
        let girx = bytes32("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");
        assert_eq!(shared(&i, &gr), Some(girx));
        assert_eq!(shared(&r, &gi), Some(girx));
    }

    /// 0 and n and above are refused; 1 gives G and n - 1 gives -G.
    #[test]
    fn scalars() {
        let g = point(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        );
        let minus_g = point(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
        );
        let n = bytes32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let n_minus_1 = bytes32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
        let mut one = [0; SECRET_BYTES];
        one[31] = 1;
        assert_eq!(public_key(&one), Some(g));
        assert_eq!(public_key(&n_minus_1), Some(minus_g));
        assert_eq!(public_key(&[0; SECRET_BYTES]), None);
        assert_eq!(public_key(&n), None);
        assert_eq!(public_key(&[0xff; SECRET_BYTES]), None);
        assert_eq!(shared(&[0; SECRET_BYTES], &g), None);
        assert_eq!(shared(&n, &g), None);
        // 1 times -G is -G, whose x is G's.
        assert_eq!(shared(&one, &minus_g), shared(&one, &g));
    }

    /// Encodings TLS must refuse: the wrong length, compressed, a tag
    /// other than 4, a coordinate of p, a point off the curve.
    #[test]
    fn refuses_points() {
        let mut one = [0; SECRET_BYTES];
        one[31] = 1;
        let g = public_key(&one).expect("1 is a scalar");
        assert!(shared(&one, &g).is_some());
        assert_eq!(shared(&one, &g[..64]), None);
        assert_eq!(shared(&one, &g[..33]), None);
        assert_eq!(shared(&one, &[]), None);
        let mut longer = [0; PUBLIC_BYTES + 1];
        longer[..PUBLIC_BYTES].copy_from_slice(&g);
        assert_eq!(shared(&one, &longer), None);
        let mut compressed = g;
        compressed[0] = 3;
        assert_eq!(shared(&one, &compressed), None);
        let mut off = g;
        off[64] ^= 1;
        assert_eq!(shared(&one, &off), None);
        // x = p: G's y, x out of range.
        let mut big = g;
        big[1..33].copy_from_slice(&bytes32(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        ));
        assert_eq!(shared(&one, &big), None);
    }

    /// Two parties reach one secret.
    #[test]
    fn agree() {
        let a = [7; SECRET_BYTES];
        let b = [0x5a; SECRET_BYTES];
        let pa = public_key(&a).expect("a scalar");
        let pb = public_key(&b).expect("a scalar");
        assert!(shared(&a, &pb).is_some());
        assert_eq!(shared(&a, &pb), shared(&b, &pa));
    }

    /// A seed's first half when it is a scalar, else its second, else
    /// the second less n, odd: always a scalar in [1, n - 1].
    #[test]
    fn seeds() {
        let n = store(&N);
        let mut one = [0; SECRET_BYTES];
        one[31] = 1;
        let key = |first: &[u8; 32], second: &[u8; 32]| {
            let mut seed = [0; 64];
            seed[..32].copy_from_slice(first);
            seed[32..].copy_from_slice(second);
            Secret::new(Seed64::for_tests(seed)).k
        };
        assert_eq!(key(&[7; 32], &[9; 32]), [7; 32]);
        assert_eq!(key(&n, &[9; 32]), [9; 32]);
        assert_eq!(key(&[0; 32], &one), one);
        assert_eq!(key(&[0xff; 32], &[0xff; 32])[..4], [0, 0, 0, 0]);
        // Neither: 0 less n is 2^256 - n, odd already; n less n is 0,
        // made 1.
        let mut expected = n;
        for byte in &mut expected {
            *byte = !*byte;
        }
        let complement = |bytes: &mut [u8; 32]| {
            for byte in bytes.iter_mut().rev() {
                let (sum, carry) = byte.overflowing_add(1);
                *byte = sum;
                if !carry {
                    break;
                }
            }
        };
        complement(&mut expected);
        assert_eq!(key(&n, &[0; 32]), expected);
        assert_eq!(key(&[0; 32], &n), one);
        for _ in 0..8 {
            let secret = Secret::new(random::seed64());
            assert!(Secret::from_scalar(&secret.k).is_some());
        }
    }

    /// As TLS uses it: each side's secret from the system, the public
    /// keys exchanged and parsed, one secret agreed on; a key that is not
    /// a point is refused at parse.
    #[test]
    fn exchange() {
        let (alice, bob) = (Secret::new(random::seed64()), Secret::new(random::seed64()));
        let to_bob = PublicKey::parse(alice.public_key().bytes()).unwrap();
        let to_alice = PublicKey::parse(bob.public_key().bytes()).unwrap();
        let ours = alice.agree(&to_alice);
        assert_eq!(ours.kdf_input(), bob.agree(&to_bob).kdf_input());
        assert_eq!(alice.agree(&to_alice).kdf_input(), ours.kdf_input());
        let mut bad = *to_alice.bytes();
        bad[64] ^= 1;
        assert_eq!(PublicKey::parse(&bad).err(), Some(Error::Invalid));
        assert_eq!(PublicKey::parse(&bad[..33]).err(), Some(Error::Invalid));
    }

    /// One public key, as a TLS client makes for its key share.
    #[bench]
    fn one_public_key(b: &mut Bencher) {
        let secret = Secret::from_scalar(&[42; SECRET_BYTES]).unwrap();
        b.iter(|| core::hint::black_box(&secret).public_key());
    }

    /// One key agreement.
    #[bench]
    fn one_shared(b: &mut Bencher) {
        let secret = Secret::from_scalar(&[42; SECRET_BYTES]).unwrap();
        let peer = PublicKey::parse(&public_key(&[3; SECRET_BYTES]).unwrap()).unwrap();
        b.iter(|| core::hint::black_box(&secret).agree(&peer));
    }
}
