//! The client against RFC 8448's trace, and against a TLS 1.3 server of
//! the tests' own: it signs with the test PKI's keys of x509-tests.pem
//! and retries, splits, tampers and misbehaves as each test asks.

use super::{
    AES_128_GCM_SHA256, AES_256_GCM_SHA384, ALERT, APPLICATION, CHANGE_CIPHER_SPEC, Client, Digest,
    Error, HANDSHAKE, HELLO_RETRY, IDLE_MAX, KEY_RECORDS_MAX, Keys, MESSAGE_MAX, Opening,
    PENDING_MAX, RECORD_MAX, RECORDS_PER_INPUT, Random, Reader, SECP256R1, State, Taken,
    Transcript, VERIFY_CONTEXT, Verify, X25519, X25519MLKEM768, derive, expand, handshake_secrets,
    mac,
};
use crate::base::ecdh;
use crate::base::mlkem;
use crate::base::random::{Seed32, Seed64};
use crate::base::sha256::{self, Sha256};
use crate::base::sha384;
use crate::base::x509::{self, Approval, Store, TEST_NOW, test_certificate};
use crate::base::x25519;
use alloc::vec::Vec;
use test::Bencher;

/// The session ID the client sends, from random().
const SESSION: [u8; 32] = [0x5c; 32];
const HOST: &str = "api.example.test";
/// A split that brings everything at once.
const WHOLE: usize = 1 << 24;

/// The client's randomness in every test: the bytes 0x5c.
fn random() -> Random {
    Random::fixed([0x5c; 32])
}

/// Bytes from hex digits; anything between them is skipped.
fn hex(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut high = None;
    for c in text.chars() {
        let Some(digit) = c.to_digit(16) else {
            continue;
        };
        let digit = u8::try_from(digit).unwrap();
        match high.take() {
            None => high = Some(digit),
            Some(top) => out.push((top << 4) | digit),
        }
    }
    out
}

/// Numbers as 64-bit limbs, least first, for the server's signatures:
/// slow and in variable time, which a test may be.
type Limbs = Vec<u64>;

fn limbs(bytes: &[u8], count: usize) -> Limbs {
    let mut out = Vec::new();
    out.resize(count, 0);
    for (at, byte) in bytes.iter().rev().enumerate() {
        out[at / 8] |= u64::from(*byte) << (8 * (at % 8));
    }
    out
}

fn big_endian(value: &[u64], length: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for at in (0..length).rev() {
        out.push(u8::try_from((value[at / 8] >> (8 * (at % 8))) & 0xff).unwrap());
    }
    out
}

fn low(sum: u128) -> u64 {
    u64::try_from(sum & u128::from(u64::MAX)).unwrap()
}

fn high(sum: u128) -> u64 {
    u64::try_from(sum >> 64).unwrap()
}

/// a += b; the carry out.
fn add_into(a: &mut [u64], b: &[u64]) -> bool {
    let mut carry = false;
    for (x, y) in a.iter_mut().zip(b) {
        let (sum, first) = x.overflowing_add(*y);
        let (total, second) = sum.overflowing_add(u64::from(carry));
        *x = total;
        carry = first | second;
    }
    carry
}

/// a -= b; the borrow out.
fn sub_from(a: &mut [u64], b: &[u64]) -> bool {
    let mut borrow = false;
    for (x, y) in a.iter_mut().zip(b) {
        let (difference, first) = x.overflowing_sub(*y);
        let (rest, second) = difference.overflowing_sub(u64::from(borrow));
        *x = rest;
        borrow = first | second;
    }
    borrow
}

fn below(a: &[u64], b: &[u64]) -> bool {
    for (x, y) in a.iter().zip(b).rev() {
        if x != y {
            return x < y;
        }
    }
    false
}

/// An odd modulus for Montgomery multiplication.
struct Modulus {
    n: Limbs,
    /// -n^-1 mod 2^64.
    inverse: u64,
    /// R^2 mod n, R being 2^(64 * limbs).
    square: Limbs,
    bytes: usize,
}

impl Modulus {
    fn new(bytes: &[u8]) -> Modulus {
        let count = bytes.len().div_ceil(8);
        let n = limbs(bytes, count);
        // Newton's iteration doubles the bits of n^-1 that are right.
        let mut inverse: u64 = 1;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inverse)));
        }
        let mut modulus = Modulus {
            n,
            inverse: inverse.wrapping_neg(),
            square: limbs(&[1], count),
            bytes: bytes.len(),
        };
        for _ in 0..128 * count {
            modulus.square = modulus.add(&modulus.square, &modulus.square);
        }
        modulus
    }

    fn add(&self, a: &[u64], b: &[u64]) -> Limbs {
        let mut sum = Limbs::new();
        let mut carry = false;
        for (x, y) in a.iter().zip(b) {
            let (part, first) = x.overflowing_add(*y);
            let (total, second) = part.overflowing_add(u64::from(carry));
            sum.push(total);
            carry = first | second;
        }
        if carry || !below(&sum, &self.n) {
            sub_from(&mut sum, &self.n);
        }
        sum
    }

    fn sub(&self, a: &[u64], b: &[u64]) -> Limbs {
        let mut difference = Limbs::new();
        let mut borrow = false;
        for (x, y) in a.iter().zip(b) {
            let (part, first) = x.overflowing_sub(*y);
            let (rest, second) = part.overflowing_sub(u64::from(borrow));
            difference.push(rest);
            borrow = first | second;
        }
        if borrow {
            add_into(&mut difference, &self.n);
        }
        difference
    }

    /// a mod n for a below 2n.
    fn reduce(&self, mut a: Limbs) -> Limbs {
        if !below(&a, &self.n) {
            sub_from(&mut a, &self.n);
        }
        a
    }

    /// a b / R mod n, word by word of b (CIOS).
    fn montgomery(&self, a: &[u64], b: &[u64]) -> Limbs {
        let k = self.n.len();
        let mut t = Limbs::new();
        t.resize(k + 2, 0);
        for &word in b {
            let mut carry = 0;
            for j in 0..k {
                let sum =
                    u128::from(t[j]) + u128::from(a[j]) * u128::from(word) + u128::from(carry);
                t[j] = low(sum);
                carry = high(sum);
            }
            let top = u128::from(t[k]) + u128::from(carry);
            t[k] = low(top);
            t[k + 1] = high(top);
            let m = t[0].wrapping_mul(self.inverse);
            let mut shifted = high(u128::from(t[0]) + u128::from(m) * u128::from(self.n[0]));
            for j in 1..k {
                let sum =
                    u128::from(t[j]) + u128::from(m) * u128::from(self.n[j]) + u128::from(shifted);
                t[j - 1] = low(sum);
                shifted = high(sum);
            }
            let last = u128::from(t[k]) + u128::from(shifted);
            t[k - 1] = low(last);
            t[k] = t[k + 1] + high(last);
            t[k + 1] = 0;
        }
        let over = t[k];
        t.truncate(k);
        if over != 0 || !below(&t, &self.n) {
            sub_from(&mut t, &self.n);
        }
        t
    }

    fn product(&self, a: &[u64], b: &[u64]) -> Limbs {
        self.montgomery(&self.montgomery(a, b), &self.square)
    }

    fn pow(&self, base: &[u64], exponent: &[u8]) -> Limbs {
        let mut x = limbs(&[1], self.n.len());
        for byte in exponent {
            for bit in (0..8).rev() {
                x = self.product(&x, &x);
                if (byte >> bit) & 1 == 1 {
                    x = self.product(&x, base);
                }
            }
        }
        x
    }

    /// a^-1 for a prime n, as a^(n - 2).
    fn invert(&self, a: &[u64]) -> Limbs {
        let two = limbs(&[2], self.n.len());
        let zero = limbs(&[], self.n.len());
        // n - 2 is below n: sub does not wrap it.
        let exponent = self.sub(&zero, &two);
        self.pow(a, &big_endian(&exponent, self.bytes))
    }
}

/// A short Weierstrass curve with a = -3, in affine coordinates.
struct Curve {
    p: Modulus,
    n: Modulus,
    g: (Limbs, Limbs),
}

type Point = Option<(Limbs, Limbs)>;

impl Curve {
    fn new(p: &str, n: &str, x: &str, y: &str) -> Curve {
        let field = Modulus::new(&hex(p));
        let count = field.n.len();
        Curve {
            g: (limbs(&hex(x), count), limbs(&hex(y), count)),
            p: field,
            n: Modulus::new(&hex(n)),
        }
    }

    fn p256() -> Curve {
        Curve::new(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
    }

    fn p384() -> Curve {
        Curve::new(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
             ffffffff0000000000000000ffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
             581a0db248b0a77aecec196accc52973",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
             0a60b1ce1d7e819d7a431d7c90ea0e5f",
        )
    }

    /// a + b; None is the point at infinity.
    fn add(&self, a: Point, b: Point) -> Point {
        let (Some((x1, y1)), Some((x2, y2))) = (&a, &b) else {
            return a.or(b);
        };
        let p = &self.p;
        let slope = if x1 == x2 {
            if y1 != y2 || y1.iter().all(|word| *word == 0) {
                return None;
            }
            let square = p.product(x1, x1);
            let three = limbs(&[3], square.len());
            let numerator = p.sub(&p.add(&p.add(&square, &square), &square), &three);
            p.product(&numerator, &p.invert(&p.add(y1, y1)))
        } else {
            p.product(&p.sub(y2, y1), &p.invert(&p.sub(x2, x1)))
        };
        let x3 = p.sub(&p.sub(&p.product(&slope, &slope), x1), x2);
        let y3 = p.sub(&p.product(&slope, &p.sub(x1, &x3)), y1);
        Some((x3, y3))
    }

    /// k G, by doubling and adding.
    fn times(&self, k: &[u8]) -> Point {
        let mut point = None;
        for byte in k {
            for bit in (0..8).rev() {
                // rr: escape(copy): a point is added to itself.
                let twice = point.clone();
                point = self.add(point, twice);
                if (byte >> bit) & 1 == 1 {
                    // rr: escape(copy): the base point is added again.
                    point = self.add(point, Some(self.g.clone()));
                }
            }
        }
        point
    }

    /// ECDSA (FIPS 186-4) of a digest no longer than n, with a nonce
    /// from the key and the digest, DER-encoded.
    fn sign(&self, key: &[u8], digest: &[u8]) -> Vec<u8> {
        let n = &self.n;
        let count = n.n.len();
        let e = n.reduce(limbs(digest, count));
        let mut seed = Sha256::new();
        seed.update(key);
        seed.update(digest);
        let k = n.reduce(limbs(&seed.finish(), count));
        let (x, _) = self.times(&big_endian(&k, n.bytes)).unwrap();
        let r = n.reduce(x);
        let rd = n.product(&r, &limbs(key, count));
        let s = n.product(&n.invert(&k), &n.add(&e, &rd));
        let mut der = Vec::from([0x30, 0]);
        integer(&mut der, &big_endian(&r, n.bytes));
        integer(&mut der, &big_endian(&s, n.bytes));
        der[1] = u8::try_from(der.len() - 2).unwrap();
        der
    }
}

/// A DER INTEGER of a big-endian unsigned number, onto out.
fn integer(out: &mut Vec<u8>, value: &[u8]) {
    let start = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len() - 1);
    let digits = &value[start..];
    let pad = digits[0] >= 0x80;
    out.push(0x02);
    out.push(u8::try_from(digits.len() + usize::from(pad)).unwrap());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

fn hashed(wide: bool, data: &[u8]) -> Vec<u8> {
    if wide {
        Vec::from(sha384::digest384(data))
    } else {
        Vec::from(sha256::digest(data))
    }
}

/// RSASSA-PSS (RFC 8017 8.1) with MGF1 and a salt as long as the hash,
/// for a modulus of whole bytes whose top bit is set.
fn pss(modulus: &Modulus, exponent: &[u8], wide: bool, message: &[u8]) -> Vec<u8> {
    let size = modulus.bytes;
    let digest = hashed(wide, message);
    let mut salt = Vec::new();
    salt.resize(digest.len(), 0xa5);
    let mut prime = Vec::new();
    prime.resize(8, 0);
    prime.extend_from_slice(&digest);
    prime.extend_from_slice(&salt);
    let h = hashed(wide, &prime);
    let mut db = Vec::new();
    db.resize(size - 2 * digest.len() - 2, 0);
    db.push(1);
    db.extend_from_slice(&salt);
    let mut seed = Vec::new();
    let mut at = 0;
    for counter in 0u32.. {
        if at >= db.len() {
            break;
        }
        seed.clear();
        seed.extend_from_slice(&h);
        seed.extend_from_slice(&counter.to_be_bytes());
        for byte in hashed(wide, &seed) {
            if let Some(slot) = db.get_mut(at) {
                *slot ^= byte;
            }
            at += 1;
        }
    }
    // emBits is one under the modulus's bits: its top bit is cleared.
    db[0] &= 0x7f;
    db.extend_from_slice(&h);
    db.push(0xbc);
    let signature = modulus.pow(&limbs(&db, modulus.n.len()), exponent);
    big_endian(&signature, size)
}

/// The key a server signs CertificateVerify with.
enum Signer {
    P256(Vec<u8>),
    P384(Vec<u8>),
    Rsa(Modulus, Vec<u8>),
}

/// The server's certificates and key, from x509-tests.pem.
#[derive(Clone, Copy)]
enum Kind {
    P256,
    P384,
    RsaSha256,
    RsaSha384,
}

/// A server's chain, the anchor that trusts it, its key and the scheme
/// it signs with.
struct Identity {
    chain: Vec<Vec<u8>>,
    anchor: Vec<u8>,
    signer: Signer,
    scheme: u16,
}

/// test.rsaleaf's private exponent.
const RSA_EXPONENT: &str = "\
    091961c6b983d26363a138b62fc8903e39384af207a1216aa6d4c0f8ede3c7ef03e543654a9a4d1ebbad16333f3ca5f8\
    bab07ad0524aea1bec5358741e6a704478eb63cae3b0fdb1b7eb7a23e276a89c03cf571fc5a43f663a13a4422c9da7b6\
    afbb4efa2cdbad7bffed993bb621d6eeb7bfcd36e0a3e303b8cf58c4ce45d663d3817e17741fe7ec6dd1fa395ed70fd1\
    0b1efa2cb2bf04351ce29b1c56b591656120f08841a367647bf409e47f23944074c728a1fa8db3a442a449cbd9a22d81\
    ce108e61a45c4f07dfae418516a65cd9d00ff44f7a5b819560cbde6be91c72f9f05bcdbb261eeebca44c86128a7424e9\
    c6e6d0803fb2ba985455fe472f501981";

impl Identity {
    fn new(kind: Kind) -> Identity {
        let der = |name: &str| test_certificate(name).unwrap();
        match kind {
            Kind::P256 => Identity {
                chain: Vec::from([der("test.leaf"), der("test.inter")]),
                anchor: der("test.root"),
                signer: Signer::P256(hex(
                    "9f8036daa9ec08582c6de4f6b0b14d03c49abb1d6424ab0b34f8c2c800239fce",
                )),
                scheme: 0x0403,
            },
            Kind::P384 => Identity {
                chain: Vec::from([der("test.leaf384"), der("test.inter")]),
                anchor: der("test.root"),
                signer: Signer::P384(hex(
                    "9c2b3d342af932742c4ef49e2aa4a871deb6c37e246942027c45a907b524b7e0\
                     bb5f8ad1479bc74f15df145a386e439e",
                )),
                scheme: 0x0503,
            },
            Kind::RsaSha256 | Kind::RsaSha384 => {
                let leaf = der("test.rsaleaf");
                let x509::Key::Rsa { modulus, .. } = x509::parse(&leaf).unwrap().key else {
                    panic!("test.rsaleaf has an RSA key");
                };
                let signer = Signer::Rsa(Modulus::new(modulus), hex(RSA_EXPONENT));
                let scheme = if matches!(kind, Kind::RsaSha256) {
                    0x0804
                } else {
                    0x0805
                };
                Identity {
                    chain: Vec::from([leaf]),
                    anchor: der("test.rsaroot"),
                    signer,
                    scheme,
                }
            }
        }
    }

    fn store(&self) -> Store {
        let mut store = Store::new();
        assert_eq!(store.add_der(&self.anchor), Ok(()));
        store
    }

    fn sign(&self, content: &[u8]) -> Vec<u8> {
        match &self.signer {
            Signer::P256(key) => Curve::p256().sign(key, &sha256::digest(content)),
            Signer::P384(key) => Curve::p384().sign(key, &sha384::digest384(content)),
            Signer::Rsa(modulus, exponent) => {
                pss(modulus, exponent, self.scheme == 0x0805, content)
            }
        }
    }
}

/// What the server does besides a plain handshake.
struct Script {
    identity: Identity,
    /// A HelloRetryRequest first, with this cookie, this group or both.
    cookie: Option<&'static [u8]>,
    retry_group: Option<u16>,
    /// The group ServerHello chooses without a retry that names one.
    group: u16,
    /// The suite ServerHello chooses, and the one a HelloRetryRequest
    /// names.
    suite: u16,
    retry_suite: u16,
    /// The protocol EncryptedExtensions chooses, if any.
    alpn: Option<&'static [u8]>,
    /// Extensions added to EncryptedExtensions, as on the wire.
    extensions: Vec<u8>,
    /// The leaf's CertificateEntry extensions, as on the wire.
    entry: Vec<u8>,
    /// A CertificateRequest's body, before the Certificate.
    request: Option<Vec<u8>>,
    /// A change_cipher_spec after ServerHello.
    compatible: bool,
    /// Whether the flight after ServerHello is sent.
    flight: bool,
    /// The most handshake plaintext of one record.
    piece: usize,
}

impl Script {
    fn new(kind: Kind) -> Script {
        Script {
            identity: Identity::new(kind),
            cookie: None,
            retry_group: None,
            group: X25519MLKEM768,
            suite: AES_128_GCM_SHA256,
            retry_suite: AES_128_GCM_SHA256,
            alpn: None,
            extensions: Vec::new(),
            entry: Vec::new(),
            request: None,
            compatible: false,
            flight: true,
            piece: RECORD_MAX,
        }
    }
}

/// What the client's ClientHello said.
struct Hello {
    name: Option<Vec<u8>>,
    // rr: escape(bound): one ClientHello's.
    alpn: Vec<Vec<u8>>,
    cookie: Option<Vec<u8>>,
    session: Vec<u8>,
    /// The key shares, by group.
    // rr: escape(bound): one ClientHello's.
    shares: Vec<(u16, Vec<u8>)>,
    // rr: escape(bound): one ClientHello's.
    suites: Vec<u16>,
    // rr: escape(bound): one ClientHello's.
    signatures: Vec<u16>,
}

/// The test server: it answers each record the client sends.
struct Server {
    script: Script,
    transcript: Transcript,
    read: Option<Opening>,
    write: Option<Keys>,
    master: Digest,
    client_secret: Option<Digest>,
    retried: bool,
    input: Vec<u8>,
    /// Bytes for the client.
    // rr: escape(bound): a test's few records.
    output: Vec<u8>,
    /// The client's application data.
    received: Vec<u8>,
    /// The descriptions of the client's alerts.
    // rr: escape(bound): a test's few records.
    alerts: Vec<u8>,
    hello: Hello,
    /// The Certificate that answered a CertificateRequest.
    certificate: Option<Vec<u8>>,
    /// KeyUpdates the client sent.
    updates: usize,
    /// change_cipher_spec records the client sent.
    ccs: usize,
    finished: bool,
}

impl Server {
    fn new(script: Script) -> Server {
        Server {
            script,
            transcript: Transcript::new(),
            read: None,
            write: None,
            master: Digest::Sha256([0; 32]),
            client_secret: None,
            retried: false,
            input: Vec::new(),
            output: Vec::new(),
            received: Vec::new(),
            alerts: Vec::new(),
            hello: Hello {
                name: None,
                alpn: Vec::new(),
                cookie: None,
                session: Vec::new(),
                shares: Vec::new(),
                suites: Vec::new(),
                signatures: Vec::new(),
            },
            certificate: None,
            updates: 0,
            ccs: 0,
            finished: false,
        }
    }

    fn hash(&self) -> Digest {
        self.transcript.hash()
    }

    /// Takes the client's bytes and answers each whole record.
    fn receive(&mut self, bytes: &[u8]) {
        self.input.extend_from_slice(bytes);
        while self.input.len() >= 5 {
            let length = usize::from(u16::from_be_bytes([self.input[3], self.input[4]]));
            if self.input.len() < 5 + length {
                break;
            }
            let rest = self.input.split_off(5 + length);
            let mut record = core::mem::replace(&mut self.input, rest);
            if record[0] == CHANGE_CIPHER_SPEC {
                // Middlebox compatibility's, in the clear.
                assert_eq!(record[5..], [1]);
                self.ccs += 1;
                continue;
            }
            let kind = match &mut self.read {
                Some(keys) => opened(keys, &mut record),
                None => {
                    let kind = record[0];
                    record.drain(..5);
                    kind
                }
            };
            match kind {
                HANDSHAKE => self.message(&record),
                APPLICATION => self.received.extend_from_slice(&record),
                ALERT => self.alerts.push(record[1]),
                _ => panic!("record type {kind}"),
            }
        }
    }

    fn message(&mut self, message: &[u8]) {
        match message[0] {
            1 => self.hello(message),
            11 => {
                self.transcript.update(message);
                // rr: escape(copy): the test looks at it later.
                self.certificate = Some(message.to_vec());
            }
            20 => {
                let key = derive(&self.read.as_ref().unwrap().secret, b"finished", &[]);
                assert_eq!(message[4..], *mac(&key, &self.hash()).bytes());
                self.read = self.client_secret.take().map(Opening::new);
                self.finished = true;
            }
            24 => {
                self.read = Some(self.read.as_ref().unwrap().next());
                self.updates += 1;
            }
            kind => panic!("handshake message {kind}"),
        }
    }

    fn hello(&mut self, message: &[u8]) {
        let hello = &mut self.hello;
        hello.alpn.clear();
        hello.name = None;
        hello.cookie = None;
        let mut fields = Reader {
            rest: &message[4..],
        };
        assert_eq!(fields.u16().unwrap(), 0x0303);
        fields.take(32).unwrap();
        // rr: escape(copy): ServerHello echoes it.
        hello.session = fields.vector(1).unwrap().to_vec();
        let mut suites = Reader {
            rest: fields.vector(2).unwrap(),
        };
        hello.suites.clear();
        while let Ok(suite) = suites.u16() {
            hello.suites.push(suite);
        }
        assert_eq!(fields.vector(1).unwrap(), [0]);
        let mut extensions = Reader {
            rest: fields.vector(2).unwrap(),
        };
        fields.end().unwrap();
        while !extensions.rest.is_empty() {
            let kind = extensions.u16().unwrap();
            let mut data = Reader {
                rest: extensions.vector(2).unwrap(),
            };
            let mut list = Reader {
                rest: data.vector(if kind == 43 { 1 } else { 2 }).unwrap(),
            };
            match kind {
                0 => {
                    assert_eq!(list.u8().unwrap(), 0);
                    // rr: escape(copy): the test looks at it later.
                    hello.name = Some(list.vector(2).unwrap().to_vec());
                }
                10 => assert_eq!(list.rest, [0x11, 0xec, 0, 0x1d, 0, 0x17]),
                13 => {
                    hello.signatures.clear();
                    while let Ok(scheme) = list.u16() {
                        hello.signatures.push(scheme);
                    }
                }
                16 => {
                    while let Ok(name) = list.vector(1) {
                        // rr: escape(copy): the test looks at it later.
                        hello.alpn.push(name.to_vec());
                    }
                }
                43 => assert_eq!(list.rest, [3, 4]),
                // rr: escape(copy): the test looks at it later.
                44 => hello.cookie = Some(list.rest.to_vec()),
                51 => {
                    hello.shares.clear();
                    while let Ok(group) = list.u16() {
                        // rr: escape(copy): the server's key share needs it.
                        hello.shares.push((group, list.vector(2).unwrap().to_vec()));
                    }
                }
                other => panic!("extension {other}"),
            }
            data.end().unwrap();
        }
        self.transcript.update(message);
        let asks = self.script.cookie.is_some() || self.script.retry_group.is_some();
        if asks && !self.retried {
            self.retried = true;
            return self.retry();
        }
        if self.retried {
            assert_eq!(self.hello.cookie.as_deref(), self.script.cookie);
            if let Some(group) = self.script.retry_group {
                // A key for the group asked for, alone.
                assert_eq!(self.hello.shares.len(), 1);
                assert_eq!(self.hello.shares[0].0, group);
            }
        }
        self.server_hello();
    }

    fn retry(&mut self) {
        let mut extensions = Vec::from([0, 43, 0, 2, 3, 4]);
        if let Some(group) = self.script.retry_group {
            extensions.extend_from_slice(&[0, 51, 0, 2]);
            extensions.extend_from_slice(&group.to_be_bytes());
        }
        if let Some(cookie) = self.script.cookie {
            extensions.extend_from_slice(&[0, 44]);
            prefixed(&mut extensions, 2 + cookie.len(), &[]);
            prefixed(&mut extensions, cookie.len(), cookie);
        }
        let suite = self.script.retry_suite;
        let retry = hello_message(&HELLO_RETRY, &self.hello.session, suite, &extensions);
        self.transcript.select(suite).unwrap();
        let first = self.hash();
        self.transcript.restart();
        let length = u8::try_from(first.bytes().len()).unwrap();
        self.transcript.update(&[254, 0, 0, length]);
        self.transcript.update(first.bytes());
        self.transcript.update(&retry);
        self.plain(HANDSHAKE, &retry);
    }

    /// The server's key share for group, from the client's, and the
    /// shared secret.
    fn agree(&self, group: u16) -> (Vec<u8>, Vec<u8>) {
        let (_, share) = self
            .hello
            .shares
            .iter()
            .find(|(offered, _)| *offered == group)
            .expect("no key share for the group");
        let secret = x25519::Secret::new(Seed32::for_tests([0x3a; 32]));
        let x25519 = |peer: &[u8]| {
            let peer = x25519::PublicKey::from_bytes(peer.try_into().unwrap());
            secret.agree(&peer).unwrap()
        };
        let (mut key, mut shared) = (Vec::new(), Vec::new());
        match group {
            X25519 => {
                key.extend_from_slice(secret.public_key().bytes());
                shared.extend_from_slice(x25519(share).kdf_input());
            }
            X25519MLKEM768 => {
                let (encapsulation, peer) = share.split_at(mlkem::ENCAPSULATION_KEY_BYTES);
                let encapsulation = encapsulation.try_into().unwrap();
                let seed = Seed32::for_tests([0x4d; 32]);
                let (ciphertext, kem) = mlkem::encapsulate(encapsulation, seed).unwrap();
                key.extend_from_slice(&ciphertext);
                key.extend_from_slice(secret.public_key().bytes());
                shared.extend_from_slice(kem.kdf_input());
                shared.extend_from_slice(x25519(peer).kdf_input());
            }
            _ => {
                let p256 = ecdh::Secret::new(Seed64::for_tests([0x3a; 64]));
                key.extend_from_slice(p256.public_key().bytes());
                let peer = ecdh::PublicKey::parse(share).unwrap();
                shared.extend_from_slice(p256.agree(&peer).kdf_input());
            }
        }
        (key, shared)
    }

    fn server_hello(&mut self) {
        let group = self.script.retry_group.unwrap_or(self.script.group);
        let (share, shared) = self.agree(group);
        let mut extensions = Vec::from([0, 43, 0, 2, 3, 4, 0, 51]);
        prefixed(&mut extensions, share.len() + 4, &group.to_be_bytes());
        prefixed(&mut extensions, share.len(), &share);
        let suite = self.script.suite;
        let hello = hello_message(&[0x7e; 32], &self.hello.session, suite, &extensions);
        if self.transcript.select(suite).is_err() {
            // Another suite than the retry's: the client refuses it at
            // once, and the server goes no further.
            return self.plain(HANDSHAKE, &hello);
        }
        self.transcript.update(&hello);
        self.plain(HANDSHAKE, &hello);
        if self.script.compatible {
            self.output
                .extend_from_slice(&[CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
        }
        let secrets = handshake_secrets(&shared, &self.hash());
        let finished = derive(&secrets.server, b"finished", &[]);
        self.read = Some(Opening::new(secrets.client));
        self.write = Some(Keys::new(secrets.server));
        self.master = secrets.master;
        if !self.script.flight {
            return;
        }
        let mut flight = Vec::new();
        let mut encrypted = Vec::new();
        if let Some(alpn) = self.script.alpn {
            encrypted.extend_from_slice(&[0, 16]);
            prefixed(&mut encrypted, alpn.len() + 3, &[]);
            prefixed(
                &mut encrypted,
                alpn.len() + 1,
                &[u8::try_from(alpn.len()).unwrap()],
            );
            encrypted.extend_from_slice(alpn);
        }
        encrypted.extend_from_slice(&self.script.extensions);
        let mut body = Vec::new();
        prefixed(&mut body, encrypted.len(), &encrypted);
        self.add(&mut flight, 8, &body);
        if let Some(request) = self.script.request.take() {
            self.add(&mut flight, 13, &request);
        }
        let mut list = Vec::new();
        for (at, der) in self.script.identity.chain.iter().enumerate() {
            list.extend_from_slice(&u24(der.len()));
            list.extend_from_slice(der);
            let entry = if at == 0 { &self.script.entry[..] } else { &[] };
            prefixed(&mut list, entry.len(), entry);
        }
        body.clear();
        body.push(0);
        body.extend_from_slice(&u24(list.len()));
        body.extend_from_slice(&list);
        self.add(&mut flight, 11, &body);
        let mut content = Vec::from([0x20; 64]);
        content.extend_from_slice(VERIFY_CONTEXT);
        content.extend_from_slice(self.hash().bytes());
        let signature = self.script.identity.sign(&content);
        body.clear();
        body.extend_from_slice(&self.script.identity.scheme.to_be_bytes());
        prefixed(&mut body, signature.len(), &signature);
        self.add(&mut flight, 15, &body);
        let verify = mac(&finished, &self.hash());
        self.add(&mut flight, 20, verify.bytes());
        for piece in flight.chunks(self.script.piece) {
            self.send(HANDSHAKE, piece);
        }
        let hash = self.hash();
        self.client_secret = Some(derive(&self.master, b"c ap traffic", hash.bytes()));
        let server = derive(&self.master, b"s ap traffic", hash.bytes());
        self.write = Some(Keys::new(server));
    }

    /// A message of kind into the flight and the transcript.
    fn add(&mut self, flight: &mut Vec<u8>, kind: u8, body: &[u8]) {
        let start = flight.len();
        flight.push(kind);
        flight.extend_from_slice(&u24(body.len()));
        flight.extend_from_slice(body);
        self.transcript.update(&flight[start..]);
    }

    fn plain(&mut self, kind: u8, data: &[u8]) {
        self.output.extend_from_slice(&[kind, 3, 3]);
        prefixed(&mut self.output, data.len(), data);
    }

    /// data as a record of kind, sealed once the server has keys.
    fn send(&mut self, kind: u8, data: &[u8]) {
        if self.write.is_none() {
            return self.plain(kind, data);
        }
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
        inner.push(kind);
        self.raw(inner);
    }

    /// inner, the plaintext with its type and any padding, as one
    /// sealed record.
    fn raw(&mut self, mut inner: Vec<u8>) {
        let keys = self.write.as_mut().unwrap();
        let length = u16::try_from(inner.len() + 16).unwrap().to_be_bytes();
        let header = [APPLICATION, 3, 3, length[0], length[1]];
        let tag = keys.key.seal(&header, &mut inner).unwrap();
        self.output.extend_from_slice(&header);
        self.output.extend_from_slice(&inner);
        self.output.extend_from_slice(tag.bytes());
    }

    /// A KeyUpdate, then records under the next keys.
    fn update(&mut self, request: bool) {
        self.send(HANDSHAKE, &[24, 0, 0, 1, u8::from(request)]);
        self.write = Some(self.write.as_ref().unwrap().next());
    }

    /// Everything the server has for the client.
    fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }
}

/// A ServerHello, or a HelloRetryRequest by its random, echoing the
/// client's session ID and choosing suite.
fn hello_message(random: &[u8; 32], session: &[u8], suite: u16, extensions: &[u8]) -> Vec<u8> {
    let mut m = Vec::from([2, 0, 0, 0, 3, 3]);
    m.extend_from_slice(random);
    m.push(u8::try_from(session.len()).unwrap());
    m.extend_from_slice(session);
    m.extend_from_slice(&suite.to_be_bytes());
    m.push(0);
    prefixed(&mut m, extensions.len(), extensions);
    let length = u24(m.len() - 4);
    m[1..4].copy_from_slice(&length);
    m
}

/// Opens a record in place with the server's keys: its type, and the
/// record cut to its plaintext.
fn opened(keys: &mut Opening, record: &mut Vec<u8>) -> u8 {
    let (header, body) = record.split_at_mut(5);
    let at = body.len() - 16;
    let (data, tag) = body.split_at_mut(at);
    let tag: &[u8; 16] = (&*tag).try_into().unwrap();
    keys.key.open(header, data, tag).unwrap();
    let end = data.iter().rposition(|byte| *byte != 0).unwrap();
    let kind = data[end];
    record.truncate(5 + end);
    record.drain(..5);
    kind
}

fn u24(length: usize) -> [u8; 3] {
    let [_, a, b, c] = u32::try_from(length).unwrap().to_be_bytes();
    [a, b, c]
}

/// Appends length as two bytes, then data.
fn prefixed(out: &mut Vec<u8>, length: usize, data: &[u8]) {
    out.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

/// Sizes of the pieces the server's bytes come in: piece bytes each, or
/// from 1 to piece at random when seed is not 0.
struct Split {
    piece: usize,
    seed: u64,
}

impl Split {
    fn next(&mut self) -> usize {
        if self.seed == 0 {
            return self.piece;
        }
        // xorshift64.
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        usize::try_from(self.seed % u64::try_from(self.piece).unwrap()).unwrap() + 1
    }
}

fn whole() -> Split {
    Split {
        piece: WHOLE,
        seed: 0,
    }
}

/// Feeds bytes in pieces as reads would bring them, reading what each
/// input decrypts into got.
fn feed(
    client: &mut Client<'_>,
    bytes: &[u8],
    split: &mut Split,
    got: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut at = 0;
    while at < bytes.len() {
        let end = (at + split.next()).min(bytes.len());
        let mut piece = &bytes[at..end];
        while !piece.is_empty() || !client.read().is_empty() {
            let taken = client.input(piece)?.count();
            piece = &piece[taken..];
            let data = client.read();
            let count = data.len();
            assert!(taken > 0 || count > 0);
            assert!(count <= RECORD_MAX);
            got.extend_from_slice(data);
            client.consume(count);
        }
        at = end;
    }
    Ok(())
}

/// Moves bytes both ways until neither side has more; what the client
/// read.
fn exchange(
    client: &mut Client<'_>,
    server: &mut Server,
    split: &mut Split,
) -> Result<Vec<u8>, Error> {
    let mut got = Vec::new();
    for _ in 0..16 {
        let sent = client.pending().len();
        server.receive(client.pending());
        client.sent(sent)?;
        let back = server.take();
        if sent == 0 && back.is_empty() {
            return Ok(got);
        }
        if let Err(error) = feed(client, &back, split, &mut got) {
            // The alert the client queued reaches the server.
            server.receive(client.pending());
            return Err(error);
        }
    }
    panic!("the exchange does not end");
}

/// A handshake with the server, its bytes in the split's pieces.
fn connect<'a>(
    store: &'a Store,
    server: &mut Server,
    host: &str,
    alpn: &[&[u8]],
    split: &mut Split,
) -> Result<Client<'a>, Error> {
    let mut client = Client::with(host, alpn, Verify::Store(store), TEST_NOW, random())?;
    let got = exchange(&mut client, server, split)?;
    assert!(got.is_empty());
    Ok(client)
}

/// The handshake's outcome with a script, and the alerts the server got.
fn outcome(script: Script, host: &str, alpn: &[&[u8]], now: i64) -> (Option<Error>, Vec<u8>) {
    let store = script.identity.store();
    let mut server = Server::new(script);
    let mut client = Client::with(host, alpn, Verify::Store(&store), now, random()).unwrap();
    let result = exchange(&mut client, &mut server, &mut whole());
    (result.err(), server.alerts)
}

/// A connected client and its server.
fn connected(store: &Store) -> (Client<'_>, Server) {
    let mut server = Server::new(Script::new(Kind::P256));
    let client = connect(store, &mut server, HOST, &[], &mut whole()).unwrap();
    (client, server)
}

/// What the client makes of records the server sends once connected:
/// the result, what it read and the alerts the server got back.
fn after(records: impl FnOnce(&mut Server), piece: usize) -> (Option<Error>, Vec<u8>, Vec<u8>) {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    records(&mut server);
    let bytes = server.take();
    let mut got = Vec::new();
    let mut split = Split { piece, seed: 0 };
    let result = feed(&mut client, &bytes, &mut split, &mut got);
    server.receive(client.pending());
    (result.err(), got, server.alerts)
}

/// What the client makes of bytes after ServerHello: a record of kind
/// the server seals with its handshake keys, or bytes as they are.
fn after_hello(kind: Option<u8>, bytes: &[u8]) -> Option<Error> {
    let mut script = Script::new(Kind::P256);
    script.flight = false;
    let store = script.identity.store();
    let mut server = Server::new(script);
    let mut client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    match kind {
        Some(sealed) => server.send(sealed, bytes),
        None => server.output.extend_from_slice(bytes),
    }
    let all = server.take();
    feed(
        &mut client,
        &all,
        &mut Split { piece: 1, seed: 0 },
        &mut Vec::new(),
    )
    .err()
}

// RFC 8448 section 3, "Simple 1-RTT Handshake".
const CLIENT_PRIVATE: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
const CLIENT_HELLO: &str = "\
    010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef\
    6283024dece7000006130113031302010000910000000b000900000673657276\
    6572ff01000100000a00140012001d0017001800190100010101020103010400\
    230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e\
    51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603\
    020308040805080604010501060102010402050206020202002d00020101001c\
    00024001";
const SERVER_HELLO_RECORD: &str = "\
    160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb\
    1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095\
    fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
const CLIENT_HS: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
const SERVER_HS: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
const MASTER: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
const SERVER_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
const SERVER_HS_IV: &str = "5d313eb2671276ee13000b30";
const CLIENT_HS_KEY: &str = "dbfaa693d1762c5b666af5d950258d01";
const CLIENT_HS_IV: &str = "5bd3c71b836e0b76bb73265f";
const SERVER_FINISHED_KEY: &str =
    "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8";
const SERVER_FLIGHT: &str = "\
    17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e\
    df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78\
    b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b\
    d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9\
    d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e\
    d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092\
    8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694\
    5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368\
    4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f\
    4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26\
    f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531\
    7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e\
    1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da\
    8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4\
    61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe\
    5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb\
    992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859\
    77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038\
    ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84\
    5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5\
    d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e\
    750edc53370d2b";
const SERVER_FLIGHT_PLAIN: &str = "\
    080000240022000a00140012001d00170018001901000101010201030104001c\
    00024001000000000b0001b9000001b50001b0308201ac30820115a003020102\
    020102300d06092a864886f70d01010b0500300e310c300a0603550403130372\
    7361301e170d3136303733303031323335395a170d3236303733303031323335\
    395a300e310c300a0603550403130372736130819f300d06092a864886f70d01\
    0101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c\
    0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19e\
    aa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e2\
    2a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a\
    8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304\
    023000300b0603551d0f0404030205a0300d06092a864886f70d01010b050003\
    81810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594\
    365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd\
    335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb\
    2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4\
    2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f82\
    4cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef78\
    0c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671\
    459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda\
    65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de\
    da4ab42c309572cb7fffee5454b78f0718";
const CLIENT_AP: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
const SERVER_AP: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
const SERVER_AP_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
const SERVER_AP_IV: &str = "cf782b88dd83549aadf1e984";
const CLIENT_AP_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
const CLIENT_AP_IV: &str = "5b78923dee08579033e523d9";
const CLIENT_FINISHED_RECORD: &str = "\
    170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc\
    44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546";
const CLIENT_DATA: &str = "\
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
    202122232425262728292a2b2c2d2e2f3031";
const CLIENT_DATA_RECORD: &str = "\
    1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f\
    2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6\
    3aeebb21694915e4";

fn key_of(secret: &Digest) -> Vec<u8> {
    let mut key = [0; 16];
    expand(secret, b"key", &[], &mut key);
    Vec::from(key)
}

/// The IV of a traffic secret, which aesgcm's keys keep to themselves.
fn iv_of(secret: &Digest) -> Vec<u8> {
    let mut iv = [0; 12];
    expand(secret, b"iv", &[], &mut iv);
    Vec::from(iv)
}

/// The trace's key schedule and records through the client. Its
/// ClientHello is not this client's, so the trace's takes our own's
/// place in the transcript, and its EncryptedExtensions, an answer to
/// that ClientHello, goes in as it is; its certificate is 1024-bit RSA,
/// outside x509's profile, so Certificate and CertificateVerify go into the
/// transcript unchecked. The rest is the client's own: the secrets from
/// ServerHello, the opening of the flight, the check of the server's
/// Finished, and the exact bytes of the client's Finished and of its
/// first application record.
#[test]
fn rfc8448_simple_1rtt() {
    let store = Store::new();
    let random = Random {
        client: [0; 32],
        session: [0; 32],
        x25519: Seed32::for_tests(hex(CLIENT_PRIVATE).try_into().unwrap()),
        mlkem: Seed64::for_tests([0; 64]),
        p256: Seed64::for_tests([0; 64]),
    };
    let mut client = Client::with("server", &[], Verify::Store(&store), 0, random).unwrap();
    // RFC 8448's client offers X25519 alone, without middlebox
    // compatibility.
    client.session = None;
    client.kem = None;
    client.sent(client.pending().len()).unwrap();
    client.transcript = Transcript::new();
    client.transcript.update(&hex(CLIENT_HELLO));
    let hello = hex(SERVER_HELLO_RECORD);
    assert_eq!(client.input(&hello), Ok(Taken(hello.len())));
    let reading = client.input_keys.as_ref().unwrap();
    let writing = client.output_keys.as_ref().unwrap();
    assert_eq!(reading.secret.bytes(), hex(SERVER_HS));
    assert_eq!(writing.secret.bytes(), hex(CLIENT_HS));
    assert_eq!(client.master.bytes(), hex(MASTER));
    assert_eq!(key_of(&reading.secret), hex(SERVER_HS_KEY));
    assert_eq!(iv_of(&reading.secret), hex(SERVER_HS_IV));
    assert_eq!(key_of(&writing.secret), hex(CLIENT_HS_KEY));
    assert_eq!(iv_of(&writing.secret), hex(CLIENT_HS_IV));
    assert_eq!(client.server_finished.bytes(), hex(SERVER_FINISHED_KEY));
    let mut flight = hex(SERVER_FLIGHT);
    let keys = client.input_keys.as_mut().unwrap();
    let kind = opened(keys, &mut flight);
    assert_eq!(kind, HANDSHAKE);
    assert_eq!(flight, hex(SERVER_FLIGHT_PLAIN));
    let mut rest = &flight[..];
    while !rest.is_empty() {
        let length = usize::from(rest[2]) * 256 + usize::from(rest[3]);
        let (message, next) = rest.split_at(4 + length);
        match message[0] {
            // Its EncryptedExtensions answers the trace's ClientHello,
            // which offered record_size_limit; this client never does,
            // so it refuses the extension (RFC 9846 4.3), and the message
            // goes into the transcript as the trace has it.
            8 => {
                assert_eq!(client.message(8, message), Err(Error::Extension));
                assert!(matches!(client.state, State::Extensions));
                client.transcript.update(message);
                client.state = State::Certificate;
            }
            11 => client.transcript.update(message),
            15 => {
                client.transcript.update(message);
                client.state = State::Finished;
            }
            _ => assert_eq!(client.message(20, message), Ok(true)),
        }
        rest = next;
    }
    assert!(client.connected());
    assert_eq!(client.pending(), hex(CLIENT_FINISHED_RECORD));
    let app_reading = client.input_keys.as_ref().unwrap();
    let app_writing = client.output_keys.as_ref().unwrap();
    assert_eq!(app_reading.secret.bytes(), hex(SERVER_AP));
    assert_eq!(app_writing.secret.bytes(), hex(CLIENT_AP));
    assert_eq!(key_of(&app_reading.secret), hex(SERVER_AP_KEY));
    assert_eq!(iv_of(&app_reading.secret), hex(SERVER_AP_IV));
    assert_eq!(key_of(&app_writing.secret), hex(CLIENT_AP_KEY));
    assert_eq!(iv_of(&app_writing.secret), hex(CLIENT_AP_IV));
    client.sent(client.pending().len()).unwrap();
    let data = hex(CLIENT_DATA);
    assert_eq!(client.write(&data), Ok(Taken(data.len())));
    assert_eq!(client.pending(), hex(CLIENT_DATA_RECORD));
}

/// What the ClientHello offers, as the server parsed it; an IP literal
/// goes without SNI.
#[test]
fn client_hello() {
    let store = Identity::new(Kind::P256).store();
    let mut server = Server::new(Script::new(Kind::P256));
    let named = Client::with(
        "api.example.test.",
        &[b"h2", b"http/1.1"],
        Verify::Store(&store),
        0,
        random(),
    );
    let client = named.unwrap();
    assert_eq!(client.pending()[..3], [22, 3, 1]);
    server.receive(client.pending());
    let hello = &server.hello;
    assert_eq!(hello.name.as_deref(), Some(&b"api.example.test"[..]));
    assert_eq!(hello.alpn, [&b"h2"[..], b"http/1.1"]);
    assert_eq!(hello.suites, [AES_128_GCM_SHA256, AES_256_GCM_SHA384]);
    assert_eq!(
        hello.signatures,
        [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601
        ]
    );
    assert_eq!(hello.cookie, None);
    let mut other = Server::new(Script::new(Kind::P256));
    let literal = Client::with("192.0.2.1", &[], Verify::Store(&store), 0, random()).unwrap();
    other.receive(literal.pending());
    assert_eq!(other.hello.name, None);
    assert!(other.hello.alpn.is_empty());
}

#[test]
fn refuses_bad_arguments() {
    let store = Store::new();
    let long = "a".repeat(254);
    for host in ["", "a..b", ".a", "a b", "\u{e9}.test", "a/b", &long] {
        let made = Client::with(host, &[], Verify::Store(&store), 0, random());
        assert_eq!(made.err(), Some(Error::Host), "{host}");
    }
    for host in [
        "localhost",
        "a-b_c.test",
        "[2001:db8::1]",
        "::1",
        "10.0.0.1",
    ] {
        assert!(
            Client::with(host, &[], Verify::Store(&store), 0, random()).is_ok(),
            "{host}"
        );
    }
    let name = [b'x'; 256];
    let many = [&name[..200]; 8];
    for alpn in [&[&b""[..]][..], &[&name[..]], &many] {
        let made = Client::with(HOST, alpn, Verify::Store(&store), 0, random());
        assert_eq!(made.err(), Some(Error::Alpn));
    }
}

/// Each kind of key and scheme, then data both ways and close_notify
/// both ways.
#[test]
fn handshakes() {
    for kind in [Kind::P256, Kind::P384, Kind::RsaSha256, Kind::RsaSha384] {
        let store = Identity::new(kind).store();
        let mut server = Server::new(Script::new(kind));
        let mut split = whole();
        let mut client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
        assert!(client.connected() && !client.closed());
        assert!(server.finished);
        assert_eq!(client.alpn(), None);
        assert_eq!(client.write(b"ping"), Ok(Taken(4)));
        server.send(APPLICATION, b"pong");
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::from(*b"pong"))
        );
        assert_eq!(server.received, b"ping");
        server.send(ALERT, &[1, 0]);
        server.send(APPLICATION, b"ignored");
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert!(client.closed() && client.connected());
        // The write side stays open until close.
        assert_eq!(client.write(b"late"), Ok(Taken(4)));
        client.close();
        assert_eq!(client.write(b"x"), Err(Error::Closed));
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert_eq!(server.received, b"pinglate");
        assert_eq!(server.alerts, [0]);
    }
}

/// The server's bytes for a handshake, two records of data and
/// close_notify.
fn recorded(store: &Store) -> Vec<u8> {
    let mut server = Server::new(Script::new(Kind::P256));
    let mut client = Client::with(HOST, &[], Verify::Store(store), TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    client.sent(client.pending().len()).unwrap();
    let mut bytes = server.take();
    feed(&mut client, &bytes, &mut whole(), &mut Vec::new()).unwrap();
    server.receive(client.pending());
    assert!(server.finished);
    server.send(APPLICATION, b"hello, ");
    server.send(APPLICATION, b"world");
    server.send(ALERT, &[1, 0]);
    bytes.append(&mut server.output);
    bytes
}

/// bytes into a fresh client in parts, each in the split's pieces.
fn replay(store: &Store, parts: &[&[u8]], split: &mut Split) -> Vec<u8> {
    let mut client = Client::with(HOST, &[], Verify::Store(store), TEST_NOW, random()).unwrap();
    let mut got = Vec::new();
    for part in parts {
        feed(&mut client, part, split, &mut got).unwrap();
    }
    assert!(client.connected() && client.closed());
    got
}

/// The server's bytes in every split in two, a byte at a time and in
/// random pieces give the same handshake and data.
#[test]
fn any_split() {
    let store = Identity::new(Kind::P256).store();
    let bytes = recorded(&store);
    let bytewise = replay(&store, &[&bytes], &mut Split { piece: 1, seed: 0 });
    assert_eq!(bytewise, b"hello, world");
    for seed in 1..40 {
        let got = replay(&store, &[&bytes], &mut Split { piece: 300, seed });
        assert_eq!(got, b"hello, world");
    }
    for cut in 1..bytes.len() {
        let (first, second) = bytes.split_at(cut);
        let got = replay(&store, &[first, second], &mut whole());
        assert_eq!(got, b"hello, world", "cut at {cut}");
    }
}

/// Handshake messages split across records, down to a byte each, and
/// a change_cipher_spec after ServerHello, which is dropped.
#[test]
fn fragmented_messages() {
    for piece in [1, 2, 7, 100, 1000] {
        let mut script = Script::new(Kind::P256);
        script.piece = piece;
        script.compatible = piece == 7;
        let store = script.identity.store();
        let mut server = Server::new(script);
        let seed = u64::try_from(piece).unwrap();
        let mut split = Split { piece: 500, seed };
        let client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
        assert!(client.connected());
    }
}

/// Each group the client shares a key for, and P-256 in a retry that
/// asks for it, with a cookie or not; the client sends one
/// change_cipher_spec, before its second flight.
#[test]
fn groups() {
    for (group, retry, cookie) in [
        (X25519MLKEM768, None, None),
        (X25519, None, None),
        (X25519, Some(SECP256R1), None),
        (X25519, Some(SECP256R1), Some(&b"\x01"[..])),
    ] {
        let mut script = Script::new(Kind::P256);
        script.group = group;
        script.retry_group = retry;
        script.cookie = cookie;
        let store = script.identity.store();
        let mut server = Server::new(script);
        let mut client = connect(&store, &mut server, HOST, &[], &mut whole()).unwrap();
        assert!(client.connected() && server.finished);
        assert_eq!(server.ccs, 1);
        assert_eq!(server.hello.session, SESSION);
        assert!(client.kem.is_none() && client.p256.is_none() && client.secret.is_none());
        assert_eq!(client.write(b"x"), Ok(Taken(1)));
        assert_eq!(
            exchange(&mut client, &mut server, &mut whole()),
            Ok(Vec::new())
        );
        assert_eq!(server.received, b"x");
    }
    // The first ClientHello shares X25519MLKEM768's key and X25519's.
    let store = Store::new();
    let mut server = Server::new(Script::new(Kind::P256));
    let client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    let shares = &server.hello.shares;
    assert_eq!(shares.len(), 2);
    assert_eq!(
        (shares[0].0, shares[0].1.len()),
        (X25519MLKEM768, 1184 + 32)
    );
    assert_eq!((shares[1].0, shares[1].1.len()), (X25519, 32));
}

/// A ServerHello whose key share is for a group without one, or after
/// a retry for another than it asked, or of the wrong length, or a
/// session ID that is not the client's.
#[test]
fn server_hello_refused() {
    for (share, asked, session) in [
        ("0017 0041", None, true),
        ("001d 0020", Some("0017"), true),
        ("11ec 0441", None, true),
        ("001d 001f", None, true),
        ("001d 0020", None, false),
    ] {
        let store = Store::new();
        let mut client =
            Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        client.sent(client.pending().len()).unwrap();
        if let Some(group) = asked {
            let mut all = hex("002b 0002 0304  0033 0002");
            all.extend(hex(group));
            let retry = hello_message(&HELLO_RETRY, &SESSION, AES_128_GCM_SHA256, &all);
            let mut record = Vec::from([22, 3, 3]);
            prefixed(&mut record, retry.len(), &retry);
            assert_eq!(client.input(&record), Ok(Taken(record.len())));
        }
        let mut all = hex("002b 0002 0304  0033");
        let mut entry = hex(share);
        let length = usize::from(entry[2]) * 256 + usize::from(entry[3]);
        entry.resize(4 + length, 9);
        prefixed(&mut all, entry.len(), &entry);
        let echo = if session { &SESSION[..] } else { &[][..] };
        let hello = hello_message(&[0x7e; 32], echo, AES_128_GCM_SHA256, &all);
        let mut record = Vec::from([22, 3, 3]);
        prefixed(&mut record, hello.len(), &hello);
        assert_eq!(client.input(&record), Err(Error::Parameter), "{share}");
    }
}

/// Records that carry nothing, IDLE_MAX in a row, are taken; one more
/// ends the connection. Data in between starts the count again.
#[test]
fn idle_records() {
    let (result, got, _) = after(
        |server| {
            for round in 0..2 * IDLE_MAX {
                server.send(APPLICATION, b"");
                if round == IDLE_MAX - 1 {
                    server.send(APPLICATION, b"!");
                }
            }
        },
        WHOLE,
    );
    assert_eq!((result, got), (None, Vec::from(*b"!")));
    let (flooded, _, alerts) = after(
        |server| {
            for _ in 0..=IDLE_MAX {
                server.send(HANDSHAKE, &[4, 0, 0, 0]);
            }
        },
        WHOLE,
    );
    assert_eq!(flooded, Some(Error::Unexpected));
    assert_eq!(alerts, [10]);
}

#[test]
fn hello_retry() {
    let mut script = Script::new(Kind::P256);
    script.cookie = Some(b"\xc0\x0c\xee");
    script.compatible = true;
    let store = script.identity.store();
    let mut server = Server::new(script);
    let mut split = Split { piece: 3, seed: 9 };
    let mut client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
    assert!(client.connected());
    assert_eq!(server.hello.cookie.as_deref(), Some(&b"\xc0\x0c\xee"[..]));
    assert_eq!(client.write(b"after retry"), Ok(Taken(11)));
    assert_eq!(
        exchange(&mut client, &mut server, &mut split),
        Ok(Vec::new())
    );
    assert_eq!(server.received, b"after retry");
}

/// What the client makes of a HelloRetryRequest with these extensions
/// after supported_versions, sent once or twice.
fn retried(extensions: Vec<u8>, twice: bool) -> Option<Error> {
    let store = Store::new();
    let mut all = hex("002b 0002 0304");
    all.extend(extensions);
    let retry = hello_message(&HELLO_RETRY, &SESSION, AES_128_GCM_SHA256, &all);
    let mut record = Vec::from([22, 3, 3]);
    prefixed(&mut record, retry.len(), &retry);
    let mut client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    client.sent(client.pending().len()).unwrap();
    let first = client.input(&record).err();
    if first.is_some() || !twice {
        if first.is_some() {
            // The alert goes in the clear: the client has no keys yet.
            assert_eq!(client.pending()[..5], [21, 3, 3, 0, 2]);
        }
        return first;
    }
    client.input(&record).err()
}

/// P-256, with a cookie or not; a group not offered, one already shared,
/// nothing to change, a cookie too long, and a second retry.
#[test]
fn hello_retry_refused() {
    for (extensions, twice, error) in [
        ("0033 0002 0017  002c 0003 0001 01", false, None),
        ("0033 0002 0017", false, None),
        ("0033 0002 0018", false, Some(Error::Parameter)),
        ("0033 0002 11ec", false, Some(Error::Parameter)),
        (
            "0033 0002 001d  002c 0003 0001 01",
            false,
            Some(Error::Parameter),
        ),
        ("", false, Some(Error::Parameter)),
        ("002c 0002 0000", false, Some(Error::Decode)),
        (
            "002c 0003 0001 01  002c 0003 0001 01",
            false,
            Some(Error::Decode),
        ),
        ("002c 0003 0001 01", true, Some(Error::Unexpected)),
        ("002c 0003 0001 01", false, None),
    ] {
        assert_eq!(retried(hex(extensions), twice), error, "{extensions}");
    }
    let mut long = hex("002c 1003 1001");
    long.resize(long.len() + 4097, 1);
    assert_eq!(retried(long, false), Some(Error::TooLarge));
}

#[test]
fn alpn() {
    let offer: [&[u8]; 2] = [b"h2", b"http/1.1"];
    for chosen in [&b"http/1.1"[..], b"h2"] {
        let mut script = Script::new(Kind::P256);
        script.alpn = Some(chosen);
        let store = script.identity.store();
        let mut server = Server::new(script);
        let client = connect(&store, &mut server, HOST, &offer, &mut whole()).unwrap();
        assert_eq!(client.alpn(), Some(chosen));
    }
    for (chosen, offered, error) in [
        (&b"h3"[..], &offer[..], Error::Parameter),
        (b"", &offer, Error::Decode),
        (b"h2", &[], Error::Extension),
    ] {
        let mut script = Script::new(Kind::P256);
        script.alpn = Some(chosen);
        let (result, alerts) = outcome(script, HOST, offered, TEST_NOW);
        assert_eq!(result, Some(error));
        // The client's alert goes under its handshake keys.
        assert_eq!(alerts, [error.alert().unwrap()]);
    }
}

/// EncryptedExtensions: unknown and informational extensions pass,
/// those that do not belong there fail.
#[test]
fn encrypted_extensions() {
    for (extensions, error) in [
        ("000a 0004 0002 001d  0000 0000", None),
        ("0000 0001 00", Some(Error::Decode)),
        // Offered in the ClientHello, not for this message (RFC 9846 4.3).
        ("002b 0002 0304", Some(Error::Parameter)),
        ("0033 0000", Some(Error::Parameter)),
        // Never offered, known or not (4.3): pre_shared_key, early_data,
        // ALPN without protocols offered, and a type of no meaning.
        ("0029 0002 0000", Some(Error::Extension)),
        ("002a 0000", Some(Error::Extension)),
        ("0010 0005 0003 0268 32", Some(Error::Extension)),
        ("ff99 0000", Some(Error::Extension)),
        ("0010", Some(Error::Decode)),
        // Each extension once (4.3).
        (
            "000a 0004 0002 001d  000a 0004 0002 001d",
            Some(Error::Decode),
        ),
    ] {
        let mut script = Script::new(Kind::P256);
        script.extensions = hex(extensions);
        let (result, _) = outcome(script, HOST, &[], TEST_NOW);
        assert_eq!(result, error, "{extensions}");
    }
    let mut script = Script::new(Kind::P256);
    script.extensions = hex("0000 0000");
    let (result, _) = outcome(script, "192.0.2.1", &[], TEST_NOW);
    assert_eq!(result, Some(Error::Extension));
}

/// RFC 9846 4.5.1: without a certificate the client answers a request
/// with an empty Certificate, and the handshake goes on.
#[test]
fn certificate_request() {
    let mut script = Script::new(Kind::P384);
    // An empty context and signature_algorithms, as RFC 9846 4.4.2 asks.
    script.request = Some(hex("00 0008 000d 0004 0002 0403"));
    let store = script.identity.store();
    let mut server = Server::new(script);
    let client = connect(&store, &mut server, HOST, &[], &mut whole()).unwrap();
    assert!(client.connected() && server.finished);
    assert_eq!(server.certificate, Some(hex("0b000004 00 000000")));
    for (request, error) in [
        // A context, which only a request after the handshake has.
        ("02 c0de 0008 000d 0004 0002 0403", Error::Parameter),
        // No signature_algorithms.
        ("00 0004 002f 0000", Error::Missing),
        ("00 0000", Error::Missing),
        // signature_algorithms twice.
        (
            "00 0010 000d 0004 0002 0403 000d 0004 0002 0403",
            Error::Decode,
        ),
        ("00 0006 000d 0002 0000", Error::Decode),
    ] {
        let mut refused = Script::new(Kind::P384);
        refused.request = Some(hex(request));
        let (error_found, alerts) = outcome(refused, HOST, &[], TEST_NOW);
        assert_eq!(error_found, Some(error), "{request}");
        assert_eq!(alerts.len(), 1);
    }
}

#[test]
fn certificates_refused() {
    let p256 = || Script::new(Kind::P256);
    for (host, now, error) in [
        ("other.example.test", TEST_NOW, Error::Name),
        (HOST, 2_200_000_000, Error::Expired),
        (HOST, 1_700_000_000, Error::Expired),
    ] {
        let (result, alerts) = outcome(p256(), host, &[], now);
        assert_eq!(result, Some(error));
        // The alert reached the server under the handshake keys.
        assert_eq!(alerts, [error.alert().unwrap()]);
    }
    let mut untrusted = p256();
    untrusted.identity.anchor = Identity::new(Kind::RsaSha256).anchor;
    assert_eq!(
        outcome(untrusted, HOST, &[], TEST_NOW),
        (Some(Error::Untrusted), Vec::from([48]))
    );
    let mut short = p256();
    short.identity.chain.truncate(1);
    assert_eq!(
        outcome(short, HOST, &[], TEST_NOW).0,
        Some(Error::Untrusted)
    );
    let mut empty = p256();
    empty.identity.chain.clear();
    assert_eq!(outcome(empty, HOST, &[], TEST_NOW).0, Some(Error::Decode));
    // An IP literal the leaf names.
    assert_eq!(outcome(p256(), "192.0.2.1", &[], TEST_NOW).0, None);
}

/// A signature by another key, and a scheme not offered.
#[test]
fn certificate_verify_refused() {
    let mut forged = Script::new(Kind::P256);
    forged.identity.signer = Identity::new(Kind::P384).signer;
    assert_eq!(
        outcome(forged, HOST, &[], TEST_NOW),
        (Some(Error::Signature), Vec::from([51]))
    );
    let mut pkcs1 = Script::new(Kind::P256);
    pkcs1.identity.scheme = 0x0401;
    assert_eq!(
        outcome(pkcs1, HOST, &[], TEST_NOW).0,
        Some(Error::Parameter)
    );
}

/// The server's KeyUpdates are honoured; requests that come before the
/// client's answer is sent share it.
#[test]
fn key_update() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    let mut split = whole();
    server.update(true);
    server.send(APPLICATION, b"one");
    server.update(true);
    server.send(APPLICATION, b"two");
    server.update(false);
    server.send(APPLICATION, b"three");
    let mut got = Vec::new();
    feed(&mut client, &server.take(), &mut split, &mut got).unwrap();
    assert_eq!(got, b"onetwothree");
    assert_eq!(client.write(b"four"), Ok(Taken(4)));
    assert_eq!(
        exchange(&mut client, &mut server, &mut split),
        Ok(Vec::new())
    );
    assert_eq!(server.updates, 1);
    assert_eq!(server.received, b"four");
    // Asked again once that answer is sent.
    server.update(true);
    assert_eq!(
        exchange(&mut client, &mut server, &mut split),
        Ok(Vec::new())
    );
    assert_eq!(server.updates, 2);
    // The client's own, every 2^24 records.
    client
        .output_keys
        .as_mut()
        .unwrap()
        .key
        .set_sequence_less_safe(KEY_RECORDS_MAX);
    server
        .read
        .as_mut()
        .unwrap()
        .key
        .set_sequence_for_tests(KEY_RECORDS_MAX);
    assert_eq!(client.write(b"five"), Ok(Taken(4)));
    assert_eq!(
        exchange(&mut client, &mut server, &mut split),
        Ok(Vec::new())
    );
    assert_eq!(server.updates, 3);
    assert_eq!(server.received, b"fourfive");
    assert_eq!(client.output_keys.as_ref().unwrap().key.sequence(), 1);
}

/// A request value other than 0 or 1, a KeyUpdate of two bytes, and one
/// whose record goes on.
#[test]
fn key_update_refused() {
    for (body, error) in [
        (&[24, 0, 0, 1, 2][..], Error::Parameter),
        (&[24, 0, 0, 2, 0, 0], Error::Decode),
        (&[24, 0, 0, 1, 0, 4, 0, 0, 0], Error::Unexpected),
    ] {
        let (result, _, alerts) = after(|server| server.send(HANDSHAKE, body), WHOLE);
        assert_eq!(result, Some(error));
        assert_eq!(alerts, [error.alert().unwrap()]);
    }
}

#[test]
fn alerts() {
    let store = Store::new();
    // Before ServerHello, in the clear; no alert answers the server's.
    let mut client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    client.sent(client.pending().len()).unwrap();
    assert_eq!(
        client.input(&[21, 3, 3, 0, 2, 2, 40]),
        Err(Error::Alert(40))
    );
    assert_eq!(client.input(&[22]), Err(Error::Alert(40)));
    assert!(client.pending().is_empty());
    // After it, sealed; a warning is an error too, but user_canceled.
    for (alert, error) in [
        ([2, 80], Some(Error::Alert(80))),
        ([1, 42], Some(Error::Alert(42))),
        ([1, 90], None),
    ] {
        let send = |server: &mut Server| {
            server.send(ALERT, &alert);
            server.send(APPLICATION, b"after");
        };
        let (result, got, alerts) = after(send, 1);
        assert_eq!(result, error);
        assert_eq!(got.is_empty(), error.is_some());
        assert!(alerts.is_empty());
    }
    // A long alert.
    let (result, _, alerts) = after(|server| server.send(ALERT, &[2, 80, 0]), 1);
    assert_eq!((result, alerts), (Some(Error::Decode), Vec::from([50])));
    // An empty one, sealed: unexpected_message (RFC 9846 5.4).
    let (empty, _, refused) = after(|server| server.send(ALERT, &[]), 1);
    assert_eq!((empty, refused), (Some(Error::Unexpected), Vec::from([10])));
    // close_notify during the handshake.
    assert_eq!(after_hello(Some(ALERT), &[1, 0]), Some(Error::Alert(0)));
}

/// Every byte of a sealed record flipped, header and tag included,
/// fails it, and the client tells the server; a record replayed fails.
#[test]
fn tampered() {
    let store = Identity::new(Kind::P256).store();
    let (_, mut first) = connected(&store);
    first.send(APPLICATION, b"data");
    let record = first.take();
    for at in 0..record.len() {
        let error = match at {
            0 => Some(Error::Unexpected),
            3 => Some(Error::Overflow),
            // The record now looks longer: the client waits for it.
            4 => None,
            // legacy_record_version is ignored, but it is in the AAD.
            _ => Some(Error::Forged),
        };
        let flip = |server: &mut Server| {
            server.output.extend_from_slice(&record);
            server.output[at] ^= 0x80;
        };
        let (result, _, alerts) = after(flip, 1);
        assert_eq!(result, error, "byte {at}");
        assert_eq!(alerts, Vec::from_iter(error.and_then(Error::alert)));
    }
    let twice = |server: &mut Server| {
        server.output.extend_from_slice(&record);
        server.output.extend_from_slice(&record);
    };
    assert_eq!(after(twice, WHOLE).0, Some(Error::Forged));
}

/// Records over their limits, before and after decryption, and inner
/// content types.
#[test]
fn record_limits() {
    let store = Identity::new(Kind::P256).store();
    // Ciphertext over 2^14 + 256 is refused at the header.
    let (mut over, _) = connected(&store);
    assert_eq!(over.input(&[23, 3, 3, 0x41, 0x01]), Err(Error::Overflow));
    let (mut most, _) = connected(&store);
    assert_eq!(most.input(&[23, 3, 3, 0x41, 0x00]), Ok(Taken(5)));
    // Plaintext records over 2^14, before keys, and bytes that are not
    // TLS.
    for (bytes, result) in [
        (&[22, 3, 3, 0x40, 0x01][..], Err(Error::Overflow)),
        (&[22, 3, 3, 0x40, 0x00], Ok(Taken(5))),
        (b"HTTP/1.1 400", Err(Error::Unexpected)),
    ] {
        let mut client =
            Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        assert_eq!(client.input(bytes), result);
    }
    // 2^14 bytes and the content type pass: TLSInnerPlaintext is 2^14 + 1
    // bytes at most (RFC 9846 5.4), so one byte of padding more does not,
    // nor one more byte of data.
    let full = |server: &mut Server| {
        let mut inner = Vec::new();
        inner.resize(RECORD_MAX, b'a');
        inner.push(APPLICATION);
        server.raw(inner);
    };
    let (result, got, _) = after(full, 1000);
    assert_eq!((result, got.len()), (None, RECORD_MAX));
    let padded = |server: &mut Server| {
        let mut inner = Vec::new();
        inner.resize(RECORD_MAX, b'a');
        inner.push(APPLICATION);
        inner.push(0);
        server.raw(inner);
    };
    assert_eq!(
        after(padded, 1000),
        (Some(Error::Overflow), Vec::new(), Vec::from([22]))
    );
    let large = |server: &mut Server| {
        let mut inner = Vec::new();
        inner.resize(RECORD_MAX + 1, b'a');
        inner.push(APPLICATION);
        server.raw(inner);
    };
    assert_eq!(
        after(large, 1000),
        (Some(Error::Overflow), Vec::new(), Vec::from([22]))
    );
    for (inner, error) in [
        (&[0, 0, 0][..], Some(Error::Unexpected)),
        (&[1, 20], Some(Error::Unexpected)),
        (&[1, 99, 0], Some(Error::Unexpected)),
        (&[HANDSHAKE, 0], Some(Error::Unexpected)),
        (&[], Some(Error::Unexpected)),
        (&[APPLICATION, 0, 0], None),
    ] {
        // rr: escape(copy): raw seals a buffer of its own.
        let (typed, _, _) = after(|server| server.raw(inner.to_vec()), WHOLE);
        assert_eq!(typed, error);
    }
}

/// A handshake message of MESSAGE_MAX passes, one byte more does not.
#[test]
fn message_limit() {
    for (length, error) in [
        (MESSAGE_MAX, None),
        (MESSAGE_MAX + 1, Some(Error::TooLarge)),
    ] {
        let ticket = |server: &mut Server| {
            let mut message = Vec::from([4]);
            message.extend_from_slice(&u24(length));
            message.resize(4 + length, 0);
            for piece in message.chunks(RECORD_MAX) {
                server.send(HANDSHAKE, piece);
            }
            server.send(APPLICATION, b"after");
        };
        let (result, got, _) = after(ticket, WHOLE);
        assert_eq!(result, error);
        assert_eq!(got.is_empty(), error.is_some());
    }
}

/// A message before a change of keys ends its record; records do not
/// interleave with a message that spans them.
#[test]
fn record_boundaries() {
    // ServerHello with a byte more in its record.
    let mut script = Script::new(Kind::P256);
    script.flight = false;
    let store = script.identity.store();
    let mut first = Server::new(script);
    let mut client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    first.receive(client.pending());
    let mut bytes = first.take();
    bytes[4] += 1;
    bytes.push(8);
    let result = feed(
        &mut client,
        &bytes,
        &mut Split { piece: 1, seed: 0 },
        &mut Vec::new(),
    );
    assert_eq!(result, Err(Error::Unexpected));
    // Data in the middle of a ticket that spans two records.
    let split = |server: &mut Server| {
        server.send(HANDSHAKE, &[4, 0, 0, 4, 0]);
        server.send(APPLICATION, b"x");
    };
    assert_eq!(after(split, 1).0, Some(Error::Unexpected));
    // A change_cipher_spec after the handshake, or of another value.
    let late = |server: &mut Server| server.output.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    assert_eq!(after(late, 1).0, Some(Error::Unexpected));
    let mut fresh = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    assert_eq!(fresh.input(&[20, 3, 3, 0, 1, 1]), Ok(Taken(6)));
    assert_eq!(fresh.input(&[20, 3, 3, 0, 1, 2]), Err(Error::Unexpected));
    // Data before the handshake is done; a handshake record in the clear
    // after ServerHello.
    assert_eq!(
        after_hello(Some(APPLICATION), b"early"),
        Some(Error::Unexpected)
    );
    let clear = [22, 3, 3, 0, 4, 8, 0, 0, 0];
    assert_eq!(after_hello(None, &clear), Some(Error::Unexpected));
}

/// What the client makes of a ServerHello of TLS 1.2, without
/// supported_versions: random's last 8 bytes, and its extensions block
/// or none; and the alert it sends back.
fn tls12(tail: [u8; 8], extensions: Option<&[u8]>) -> (Option<Error>, Vec<u8>) {
    let store = Store::new();
    let mut client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    client.sent(client.pending().len()).unwrap();
    let mut body = Vec::from([3, 3]);
    body.extend_from_slice(&[0x11; 24]);
    body.extend_from_slice(&tail);
    body.extend_from_slice(&[0, 0xc0, 0x2f, 0]);
    if let Some(block) = extensions {
        prefixed(&mut body, block.len(), block);
    }
    let mut message = Vec::from([2]);
    message.extend_from_slice(&u24(body.len()));
    message.extend_from_slice(&body);
    let mut record = Vec::from([22, 3, 3]);
    prefixed(&mut record, message.len(), &message);
    let error = client.input(&record).err();
    // rr: escape(copy): the client goes, its alert stays for the test.
    (error, client.pending().to_vec())
}

/// A ServerHello of TLS 1.2, with extensions or without the block (RFC
/// 9846 E.1): protocol_version; one that ends in a downgrade sentinel:
/// illegal_parameter (4.2.3).
#[test]
fn version() {
    let plain = [0x11; 8];
    let renegotiation: &[u8] = &[0xff, 1, 0, 1, 0];
    for (tail, extensions, error) in [
        (plain, Some(renegotiation), Error::Version),
        (plain, None, Error::Version),
        (*b"DOWNGRD\x01", Some(renegotiation), Error::Parameter),
        (*b"DOWNGRD\x01", None, Error::Parameter),
        (*b"DOWNGRD\x00", None, Error::Parameter),
        (*b"DOWNGRD\x02", None, Error::Version),
    ] {
        let (found, pending) = tls12(tail, extensions);
        assert_eq!(found, Some(error));
        // The alert alone, in the clear.
        assert_eq!(pending, [21, 3, 3, 0, 2, 2, error.alert().unwrap()]);
    }
}

/// The server chooses TLS_AES_256_GCM_SHA384, with or without a retry
/// that names it: the handshake by SHA-384, AES-256-GCM records both
/// ways, a KeyUpdate each way, and close_notify.
#[test]
fn aes_256_gcm_sha384() {
    for (retry, cookie) in [
        (None, None),
        (Some(SECP256R1), None),
        (None, Some(&b"\x07"[..])),
    ] {
        let mut script = Script::new(Kind::P384);
        script.suite = AES_256_GCM_SHA384;
        script.retry_suite = AES_256_GCM_SHA384;
        script.retry_group = retry;
        script.cookie = cookie;
        let store = script.identity.store();
        let mut server = Server::new(script);
        let mut split = Split { piece: 50, seed: 5 };
        let mut client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
        assert!(client.connected() && server.finished);
        let keys = client.output_keys.as_ref().unwrap();
        assert!(matches!(keys.secret, Digest::Sha384(_)));
        assert!(matches!(client.transcript, Transcript::Sha256(_)));
        assert_eq!(client.write(b"ping"), Ok(Taken(4)));
        server.update(true);
        server.send(APPLICATION, b"pong");
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::from(*b"pong"))
        );
        assert_eq!(client.write(b"again"), Ok(Taken(5)));
        client.close();
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert_eq!(server.received, b"pingagain");
        assert_eq!((server.updates, server.alerts.as_slice()), (1, &[0][..]));
    }
}

/// A suite the client did not offer, in a ServerHello or a retry, and a
/// ServerHello whose suite is not the retry's (RFC 9846 4.2.4):
/// illegal_parameter.
#[test]
fn suites_refused() {
    for suite in [0x1303, 0x1304, 0xc02f, 0] {
        let mut script = Script::new(Kind::P256);
        script.suite = suite;
        assert_eq!(
            outcome(script, HOST, &[], TEST_NOW),
            (Some(Error::Parameter), Vec::from([47]))
        );
        let retry = hello_message(
            &HELLO_RETRY,
            &SESSION,
            suite,
            &hex("002b 0002 0304 0033 0002 0017"),
        );
        let store = Store::new();
        let mut client =
            Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        let mut record = Vec::from([22, 3, 3]);
        prefixed(&mut record, retry.len(), &retry);
        assert_eq!(client.input(&record), Err(Error::Parameter));
    }
    for (first, second) in [
        (AES_128_GCM_SHA256, AES_256_GCM_SHA384),
        (AES_256_GCM_SHA384, AES_128_GCM_SHA256),
    ] {
        let mut script = Script::new(Kind::P256);
        script.retry_group = Some(SECP256R1);
        script.retry_suite = first;
        script.suite = second;
        let (error, alerts) = outcome(script, HOST, &[], TEST_NOW);
        assert_eq!((error, alerts), (Some(Error::Parameter), Vec::from([47])));
    }
}

/// An extension in a CertificateEntry: the client asks for none, so any
/// is unsupported_extension (RFC 9846 4.5.1), with Verify::Caller before
/// the caller is asked; one that does not frame is decode_error.
#[test]
fn certificate_entry_extensions() {
    for (entry, error) in [
        ("", None),
        // status_request and signed_certificate_timestamp, unsolicited.
        ("0005 0000", Some(Error::Extension)),
        ("0012 0003 000102", Some(Error::Extension)),
        ("ff99 0000", Some(Error::Extension)),
        ("0005", Some(Error::Decode)),
        ("0005 0002 00", Some(Error::Decode)),
        ("0005 0000 0012", Some(Error::Decode)),
    ] {
        let mut script = Script::new(Kind::P256);
        script.entry = hex(entry);
        let (found, alerts) = outcome(script, HOST, &[], TEST_NOW);
        assert_eq!(found, error, "{entry}");
        assert_eq!(alerts, Vec::from_iter(error.and_then(Error::alert)));
        let mut asked = Script::new(Kind::P256);
        asked.entry = hex(entry);
        let verdict = caller(asked, HOST, WHOLE, &Judge::Always(true));
        assert_eq!(verdict.error, error, "{entry}");
        assert_eq!(verdict.waits, usize::from(error.is_none()));
    }
}

/// The client's own limits are internal_error: a sequence number that
/// would wrap, either way (RFC 9846 5.3), and a record past the pending
/// buffer or a record's length.
#[test]
fn internal_errors() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    let last = u64::MAX;
    client
        .output_keys
        .as_mut()
        .unwrap()
        .key
        .set_sequence_less_safe(last);
    assert_eq!(client.write(b"x"), Err(Error::Internal));
    // No number is left for the alert either.
    assert!(client.pending().is_empty());
    server.receive(client.pending());
    assert!(server.received.is_empty() && server.alerts.is_empty());
    let (mut reading, mut other) = connected(&store);
    reading
        .input_keys
        .as_mut()
        .unwrap()
        .key
        .set_sequence_for_tests(last);
    other.send(APPLICATION, b"x");
    assert_eq!(reading.input(&other.take()), Err(Error::Internal));
    other.receive(reading.pending());
    assert_eq!(other.alerts, [80]);
    let mut keys = Keys::new(Digest::Sha256([1; 32]));
    let mut tx = Vec::new();
    tx.resize(super::TX_MAX - 20, 0);
    assert_eq!(
        super::seal(&mut keys, &mut tx, APPLICATION, &[0; 4]),
        Err(Error::Internal)
    );
    tx.clear();
    let mut large = Vec::new();
    large.resize(1 << 16, 0);
    assert_eq!(
        super::seal(&mut keys, &mut tx, APPLICATION, &large),
        Err(Error::Internal)
    );
    assert_eq!((tx.len(), keys.key.sequence()), (0, 0));
    assert_eq!(Error::Internal.alert(), Some(80));
}

/// input stops after RECORDS_PER_INPUT records, and at plaintext not yet
/// read.
#[test]
fn input_backpressure() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    // As many empty records as are taken in a row (IDLE_MAX), then more
    // after a byte of data.
    assert!(RECORDS_PER_INPUT <= usize::from(IDLE_MAX));
    for at in 0..RECORDS_PER_INPUT + 8 {
        if at == RECORDS_PER_INPUT {
            server.send(APPLICATION, b"!");
        }
        server.send(APPLICATION, b"");
    }
    let empty = server.take();
    let size = (empty.len() - 1) / (RECORDS_PER_INPUT + 9);
    assert_eq!(client.input(&empty), Ok(Taken(RECORDS_PER_INPUT * size)));
    let rest = &empty[RECORDS_PER_INPUT * size..];
    assert_eq!(client.input(rest), Ok(Taken(size + 1)));
    assert_eq!(client.read(), b"!");
    client.consume(1);
    assert_eq!(client.input(&rest[size + 1..]), Ok(Taken(8 * size)));
    server.send(APPLICATION, b"first");
    server.send(APPLICATION, b"second");
    let bytes = server.take();
    let first = 5 + 5 + 1 + 16;
    assert_eq!(client.input(&bytes), Ok(Taken(first)));
    assert_eq!(client.read(), b"first");
    // The next record waits until this one is read, and input says so.
    assert_eq!(client.input(&bytes[first..]), Err(Error::Unconsumed));
    client.consume(2);
    assert_eq!(client.read(), b"rst");
    client.consume(10);
    assert_eq!(
        client.input(&bytes[first..]),
        Ok(Taken(bytes.len() - first))
    );
    assert_eq!(client.read(), b"second");
}

/// write takes what fits under PENDING_MAX, and nothing more until
/// pending is sent.
#[test]
fn write_backpressure() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    let mut data = Vec::new();
    data.resize(1 << 20, 7);
    let mut total = client.write(&data).unwrap().count();
    assert_eq!(total, RECORD_MAX);
    assert_eq!(client.pending().len(), PENDING_MAX);
    assert!(client.pending().len() <= PENDING_MAX);
    assert_eq!(client.write(&data), Ok(Taken(0)));
    server.receive(&client.pending()[..1000]);
    client.sent(1000).unwrap();
    assert_eq!(client.write(&data), Ok(Taken(0)));
    while total < data.len() {
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        total += client.write(&data[total..]).unwrap().count();
    }
    server.receive(client.pending());
    assert_eq!(server.received, data);
    assert_eq!(client.write(&[]), Ok(Taken(0)));
    // Before the handshake nothing is written, and close_notify goes in
    // the clear.
    let mut fresh = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    assert_eq!(fresh.write(b"x"), Err(Error::NotConnected));
    fresh.close();
    let pending = fresh.pending();
    assert_eq!(pending[pending.len() - 7..], [21, 3, 3, 0, 2, 1, 0]);
}

/// A failure sticks, and drops the data waiting to be read.
#[test]
fn failure_sticks() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    server.send(APPLICATION, b"unread");
    let mut bytes = server.take();
    let first = bytes.len();
    bytes.extend_from_slice(&[99, 3, 3, 0, 0]);
    assert_eq!(client.input(&bytes), Ok(Taken(first)));
    client.consume(6);
    assert_eq!(client.input(&bytes[first..]), Err(Error::Unexpected));
    assert_eq!(client.input(&bytes), Err(Error::Unexpected));
    assert_eq!(client.write(b"x"), Err(Error::Unexpected));
    assert!(client.read().is_empty() && !client.connected());
    let alert = client.pending().len();
    client.close();
    assert_eq!(client.pending().len(), alert);
}

/// One 16 KiB record sealed and sent.
#[bench]
fn write_record(b: &mut Bencher) {
    let store = Identity::new(Kind::P256).store();
    let (mut client, _) = connected(&store);
    let mut data = Vec::new();
    data.resize(RECORD_MAX, 0x61);
    b.iter(|| {
        assert_eq!(client.write(&data), Ok(Taken(RECORD_MAX)));
        client.sent(client.pending().len()).unwrap();
    });
}

/// One 16 KiB record taken in, opened in place and read.
#[bench]
fn input_record(b: &mut Bencher) {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    let mut data = Vec::new();
    data.resize(RECORD_MAX, 0x62);
    server.send(APPLICATION, &data);
    let record = server.take();
    let seq = client.input_keys.as_ref().unwrap().key.sequence();
    b.iter(|| {
        client
            .input_keys
            .as_mut()
            .unwrap()
            .key
            .set_sequence_for_tests(seq);
        assert_eq!(client.input(&record), Ok(Taken(record.len())));
        assert_eq!(client.read().len(), RECORD_MAX);
        client.consume(RECORD_MAX);
    });
}

/// A whole handshake against the server's recorded flight: X25519 twice,
/// the chain's two ECDSA signatures and CertificateVerify's, and the key
/// schedule.
#[bench]
fn handshake(b: &mut Bencher) {
    let store = Identity::new(Kind::P256).store();
    let mut server = Server::new(Script::new(Kind::P256));
    let client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    let flight = server.take();
    b.iter(|| {
        let mut fresh = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        assert_eq!(fresh.input(&flight), Ok(Taken(flight.len())));
        assert!(fresh.connected());
    });
}

/// The same with the server choosing TLS_AES_256_GCM_SHA384: SHA-384
/// beside SHA-256 until ServerHello, then alone.
#[bench]
fn handshake_aes256(b: &mut Bencher) {
    let mut script = Script::new(Kind::P256);
    script.suite = AES_256_GCM_SHA384;
    let store = script.identity.store();
    let mut server = Server::new(script);
    let client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    let flight = server.take();
    b.iter(|| {
        let mut fresh = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        assert_eq!(fresh.input(&flight), Ok(Taken(flight.len())));
        assert!(fresh.connected());
    });
}

/// The bytes a Client holds after a handshake, its buffers' capacities
/// included, and what is left once data both ways and a KeyUpdate are
/// done.
fn held(client: &Client<'_>) -> usize {
    let kem = client
        .kem
        .as_ref()
        .map_or(0, |_| size_of::<mlkem::DecapsulationKey>());
    size_of::<Client<'_>>()
        + client.rx.capacity()
        + client.tx.capacity()
        + client.hs.capacity()
        + client.leaf.capacity()
        + client.offer.capacity()
        + client.host.capacity()
        + kem
}

#[test]
fn memory() {
    let mut script = Script::new(Kind::RsaSha256);
    script.alpn = Some(b"h2");
    script.request = Some(hex("00 0008 000d 0004 0002 0403"));
    let store = script.identity.store();
    let mut server = Server::new(script);
    let mut split = Split { piece: 7, seed: 3 };
    let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let mut client = connect(&store, &mut server, HOST, &alpn, &mut split).unwrap();
    let after = held(&client);
    server.update(true);
    server.send(APPLICATION, b"data");
    assert_eq!(client.write(b"ping"), Ok(Taken(4)));
    assert_eq!(
        exchange(&mut client, &mut server, &mut split),
        Ok(Vec::from(*b"data"))
    );
    assert_eq!(client.alpn(), Some(&b"h2"[..]));
    assert_eq!(held(&client), after);
    // The structure, one record in, one out, and the ALPN choice.
    let buffers = 5 + RECORD_MAX + 256 + super::TX_MAX + 2;
    assert_eq!(after, size_of::<Client<'_>>() + buffers);
}

/// Requests for a KeyUpdate while pending holds a full record that goes
/// out a piece at a time: each is answered once, and pending stays
/// within its bound.
#[test]
fn key_update_pending() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    let mut data = Vec::new();
    data.resize(RECORD_MAX, 3);
    client
        .output_keys
        .as_mut()
        .unwrap()
        .key
        .set_sequence_less_safe(KEY_RECORDS_MAX);
    server
        .read
        .as_mut()
        .unwrap()
        .key
        .set_sequence_for_tests(KEY_RECORDS_MAX);
    let mut written = 0;
    for _ in 0..6 {
        written += client.write(&data).unwrap().count();
        server.update(true);
        feed(&mut client, &server.take(), &mut whole(), &mut Vec::new()).unwrap();
        assert!(client.tx.len() <= super::TX_MAX);
        // All but the last byte goes out: pending never drains.
        let ready = client.pending().len() - 1;
        server.receive(&client.pending()[..ready]);
        client.sent(ready).unwrap();
    }
    server.receive(client.pending());
    client.sent(1).unwrap();
    assert_eq!(server.received.len(), written);
    // The client's own KeyUpdate, and one answer: the requests after it
    // came while its last byte was still pending.
    assert_eq!(server.updates, 2);
    client.close();
    assert!(client.tx.len() <= super::TX_MAX);
}

/// What a client that verifies through its caller made of a server.
struct Verdict {
    error: Option<Error>,
    /// How often it awaited a verdict, and how many bytes the input that
    /// first stopped there left untaken.
    waits: usize,
    left: usize,
    connected: bool,
    /// What it read after the handshake, and the alerts the server got.
    got: Vec<u8>,
    alerts: Vec<u8>,
}

/// How the caller decides on a chain.
enum Judge<'s> {
    /// A system that approves any chain for the host, or none.
    Always(bool),
    /// x509 against the store, for the host.
    X509(&'s Store, &'static str),
}

impl Judge<'_> {
    /// The approval of chain for host, or none.
    fn approval(&self, chain: &[&[u8]], host: &str) -> Option<Approval> {
        match self {
            Judge::Always(true) => Some(Approval::system(chain[0], host)),
            Judge::Always(false) => None,
            Judge::X509(store, name) => x509::verify(chain, store, name, TEST_NOW).ok(),
        }
    }
}

/// A handshake with Verify::Caller, the server's bytes in pieces of
/// piece, and the judge's verdict on the chain; then data from the
/// server and back.
fn caller(script: Script, host: &str, piece: usize, judge: &Judge<'_>) -> Verdict {
    let mut server = Server::new(script);
    let mut client = Client::with(host, &[], Verify::Caller, TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    client.sent(client.pending().len()).unwrap();
    let mut bytes = server.take();
    let mut verdict = Verdict {
        error: None,
        waits: 0,
        left: 0,
        connected: false,
        got: Vec::new(),
        alerts: Vec::new(),
    };
    let mut at = 0;
    while verdict.error.is_none() && (at < bytes.len() || !client.read().is_empty()) {
        let end = (at + piece).min(bytes.len());
        match client.input(&bytes[at..end]) {
            Ok(taken) => at += taken.count(),
            Err(error) => verdict.error = Some(error),
        }
        if client.awaiting() {
            assert!(client.chain(&mut []).is_none());
            let approval = {
                let mut slots = [&[][..]; x509::CHAIN_MAX];
                let count = client.chain(&mut slots).unwrap();
                assert_eq!(slots[..count], server.script.identity.chain[..]);
                judge.approval(&slots[..count], host)
            };
            if verdict.waits == 0 {
                verdict.left = end - at;
            }
            verdict.waits += 1;
            // Nothing more is taken until the verdict, and loudly.
            assert_eq!(client.input(&bytes[at..]), Err(Error::Awaiting));
            match approval {
                Some(approval) => {
                    if let Err(error) = client.verified(approval) {
                        verdict.error = Some(error);
                    }
                }
                None => client.refused(),
            }
            // A refusal ends the wait: a loop that asks awaiting before
            // input sees it fail, not wait again.
            assert!(!client.awaiting());
            let mut slots = [&[][..]; x509::CHAIN_MAX];
            assert!(client.chain(&mut slots).is_none());
            if let Err(error) = client.input(&[]) {
                verdict.error = Some(error);
            }
        }
        let count = client.read().len();
        verdict.got.extend_from_slice(client.read());
        client.consume(count);
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        if at == bytes.len() && server.finished && verdict.got.is_empty() {
            server.send(APPLICATION, b"after");
            bytes.append(&mut server.output);
        }
    }
    verdict.connected = client.connected();
    if verdict.connected {
        assert_eq!(client.write(b"back"), Ok(Taken(4)));
        server.receive(client.pending());
        assert_eq!(server.received, b"back");
    }
    verdict.alerts = server.alerts;
    verdict
}

/// Trusted: the handshake ends and data flows, for any split of the
/// server's bytes and with Certificate across records or in one with the
/// rest of the flight. The host is the caller's to match, not the
/// client's.
#[test]
fn caller_trusts() {
    for (piece, records) in [
        (1, RECORD_MAX),
        (7, 100),
        (1000, 300),
        (WHOLE, RECORD_MAX),
        (WHOLE, 500),
    ] {
        let mut script = Script::new(Kind::P256);
        script.piece = records;
        let verdict = caller(script, HOST, piece, &Judge::Always(true));
        assert_eq!(verdict.error, None);
        assert_eq!(verdict.waits, 1);
        assert!(verdict.connected);
        assert_eq!(verdict.got, b"after");
    }
    // Certificate's record ends the flight's first record: the rest
    // waits untaken, and goes in after the verdict.
    let mut split = Script::new(Kind::RsaSha256);
    split.piece = 600;
    let verdict = caller(split, HOST, WHOLE, &Judge::Always(true));
    assert!(verdict.left > 0 && verdict.connected);
    let elsewhere = caller(
        Script::new(Kind::P384),
        "other.example.test",
        3,
        &Judge::Always(true),
    );
    assert!(elsewhere.connected);
}

/// close while the client awaits the verdict: close_notify is the last
/// thing it sends, and the trusted verdict after it sends no Finished.
#[test]
fn close_while_awaiting() {
    let mut server = Server::new(Script::new(Kind::P256));
    let mut client = Client::with(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    client.sent(client.pending().len()).unwrap();
    let bytes = server.take();
    let mut at = 0;
    while !client.awaiting() {
        at += client.input(&bytes[at..]).unwrap().count();
    }
    client.close();
    let closing = client.pending().len();
    assert!(closing > 0);
    let leaf = &server.script.identity.chain[0];
    let late = client.verified(Approval::system(leaf, HOST));
    assert_eq!(late, Err(Error::NotAwaiting));
    assert!(client.input(&bytes[at..]).is_ok());
    assert_eq!(client.pending().len(), closing);
}

/// Refused: Untrusted, and unknown_ca reaches the server.
#[test]
fn caller_refuses() {
    for piece in [1, WHOLE] {
        let verdict = caller(Script::new(Kind::P256), HOST, piece, &Judge::Always(false));
        assert_eq!(verdict.error, Some(Error::Untrusted));
        assert_eq!((verdict.waits, verdict.connected), (1, false));
        assert_eq!(verdict.alerts, [48]);
    }
}

/// A trusted chain still has its key check CertificateVerify, and its
/// leaf must parse.
#[test]
fn caller_checks_the_signature() {
    let mut forged = Script::new(Kind::P256);
    forged.identity.signer = Identity::new(Kind::P384).signer;
    let verdict = caller(forged, HOST, 5, &Judge::Always(true));
    assert_eq!(verdict.error, Some(Error::Signature));
    assert_eq!(verdict.alerts, [51]);
    let mut garbage = Script::new(Kind::P256);
    garbage.identity.chain[0].truncate(40);
    let broken = caller(garbage, HOST, WHOLE, &Judge::Always(true));
    assert_eq!(broken.error, Some(Error::Certificate));
}

/// The caller's verdict from x509, as a program that verifies on its
/// own thread would give it.
#[test]
fn caller_with_x509() {
    let store = Identity::new(Kind::P256).store();
    let judge = Judge::X509(&store, HOST);
    assert!(caller(Script::new(Kind::P256), HOST, 9, &judge).connected);
    let other = Judge::X509(&store, "x.test");
    let refused = caller(Script::new(Kind::P256), HOST, 9, &other);
    assert_eq!(refused.error, Some(Error::Untrusted));
}

/// A connected client with "queued" written and not sent, and its server.
fn queued(store: &Store) -> (Client<'_>, Server) {
    let (mut client, server) = connected(store);
    assert_eq!(client.write(b"queued"), Ok(Taken(6)));
    (client, server)
}

/// After a failure nothing that was queued goes out (RFC 9846 6, 6.2):
/// the server's fatal alert leaves nothing to send, the client's own
/// error only its alert, under the keys and number the server expects.
#[test]
fn failure_drops_pending() {
    let store = Identity::new(Kind::P256).store();
    let (mut alerted, mut sender) = queued(&store);
    sender.send(ALERT, &[2, 40]);
    assert_eq!(alerted.input(&sender.take()), Err(Error::Alert(40)));
    assert!(alerted.pending().is_empty());
    let (mut client, mut server) = queued(&store);
    server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
    assert_eq!(client.input(&server.take()), Err(Error::Unexpected));
    server.receive(client.pending());
    assert!(server.received.is_empty());
    assert_eq!(server.alerts, [10]);
    // A close_notify not yet begun gives way to the error's alert.
    let (mut closing, mut its_server) = queued(&store);
    closing.close();
    its_server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
    assert_eq!(closing.input(&its_server.take()), Err(Error::Unexpected));
    its_server.receive(closing.pending());
    assert!(its_server.received.is_empty());
    assert_eq!(its_server.alerts, [10]);
}

/// A record the caller began to send is finished before the alert: a
/// torn one would garble it.
#[test]
fn failure_finishes_a_begun_record() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = queued(&store);
    assert_eq!(client.write(b"dropped"), Ok(Taken(7)));
    server.receive(&client.pending()[..10]);
    client.sent(10).unwrap();
    server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
    assert_eq!(client.input(&server.take()), Err(Error::Unexpected));
    server.receive(client.pending());
    assert_eq!(server.received, b"queued");
    assert_eq!(server.alerts, [10]);
    // close_notify begun: nothing goes after it.
    let (mut closing, mut its_server) = connected(&store);
    closing.close();
    its_server.receive(&closing.pending()[..3]);
    closing.sent(3).unwrap();
    its_server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
    assert_eq!(closing.input(&its_server.take()), Err(Error::Unexpected));
    its_server.receive(closing.pending());
    assert_eq!(its_server.alerts, [0]);
}

/// Dropped records past a change of keys take the keys back: data before
/// a KeyUpdate the client answers with, and the client's Finished with
/// data after it, are not sent, and the alert goes under the keys the
/// server reads with.
#[test]
fn failure_takes_the_keys_back() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = queued(&store);
    server.update(true);
    server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
    let bytes = server.take();
    assert_eq!(client.input(&bytes), Err(Error::Unexpected));
    server.receive(client.pending());
    assert!(server.received.is_empty());
    assert_eq!((server.updates, server.alerts.as_slice()), (0, &[10][..]));
    // The whole flight in, the client's own not yet sent.
    let mut fresh = Server::new(Script::new(Kind::P256));
    let mut early = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    fresh.receive(early.pending());
    early.sent(early.pending().len()).unwrap();
    let flight = fresh.take();
    assert_eq!(early.input(&flight), Ok(Taken(flight.len())));
    assert!(early.connected());
    assert_eq!(early.write(b"early"), Ok(Taken(5)));
    assert_eq!(early.input(&[99, 3, 3, 0, 0]), Err(Error::Unexpected));
    fresh.receive(early.pending());
    assert!(!fresh.finished && fresh.received.is_empty());
    assert_eq!((fresh.ccs, fresh.alerts.as_slice()), (0, &[10][..]));
}

/// close before the handshake is complete ends it: the client's Finished
/// never goes, it never connects, and what the server sends after is
/// taken and ignored.
#[test]
fn close_during_handshake() {
    let store = Identity::new(Kind::P256).store();
    let mut server = Server::new(Script::new(Kind::P256));
    let mut client = Client::with(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    client.sent(client.pending().len()).unwrap();
    let flight = server.take();
    let hello = 5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]));
    assert_eq!(client.input(&flight[..hello]), Ok(Taken(hello)));
    client.close();
    assert_eq!(
        client.input(&flight[hello..]),
        Ok(Taken(flight.len() - hello))
    );
    assert!(!client.connected() && !client.awaiting() && !client.closed());
    assert_eq!(client.write(b"x"), Err(Error::Closed));
    server.receive(client.pending());
    assert!(!server.finished);
    assert_eq!(server.alerts, [0]);
}

/// A chain the caller trusts still needs a leaf whose key may sign the
/// handshake: keyUsage keyEncipherment alone is refused before the
/// server's CertificateVerify.
#[test]
fn caller_needs_a_signing_key() {
    let mut script = Script::new(Kind::P256);
    script.identity.chain = Vec::from([test_certificate("test.kencleaf").unwrap()]);
    let verdict = caller(script, HOST, WHOLE, &Judge::Always(true));
    assert_eq!(verdict.error, Some(Error::Certificate));
    assert!(!verdict.connected);
}

/// A socket to a test server, as a program sees one: reads and writes
/// of at most piece bytes, and a read of nothing once the server has no
/// more to say. Once the whole request is in, the server answers with
/// the response, then close_notify unless it hangs up without.
struct Socket {
    server: Server,
    inbound: Vec<u8>,
    at: usize,
    piece: usize,
    request: usize,
    response: Vec<u8>,
    closes: bool,
    answered: bool,
}

impl Socket {
    fn new(script: Script, piece: usize, request: usize, closes: bool) -> Socket {
        let mut response = Vec::new();
        for at in 0..20_000 {
            response.push(u8::try_from(at % 251).unwrap());
        }
        Socket {
            server: Server::new(script),
            inbound: Vec::new(),
            at: 0,
            piece,
            request,
            response,
            closes,
            answered: false,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> usize {
        let count = bytes.len().min(self.piece);
        self.server.receive(&bytes[..count]);
        count
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        if self.at == self.inbound.len() {
            if !self.answered && self.server.received.len() == self.request {
                for record in self.response.chunks(RECORD_MAX) {
                    self.server.send(APPLICATION, record);
                }
                if self.closes {
                    self.server.send(ALERT, &[1, 0]);
                }
                self.answered = true;
            }
            self.inbound = self.server.take();
            self.at = 0;
        }
        let count = (self.inbound.len() - self.at)
            .min(self.piece)
            .min(buffer.len());
        buffer[..count].copy_from_slice(&self.inbound[self.at..self.at + count]);
        self.at += count;
        count
    }
}

/// The module's loop, as a program writes it: send what is pending, ask
/// the verifier when the client awaits (x509 against store, standing for
/// the system's), write the request, read until the socket ends. Every
/// count is used and every error goes up, the alert sent first; what it
/// read is in got.
fn program(
    client: &mut Client<'_>,
    socket: &mut Socket,
    request: &[u8],
    store: &Store,
    got: &mut Vec<u8>,
) -> Result<(), Error> {
    let result = converse(client, socket, request, store, got);
    if result.is_err() {
        while !client.pending().is_empty() {
            let count = socket.write(client.pending());
            client.sent(count)?;
        }
    }
    result
}

/// program's loop, until it ends or fails.
fn converse(
    client: &mut Client<'_>,
    socket: &mut Socket,
    mut request: &[u8],
    store: &Store,
    got: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut buffer = [0; 1024];
    let (mut at, mut end) = (0, 0);
    for _ in 0..200_000 {
        while !client.pending().is_empty() {
            let count = socket.write(client.pending());
            client.sent(count)?;
        }
        if client.awaiting() {
            let mut chain = [&[][..]; x509::CHAIN_MAX];
            let count = client.chain(&mut chain).unwrap_or(0);
            let verdict = x509::verify(&chain[..count], store, HOST, TEST_NOW);
            match verdict {
                Ok(approval) => client.verified(approval)?,
                Err(_) => client.refused(),
            }
            continue;
        }
        if client.connected() && !request.is_empty() {
            let taken = client.write(request)?.count();
            request = &request[taken..];
            continue;
        }
        if at == end {
            (at, end) = (0, socket.read(&mut buffer));
            if end == 0 {
                return client.eof();
            }
        }
        at += client.input(&buffer[at..end])?.count();
        got.extend_from_slice(client.read());
        let count = client.read().len();
        client.consume(count);
    }
    panic!("the program does not end");
}

/// The loop of the module's doc, over short reads and writes: the
/// whole response once close_notify ends it, Truncated when the socket
/// ends without, and the chain's refusal or the server's error as they
/// are, with their alerts.
#[test]
fn a_program() {
    let store = Identity::new(Kind::P256).store();
    let mut request = Vec::new();
    request.resize(40_000, b'q');
    let mut got = Vec::new();
    for piece in [1, 7, 100, 5000, WHOLE] {
        for closes in [true, false] {
            let mut socket = Socket::new(Script::new(Kind::P256), piece, request.len(), closes);
            let mut client = Client::with(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
            got.clear();
            let result = program(&mut client, &mut socket, &request, &store, &mut got);
            let ending = if closes { None } else { Some(Error::Truncated) };
            assert_eq!(result.err(), ending, "{piece}");
            assert_eq!(got, socket.response, "{piece}");
            assert_eq!(socket.server.received, request, "{piece}");
            // A failure sticks, and the end of the socket says it again.
            assert_eq!(client.eof().err(), ending);
        }
    }
    // A chain the verifier refuses: unknown_ca, and nothing read.
    let other = Identity::new(Kind::RsaSha256).store();
    let mut socket = Socket::new(Script::new(Kind::P256), 9, 4, true);
    let mut client = Client::with(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
    got.clear();
    let refused = program(&mut client, &mut socket, b"ping", &other, &mut got);
    assert_eq!(refused, Err(Error::Untrusted));
    assert_eq!((got.len(), socket.server.alerts.as_slice()), (0, &[48][..]));
    // A server whose signature does not verify: decrypt_error.
    let mut forged = Script::new(Kind::P256);
    forged.identity.signer = Identity::new(Kind::P384).signer;
    let mut signed = Socket::new(forged, 9, 4, true);
    let mut checking = Client::with(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
    let wrong = program(&mut checking, &mut signed, b"ping", &store, &mut got);
    assert_eq!(wrong, Err(Error::Signature));
    assert_eq!(signed.server.alerts, [51]);
}

/// A client of Verify::Caller with the server's first flight in, at
/// the Certificate: the server, its bytes and how many the client took.
fn awaiting() -> (Client<'static>, Server, Vec<u8>, usize) {
    let mut server = Server::new(Script::new(Kind::P256));
    let mut client = Client::with(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
    server.receive(client.pending());
    client.sent(client.pending().len()).unwrap();
    let bytes = server.take();
    let mut at = 0;
    while !client.awaiting() {
        at += client.input(&bytes[at..]).unwrap().count();
    }
    (client, server, bytes, at)
}

/// The caller's mistakes are loud: a count of more than pending, input
/// that would take nothing while a verdict is awaited or plaintext is
/// unread, a verdict with nothing to judge; and an approval of another
/// leaf or host ends the connection with internal_error.
#[test]
fn mistakes_are_loud() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server, bytes, at) = awaiting();
    assert_eq!(client.sent(1), Err(Error::Sent));
    // Forgetting the verdict: input refuses, each time, and waits on.
    for _ in 0..2 {
        assert_eq!(client.input(&bytes[at..]), Err(Error::Awaiting));
        assert!(client.awaiting());
    }
    let (leaf, inter) = (
        test_certificate("test.leaf").unwrap(),
        test_certificate("test.inter").unwrap(),
    );
    let approval = x509::verify(&[&leaf, &inter], &store, HOST, TEST_NOW).unwrap();
    assert_eq!(client.verified(approval), Ok(()));
    assert_eq!(client.input(&bytes[at..]), Ok(Taken(bytes.len() - at)));
    assert!(client.connected());
    let again = x509::verify(&[&leaf, &inter], &store, HOST, TEST_NOW).unwrap();
    assert_eq!(client.verified(again), Err(Error::NotAwaiting));
    server.receive(client.pending());
    client.sent(client.pending().len()).unwrap();
    // Plaintext unread: the next record waits, and input says so.
    server.send(APPLICATION, b"one");
    server.send(APPLICATION, b"two");
    let records = server.take();
    let first = client.input(&records).unwrap().count();
    assert_eq!(client.input(&records[first..]), Err(Error::Unconsumed));
    assert_eq!(client.read(), b"one");
    client.consume(3);
    assert_eq!(
        client.input(&records[first..]),
        Ok(Taken(records.len() - first))
    );
    assert_eq!(client.read(), b"two");
    client.consume(3);
    // The socket ends with no close_notify: Truncated, and it sticks.
    assert_eq!(client.eof(), Err(Error::Truncated));
    assert_eq!(client.write(b"x"), Err(Error::Truncated));
    // Approvals of the leaf for another host, and of another leaf.
    let elsewhere = Approval::system(&leaf, "other.example.test");
    let other = test_certificate("test.leaf384").unwrap();
    for wrong in [elsewhere, Approval::system(&other, HOST)] {
        let (mut misled, mut its_server, flight, taken) = awaiting();
        assert_eq!(misled.verified(wrong), Err(Error::Approval));
        assert!(!misled.awaiting() && !misled.connected());
        assert_eq!(misled.input(&flight[taken..]), Err(Error::Approval));
        its_server.receive(misled.pending());
        assert_eq!(its_server.alerts, [80]);
    }
    // The same host, as written another way, is the same.
    let (mut written, _, _, _) = awaiting();
    let dotted = Approval::system(&leaf, "API.example.test.");
    assert_eq!(written.verified(dotted), Ok(()));
}

/// Secrets are not left behind: the marks the caller's sending let go,
/// and a failure's, hold none, and a KeyUpdate's old secret is gone.
#[test]
fn secrets_let_go() {
    let store = Identity::new(Kind::P256).store();
    let (mut client, mut server) = connected(&store);
    client
        .output_keys
        .as_mut()
        .unwrap()
        .key
        .set_sequence_less_safe(KEY_RECORDS_MAX);
    server
        .read
        .as_mut()
        .unwrap()
        .key
        .set_sequence_for_tests(KEY_RECORDS_MAX);
    let mut data = Vec::new();
    data.resize(100, 1);
    assert_eq!(client.write(&data), Ok(Taken(100)));
    // The client's own KeyUpdate before the record: one mark.
    assert_eq!(client.marked, 1);
    assert!(client.marks[0].secret.is_some());
    let ready = client.pending().len();
    server.receive(client.pending());
    client.sent(ready - 1).unwrap();
    assert_eq!(client.marked, 0);
    assert!(client.marks.iter().all(|mark| mark.secret.is_none()));
    client.sent(1).unwrap();
    assert_eq!(server.received, data);
    // A failure with marks queued lets them go.
    let (mut failing, mut its_server) = connected(&store);
    its_server.update(true);
    feed(
        &mut failing,
        &its_server.take(),
        &mut whole(),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(failing.marked, 1);
    let result = failing.input(&[99, 3, 3, 0, 0]);
    assert_eq!(result, Err(Error::Unexpected));
    assert_eq!(failing.marked, 0);
    assert!(failing.marks.iter().all(|mark| mark.secret.is_none()));
}

/// Client::new draws from the system: two clients' ClientHellos are
/// as long, and differ in their random, session ID and key shares.
#[test]
fn system_randomness() {
    let store = Store::new();
    let a = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW).unwrap();
    let b = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW).unwrap();
    assert_eq!(a.pending().len(), b.pending().len());
    assert_eq!(a.pending()[..11], b.pending()[..11]);
    assert_ne!(a.pending()[11..43], b.pending()[11..43]);
    assert_ne!((a.random, a.session), (b.random, b.session));
    assert_ne!(a.public, b.public);
}
