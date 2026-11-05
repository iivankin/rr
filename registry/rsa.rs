//! RSA signature verification (RFC 8017): RSASSA-PKCS1-v1_5, which
//! certificates use, and RSASSA-PSS with MGF1 and a salt as long as the
//! hash, which TLS 1.3's CertificateVerify uses (RFC 8446 4.2.3).
//!
//! The key, the digest and the signature are public, so the arithmetic
//! is not constant time; what an attacker controls is bounded instead:
//! moduli of 2048 to 4096 bits and exponents of at most 33 bits, as
//! BoringSSL allows, so one verification costs at most 33 squarings of
//! 4096 bits. Numbers are little-endian 64-bit limbs, multiplied in the
//! Montgomery domain.

use crate::sha256;
use crate::sha384;

/// The hash a signature covers; PSS's MGF1 uses the same.
pub enum Hash {
    Sha256,
    Sha384,
}

const MODULUS_BITS_MIN: usize = 2048;
const MODULUS_BITS_MAX: usize = 4096;
const EXPONENT_BITS_MAX: u32 = 33;
const LIMBS_MAX: usize = MODULUS_BITS_MAX / 64;
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

/// A public key, checked: an odd modulus of MODULUS_BITS_MIN to
/// MODULUS_BITS_MAX bits and an odd exponent from 3 to 2^33 - 1.
struct Key {
    m: [u64; LIMBS_MAX],
    limbs: usize,
    bits: usize,
    /// -m^-1 mod 2^64.
    m0inv: u64,
    e: u64,
}

impl Hash {
    fn len(&self) -> usize {
        match self {
            Hash::Sha256 => sha256::DIGEST_BYTES,
            Hash::Sha384 => sha384::DIGEST_BYTES,
        }
    }

    /// The digest of the parts one after another, in the first len()
    /// bytes.
    fn digest(&self, parts: &[&[u8]]) -> [u8; sha384::DIGEST_BYTES] {
        let mut out = [0; sha384::DIGEST_BYTES];
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
                out = hash.finish();
            }
        }
        out
    }
}

/// Whether signature is an RSASSA-PKCS1-v1_5 signature of digest under
/// the key (modulus, exponent), both big-endian. The whole encoded
/// message is compared: 00 01 FF..FF 00 DigestInfo digest.
pub fn verify_pkcs1(
    modulus: &[u8],
    exponent: &[u8],
    hash: &Hash,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    if digest.len() != hash.len() {
        return false;
    }
    let Some(key) = Key::new(modulus, exponent) else {
        return false;
    };
    let mut buffer = [0; BYTES_MAX];
    let Some(em) = key.public(signature, &mut buffer) else {
        return false;
    };
    let prefix = match hash {
        Hash::Sha256 => &SHA256_PREFIX,
        Hash::Sha384 => &SHA384_PREFIX,
    };
    // A 2048-bit key leaves 256 - 3 - 19 - 48 bytes of padding at least.
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

/// Whether signature is an RSASSA-PSS signature of digest under the key
/// (modulus, exponent), with MGF1 of hash and a salt of the hash's
/// length (RFC 8017 9.1.2).
pub fn verify_pss(
    modulus: &[u8],
    exponent: &[u8],
    hash: &Hash,
    digest: &[u8],
    signature: &[u8],
) -> bool {
    let length = hash.len();
    if digest.len() != length {
        return false;
    }
    let Some(key) = Key::new(modulus, exponent) else {
        return false;
    };
    let mut buffer = [0; BYTES_MAX];
    let Some(em) = key.public(signature, &mut buffer) else {
        return false;
    };
    // EM has emBits = modBits - 1 bits. When those fill whole bytes the
    // integer's first byte, one more, must be zero.
    let em_bits = key.bits - 1;
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
/// counter, block by block. db is under 512 bytes, so the counter is too.
fn mgf1_xor(hash: &Hash, seed: &[u8], db: &mut [u8]) {
    for (counter, chunk) in (0_u32..).zip(db.chunks_mut(hash.len())) {
        let mask = hash.digest(&[seed, &counter.to_be_bytes()]);
        for (byte, bits) in chunk.iter_mut().zip(mask) {
            *byte ^= bits;
        }
    }
}

impl Key {
    /// The key from its big-endian integers, leading zeros allowed; None
    /// outside the bounds the type states.
    fn new(modulus: &[u8], exponent: &[u8]) -> Option<Key> {
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
        let mut m = [0; LIMBS_MAX];
        load(modulus, &mut m);
        let limbs = modulus.len().div_ceil(8);
        let top = *m.get(limbs.checked_sub(1)?)?;
        let bits = 64 * limbs - top.leading_zeros() as usize;
        if !(MODULUS_BITS_MIN..=MODULUS_BITS_MAX).contains(&bits) || m[0] & 1 == 0 {
            return None;
        }
        // Newton's iteration for m^-1 mod 2^64: each step doubles the
        // bits that are right, from 3 (m m = 1 mod 8 for odd m) to 96.
        let mut inverse = m[0];
        for _ in 0..5 {
            inverse = inverse.wrapping_mul(2_u64.wrapping_sub(m[0].wrapping_mul(inverse)));
        }
        Some(Key {
            m,
            limbs,
            bits,
            m0inv: inverse.wrapping_neg(),
            e,
        })
    }

    fn modulus(&self) -> &[u64] {
        // rr: escape(panic): new bounds limbs by LIMBS_MAX.
        &self.m[..self.limbs]
    }

    /// signature^e mod m as the modulus's bytes, in the first of them in
    /// out; None unless the signature has that length and is below m.
    fn public<'out>(
        &self,
        signature: &[u8],
        out: &'out mut [u8; BYTES_MAX],
    ) -> Option<&'out mut [u8]> {
        let bytes = self.bits.div_ceil(8);
        if signature.len() != bytes {
            return None;
        }
        let n = self.limbs;
        let mut s = [0; LIMBS_MAX];
        load(signature, &mut s);
        // rr: escape(panic): n is at most LIMBS_MAX.
        let s = &s[..n];
        if !below(s, self.modulus()) {
            return None;
        }
        let mut x = [0; LIMBS_MAX];
        // rr: escape(panic): as above.
        let x = &mut x[..n];
        self.to_montgomery(s, x);
        let mut acc = [0; LIMBS_MAX];
        // rr: escape(panic): as above.
        let mut acc = &mut acc[..n];
        acc.copy_from_slice(x);
        let mut scratch = [0; LIMBS_MAX];
        // rr: escape(panic): as above.
        let mut scratch = &mut scratch[..n];
        // Left to right below the top bit, which acc holds already. e is
        // odd, so the last step multiplies, by s and not s R: that brings
        // s^(e - 1) R to s^e, out of the domain.
        let top = u64::BITS - 1 - self.e.leading_zeros();
        for bit in (0..top).rev() {
            self.square(acc, scratch);
            if bit == 0 {
                self.multiply(scratch, s, acc);
            } else if (self.e >> bit) & 1 == 1 {
                self.multiply(scratch, x, acc);
            } else {
                core::mem::swap(&mut acc, &mut scratch);
            }
        }
        // rr: escape(panic): bytes is at most BYTES_MAX.
        let out = &mut out[..bytes];
        for (place, byte) in out.iter_mut().rev().enumerate() {
            // rr: escape(panic, cast): place / 8 < n, as bytes <= 8n; the
            // shift picks one byte of the limb.
            *byte = (acc[place / 8] >> (8 * (place % 8))) as u8;
        }
        Some(out)
    }

    /// out = s R mod m, for s below m: n steps that each take a number
    /// v below m to v 2^64 mod m, by a quotient word estimated from the
    /// top words (Knuth's algorithm D, TAOCP 4.3.1), with m and v shifted
    /// so that m's top bit is set: the estimate is then at most 2 above
    /// the quotient. Cheaper than R^2 mod m and a multiplication by it.
    fn to_montgomery(&self, s: &[u64], out: &mut [u64]) {
        let m = self.modulus();
        let n = m.len();
        let mut d = [0; LIMBS_MAX];
        let mut v = [0; LIMBS_MAX];
        // rr: escape(panic): new keeps limbs in 32..=LIMBS_MAX, as a
        // modulus has at least 2048 bits.
        let (d, v, shift) = (&mut d[..n], &mut v[..n], m[n - 1].leading_zeros());
        shift_left(m, shift, d);
        shift_left(s, shift, v);
        // rr: escape(panic): as above.
        let divisor = d[n - 1];
        for _ in 0..n {
            // rr: escape(panic): as above.
            let (high, next) = (v[n - 1], v[n - 2]);
            let quotient = if high >= divisor {
                u64::MAX
            } else {
                low(((u128::from(high) << 64) | u128::from(next)) / u128::from(divisor))
            };
            // v 2^64 - quotient d: v's words move up one.
            let (mut carry, mut borrow, mut below_word) = (0, false, 0_u64);
            for (word, y) in v.iter_mut().zip(&*d) {
                let product = u128::from(quotient)
                    .wrapping_mul(u128::from(*y))
                    .wrapping_add(u128::from(carry));
                carry = low(product >> 64);
                let (r, b1) = below_word.overflowing_sub(low(product));
                let (r, b2) = r.overflowing_sub(u64::from(borrow));
                below_word = *word;
                *word = r;
                borrow = b1 | b2;
            }
            let (extra, b1) = below_word.overflowing_sub(carry);
            let (mut extra, b2) = extra.overflowing_sub(u64::from(borrow));
            // Too large an estimate leaves the difference negative.
            let mut negative = b1 | b2;
            for _ in 0..2 {
                if !negative {
                    break;
                }
                let mut carried = false;
                for (word, y) in v.iter_mut().zip(&*d) {
                    let (r, c1) = word.overflowing_add(*y);
                    let (r, c2) = r.overflowing_add(u64::from(carried));
                    *word = r;
                    carried = c1 | c2;
                }
                let (sum, over) = extra.overflowing_add(u64::from(carried));
                extra = sum;
                negative = !over;
            }
        }
        shift_right(v, shift, out);
    }

    /// out = a b / R mod m, for a and b below m, all of n limbs.
    fn multiply(&self, a: &[u64], b: &[u64], out: &mut [u64]) {
        self.montgomery(&Operand::Product(a, b), out);
    }

    /// out = a^2 / R mod m.
    fn square(&self, a: &[u64], out: &mut [u64]) {
        self.montgomery(&Operand::Square(a), out);
    }

    /// out = t / R mod m, column by column (Montgomery product scanning):
    /// the low n columns of t each with the multiple u_i m that clears
    /// it, the high n the result. That is below 2m, so one subtraction
    /// brings it below m.
    fn montgomery(&self, t: &Operand<'_>, out: &mut [u64]) {
        let m = self.modulus();
        let n = m.len();
        let mut u = [0; LIMBS_MAX];
        let mut sum = Column::new();
        for i in 0..2 * n {
            t.column(i, &u, m, &mut sum);
            if let Some(slot) = u.get_mut(i).filter(|_| i < n) {
                *slot = sum.word().wrapping_mul(self.m0inv);
                // rr: escape(panic): new keeps n at least 1.
                sum.add(*slot, m[0]);
            } else if let Some(word) = out.get_mut(i - n) {
                *word = sum.word();
            } else {
                return;
            }
            sum.shift();
        }
        if sum.word() != 0 || !below(out, m) {
            subtract(out, m);
        }
    }
}

/// What montgomery reduces, by its columns.
enum Operand<'a> {
    Product(&'a [u64], &'a [u64]),
    Square(&'a [u64]),
}

impl Operand<'_> {
    /// Adds column i of the number and of the reduction so far, u m, to
    /// sum: the products whose indices add up to i, of the n limbs.
    /// Pairs of the two go to two sums in one loop, whose additions do
    /// not wait for each other.
    #[inline(always)]
    fn column(&self, i: usize, u: &[u64; LIMBS_MAX], m: &[u64], sum: &mut Column) {
        let n = m.len();
        // u_j m_(i - j) for j in from..to: u_i is not known yet.
        let (from, to) = ((i + 1).saturating_sub(n), i.min(n));
        let mut part = Column::new();
        match self {
            Operand::Product(a, b) => {
                if let (Some(x), Some(y)) = (a.get(i), b.first()) {
                    part.add(*x, *y);
                }
                // rr: escape(panic): from <= to <= n and i - from < n.
                let these = (&a[from..to], &b[i + 1 - to..=i - from]);
                // rr: escape(panic): as above.
                let reduction = (&u[from..to], &m[i + 1 - to..=i - from]);
                part.add_both(these, sum, reduction);
                sum.add_column(&part);
            }
            Operand::Square(a) => {
                // Each pair below the diagonal twice, and the square on it:
                // j in from..half, with half <= to.
                let half = i.div_ceil(2).max(from);
                // rr: escape(panic): as above.
                let these = (&a[from..half], &a[i + 1 - half..=i - from]);
                // rr: escape(panic): as above.
                let reduction = (&u[from..half], &m[i + 1 - half..=i - from]);
                part.add_both(these, sum, reduction);
                // rr: escape(panic): as above.
                let (rest, partners) = (&u[half..to], &m[i + 1 - to..=i - half]);
                for (x, y) in rest.iter().zip(partners.iter().rev()) {
                    sum.add(*x, *y);
                }
                sum.add_column(&part);
                sum.add_column(&part);
                if let Some(x) = a.get(i / 2).filter(|_| i.is_multiple_of(2)) {
                    sum.add(*x, *x);
                }
            }
        }
    }
}

/// A sum of products of two limbs, three words: a column of at most 2
/// LIMBS_MAX of them, under 2^135, with what the column below carries
/// in, stays below 2^136, so top never wraps.
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
    let hash = if choice & 1 == 0 {
        Hash::Sha256
    } else {
        Hash::Sha384
    };
    let (exponent, rest) = rest.split_at(usize::from(choice >> 1).min(rest.len()));
    let (digest, rest) = rest.split_at(hash.len().min(rest.len()));
    let modulus_length = rest.len() / 2 + usize::from(split % 3);
    let (modulus, signature) = rest.split_at(modulus_length.min(rest.len()));
    verify_pkcs1(modulus, exponent, &hash, digest, signature);
    verify_pss(modulus, exponent, &hash, digest, signature);
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
    for hash in [Hash::Sha256, Hash::Sha384] {
        let digest = [0x5a; 48];
        let digest = &digest[..hash.len()];
        for exponent in [&[3][..], &[1, 0, 1]] {
            verify_pkcs1(&modulus, exponent, &hash, digest, &signature);
            verify_pss(&modulus, exponent, &hash, digest, &signature);
            verify_pss(&modulus, exponent, &hash, digest, input);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash, Key, verify_pkcs1, verify_pss};
    use alloc::vec::Vec;
    use test::Bencher;

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

    /// Wycheproof's first cases verify; its case 8 of PKCS #1, a
    /// DigestInfo without the NULL parameters that some accept, does not.
    #[test]
    fn wycheproof() {
        let (modulus, e, empty) = (hex(MODULUS), [1, 0, 1], hex(EMPTY));
        assert!(verify_pkcs1(
            &modulus,
            &e,
            &Hash::Sha256,
            &empty,
            &hex(PKCS1)
        ));
        assert!(verify_pss(&modulus, &e, &Hash::Sha256, &empty, &hex(PSS)));
        let missing_null = hex(
            "095dad1fd82bcd36652a381b7f4dd656bd89b40aa58b56da4f6aa8247874b935e65d2b86752d53\
             7df7103884d39dd9ad3d65f87404526b09094c5615c6249979b0dc58d2199ae8696a5b76b4bb03ea\
             f08c2ab6aec686c6b1b289c9b44f648bd30cb1ac6a64a73d68e59cd05e7aa1b780f4bfd7b83dfe3b\
             884ec11821a93dc5bbb47a00eea4557b6b96b5656276001f1f295ddbbbc511a99b9a665b9c2674c8\
             af0d812286d0be3ce74817ba2cad283757de35dfb149f2835f60cb03ff155524a57f78b148feceb8\
             4cd20b0ae22e3e48f433fbd9bfd60be8afec93165ee0310be961d3695f309d031320c830aa6ba08b\
             5a51d943797097c57630be391bd23736cc",
        );
        // SHA-256 of "123400".
        let digest = hex("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023");
        assert!(!verify_pkcs1(
            &modulus,
            &e,
            &Hash::Sha256,
            &digest,
            &missing_null
        ));
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

    /// Moduli of 2048 to 4096 bits, odd; exponents odd, from 3 to 2^33 -
    /// 1. The numbers need not be keys: the bounds come first.
    #[test]
    fn key_bounds() {
        let mut modulus = [0xff; 513];
        modulus[0] = 1;
        let e = [1, 0, 1];
        assert!(Key::new(&modulus[257..], &e).is_some());
        assert!(Key::new(&modulus[1..], &e).is_some());
        assert!(Key::new(&modulus, &e).is_none());
        assert!(Key::new(&modulus[258..], &e).is_none());
        modulus[257] = 0x7f;
        assert!(Key::new(&modulus[257..], &e).is_none());
        modulus[257] = 0x80;
        assert!(Key::new(&modulus[257..], &e).is_some());
        modulus[512] = 0xfe;
        assert!(Key::new(&modulus[257..], &e).is_none());
        modulus[512] = 0xff;
        assert!(Key::new(&[], &e).is_none());
        let modulus = &modulus[257..];
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
}
