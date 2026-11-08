//! P-521's numbers in nine limbs: p = 2^521 - 1 reduces by adding the
//! bits past 521 to those below, so its numbers are plain, with R = 1.
//!
//! registry/ecdsa/ecdsa-gen.py in rr's repository writes this file
//! from curve.rs.in beside it, which is where to change it.

use super::{TABLE, mac, width};

/// The limbs of a number.
const LIMBS: usize = 9;
/// Bytes of a coordinate and of a scalar.
pub(super) const BYTES: usize = 66;
/// Bits of the order n.
const BITS: usize = 521;

/// A number below 2^(64 LIMBS), little-endian limbs.
type Fe = [u64; LIMBS];
/// A product of two numbers.
type Wide = [u64; 2 * LIMBS];

/// The digits of a NAF of a scalar, one more than its bits.
const DIGITS: usize = 64 * LIMBS + 1;

/// A modulus and what Montgomery multiplication by it needs.
struct Modulus {
    m: Fe,
    /// -m^-1 mod 2^64.
    m0inv: u64,
    /// R^2 mod m, to bring a number in.
    rr: Fe,
}

/// A point (x, y) in Montgomery form.
struct Affine {
    x: Fe,
    y: Fe,
}

/// A point in Jacobian coordinates, (X / Z^2, Y / Z^3), in Montgomery
/// form; Z = 0 is the point at infinity.
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// Whether r and s, the signature's numbers as DER wrote them, sign hash
/// under public, an uncompressed point 04 || X || Y. The hash is cut to
/// the order's bits when longer (SEC 1 4.1.4 step 5), and may be of any
/// length.
pub(super) fn verify(public: &[u8], hash: &[u8], r: &[u8], s: &[u8]) -> bool {
    let (Some(r), Some(s)) = (scalar(r), scalar(s)) else {
        return false;
    };
    let Some(q) = public_point(public) else {
        return false;
    };
    let e = truncated(hash);
    // w = s^-1; u1 = e w and u2 = r w, all mod n. w goes into Montgomery
    // form, so each product with a plain number comes out plain.
    let w = nmul(&invert(&s), &N.rr);
    let u1 = nmul(&e, &w);
    let u2 = nmul(&r, &w);
    let mut sum = infinity();
    combine(&u1, &q, &u2, &mut sum);
    if is_zero(&sum.z) {
        return false;
    }
    x_matches(&sum, &r)
}

/// A scalar of the signature as a number in [1, n - 1].
fn scalar(bytes: &[u8]) -> Option<Fe> {
    let value = load(bytes)?;
    let (_, below) = sub_limbs(&value, &N.m);
    if is_zero(&value) || !below {
        return None;
    }
    Some(value)
}

/// The public key as a point in Montgomery form: 04 || X || Y with X and
/// Y below p and on the curve. Infinity has no such encoding.
fn public_point(public: &[u8]) -> Option<Affine> {
    let ([4], coordinates) = public.split_at_checked(1)? else {
        return None;
    };
    let (x, y) = coordinates.split_at_checked(BYTES)?;
    if y.len() != BYTES {
        return None;
    }
    let (x, y) = (load(x)?, load(y)?);
    let (_, x_below) = sub_limbs(&x, &P.m);
    let (_, y_below) = sub_limbs(&y, &P.m);
    if !x_below || !y_below {
        return None;
    }
    let x = fmul(&x, &P.rr);
    let y = fmul(&y, &P.rr);
    // y^2 = x^3 - 3x + b.
    let x3 = fmul(&fsqr(&x), &x);
    let three_x = fadd(&fadd(&x, &x), &x);
    let right = fadd(&fsub(&x3, &three_x), &B);
    if fsqr(&y) != right {
        return None;
    }
    Some(Affine { x, y })
}

/// The hash as a number mod n: its leftmost bits, as many as n has. A
/// hash of BYTES or more is cut there and shifted down by the bits of
/// the BYTES past BITS, which only P-521's order, of 521 bits, has.
fn truncated(hash: &[u8]) -> Fe {
    let (hash, excess) = match hash.get(..BYTES) {
        Some(head) => (head, 8 * BYTES - BITS),
        None => (hash, 0),
    };
    let mut e = [0; LIMBS];
    for (limb, chunk) in e.iter_mut().zip(hash.rchunks(8)) {
        *limb = chunk
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
    }
    if excess > 0 {
        // rr: escape(cast): excess is below 8, the bits of a byte.
        shift_right(&mut e, 0, excess as u32);
    }
    // e < 2^bits < 2n: one subtraction reduces it.
    let (reduced, below) = sub_limbs(&e, &N.m);
    if below { e } else { reduced }
}

/// Big-endian bytes as limbs; None past the limbs' bytes.
fn load(bytes: &[u8]) -> Option<Fe> {
    if bytes.len() > 8 * LIMBS {
        return None;
    }
    let mut value = [0; LIMBS];
    for (limb, chunk) in value.iter_mut().zip(bytes.rchunks(8)) {
        *limb = chunk
            .iter()
            .fold(0, |acc, byte| (acc << 8) | u64::from(*byte));
    }
    Some(value)
}

/// Whether the affine x of point, reduced mod n, is r. x = X / Z^2, so
/// this compares X with r Z^2, and with (r + n) Z^2 when r + n < p,
/// sparing the inversion of Z.
fn x_matches(point: &Point, r: &Fe) -> bool {
    let zz = fsqr(&point.z);
    let candidate = fmul(&fmul(r, &P.rr), &zz);
    if candidate == point.x {
        return true;
    }
    let (wide, carry) = add_limbs(r, &N.m);
    let (_, below) = sub_limbs(&wide, &P.m);
    if carry || !below {
        return false;
    }
    fmul(&fmul(&wide, &P.rr), &zz) == point.x
}

/// k1 G + k2 q into acc: both scalars in NAF, one doubling per bit for
/// both and an addition per nonzero digit of either. q's is width 5,
/// from TABLE odd multiples; G's are constants, affine, whose additions
/// cost less, and on P-256 enough for width 7. The points are built in
/// place: a whole point is a copy that x86-64 makes by a call to memcpy.
fn combine(k1: &Fe, q: &Affine, k2: &Fe, acc: &mut Point) {
    let mut table = [const { infinity() }; TABLE];
    odd_multiples(q, &mut table);
    let (mut d1, mut d2) = ([0; DIGITS], [0; DIGITS]);
    naf(k1, width(G.len()), &mut d1);
    naf(k2, width(TABLE), &mut d2);
    *acc = infinity();
    for (g_digit, q_digit) in d1.iter().zip(&d2).rev() {
        double(acc);
        if *g_digit != 0 {
            let entry = base_multiple(*g_digit);
            add_affine(acc, &entry);
        }
        if *q_digit != 0 {
            add_digit(acc, &table, *q_digit);
        }
    }
}

/// digit times G, affine, from the constant table.
fn base_multiple(digit: i8) -> Affine {
    // rr: escape(panic): naf's digits for G are odd and below 2^(width -
    // 1) in magnitude, so half the magnitude is below the table's length.
    let [x, y] = &G[usize::from(digit.unsigned_abs() >> 1)];
    let y = if digit < 0 { fsub(&[0; LIMBS], y) } else { *y };
    Affine { x: *x, y }
}

/// Adds to acc digit times the point whose odd multiples table holds.
fn add_digit(acc: &mut Point, table: &[Point; TABLE], digit: i8) {
    // rr: escape(panic): as in base_multiple.
    let entry = &table[usize::from(digit.unsigned_abs() >> 1)];
    if digit > 0 {
        add(acc, entry);
        return;
    }
    let negated = Point {
        x: entry.x,
        y: fsub(&[0; LIMBS], &entry.y),
        z: entry.z,
    };
    add(acc, &negated);
}

/// P, 3P, ..., 15P into table: P, then each the one before it plus 2P.
/// Points are written a coordinate at a time, as add writes them.
fn odd_multiples(p: &Affine, table: &mut [Point; TABLE]) {
    let mut twice = infinity();
    add_affine(&mut twice, p);
    double(&mut twice);
    let [first, rest @ ..] = table;
    add_affine(first, p);
    let mut before: &Point = first;
    for slot in rest {
        slot.x = before.x;
        slot.y = before.y;
        slot.z = before.z;
        add(slot, &twice);
        before = slot;
    }
}

/// The NAF of k, of a width up to 7, least significant digit first:
/// each digit 0 or odd and below 2^(width - 1) in magnitude, and of any
/// width in a row at most one is nonzero.
fn naf(k: &Fe, width: u32, digits: &mut [i8; DIGITS]) {
    // One limb more: rounding a digit up may carry past k's top.
    let mut rest = [0_u64; LIMBS + 1];
    for (limb, word) in rest.iter_mut().zip(k) {
        *limb = *word;
    }
    let size = 1 << width;
    for digit in digits.iter_mut() {
        *digit = 0;
        let low = rest[0] & (size - 1);
        if low & 1 == 1 {
            if low < size / 2 {
                // rr: escape(cast): low is below 2^(width - 1), at most 64.
                *digit = low as i8;
                rest[0] -= low;
            } else {
                // rr: escape(cast): size - low is at most 2^(width - 1).
                *digit = -((size - low) as i8);
                let mut carry = size - low;
                for limb in &mut rest {
                    let (sum, over) = limb.overflowing_add(carry);
                    *limb = sum;
                    carry = u64::from(over);
                }
            }
        }
        let mut high = 0_u64;
        for limb in rest.iter_mut().rev() {
            let next = *limb << 63;
            *limb = (*limb >> 1) | high;
            high = next;
        }
    }
}

const fn infinity() -> Point {
    Point {
        x: [0; LIMBS],
        y: [0; LIMBS],
        z: [0; LIMBS],
    }
}

/// a doubled in place, by dbl-2001-b for a = -3.
fn double(a: &mut Point) {
    if is_zero(&a.z) || is_zero(&a.y) {
        *a = infinity();
        return;
    }
    let delta = fsqr(&a.z);
    let gamma = fsqr(&a.y);
    let beta = fmul(&a.x, &gamma);
    let product = fmul(&fsub(&a.x, &delta), &fadd(&a.x, &delta));
    let alpha = fadd(&fadd(&product, &product), &product);
    let beta2 = fadd(&beta, &beta);
    let beta4 = fadd(&beta2, &beta2);
    let beta8 = fadd(&beta4, &beta4);
    let x = fsub(&fsqr(&alpha), &beta8);
    let yz = fadd(&a.y, &a.z);
    let z = fsub(&fsub(&fsqr(&yz), &gamma), &delta);
    let gamma2 = fsqr(&gamma);
    let gamma4 = fadd(&gamma2, &gamma2);
    let gamma8 = fadd(&gamma4, &gamma4);
    let gamma16 = fadd(&gamma8, &gamma8);
    let y = fsub(&fmul(&alpha, &fsub(&beta4, &x)), &gamma16);
    // Each coordinate on its own: a Point built whole goes through a
    // copy of all its bytes, a call to memcpy on x86-64.
    a.x = x;
    a.y = y;
    a.z = z;
}

/// b added to a in place, by add-2007-bl, with the cases it leaves
/// out: infinity on either side, a = b and a = -b.
fn add(a: &mut Point, b: &Point) {
    if is_zero(&a.z) {
        a.x = b.x;
        a.y = b.y;
        a.z = b.z;
        return;
    }
    if is_zero(&b.z) {
        return;
    }
    let z1z1 = fsqr(&a.z);
    let z2z2 = fsqr(&b.z);
    let u1 = fmul(&a.x, &z2z2);
    let u2 = fmul(&b.x, &z1z1);
    let s1 = fmul(&fmul(&a.y, &b.z), &z2z2);
    let s2 = fmul(&fmul(&b.y, &a.z), &z1z1);
    let h = fsub(&u2, &u1);
    let r = fsub(&s2, &s1);
    if is_zero(&h) {
        if is_zero(&r) {
            double(a);
        } else {
            *a = infinity();
        }
        return;
    }
    let r = fadd(&r, &r);
    let h2 = fadd(&h, &h);
    let i = fsqr(&h2);
    let j = fmul(&h, &i);
    let v = fmul(&u1, &i);
    let x = fsub(&fsub(&fsub(&fsqr(&r), &j), &v), &v);
    let s1j = fmul(&s1, &j);
    let y = fsub(&fmul(&r, &fsub(&v, &x)), &fadd(&s1j, &s1j));
    let zs = fadd(&a.z, &b.z);
    let zz = fsub(&fsub(&fsqr(&zs), &z1z1), &z2z2);
    let z = fmul(&zz, &h);
    // Each coordinate on its own, as in double.
    a.x = x;
    a.y = y;
    a.z = z;
}

/// An affine b added to a in place, by madd-2007-bl, with the cases
/// it leaves out as add has them.
fn add_affine(a: &mut Point, b: &Affine) {
    if is_zero(&a.z) {
        a.x = b.x;
        a.y = b.y;
        a.z = ONE;
        return;
    }
    let z1z1 = fsqr(&a.z);
    let u2 = fmul(&b.x, &z1z1);
    let s2 = fmul(&fmul(&b.y, &a.z), &z1z1);
    let h = fsub(&u2, &a.x);
    let r = fsub(&s2, &a.y);
    if is_zero(&h) {
        if is_zero(&r) {
            double(a);
        } else {
            *a = infinity();
        }
        return;
    }
    let hh = fsqr(&h);
    let hh2 = fadd(&hh, &hh);
    let i = fadd(&hh2, &hh2);
    let j = fmul(&h, &i);
    let r = fadd(&r, &r);
    let v = fmul(&a.x, &i);
    let x = fsub(&fsub(&fsub(&fsqr(&r), &j), &v), &v);
    let y1j = fmul(&a.y, &j);
    let y = fsub(&fmul(&r, &fsub(&v, &x)), &fadd(&y1j, &y1j));
    let zh = fadd(&a.z, &h);
    let z = fsub(&fsub(&fsqr(&zh), &z1z1), &hh);
    // Each coordinate on its own, as in double.
    a.x = x;
    a.y = y;
    a.z = z;
}

/// a^-1 mod n for a in [1, n - 1], plain, by the binary extended
/// Euclidean algorithm. It keeps x1 a = u and x2 a = v (mod n), u and v
/// odd, from u = a and v = n; each round takes the smaller from the
/// larger, which halves at least once, until u = v = 1. Not constant
/// time, which public scalars do not need: about half the time of the
/// Fermat power a^(n - 2).
fn invert(a: &Fe) -> Fe {
    let mut u = *a;
    let mut v = N.m;
    let mut x1 = [0; LIMBS];
    x1[0] = 1;
    let mut x2 = [0; LIMBS];
    halve(&mut u, &mut x1);
    // Each round takes a bit off u or v at least: their bits bound it.
    for _ in 0..2 * 64 * LIMBS {
        let (difference, below) = sub_limbs(&u, &v);
        if is_zero(&difference) {
            break;
        }
        if below {
            v = sub_limbs(&v, &u).0;
            x2 = sub_mod(&N.m, &x2, &x1);
            halve(&mut v, &mut x2);
        } else {
            u = difference;
            x1 = sub_mod(&N.m, &x1, &x2);
            halve(&mut u, &mut x1);
        }
    }
    x1
}

/// Divides w, nonzero, by its largest power of two, and x by the same
/// mod n: x + c n with c = -x n^-1 mod 2^k is a multiple of 2^k, and
/// below 2n once divided. k is at most 63 a step.
#[inline(always)]
fn halve(w: &mut Fe, x: &mut Fe) {
    for _ in 0..=LIMBS * 64 / 63 {
        let zeros = trailing_zeros(w).min(63);
        if zeros == 0 {
            return;
        }
        shift_right(w, 0, zeros);
        let c = x[0].wrapping_mul(N.m0inv) & ((1 << zeros) - 1);
        let mut carry = 0;
        for (limb, y) in x.iter_mut().zip(&N.m) {
            (*limb, carry) = mac(c, *y, *limb, carry);
        }
        // The carry is the word above the limbs.
        shift_right(x, carry, zeros);
        let (reduced, below) = sub_limbs(x, &N.m);
        if !below {
            *x = reduced;
        }
    }
}

/// The trailing zero bits of w, nonzero.
fn trailing_zeros(w: &Fe) -> u32 {
    let mut zeros = 0;
    for limb in w {
        if *limb != 0 {
            return zeros + limb.trailing_zeros();
        }
        zeros += 64;
    }
    zeros
}

/// w = (w + top 2^(64 LIMBS)) / 2^k, for k in 1..64 and w + top 2^(64
/// LIMBS) a multiple of 2^k.
fn shift_right(w: &mut Fe, top: u64, k: u32) {
    let mut above = top;
    for limb in w.iter_mut().rev() {
        let pair = (u128::from(above) << 64) | u128::from(*limb);
        above = *limb;
        // rr: escape(cast): the low word of the pair shifted by under 64.
        *limb = (pair >> k) as u64;
    }
}

fn is_zero(a: &Fe) -> bool {
    a.iter().all(|limb| *limb == 0)
}

/// a b / R mod n.
#[inline(always)]
fn nmul(a: &Fe, b: &Fe) -> Fe {
    reduce(&N, product(a, b))
}

/// a + b mod p, for a and b below p.
#[inline(always)]
fn fadd(a: &Fe, b: &Fe) -> Fe {
    add_mod(&P.m, a, b)
}

/// a - b mod p, for a and b below p.
#[inline(always)]
fn fsub(a: &Fe, b: &Fe) -> Fe {
    sub_mod(&P.m, a, b)
}

/// a b mod p: P-521's numbers are plain, as if R were 1.
#[inline(always)]
fn fmul(a: &Fe, b: &Fe) -> Fe {
    reduce_p521(&product(a, b))
}

/// a^2 mod p.
#[inline(always)]
fn fsqr(a: &Fe) -> Fe {
    reduce_p521(&square(a))
}

/// t mod P-521's p = 2^521 - 1, for t below p^2: 2^521 is 1 mod p, so
/// t is its low 521 bits plus the rest shifted down, a sum below 2p that
/// one subtraction brings below p.
#[inline(always)]
fn reduce_p521(t: &Wide) -> Fe {
    let mut low = [0; LIMBS];
    for (word, limb) in low.iter_mut().zip(t) {
        *word = *limb;
    }
    low[LIMBS - 1] &= 0x1ff;
    let mut high = [0; LIMBS];
    for ((word, below), above) in high.iter_mut().zip(t.iter().skip(8)).zip(t.iter().skip(9)) {
        *word = (below >> 9) | (above << 55);
    }
    let (sum, _) = add_limbs(&low, &high);
    let (reduced, below) = sub_limbs(&sum, &P.m);
    if below { sum } else { reduced }
}

// The limb arithmetic below wraps instead of checking: each product and
// sum is bounded in its comment, and an overflow check on each would
// cost the verification a large part of its time.

/// a b: products independent of each other, which the processor
/// overlaps.
#[inline(always)]
fn product(a: &Fe, b: &Fe) -> Wide {
    let mut t = [0_u64; 2 * LIMBS];
    for (i, x) in a.iter().enumerate() {
        // rr: escape(panic): i < LIMBS, and t holds 2 LIMBS words.
        let row = &mut t[i..];
        let mut carry = 0;
        for (limb, y) in row.iter_mut().zip(b) {
            (*limb, carry) = mac(*x, *y, *limb, carry);
        }
        // rr: escape(panic): i + LIMBS < 2 LIMBS.
        row[LIMBS] = carry;
    }
    t
}

/// a^2, each product of two limbs taken once and doubled.
#[inline(always)]
fn square(a: &Fe) -> Wide {
    let mut t = [0_u64; 2 * LIMBS];
    for (i, x) in a.iter().enumerate() {
        // rr: escape(panic): i < LIMBS, and t holds 2 LIMBS words.
        let row = &mut t[2 * i + 1..];
        let mut carry = 0;
        // rr: escape(panic): as above.
        for (limb, y) in row.iter_mut().zip(&a[i + 1..]) {
            (*limb, carry) = mac(*x, *y, *limb, carry);
        }
        // rr: escape(panic): the row ends at word i + LIMBS < 2 LIMBS.
        row[LIMBS - i - 1] = carry;
    }
    // Twice the products above the diagonal, plus the squares on it.
    let mut high = 0;
    for word in &mut t {
        let next = *word >> 63;
        *word = (*word << 1) | high;
        high = next;
    }
    let mut carry = 0;
    for (pair, x) in t.as_chunks_mut::<2>().0.iter_mut().zip(a) {
        let [low, top] = pair;
        let (square, spill) = mac(*x, *x, *low, carry);
        *low = square;
        let (sum, over) = top.overflowing_add(spill);
        *top = sum;
        carry = u64::from(over);
    }
    t
}

/// t / R mod m for t below m R: LIMBS rounds that each add the multiple
/// of m that clears the lowest word. The result is below 2m, so one
/// subtraction brings it below m.
#[inline(always)]
fn reduce(modulus: &Modulus, mut t: Wide) -> Fe {
    let mut over = false;
    for i in 0..LIMBS {
        // rr: escape(panic): i < LIMBS, and t holds 2 LIMBS words.
        let row = &mut t[i..];
        // rr: escape(panic): as above.
        let u = row[0].wrapping_mul(modulus.m0inv);
        let mut carry = 0;
        for (limb, y) in row.iter_mut().zip(&modulus.m) {
            (*limb, carry) = mac(u, *y, *limb, carry);
        }
        // The carry out of this word is due in the next round's top one.
        // rr: escape(panic): i + LIMBS < 2 LIMBS.
        let (sum, o1) = row[LIMBS].overflowing_add(carry);
        let (sum, o2) = sum.overflowing_add(u64::from(over));
        // rr: escape(panic): as above.
        row[LIMBS] = sum;
        over = o1 | o2;
    }
    let mut r = [0; LIMBS];
    for (limb, word) in r.iter_mut().zip(t.iter().skip(LIMBS)) {
        *limb = *word;
    }
    let (reduced, below) = sub_limbs(&r, &modulus.m);
    if over || !below { reduced } else { r }
}

/// a + b and whether it carried out.
#[inline(always)]
fn add_limbs(a: &Fe, b: &Fe) -> (Fe, bool) {
    let mut sum = [0; LIMBS];
    let mut carry = false;
    for ((out, x), y) in sum.iter_mut().zip(a).zip(b) {
        let (s, c1) = x.overflowing_add(*y);
        let (s, c2) = s.overflowing_add(u64::from(carry));
        *out = s;
        carry = c1 | c2;
    }
    (sum, carry)
}

/// a - b, and whether a < b, which wraps it.
#[inline(always)]
fn sub_limbs(a: &Fe, b: &Fe) -> (Fe, bool) {
    let mut difference = [0; LIMBS];
    let mut borrow = false;
    for ((out, x), y) in difference.iter_mut().zip(a).zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        *out = d;
        borrow = b1 | b2;
    }
    (difference, borrow)
}

#[inline(always)]
fn add_mod(m: &Fe, a: &Fe, b: &Fe) -> Fe {
    let (sum, carry) = add_limbs(a, b);
    let (reduced, below) = sub_limbs(&sum, m);
    if carry || !below { reduced } else { sum }
}

#[inline(always)]
fn sub_mod(m: &Fe, a: &Fe, b: &Fe) -> Fe {
    let (difference, borrow) = sub_limbs(a, b);
    if borrow {
        add_limbs(&difference, m).0
    } else {
        difference
    }
}

// The curve's numbers, from FIPS 186-4's, and the odd multiples of G
// as affine x and y in Montgomery form, which registry/ecdsa/
// ecdsa-gen.py in rr's repository computes.

#[rustfmt::skip]
const P: Modulus = Modulus {
    m: [0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff],
    m0inv: 0x0000000000000001,
    rr: [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000],
};
#[rustfmt::skip]
const N: Modulus = Modulus {
    m: [0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b, 0xfffffffffffffffa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff],
    m0inv: 0x1d2f5ccd79a995c7,
    rr: [0x137cd04dcf15dd04, 0xf707badce5547ea3, 0x12a78d38794573ff, 0xd3721ef557f75e06, 0xdd6e23d82e49c7db, 0xcff3d142b7756e3e, 0x5bcc6d61a8e567bc, 0x2d8e03d1492d0d45, 0x000000000000003d],
};
/// b, in Montgomery form.
#[rustfmt::skip]
const B: Fe = [0xef451fd46b503f00, 0x3573df883d2c34f1, 0x1652c0bd3bb1bf07, 0x56193951ec7e937b, 0xb8b489918ef109e1, 0xa2da725b99b315f3, 0x929a21a0b68540ee, 0x953eb9618e1c9a1f, 0x0000000000000051];
/// One in Montgomery form: R mod p.
#[rustfmt::skip]
const ONE: Fe = [0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

#[rustfmt::skip]
const G: [[Fe; 2]; 8] = [
    [[0xf97e7e31c2e5bd66, 0x3348b3c1856a429b, 0xfe1dc127a2ffa8de, 0xa14b5e77efe75928, 0xf828af606b4d3dba, 0x9c648139053fb521, 0x9e3ecb662395b442, 0x858e06b70404e9cd, 0x00000000000000c6],
     [0x88be94769fd16650, 0x353c7086a272c240, 0xc550b9013fad0761, 0x97ee72995ef42640, 0x17afbd17273e662c, 0x98f54449579b4468, 0x5c8a5fb42c7d1bd9, 0x39296a789a3bc004, 0x0000000000000118]],
    [[0xa5919d2ede37ad7d, 0xaeb490862c32ea05, 0x1da6bd16b59fe21b, 0xad3f164a3a483205, 0xe5ad7a112d7a8dd1, 0xb52a6e5b123d9ab9, 0xd91d6a64b5959479, 0x3d352443de29195d, 0x00000000000001a7],
     [0x5f588ca1ee86c0e5, 0xf105c9bc93a59042, 0x2d5aced1dec3c70c, 0x2e2dd4cf8dc575b0, 0xd2f8ab1fa355ceec, 0xf1557fa82a9d0317, 0x979f86c6cab814f2, 0x9b03b97dfa62ddd9, 0x000000000000013e]],
    [[0xd5ab5096ec8f3078, 0x29d7e1e6d8931738, 0x7112feaf137e79a3, 0x383c0c6d5e301423, 0xcf03dab8f177ace4, 0x7a596efdb53f0d24, 0x3dbc3391c04eb0bf, 0x2bf3c52927a432c7, 0x0000000000000065],
     [0x173cc3e8deb090cb, 0xd1f007257354f7f8, 0x311540211cf5ff79, 0xbb6897c9072cf374, 0xedd817c9a0347087, 0x1cd8fe8e872e0051, 0x8a2b73114a811291, 0xe6ef1bdd6601d6ec, 0x000000000000015b]],
    [[0x01cead882816ecd4, 0x6f953f50fdc2619a, 0xc9a6df30dce3bbc4, 0x8c308d0abfc698d8, 0xf018d2c2f7114c5d, 0x5f22e0e8f5483228, 0xeeb65fda0b073a0c, 0xd5d1d99d5b7f6346, 0x0000000000000056],
     [0x5c6b8bc90525251b, 0x9e76712a5ddefc7b, 0x9523a34591ce1a5f, 0x6bd0f293cdec9e2b, 0x71dbd98a26cbde55, 0xb5c582d02824f0dd, 0xd1d8317a39d68478, 0x2d1b7d9baaa2a110, 0x000000000000003d]],
    [[0x1f45627967cbe207, 0x4f50babd85cd2866, 0xf3c556df725a318f, 0x7429e1396134da35, 0x2c4ab145b8c6b665, 0xed34541b98874699, 0xa2f5bf157156d488, 0x5389e359e1e21826, 0x0000000000000158],
     [0x3aa0ea86b9ad2a4e, 0x736c2ae928880f34, 0x0ff56ecf4abfd87d, 0x0d69e5756057ac84, 0xc825ba263ddb446e, 0x3088a654ee1cebb6, 0x0b55557a27ae938e, 0x2e618c9a8aedf39f, 0x000000000000002a]],
    [[0xecc0e02dda0cdb9a, 0x015c024fa4c9a902, 0xd19b1aebe3191085, 0xf3dbc5332663da1b, 0x43ef2c54f2991652, 0xed5dc7ed7c178495, 0x6f1a39573b4315cf, 0x75841259fdedff54, 0x000000000000008a],
     [0x58874f92ce48c808, 0xdcac80e3f4819b5d, 0x3892331914a95336, 0x1bc8a90e8b42a4ab, 0xed2e95d4e0b9b82b, 0x3add566210bd0493, 0x9d0ca877054fb229, 0xfb303fcbba212984, 0x0000000000000096]],
    [[0x1887848d32fbcda7, 0x4bec3b00ab38eff8, 0x3550a5e79ab88ee9, 0x32c45908e03c996a, 0x4eedd2beaf5b8661, 0x93f736cde1b4c238, 0xd7865d2b4924861a, 0x3e98f984c396ad9c, 0x000000000000007e],
     [0x291a01fb022a71c9, 0x6199eaaf9117e9f7, 0x26dfdd351cbfbbc3, 0xc1bd5d5838bc763f, 0x9c7a67ae5c1e212a, 0xced50a386d5421c6, 0x1a1926daa3ed5a08, 0xee58eb6d781feda9, 0x0000000000000108]],
    [[0xe9afe337bcb8db55, 0x9b8d96981e3f92bd, 0x7875bd1c8fc0331d, 0xb91cce27dbd00ffe, 0xd697b532df128e11, 0xb8fbcc30b40a0852, 0x41558fc546d4300f, 0x6ad89abcb92465f0, 0x000000000000006b],
     [0x56343480a1475465, 0x46fd90cc446abdd9, 0x2148e2232c96c992, 0x7e9062c899470a80, 0x4b62106997485ed5, 0xdf0496a9bad20cba, 0x7ce64d2333edbf63, 0x68da271571391d6a, 0x00000000000001b4]],
];

#[cfg(test)]
mod tests {
    use super::super::hex;
    use super::{
        B, Fe, G, LIMBS, N, ONE, P, add, add_affine, add_mod, base_multiple, combine, double, fmul,
        fsqr, infinity, invert, is_zero, nmul, public_point, sub_limbs,
    };

    /// G, uncompressed and plain.
    #[rustfmt::skip]
    const G_POINT: &str = "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";

    /// R is 1: products are reduced by the shape of p.
    const R_BITS: usize = 0;

    /// (p - 1)^2 = 1, (p - 1) 1 = p - 1 and 0 1 = 0.
    #[test]
    fn reduction() {
        let mut minus_one = P.m;
        minus_one[0] -= 1;
        let mut one = [0; LIMBS];
        one[0] = 1;
        assert_eq!(fmul(&minus_one, &minus_one), one);
        assert_eq!(fsqr(&minus_one), one);
        assert_eq!(fmul(&minus_one, &one), minus_one);
        assert_eq!(fmul(&one, &[0; LIMBS]), [0; LIMBS]);
    }

    /// The constants beside FIPS 186-4's: -m^-1 and R^2 mod m for each
    /// modulus, R mod p, b on the curve with G, G's table, and n G at
    /// infinity.
    #[test]
    fn constants() {
        for (modulus, bits) in [(&P, R_BITS), (&N, 64 * LIMBS)] {
            assert_eq!(modulus.m[0].wrapping_mul(modulus.m0inv), u64::MAX);
            let mut rr = [0; LIMBS];
            rr[0] = 1;
            for _ in 0..2 * bits {
                rr = add_mod(&modulus.m, &rr, &rr);
            }
            assert_eq!(rr, modulus.rr);
        }
        let mut one = [0; LIMBS];
        one[0] = 1;
        assert_eq!(fmul(&one, &P.rr), ONE);
        // G checked on the curve, which needs b. The table's (x, y) is
        // the Jacobian (X, Y, Z) that adding G gives when x Z^2 = X and
        // y Z^3 = Y.
        let g = public_point(&hex(G_POINT)).unwrap();
        let mut twice = infinity();
        add_affine(&mut twice, &g);
        double(&mut twice);
        let mut multiple = infinity();
        add_affine(&mut multiple, &g);
        for digit in (1..2 * i8::try_from(G.len()).unwrap()).step_by(2) {
            let entry = base_multiple(digit);
            let zz = fsqr(&multiple.z);
            assert_eq!(fmul(&entry.x, &zz), multiple.x);
            let zzz = fmul(&zz, &multiple.z);
            assert_eq!(fmul(&entry.y, &zzz), multiple.y);
            add(&mut multiple, &twice);
        }
        let mut sum = infinity();
        combine(&N.m, &g, &[0; LIMBS], &mut sum);
        assert!(is_zero(&sum.z));
        let (below_n, _) = sub_limbs(&N.m, &one);
        combine(&one, &g, &below_n, &mut sum);
        assert!(is_zero(&sum.z));
        combine(&one, &g, &one, &mut sum);
        assert!(!is_zero(&sum.z));
    }

    /// Squares agree with products, from b and p - 1 on.
    #[test]
    fn squares() {
        let mut top = P.m;
        top[0] -= 1;
        let mut a = B;
        for _ in 0..1000 {
            for b in [a, top] {
                assert_eq!(fsqr(&b), fmul(&b, &b));
            }
            a = fmul(&a, &G[0][0]);
        }
    }

    /// s s^-1 = 1 mod n for the ends of [1, n - 1] and values between,
    /// each with many and few factors of two along the way.
    #[test]
    fn scalar_inverse() {
        let mut one: Fe = [0; LIMBS];
        one[0] = 1;
        let (top, _) = sub_limbs(&N.m, &one);
        let mut s = N.rr;
        let mut power = one;
        for _ in 0..200 {
            for value in [s, top, one, power] {
                let inverse = invert(&value);
                assert_eq!(nmul(&nmul(&value, &inverse), &N.rr), one);
            }
            s = nmul(&s, &N.rr);
            power = add_mod(&N.m, &power, &power);
        }
    }
}
