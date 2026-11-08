//! P-256's numbers in four limbs, multiplied with the reduction its
//! special prime allows.
//!
//! registry/ecdsa/ecdsa-gen.py in rr's repository writes this file
//! from curve.rs.in beside it, which is where to change it.

use super::{TABLE, mac, width};

/// The limbs of a number.
const LIMBS: usize = 4;
/// Bytes of a coordinate and of a scalar.
pub(super) const BYTES: usize = 32;
/// Bits of the order n.
const BITS: usize = 256;

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

/// a b / R mod p.
#[inline(always)]
fn fmul(a: &Fe, b: &Fe) -> Fe {
    reduce_p256(&product(a, b))
}

/// a^2 / R mod p.
#[inline(always)]
fn fsqr(a: &Fe) -> Fe {
    reduce_p256(&square(a))
}

/// reduce for P-256's p = 2^256 - 2^224 + 2^192 + 2^96 - 1, whose
/// -p^-1 mod 2^64 is 1: each round's u is the low word, and u p is
/// shifts of u but for the top word's product. The rounds depend on
/// each other, so this shortens the multiplication's longest path.
#[inline(always)]
fn reduce_p256(t: &Wide) -> Fe {
    let [t0, t1, t2, t3, t4, t5, t6, t7] = *t;
    let ([t1, t2, t3, t4], over) = round_p256([t0, t1, t2, t3, t4], false);
    let ([t2, t3, t4, t5], over) = round_p256([t1, t2, t3, t4, t5], over);
    let ([t3, t4, t5, t6], over) = round_p256([t2, t3, t4, t5, t6], over);
    let ([t4, t5, t6, t7], over) = round_p256([t3, t4, t5, t6, t7], over);
    let r = [t4, t5, t6, t7];
    let (reduced, below) = sub_limbs(&r, &P.m);
    if over || !below { reduced } else { r }
}

/// One round of reduce_p256 on five words, low first: adds u p, with u
/// the low word, which clears it. over is the carry due in the top word.
#[inline(always)]
fn round_p256(words: [u64; 5], over: bool) -> ([u64; 4], bool) {
    let [u, w1, w2, w3, w4] = words;
    // u + u (2^64 - 1) is u 2^64, and with it w1 + u (2^32 - 1) + u is
    // w1 + u 2^32, whose high word is at most 2^32.
    let (s1, c1) = w1.overflowing_add(u << 32);
    let (s2, c2) = w2.overflowing_add((u >> 32) + u64::from(c1));
    let (s3, c3) = mac(u, P.m[3], w3, u64::from(c2));
    let (s4, o1) = w4.overflowing_add(c3);
    let (s4, o2) = s4.overflowing_add(u64::from(over));
    ([s1, s2, s3, s4], o1 | o2)
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
    m: [0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001],
    m0inv: 0x0000000000000001,
    rr: [0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd],
};
#[rustfmt::skip]
const N: Modulus = Modulus {
    m: [0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000],
    m0inv: 0xccd1c8aaee00bc4f,
    rr: [0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59, 0x66e12d94f3d95620],
};
/// b, in Montgomery form.
#[rustfmt::skip]
const B: Fe = [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];
/// One in Montgomery form: R mod p.
#[rustfmt::skip]
const ONE: Fe = [0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe];

#[rustfmt::skip]
const G: [[Fe; 2]; 32] = [
    [[0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6],
     [0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85]],
    [[0xffac3f904eebc127, 0xb027f84a087d81fb, 0x66ad77dd87cbbc98, 0x26936a3fb6ff747e],
     [0xb04c5c1fc983a7eb, 0x583e47ad0861fe1a, 0x788208311a2ee98e, 0xd5f06a29e587cc07]],
    [[0xbe1b8aaec45c61f5, 0x90ec649a94b9537d, 0x941cb5aad076c20c, 0xc9079605890523c8],
     [0xeb309b4ae7ba4f10, 0x73c568efe5eb882b, 0x3540a9877e7a1f68, 0x73a076bb2dd1e916]],
    [[0x0746354ea0173b4f, 0x2bd20213d23c00f7, 0xf43eaab50c23bb08, 0x13ba5119c3123e03],
     [0x2847d0303f5b9d4d, 0x6742f2f25da67bdd, 0xef933bdc77c94195, 0xeaedd9156e240867]],
    [[0x75c96e8f264e20e8, 0xabe6bfed59a7a841, 0x2cc09c0444c8eb00, 0xe05b3080f0c4e16b],
     [0x1eb7777aa45f3314, 0x56af7bedce5d45e3, 0x2b6e019a88b12f1a, 0x086659cdfd835f9b]],
    [[0xea7d260a6245e404, 0x9de407956e7fdfe0, 0x1ff3a4158dac1ab5, 0x3e7090f1649c9073],
     [0x1a7685612b944e88, 0x250f939ee57f61c8, 0x0c0daa891ead643d, 0x68930023e125b88e]],
    [[0xccc425634b2ed709, 0x0e356769856fd30d, 0xbcbcd43f559e9811, 0x738477ac5395b759],
     [0x35752b90c00ee17f, 0x68748390742ed2e3, 0x7cd06422bd1f5bc1, 0xfbc08769c9e7b797]],
    [[0x72bcd8b7bc60055b, 0x03cc23ee56e27e4b, 0xee337424e4819370, 0xe2aa0e430ad3da09],
     [0x40b8524f6383c45d, 0xd766355442a41b25, 0x64efa6de778a4797, 0x2042170a7079adf4]],
    [[0x97091dcbd53c5c9d, 0xf17624b6ac0a177b, 0xb0f139752cfe2dff, 0xc1a35c0a6c7a574e],
     [0x227d314693e79987, 0x0575bf30e89cb80e, 0x2f4e247f0d1883bb, 0xebd512263274c3d0]],
    [[0xfea912baa5659ae8, 0x68363aba25e1a16e, 0xb8842277752c41ac, 0xfe545c282897c3fc],
     [0x2d36e9e7dc4c696b, 0x5806244afba977c5, 0x85665e9be39508c1, 0xf720ee256d12597b]],
    [[0x562e4cecc135b208, 0x74e1b2654783f47d, 0x6d2a506c5a3f3b30, 0xecead9f4c16762fc],
     [0xf29dd4b2e286e5b9, 0x1b0fadc083bb3c61, 0x7a75023e7fac29a4, 0xc086d5f1c9477fa3]],
    [[0xf4f876532de45068, 0x37c7a7e89e2e1f6e, 0xd0825fa2a3584069, 0xaf2cea7c1727bf42],
     [0x0360a4fb9e4785a9, 0xe5fda49c27299f4a, 0x48068e1371ac2f71, 0x83d0687b9077666f]],
    [[0xa4a319acd837879f, 0x6fc1b49eed6b67b0, 0xe395993332f1f3af, 0x966742eb65432a2e],
     [0x4b8dc9feb4966228, 0x96cc631243f43950, 0x12068859c9b731ee, 0x7b948dc356f79968]],
    [[0x042c2af497e2feb4, 0xd36a42d7aebf7313, 0x49d2c9eb084ffdd7, 0x9f8aa54b2ef7c76a],
     [0x9200b7ba09895e70, 0x3bd0c66fddb7fb58, 0x2d97d10878eb4cbb, 0x2d431068d84bde31]],
    [[0x5e5db46acb66e132, 0xf1be963a0d925880, 0x944a70270317b9e2, 0xe266f95948603d48],
     [0x98db66735c208899, 0x90472447a2fb18a3, 0x8a966939777c619f, 0x3798142a2a3be21b]],
    [[0xe2f73c696755ff89, 0xdd3cf7e7473017e6, 0x8ef5689d3cf7600d, 0x948dc4f8b1fc87b4],
     [0xd9e9fe814ea53299, 0x2d921ca298eb6028, 0xfaecedfd0c9803fc, 0xf38ae8914d7b4745]],
    [[0x871514560f664534, 0x85ceae7c4b68f103, 0xac09c4ae65578ab9, 0x33ec6868f044b10c],
     [0x6ac4832b3a8ec1f1, 0x5509d1285847d5ef, 0xf909604f763f1574, 0xb16c4303c32f63c4]],
    [[0xfd16847fdec67ef5, 0x742ee464233e76b7, 0x0b8e4134efc2b4c8, 0xca640b8642a3e521],
     [0x653a01908ceb6aa9, 0x313c300c547852d5, 0x24e4ab126b237af7, 0x2ba901628bb47af8]],
    [[0x00467bc58cce08b5, 0xb636458c7f178d55, 0xc5748baea677d806, 0x2763a387dfa394eb],
     [0xa12b448a7d3cebb6, 0xe7adda3e6f20d850, 0xf63ebce51558462c, 0x58b36143620088a8]],
    [[0xa9d89488a059c142, 0x6f5ae714ff0b9346, 0x068f237d16fb3664, 0x5853e4c4363186ac],
     [0xe2d87d2363c52f98, 0x2ec4a76681828876, 0x47b864fae14e7b1c, 0x0c0bc0e569192408]],
    [[0x624d60492ed22e91, 0x6fdfe0b56f072822, 0xeeca111539ce2271, 0x98100a4fdb01614f],
     [0xb6b0daa2a35c628f, 0xb6f94d2ec87e9a47, 0xc67732591d57d9ce, 0xf70bfeec03884a7b]],
    [[0x4ff23ffd248a7d06, 0x80c5bfb4878873fa, 0xb7d9ad9005745981, 0x179c85db3db01994],
     [0xba41b06261a6966c, 0x4d82d052eadce5a8, 0x9e91cd3ba5e6a318, 0x47795f4f95b2dda0]],
    [[0x1ee426ccd5cd79bf, 0x0032940b946c6e18, 0x1b1e8ae057477f58, 0xe94f7d346d823278],
     [0xc747cb96782ba21a, 0xc5254469f72b33a5, 0x772ef6dec7f80c81, 0xd73acbfe2cd9e6b5]],
    [[0x283c7513caa76097, 0x0a624fa936c83906, 0x6b20afec715af2c7, 0x4b969974eba78bfd],
     [0x220755ccd921d60e, 0x9b944e107baeca13, 0x04819d515ded93d4, 0x9bbff86e6dddfd27]],
    [[0x21950b421ff6acd3, 0xffe7048453dc6909, 0xff4cd0b228766127, 0xabdbe6084fb7db2b],
     [0x837c92285e1109e8, 0x26147d27f4645b5a, 0x4d78f592f7818ed8, 0xd394077ef247fa36]],
    [[0x508cec1c3b3f64c9, 0xe20bc0ba1e5edf3f, 0xda1deb852f4318d4, 0xd20ebe0d5c3fa443],
     [0x370b4ea773241ea3, 0x61f1511c5e1a5f65, 0x99a5e23d82681c62, 0xd731e383a2f54c2d]],
    [[0x97359638546c4d8d, 0x5f9c3fc492f24679, 0x912e8beda8c8acd9, 0xec3a318d306634b0],
     [0x80167f41c31cb264, 0x3db82f6f522113f2, 0xb155bcd2dcafe197, 0xfba1da5943465283]],
    [[0x258bbbf9e7305683, 0x31eea5bf07ef5be6, 0x0deb0e4a46c814c1, 0x5cee8449a7b730dd],
     [0xeab495c5a0182bde, 0xee759f879e27a6b4, 0xc2cf6a6880e518ca, 0x25e8013ff14cf3f4]],
    [[0x3ec832e77acaca28, 0x1bfeea57c7385b29, 0x068212e3fd1eaf38, 0xc13298306acf8ccc],
     [0xb909f2db2aac9e59, 0x5748060db661782a, 0xc5ab2632c79b7a01, 0xda44c6c600017626]],
    [[0x69d44ed65c46aa8e, 0x2100d5d3a8d063d1, 0xcb9727eaa2d17c36, 0x4c2bab1b8add53b7],
     [0xa084e90c15426704, 0x778afcd3a837ebea, 0x6651f7017ce477f8, 0xa062499846fb7a8b]],
    [[0x3667eb1a7f4c04cc, 0x59556621a9404f84, 0x71cdf6537eceb50a, 0x994a44a69b8335fa],
     [0xd7faf819dbeb9b69, 0x473c5680eed4350d, 0xb6658466da44bba2, 0x0d1bc780872bdbf3]],
    [[0xb8d3d9319ff91fe5, 0x039c4800f0518eed, 0x95c376329182cb26, 0x0763a43482fc568d],
     [0x707c04d5383e76ba, 0xac98b930824e8197, 0x92bf7c8f91230de0, 0x90876a0140959b70]],
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
    const G_POINT: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    /// Montgomery's R is 2^256.
    const R_BITS: usize = 256;

    /// The special reduction agrees with Montgomery's, up to (p - 1)^2.
    #[test]
    fn reduction() {
        let mut top = P.m;
        top[0] -= 1;
        let mut a = B;
        for _ in 0..1000 {
            for b in [a, top, G[0][0], [1, 0, 0, 0], [0; LIMBS]] {
                let t = super::product(&a, &b);
                assert_eq!(super::reduce_p256(&t), super::reduce(&P, t));
            }
            a = fmul(&a, &G[0][0]);
        }
        let t = super::product(&top, &top);
        assert_eq!(super::reduce_p256(&t), super::reduce(&P, t));
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
