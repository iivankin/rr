//! ECDSA signature verification on P-256, P-384 and P-521 (FIPS 186-4, SEC 1)
//! of a digest that names its hash, answering which part is wrong (key,
//! encoding, signature): strict DER signatures, uncompressed keys checked on
//! the curve, Montgomery field arithmetic with P-256's special reduction and
//! NAF double-scalar multiplies.
//!
//! ECDSA signature verification on P-256, P-384 and P-521 (FIPS 186-4,
//! SEC 1 4.1.4). Everything it reads is public: the key, the hash and the
//! signature. So the arithmetic is not constant time, but every length
//! an attacker picks is checked before it is used.
//!
//! Field elements are little-endian 64-bit limbs in Montgomery form,
//! multiplied and reduced (Montgomery) against each modulus as a
//! constant. Each curve has its own module, p256, p384 and p521, with
//! numbers of its own limbs, four, six and nine, which the compiler
//! unrolls: rr has no const generics, and numbers as wide as P-521's for
//! every curve would copy and loop over limbs the others do not use.
//! registry/gen/ecdsa-gen.py in rr's repository writes the three from
//! one template. P-256's reduction is shifts of its special prime;
//! P-521's p = 2^521 - 1 reduces by adding the bits past 521 to those
//! below, with R = 1. Points are Jacobian; u1 G + u2 Q is one run of
//! doublings over both scalars in NAF, G's multiples a constant table.
//!
//! What is verified is a digest that names its hash (digest::Digest),
//! never bytes of any length: a signature of a digest h verifies for any
//! hash that begins with h's leftmost bits, so a message, or a digest of
//! another hash, must not pass for one. The answer is a Result that says
//! which part is wrong:
//!
//! ```text
//! let digest = sha256::digest(message);
//! ecdsa::verify(&Curve::P256, key, &Digest::Sha256(&digest), signature)?;
//! ```

// rr: checked(0.5.2)
// rr: needs(digest)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
// rr: file(ecdsa-wycheproof.txt, tests = yes)

use crate::base::digest::Digest;

mod p256 {
    //! P-256's numbers in four limbs, multiplied with the reduction its
    //! special prime allows.
    //!
    //! registry/gen/ecdsa-gen.py in rr's repository writes this module
    //! from gen/curve.rs.in beside it, which is where to change it.

    use super::{Error, TABLE, mac, width};

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

    /// Ok when r and s, the signature's numbers as DER wrote them, sign hash
    /// under public, an uncompressed point 04 || X || Y: Key when public is
    /// not a point of the curve, Signature when r or s is outside [1, n - 1]
    /// or they do not sign hash. The hash is cut to the order's bits when
    /// longer (SEC 1 4.1.4 step 5), and may be of any length here.
    pub(super) fn verify(public: &[u8], hash: &[u8], r: &[u8], s: &[u8]) -> Result<(), Error> {
        let q = public_point(public).ok_or(Error::Key)?;
        let (Some(r), Some(s)) = (scalar(r), scalar(s)) else {
            return Err(Error::Signature);
        };
        let e = truncated(hash);
        // w = s^-1; u1 = e w and u2 = r w, all mod n. w goes into Montgomery
        // form, so each product with a plain number comes out plain.
        let w = nmul(&invert(&s), &N.rr);
        let u1 = nmul(&e, &w);
        let u2 = nmul(&r, &w);
        let mut sum = infinity();
        combine(&u1, &q, &u2, &mut sum);
        if is_zero(&sum.z) || !x_matches(&sum, &r) {
            return Err(Error::Signature);
        }
        Ok(())
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
    // as affine x and y in Montgomery form, which registry/gen/
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

    // rr: section(tests = yes)
    #[cfg(test)]
    mod tests {
        use super::super::hex;
        use super::{
            B, Fe, G, LIMBS, N, ONE, P, add, add_affine, add_mod, base_multiple, combine, double,
            fmul, fsqr, infinity, invert, is_zero, nmul, public_point, sub_limbs,
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
    // rr: end(tests = yes)
}
mod p384 {
    //! P-384's numbers in six limbs, multiplied and reduced
    //! (Montgomery) against p as a constant.
    //!
    //! registry/gen/ecdsa-gen.py in rr's repository writes this module
    //! from gen/curve.rs.in beside it, which is where to change it.

    use super::{Error, TABLE, mac, width};

    /// The limbs of a number.
    const LIMBS: usize = 6;
    /// Bytes of a coordinate and of a scalar.
    pub(super) const BYTES: usize = 48;
    /// Bits of the order n.
    const BITS: usize = 384;

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

    /// Ok when r and s, the signature's numbers as DER wrote them, sign hash
    /// under public, an uncompressed point 04 || X || Y: Key when public is
    /// not a point of the curve, Signature when r or s is outside [1, n - 1]
    /// or they do not sign hash. The hash is cut to the order's bits when
    /// longer (SEC 1 4.1.4 step 5), and may be of any length here.
    pub(super) fn verify(public: &[u8], hash: &[u8], r: &[u8], s: &[u8]) -> Result<(), Error> {
        let q = public_point(public).ok_or(Error::Key)?;
        let (Some(r), Some(s)) = (scalar(r), scalar(s)) else {
            return Err(Error::Signature);
        };
        let e = truncated(hash);
        // w = s^-1; u1 = e w and u2 = r w, all mod n. w goes into Montgomery
        // form, so each product with a plain number comes out plain.
        let w = nmul(&invert(&s), &N.rr);
        let u1 = nmul(&e, &w);
        let u2 = nmul(&r, &w);
        let mut sum = infinity();
        combine(&u1, &q, &u2, &mut sum);
        if is_zero(&sum.z) || !x_matches(&sum, &r) {
            return Err(Error::Signature);
        }
        Ok(())
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
        reduce(&P, product(a, b))
    }

    /// a^2 / R mod p.
    #[inline(always)]
    fn fsqr(a: &Fe) -> Fe {
        reduce(&P, square(a))
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
    // as affine x and y in Montgomery form, which registry/gen/
    // ecdsa-gen.py in rr's repository computes.

    #[rustfmt::skip]
const P: Modulus = Modulus {
    m: [0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
    m0inv: 0x0000000100000001,
    rr: [0xfffffffe00000001, 0x0000000200000000, 0xfffffffe00000000, 0x0000000200000000, 0x0000000000000001, 0x0000000000000000],
};
    #[rustfmt::skip]
const N: Modulus = Modulus {
    m: [0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
    m0inv: 0x6ed46089e88fdc45,
    rr: [0x2d319b2419b409a9, 0xff3d81e5df1aa419, 0xbc3e483afcb82947, 0xd40d49174aab1cc5, 0x3fb05b7a28266895, 0x0c84ee012b39bf21],
};
    /// b, in Montgomery form.
#[rustfmt::skip]
const B: Fe = [0x081188719d412dcc, 0xf729add87a4c32ec, 0x77f2209b1920022e, 0xe3374bee94938ae2, 0xb62b21f41f022094, 0xcd08114b604fbff9];
    /// One in Montgomery form: R mod p.
#[rustfmt::skip]
const ONE: Fe = [0xffffffff00000001, 0x00000000ffffffff, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000];

    #[rustfmt::skip]
const G: [[Fe; 2]; 8] = [
    [[0x3dd0756649c0b528, 0x20e378e2a0d6ce38, 0x879c3afc541b4d6e, 0x6454868459a30eff, 0x812ff723614ede2b, 0x4d3aadc2299e1513],
     [0x23043dad4b03a4fe, 0xa1bfa8bf7bb4a9ac, 0x8bade7562e83b050, 0xc6c3521968f4ffd9, 0xdd8002263969a840, 0x2b78abc25a15c5e9]],
    [[0x05e4dbe6c1dc4073, 0xc54ea9fff04f779c, 0x6b2034e9a170ccf0, 0x3a48d732d51c6c3e, 0xe36f7e2d263aa470, 0xd283fe68e7c1c3ac],
     [0x7e284821c04ee157, 0x92d789a77ae0e36d, 0x132663c04ef67446, 0x68012d5ad2e1d0b4, 0xf6db68b15102b339, 0x465465fc983292af]],
    [[0xbb595eba68f1f0df, 0xc185c0cbcc873466, 0x7f1eb1b5293c703b, 0x60db2cf5aacc05e6, 0xc676b987e2e8e4c6, 0xe1bb26b11d178ffb],
     [0x2b694ba07073fa21, 0x22c16e2e72f34566, 0x80b61b3101c35b99, 0x4b237faf982c0411, 0xe6c5944024de236d, 0x4db1c9d6e209e4a3]],
    [[0xdf13b9d17d69222b, 0x4ce6415f874774b1, 0x731edcf8211faa95, 0x5f4215d1659753ed, 0xf893db589db2df55, 0x932c9f811c89025b],
     [0x0996b2207706a61e, 0x135349d5a8641c79, 0x65aad76f50130844, 0x0ff37c0401fff780, 0xf57f238e693b0706, 0xd90a16b6af6c9b3e]],
    [[0x2f5d200e2353b92f, 0xe35d87293fd7e4f9, 0x26094833a96d745d, 0xdc351dc13cbfff3f, 0x26d464c6dad54d6a, 0x5cab1d1d53636c6a],
     [0xf2813072b18ec0b0, 0x3777e270d742aa2f, 0x27f061c7033ca7c2, 0xa6ecaccc68ead0d8, 0x7d9429f4ee69a754, 0xe770633431e8f5c6]],
    [[0xc7708b19b68b8c7d, 0x4532077c44377aba, 0x0dcc67706cdad64f, 0x01b8bf56147b6602, 0xf8d89885f0561d79, 0x9c19e9fc7ba9c437],
     [0x764eb146bdc4ba25, 0x604fe46bac144b83, 0x3ce813298a77e780, 0x2e070f36fe9e682e, 0x41821d0c3a53287a, 0x9aa62f9f3533f918]],
    [[0x9b7aeb7e75ccbdfb, 0xb25e28c5f6749a95, 0x8a7a8e4633b7d4ae, 0xdb5203a8d9c1bd56, 0xd2657265ed22df97, 0xb51c56e18cf23c94],
     [0xf4d394596c3d812d, 0xd8e88f1a87cae0c2, 0x789a2a48cf4d0fe3, 0xb7feac2dfec38d60, 0x81fdbd1c3b490ec3, 0x4617adb7cc6979e1]],
    [[0x446ad8884709f4a9, 0x2b7210e2ec3dabd8, 0x83ccf19550e07b34, 0x59500917789b3075, 0x0fc01fd4eb085993, 0xfb62d26f4903026b],
     [0x2309cc9d6fe989bb, 0x61609cbd144bd586, 0x4b23d3a0de06610c, 0xdddc2866d898f470, 0x8733fc41400c5797, 0x5a68c6fed0bc2716]],
];

    // rr: section(tests = yes)
    #[cfg(test)]
    mod tests {
        use super::super::hex;
        use super::{
            B, Fe, G, LIMBS, N, ONE, P, add, add_affine, add_mod, base_multiple, combine, double,
            fmul, fsqr, infinity, invert, is_zero, nmul, public_point, sub_limbs,
        };

        /// G, uncompressed and plain.
    #[rustfmt::skip]
    const G_POINT: &str = "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";

        /// Montgomery's R is 2^384.
        const R_BITS: usize = 384;

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
    // rr: end(tests = yes)
}
mod p521 {
    //! P-521's numbers in nine limbs: p = 2^521 - 1 reduces by adding the
    //! bits past 521 to those below, so its numbers are plain, with R = 1.
    //!
    //! registry/gen/ecdsa-gen.py in rr's repository writes this module
    //! from gen/curve.rs.in beside it, which is where to change it.

    use super::{Error, TABLE, mac, width};

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

    /// Ok when r and s, the signature's numbers as DER wrote them, sign hash
    /// under public, an uncompressed point 04 || X || Y: Key when public is
    /// not a point of the curve, Signature when r or s is outside [1, n - 1]
    /// or they do not sign hash. The hash is cut to the order's bits when
    /// longer (SEC 1 4.1.4 step 5), and may be of any length here.
    pub(super) fn verify(public: &[u8], hash: &[u8], r: &[u8], s: &[u8]) -> Result<(), Error> {
        let q = public_point(public).ok_or(Error::Key)?;
        let (Some(r), Some(s)) = (scalar(r), scalar(s)) else {
            return Err(Error::Signature);
        };
        let e = truncated(hash);
        // w = s^-1; u1 = e w and u2 = r w, all mod n. w goes into Montgomery
        // form, so each product with a plain number comes out plain.
        let w = nmul(&invert(&s), &N.rr);
        let u1 = nmul(&e, &w);
        let u2 = nmul(&r, &w);
        let mut sum = infinity();
        combine(&u1, &q, &u2, &mut sum);
        if is_zero(&sum.z) || !x_matches(&sum, &r) {
            return Err(Error::Signature);
        }
        Ok(())
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
    // as affine x and y in Montgomery form, which registry/gen/
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

    // rr: section(tests = yes)
    #[cfg(test)]
    mod tests {
        use super::super::hex;
        use super::{
            B, Fe, G, LIMBS, N, ONE, P, add, add_affine, add_mod, base_multiple, combine, double,
            fmul, fsqr, infinity, invert, is_zero, nmul, public_point, sub_limbs,
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
    // rr: end(tests = yes)
}

/// The odd multiples P, 3P, ..., 15P of the key that a width-5 NAF
/// picks from.
const TABLE: usize = 8;

/// Why a signature does not verify.
// rr: section(tests = yes)
#[cfg_attr(test, derive(Debug, PartialEq))]
// rr: end(tests = yes)
pub enum Error {
    /// The key is not an uncompressed point of the curve.
    Key,
    /// The signature is not DER's one encoding of two integers no longer
    /// than the order.
    Encoding,
    /// r or s is not in [1, n - 1], or they do not sign the digest under
    /// the key.
    Signature,
}

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

/// Ok when signature, DER's Ecdsa-Sig-Value, signs digest under public,
/// an uncompressed point 04 || X || Y. A digest longer than the order is
/// cut to its bits (SEC 1 4.1.4 step 5): P-256 takes SHA-384's and
/// SHA-512's leftmost 256 bits.
pub fn verify(
    curve: &Curve,
    public: &[u8],
    digest: &Digest<'_>,
    signature: &[u8],
) -> Result<(), Error> {
    verify_hash(curve, public, digest.bytes(), signature)
}

/// verify of a hash of any length, for the tests and the fuzz target.
fn verify_hash(curve: &Curve, public: &[u8], hash: &[u8], signature: &[u8]) -> Result<(), Error> {
    let (r, s) = parse(signature, curve.bytes()).ok_or(Error::Encoding)?;
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

// rr: section(tests = yes)
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
    // rr: escape(discard): any answer will do; a panic is the failure.
    let _: Result<(), Error> = verify_hash(&curve, public, hash, signature);
    // rr: escape(discard): as above.
    let _: Result<(), Error> = verify_hash(&curve, &[], hash, rest);
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
// rr: end(tests = yes)

// rr: section(tests = yes)
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
// rr: end(tests = yes)

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    use super::{Curve, Error, hex, verify, verify_hash};
    use crate::base::digest::Digest;
    use alloc::vec::Vec;
    use test::Bencher;

    /// verify with the digest of hash's length, or verify_hash for a
    /// length no hash has.
    fn check(curve: &Curve, key: &[u8], hash: &[u8], signature: &[u8]) -> Result<(), Error> {
        if let Ok(digest) = <&[u8; 32]>::try_from(hash) {
            verify(curve, key, &Digest::Sha256(digest), signature)
        } else if let Ok(digest) = <&[u8; 48]>::try_from(hash) {
            verify(curve, key, &Digest::Sha384(digest), signature)
        } else if let Ok(digest) = <&[u8; 64]>::try_from(hash) {
            verify(curve, key, &Digest::Sha512(digest), signature)
        } else {
            verify_hash(curve, key, hash, signature)
        }
    }

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
                    assert!(matches!(hash.len(), 32 | 48 | 64), "{bits} tcId {id}");
                    let verified = check(&curve, key, hash, &signature);
                    assert_eq!(verified.is_ok(), valid == "1", "{bits} tcId {id}");
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
        assert!(yes(&Curve::P521, &key, &hash, &signature));
        assert!(not(&Curve::P384, &key, &hash, &signature));
        let body = &signature[3..];
        for bad in [
            der(&[0x30, 0x82, 0, 0x88], &[body]),
            der(&[0x30, 0x88], &[body]),
            der(&[0x30, 0x81, 0x89], &[body, &[0]]),
        ] {
            assert!(not(&Curve::P521, &key, &hash, &bad));
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
            assert!(yes(&Curve::P521, &key, &moved, &signature));
            moved[0] ^= 0x80;
            assert!(not(&Curve::P521, &key, &moved, &signature));
        }
    }

    /// The valid P-256 case with one thing changed at a time.
    #[test]
    fn rejects() {
        let (key, hash, signature) = (hex(KEY256), hex(EMPTY256), hex(SIG256));
        assert!(yes(&Curve::P256, &key, &hash, &signature));
        assert!(not(&Curve::P384, &key, &hash, &signature));
        let mut wrong = hex(EMPTY256);
        wrong[31] ^= 1;
        assert_eq!(
            check(&Curve::P256, &key, &wrong, &signature),
            Err(Error::Signature)
        );
        assert!(not(&Curve::P256, &key, &hash[..31], &signature));
        // A SHA-384 digest is cut to P-256's leftmost 256 bits (SEC 1
        // 4.1.4 step 5): one that begins with this digest verifies, and a
        // bit changed there does not.
        let mut longer = [0; 48];
        longer[..32].copy_from_slice(&hash);
        let padded = Digest::Sha384(&longer);
        assert_eq!(verify(&Curve::P256, &key, &padded, &signature), Ok(()));
        longer[0] ^= 1;
        let changed = Digest::Sha384(&longer);
        assert_eq!(
            verify(&Curve::P256, &key, &changed, &signature),
            Err(Error::Signature)
        );
        assert_eq!(check(&Curve::P256, &key, &hash, &[]), Err(Error::Encoding));
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
            assert_eq!(check(&Curve::P256, bad, &hash, &signature), Err(Error::Key));
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
            assert!(not(&Curve::P256, &key, &hash, &bad));
        }
        assert!(yes(
            &Curve::P256,
            &key,
            &hash,
            &der(&[0x30, 0x45], &[&[2, 0x21], r, &[2, 0x20], s])
        ));
    }

    fn yes(curve: &Curve, key: &[u8], hash: &[u8], signature: &[u8]) -> bool {
        check(curve, key, hash, signature).is_ok()
    }

    fn not(curve: &Curve, key: &[u8], hash: &[u8], signature: &[u8]) -> bool {
        check(curve, key, hash, signature).is_err()
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
        let digest: [u8; 32] = hash.try_into().unwrap();
        b.iter(|| verify(&Curve::P256, &key, &Digest::Sha256(&digest), &signature));
    }

    /// One P-521 verification.
    #[bench]
    fn verify_p521(b: &mut Bencher) {
        let (key, hash, signature) = (hex(KEY521), hex(EMPTY512), hex(SIG521));
        let digest: [u8; 64] = hash.try_into().unwrap();
        b.iter(|| verify(&Curve::P521, &key, &Digest::Sha512(&digest), &signature));
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
        let digest: [u8; 48] = hash.try_into().unwrap();
        b.iter(|| verify(&Curve::P384, &key, &Digest::Sha384(&digest), &signature));
    }
}
// rr: end(tests = yes)
