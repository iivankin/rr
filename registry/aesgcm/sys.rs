//! AES-GCM's CTR and GHASH on the CPU's instructions: AES and PMULL
//! on aarch64, AES-NI, PCLMULQDQ and SSSE3 on x86_64, and VAES with
//! VPCLMULQDQ where x86_64 has them. Each function
//! returns false, having done nothing, where the CPU lacks them;
//! aesgcm.rs then runs its portable code.
//!
//! seal and open take one pass over the record, eight blocks a turn: the
//! eight AES chains of one turn run beside the GHASH of eight ciphertext
//! blocks (seal's from the turn before, open's own input), so the AES and
//! the carry-less multiply units work at once. GHASH folds the eight with
//! H^8..H into one unreduced Karatsuba sum, three products a block and
//! one reduction a turn. The round keys are read where the key keeps them.
//!
//! On aarch64 GHASH is in the plain polynomial basis: each byte's bits
//! are reversed, one RBIT, so bit i of the little-endian 128-bit value
//! is the coefficient of x^i, and a product is a carry-less
//! multiplication reduced by x^128 = x^7 + x^2 + x + 1 (0x87). x86-64
//! reverses bits in six instructions and bytes in one, so it reverses
//! only the bytes; its module says how that works.
//!
//! Where the CPU has more (FASTER), seal and open take a faster
//! loop: on aarch64 one in asm on SHA3's EOR3, on x86-64 one on VAES
//! and VPCLMULQDQ, two blocks to each instruction.
//!
//! AES-128 and AES-256 differ only in their round keys: 11 or 15, kept
//! so that the last ones are in the same place for both. A key's rounds
//! run from RoundKeys.first on, so the round count is where a loop
//! starts, and the last rounds keep their fixed keys.

use crate::base::cpu;

/// H to H^8, then for each the XOR of its halves in both lanes, which
/// Karatsuba's middle product takes.
pub type Table = [[u8; 16]; 16];

/// AES's round keys, aligned as a vector register is: the instructions
/// read them where the key keeps them, with no copy.
#[repr(C, align(16))]
pub struct RoundKeys {
    /// AES-256's 15, or AES-128's 11 in the last 11 places.
    pub keys: [[u8; 16]; 15],
    /// Where the first round key is: 0 for AES-256, AES128_FIRST for
    /// AES-128.
    pub first: usize,
}

/// Where AES-128's first round key is in RoundKeys.
pub const AES128_FIRST: usize = 4;

/// What the faster loop of seal and open runs on besides: SHA3's EOR3
/// on aarch64, VAES and VPCLMULQDQ on x86_64.
#[cfg(target_arch = "aarch64")]
const FASTER: u32 = cpu::AES | cpu::SHA512;
#[cfg(not(target_arch = "aarch64"))]
const FASTER: u32 = cpu::WIDE_AES;

/// Whether the CPU has the instructions the functions below need.
pub fn available() -> bool {
    cpu::has(cpu::AES)
}

/// CTR in place over data with round keys rk: the counter blocks are
/// block (the nonce, then four bytes the counter replaces) with ctr,
/// ctr + 1, ... big-endian in its last four bytes.
pub fn ctr(rk: &RoundKeys, block: &[u8; 16], ctr: u32, data: &mut [u8]) -> bool {
    if !available() {
        return false;
    }
    // rr: escape(unsafe): available() found the instructions it runs on.
    unsafe { arch::ctr(rk, block, ctr, data) };
    true
}

/// The table ghash, seal and open take, from H = E(K, 0).
pub fn ghash_key(h: &[u8; 16], tbl: &mut Table) -> bool {
    if !available() {
        return false;
    }
    // rr: escape(unsafe): available() found the instructions it runs on.
    unsafe { arch::ghash_key(h, tbl) };
    true
}

/// y = GHASH of y continued over blocks.
pub fn ghash(tbl: &Table, y: &mut [u8; 16], blocks: &[[u8; 16]]) -> bool {
    if !available() {
        return false;
    }
    // rr: escape(unsafe): available() found the instructions it runs on.
    unsafe { arch::ghash(tbl, y, blocks) };
    true
}

/// CTR in place over blocks as ctr() does, and y continued over the
/// ciphertext it makes.
pub fn seal(
    rk: &RoundKeys,
    tbl: &Table,
    block: &[u8; 16],
    ctr: u32,
    blocks: &mut [[u8; 16]],
    y: &mut [u8; 16],
) -> bool {
    if !available() {
        return false;
    }
    // rr: escape(unsafe): available() found the instructions it runs on.
    unsafe { arch::seal(rk, tbl, block, ctr, blocks, y, cpu::has(FASTER)) };
    true
}

/// y continued over the ciphertext in blocks, and CTR in place over it.
pub fn open(
    rk: &RoundKeys,
    tbl: &Table,
    block: &[u8; 16],
    ctr: u32,
    blocks: &mut [[u8; 16]],
    y: &mut [u8; 16],
) -> bool {
    if !available() {
        return false;
    }
    // rr: escape(unsafe): available() found the instructions it runs on.
    unsafe { arch::open(rk, tbl, block, ctr, blocks, y, cpu::has(FASTER)) };
    true
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::{RoundKeys, Table};
    use core::arch::aarch64::{
        uint8x16_t, uint32x4_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u8, vdupq_n_u64, veorq_u8, vextq_u8,
        vgetq_lane_p64, vld1q_u8, vmull_high_p64, vmull_p64, vrbitq_u8, vreinterpretq_p64_u8,
        vreinterpretq_u8_p128, vreinterpretq_u8_u32, vreinterpretq_u8_u64, vreinterpretq_u32_u8,
        vsetq_lane_u32, vst1q_u8,
    };

    type V = uint8x16_t;

    /// The counter blocks of one turn of AES-256's asm loop, aligned as
    /// a vector register is.
    #[repr(C, align(16))]
    struct Counters([[u8; 16]; 8]);

    #[inline(always)]
    fn load(b: &[u8; 16]) -> V {
        // rr: escape(unsafe): b is 16 readable bytes; NEON is in every aarch64.
        unsafe { vld1q_u8(b.as_ptr()) }
    }

    #[inline(always)]
    fn store(b: &mut [u8; 16], v: V) {
        // rr: escape(unsafe): b is 16 writable bytes; NEON is in every aarch64.
        unsafe { vst1q_u8(b.as_mut_ptr(), v) }
    }

    #[target_feature(enable = "aes")]
    /// The round keys as vectors, where rk keeps them: loaded into
    /// stack slots instead, x86-64 copies all of them with memcpy.
    fn round_keys(rk: &RoundKeys) -> &[V; 15] {
        // rr: escape(unsafe): RoundKeys starts with 15 blocks of 16 bytes
        // (repr(C)) and is aligned to 16, as [V; 15] is, and every bit
        // pattern is a vector.
        unsafe { &*core::ptr::from_ref(rk).cast::<[V; 15]>() }
    }

    const _: () = assert!(size_of::<RoundKeys>() >= size_of::<[V; 15]>());
    const _: () = assert!(align_of::<RoundKeys>() == align_of::<[V; 15]>());

    /// Counter blocks from ctr on, one for each of s.
    #[target_feature(enable = "aes")]
    fn counters(base: uint32x4_t, ctr: u32, s: &mut [V]) {
        for (x, i) in s.iter_mut().zip(0..) {
            let c = ctr.wrapping_add(i).to_be();
            *x = vreinterpretq_u8_u32(vsetq_lane_u32::<3>(c, base));
        }
    }

    /// One middle round on each of s.
    #[target_feature(enable = "aes")]
    fn round(s: &mut [V], k: V) {
        for x in s.iter_mut() {
            *x = vaesmcq_u8(vaeseq_u8(*x, k));
        }
    }

    /// The last round. AESE adds the round key before it substitutes, so
    /// the last key is a plain XOR.
    #[target_feature(enable = "aes")]
    fn last(s: &mut [V], k: &[V; 15]) {
        for x in s.iter_mut() {
            *x = veorq_u8(vaeseq_u8(*x, k[13]), k[14]);
        }
    }

    /// The rounds of the key from k[first] on: AESE and AESMC with each
    /// key before the last two.
    #[target_feature(enable = "aes")]
    fn aes(k: &[V; 15], first: usize, s: &mut [V]) {
        for rk in k.iter().take(13).skip(first) {
            round(s, *rk);
        }
        last(s, k);
    }

    /// Each block XORed with its key stream, CTR's last step; s keeps
    /// what was stored, for seal to hash.
    #[target_feature(enable = "aes")]
    fn xor_into(blocks: &mut [[u8; 16]], s: &mut [V]) {
        for (b, ks) in blocks.iter_mut().zip(s) {
            *ks = veorq_u8(load(b), *ks);
            store(b, *ks);
        }
    }

    #[target_feature(enable = "aes")]
    pub fn ctr(rk: &RoundKeys, block: &[u8; 16], ctr: u32, data: &mut [u8]) {
        let k = round_keys(rk);
        let base = vreinterpretq_u32_u8(load(block));
        let (blocks, tail) = data.as_chunks_mut::<16>();
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        let mut c = ctr;
        let mut s = [vdupq_n_u8(0); 4];
        for four in fours {
            counters(base, c, &mut s);
            c = c.wrapping_add(4);
            aes(k, rk.first, &mut s);
            xor_into(four, &mut s);
        }
        if rest.is_empty() && tail.is_empty() {
            return;
        }
        // Under four blocks and a part: one more batch of key stream.
        counters(base, c, &mut s);
        aes(k, rk.first, &mut s);
        xor_into(rest, &mut s);
        if let Some(ks) = s.get(rest.len()) {
            let mut t = [0; 16];
            store(&mut t, *ks);
            for (d, x) in tail.iter_mut().zip(t) {
                *d ^= x;
            }
        }
    }

    /// The 64x64 carry-less product of the low lanes of a and b.
    #[target_feature(enable = "aes")]
    fn pmul_lo(a: V, b: V) -> V {
        let a = vgetq_lane_p64::<0>(vreinterpretq_p64_u8(a));
        let b = vgetq_lane_p64::<0>(vreinterpretq_p64_u8(b));
        vreinterpretq_u8_p128(vmull_p64(a, b))
    }

    /// The same of the high lanes.
    #[target_feature(enable = "aes")]
    fn pmul_hi(a: V, b: V) -> V {
        let (a, b) = (vreinterpretq_p64_u8(a), vreinterpretq_p64_u8(b));
        vreinterpretq_u8_p128(vmull_high_p64(a, b))
    }

    /// x with its halves XORed, in both lanes: Karatsuba's middle factor.
    #[target_feature(enable = "aes")]
    fn halves(x: V) -> V {
        veorq_u8(x, vextq_u8::<8>(x, x))
    }

    /// acc (low, middle, high) += the Karatsuba products of x * h; hk is
    /// halves(h).
    #[target_feature(enable = "aes")]
    fn kmul(acc: &mut [V; 3], x: V, h: V, hk: V) {
        let [lo, mid, hi] = *acc;
        *acc = [
            veorq_u8(lo, pmul_lo(x, h)),
            veorq_u8(mid, pmul_lo(halves(x), hk)),
            veorq_u8(hi, pmul_hi(x, h)),
        ];
    }

    /// The 256-bit sum acc holds, reduced: the middle product goes to the
    /// middle, then hi * x^128 = hi * 0x87 folds into lo, and then its own
    /// 7-bit overflow.
    #[target_feature(enable = "aes")]
    fn fold(acc: [V; 3]) -> V {
        let [lo, mid, hi] = acc;
        let zero = vdupq_n_u8(0);
        let mid = veorq_u8(mid, veorq_u8(lo, hi));
        let lo = veorq_u8(lo, vextq_u8::<8>(zero, mid));
        let hi = veorq_u8(hi, vextq_u8::<8>(mid, zero));
        let red = vreinterpretq_u8_u64(vdupq_n_u64(0x87));
        let f0 = pmul_lo(hi, red);
        let f1 = pmul_hi(hi, red);
        let g = pmul_hi(f1, red);
        veorq_u8(veorq_u8(lo, f0), veorq_u8(vextq_u8::<8>(zero, f1), g))
    }

    #[target_feature(enable = "aes")]
    fn gmul(a: V, b: V) -> V {
        let zero = vdupq_n_u8(0);
        let mut acc = [zero; 3];
        kmul(&mut acc, a, b, halves(b));
        fold(acc)
    }

    /// H to H^8 and their halves, from the table.
    #[target_feature(enable = "aes")]
    fn powers(tbl: &Table) -> ([V; 8], [V; 8]) {
        let mut h = [vdupq_n_u8(0); 8];
        let mut hk = h;
        let (hb, kb) = tbl.split_at(8);
        for ((v, w), (b, c)) in h.iter_mut().zip(hk.iter_mut()).zip(hb.iter().zip(kb)) {
            *v = load(b);
            *w = load(c);
        }
        (h, hk)
    }

    /// y, already XORed into x[0], times H^8 .. H for x[0] .. x[7].
    #[target_feature(enable = "aes")]
    fn ghash8(x: &[V; 8], h: &[V; 8], hk: &[V; 8]) -> V {
        let mut acc = [vdupq_n_u8(0); 3];
        for ((xb, hp), kp) in x.iter().zip(h.iter().rev()).zip(hk.iter().rev()) {
            kmul(&mut acc, *xb, *hp, *kp);
        }
        fold(acc)
    }

    /// Eight AES chains, from k[first] on, with ghash8 of x woven between
    /// their first eight rounds.
    #[target_feature(enable = "aes")]
    fn aes8_ghash8(
        k: &[V; 15],
        first: usize,
        s: &mut [V; 8],
        x: &[V; 8],
        h: &[V; 8],
        hk: &[V; 8],
    ) -> V {
        let mut acc = [vdupq_n_u8(0); 3];
        let turns = x.iter().zip(k.iter().skip(first));
        for ((xb, rk), (hp, kp)) in turns.zip(h.iter().rev().zip(hk.iter().rev())) {
            round(s, *rk);
            kmul(&mut acc, *xb, *hp, *kp);
        }
        for rk in k.iter().take(13).skip(first + 8) {
            round(s, *rk);
        }
        last(s, k);
        fold(acc)
    }

    #[target_feature(enable = "aes")]
    pub fn ghash_key(h: &[u8; 16], tbl: &mut Table) {
        let hp = vrbitq_u8(load(h));
        let mut p = hp;
        let (pw, ks) = tbl.split_at_mut(8);
        for (i, (t, kt)) in pw.iter_mut().zip(ks).enumerate() {
            if i > 0 {
                p = gmul(p, hp);
            }
            store(t, p);
            store(kt, halves(p));
        }
    }

    /// y continued over blocks, in the reversed basis.
    #[target_feature(enable = "aes")]
    fn ghash_rev(h: &[V; 8], hk: &[V; 8], mut yp: V, blocks: &[[u8; 16]]) -> V {
        let (eights, rest) = blocks.as_chunks::<8>();
        let mut x = [vdupq_n_u8(0); 8];
        for eight in eights {
            for (v, b) in x.iter_mut().zip(eight) {
                *v = vrbitq_u8(load(b));
            }
            x[0] = veorq_u8(x[0], yp);
            yp = ghash8(&x, h, hk);
        }
        for b in rest {
            let mut acc = [vdupq_n_u8(0); 3];
            kmul(&mut acc, veorq_u8(yp, vrbitq_u8(load(b))), h[0], hk[0]);
            yp = fold(acc);
        }
        yp
    }

    #[target_feature(enable = "aes")]
    pub fn ghash(tbl: &Table, y: &mut [u8; 16], blocks: &[[u8; 16]]) {
        let (h, hk) = powers(tbl);
        let yp = ghash_rev(&h, &hk, vrbitq_u8(load(y)), blocks);
        store(y, vrbitq_u8(yp));
    }

    /// Eight blocks a turn; each turn's ciphertext is hashed in the next,
    /// beside its AES, and the last after the loop.
    #[target_feature(enable = "aes")]
    pub fn seal(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
        eor3: bool,
    ) {
        if eor3 {
            // rr: escape(unsafe): the caller found SHA3's EOR3 beside AES.
            unsafe { seal_eor3(rk, tbl, block, ctr, blocks, y) };
            return;
        }
        // The first round key's place a constant in each copy, as the
        // round count is: a loop of it, the keys then in registers, ran
        // a fifth slower.
        if rk.first == super::AES128_FIRST {
            seal_from(rk, super::AES128_FIRST, tbl, block, ctr, blocks, y);
        } else {
            seal_from(rk, 0, tbl, block, ctr, blocks, y);
        }
    }

    /// seal() with the keys from k[first] on.
    #[inline]
    #[target_feature(enable = "aes")]
    fn seal_from(
        rk: &RoundKeys,
        first: usize,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let base = vreinterpretq_u32_u8(load(block));
        let mut yp = vrbitq_u8(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [vdupq_n_u8(0); 8];
        let mut prev: Option<[V; 8]> = None;
        for eight in eights {
            counters(base, c, &mut s);
            c = c.wrapping_add(8);
            match prev {
                Some(mut x) => {
                    x[0] = veorq_u8(x[0], yp);
                    yp = aes8_ghash8(k, first, &mut s, &x, &h, &hk);
                }
                None => aes(k, first, &mut s),
            }
            xor_into(eight, &mut s);
            prev = Some(s.map(|v| vrbitq_u8(v)));
        }
        if let Some(mut x) = prev {
            x[0] = veorq_u8(x[0], yp);
            yp = ghash8(&x, &h, &hk);
        }
        self::ctr(rk, block, c, rest.as_flattened_mut());
        yp = ghash_rev(&h, &hk, yp, rest);
        store(y, vrbitq_u8(yp));
    }

    /// Eight blocks a turn: the ciphertext is hashed beside the AES that
    /// makes the key stream to decrypt it.
    #[target_feature(enable = "aes")]
    pub fn open(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
        eor3: bool,
    ) {
        if eor3 {
            // rr: escape(unsafe): the caller found SHA3's EOR3 beside AES.
            unsafe { open_eor3(rk, tbl, block, ctr, blocks, y) };
            return;
        }
        // The first round key's place a constant in each copy, as the
        // round count is: a loop of it, the keys then in registers, ran
        // a fifth slower.
        if rk.first == super::AES128_FIRST {
            open_from(rk, super::AES128_FIRST, tbl, block, ctr, blocks, y);
        } else {
            open_from(rk, 0, tbl, block, ctr, blocks, y);
        }
    }

    /// open() with the keys from k[first] on.
    #[inline]
    #[target_feature(enable = "aes")]
    fn open_from(
        rk: &RoundKeys,
        first: usize,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let base = vreinterpretq_u32_u8(load(block));
        let mut yp = vrbitq_u8(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [vdupq_n_u8(0); 8];
        let mut x = s;
        for eight in eights {
            counters(base, c, &mut s);
            c = c.wrapping_add(8);
            for (v, b) in x.iter_mut().zip(eight.iter()) {
                *v = vrbitq_u8(load(b));
            }
            x[0] = veorq_u8(x[0], yp);
            yp = aes8_ghash8(k, first, &mut s, &x, &h, &hk);
            xor_into(eight, &mut s);
        }
        yp = ghash_rev(&h, &hk, yp, rest);
        self::ctr(rk, block, c, rest.as_flattened_mut());
        store(y, vrbitq_u8(yp));
    }

    /// seal() in one asm loop after the first turn, on EOR3 too.
    #[target_feature(enable = "aes,sha3")]
    fn seal_eor3(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let (h, hk) = powers(tbl);
        let base = load(block);
        let mut yp = vrbitq_u8(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        // The first turn has no ciphertext before it to hash.
        if let Some(first) = eights.first_mut() {
            let k = round_keys(rk);
            let mut s = [vdupq_n_u8(0); 8];
            counters(vreinterpretq_u32_u8(base), c, &mut s);
            c = c.wrapping_add(8);
            aes(k, rk.first, &mut s);
            xor_into(first, &mut s);
        }
        yp = turns(rk, tbl, block, &mut c, eights, true, yp);
        if let Some(last) = eights.last() {
            yp = ghash_rev(&h, &hk, yp, last);
        }
        self::ctr(rk, block, c, rest.as_flattened_mut());
        yp = ghash_rev(&h, &hk, yp, rest);
        store(y, vrbitq_u8(yp));
    }

    /// open() in one asm loop, on EOR3 too.
    #[target_feature(enable = "aes,sha3")]
    fn open_eor3(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let (h, hk) = powers(tbl);
        let mut yp = vrbitq_u8(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        yp = turns(rk, tbl, block, &mut c, eights, false, yp);
        yp = ghash_rev(&h, &hk, yp, rest);
        self::ctr(rk, block, c, rest.as_flattened_mut());
        store(y, vrbitq_u8(yp));
    }

    /// The eight-block turns, in asm: for seal every turn but the first,
    /// hashing the turn before; for open every turn, hashing its own
    /// ciphertext before it is decrypted. c is the counter of the first
    /// turn run, and after them the next.
    ///
    /// The intrinsics did the same work in about 197 vector instructions
    /// a turn: with 11 round keys, H^8..H and their halves, eight states
    /// and eight blocks to hash live at once, LLVM spilled the GHASH keys
    /// to general registers and moved them back (fmov, dup) every turn,
    /// and put the AES and the GHASH in two blocks. Here the round keys
    /// stay in v0-v10, the GHASH keys are loaded where they are used, the
    /// GHASH sums fold with EOR3, the last round's key and the data meet
    /// in one EOR3, each AESE sits beside its AESMC so Apple's cores fuse
    /// the pair, and the GHASH steps go between the last four middle
    /// rounds, which measured best of the orders tried: about 165 vector
    /// instructions a turn. Seal on an M4 Pro, 16 KiB: 1606 ns with the
    /// intrinsics, 1450 here; 64 KiB: 6330 ns, 5700.
    ///
    /// AES-256's 15 round keys do not fit beside the rest: v0-v10 keep
    /// k0 and k5-k14, and k1-k4 are loaded each turn into registers the
    /// GHASH takes after round 4. Its turn is cut further in vector
    /// instructions, every vector unit being busy: the counter blocks are
    /// made in general registers and loaded from ctrs, two blocks share
    /// one XOR of halves, and the reduction is seven instructions. Seal,
    /// 16 KiB: 1710 ns with the intrinsics, 1620 here. aes-gen.py
    /// writes both bodies; its header says how, and why this order.
    #[target_feature(enable = "aes,sha3")]
    fn turns(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        c: &mut u32,
        eights: &mut [[[u8; 16]; 8]],
        seal: bool,
        yp: V,
    ) -> V {
        let n = eights.len().saturating_sub(usize::from(seal));
        if n == 0 {
            return yp;
        }
        let at = eights.as_mut_ptr().cast::<u8>();
        let p = if seal { at.wrapping_add(128) } else { at };
        let mut y = yp;
        let mut ctr = *c;
        if rk.first == super::AES128_FIRST {
            // rr: escape(unsafe): p writes n turns of 128 bytes, all in
            // eights, and g reads n turns from at, which for seal is a
            // turn behind p; rk's 11 keys and tbl are read whole; each
            // vector register the loop writes is named below.
            unsafe {
                core::arch::asm!(
                    "ld1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{rk}], #64",
                    "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{rk}], #64",
                    "ld1 {{v8.16b, v9.16b, v10.16b}}, [{rk}]",
                    "mov {t0}, #0x87",
                    "dup v31.2d, {t0}",
                    "2:",
                    "add {t0:w}, {c:w}, #0",
                    "rev {t0:w}, {t0:w}",
                    "mov v11.16b, v30.16b",
                    "mov v11.s[3], {t0:w}",
                    "aese v11.16b, v0.16b",
                    "aesmc v11.16b, v11.16b",
                    "add {t1:w}, {c:w}, #1",
                    "rev {t1:w}, {t1:w}",
                    "mov v12.16b, v30.16b",
                    "mov v12.s[3], {t1:w}",
                    "aese v12.16b, v0.16b",
                    "aesmc v12.16b, v12.16b",
                    "add {t0:w}, {c:w}, #2",
                    "rev {t0:w}, {t0:w}",
                    "mov v13.16b, v30.16b",
                    "mov v13.s[3], {t0:w}",
                    "aese v13.16b, v0.16b",
                    "aesmc v13.16b, v13.16b",
                    "add {t1:w}, {c:w}, #3",
                    "rev {t1:w}, {t1:w}",
                    "mov v14.16b, v30.16b",
                    "mov v14.s[3], {t1:w}",
                    "aese v14.16b, v0.16b",
                    "aesmc v14.16b, v14.16b",
                    "add {t0:w}, {c:w}, #4",
                    "rev {t0:w}, {t0:w}",
                    "mov v15.16b, v30.16b",
                    "mov v15.s[3], {t0:w}",
                    "aese v15.16b, v0.16b",
                    "aesmc v15.16b, v15.16b",
                    "add {t1:w}, {c:w}, #5",
                    "rev {t1:w}, {t1:w}",
                    "mov v16.16b, v30.16b",
                    "mov v16.s[3], {t1:w}",
                    "aese v16.16b, v0.16b",
                    "aesmc v16.16b, v16.16b",
                    "add {t0:w}, {c:w}, #6",
                    "rev {t0:w}, {t0:w}",
                    "mov v17.16b, v30.16b",
                    "mov v17.s[3], {t0:w}",
                    "aese v17.16b, v0.16b",
                    "aesmc v17.16b, v17.16b",
                    "add {t1:w}, {c:w}, #7",
                    "rev {t1:w}, {t1:w}",
                    "mov v18.16b, v30.16b",
                    "mov v18.s[3], {t1:w}",
                    "aese v18.16b, v0.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v1.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v1.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v1.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v1.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v1.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v1.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v1.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v1.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v2.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v2.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v2.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v2.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v2.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v2.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v2.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v2.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v3.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v3.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v3.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v3.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v3.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v3.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v3.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v3.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v4.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v4.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v4.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v4.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v4.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v4.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v4.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v4.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v5.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v5.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v5.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v5.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v5.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v5.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v5.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v5.16b",
                    "aesmc v18.16b, v18.16b",
                    "ldr q19, [{g}, #0]",
                    "ldr q21, [{tbl}, #112]",
                    "ldr q22, [{tbl}, #240]",
                    "rbit v19.16b, v19.16b",
                    "eor v19.16b, v19.16b, v29.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v27.1q, v19.2d, v21.2d",
                    "pmull v28.1q, v20.1d, v22.1d",
                    "ldr q19, [{g}, #16]",
                    "ldr q21, [{tbl}, #96]",
                    "ldr q22, [{tbl}, #224]",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v22.1q, v20.1d, v22.1d",
                    "pmull v20.1q, v19.1d, v21.1d",
                    "pmull2 v21.1q, v19.2d, v21.2d",
                    "eor v23.16b, v26.16b, v20.16b",
                    "eor v25.16b, v27.16b, v21.16b",
                    "eor v24.16b, v28.16b, v22.16b",
                    "ldr q19, [{g}, #32]",
                    "ldr q21, [{tbl}, #80]",
                    "ldr q22, [{tbl}, #208]",
                    "aese v11.16b, v6.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v6.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v6.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v6.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v6.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v6.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v6.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v6.16b",
                    "aesmc v18.16b, v18.16b",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v27.1q, v19.2d, v21.2d",
                    "pmull v28.1q, v20.1d, v22.1d",
                    "ldr q19, [{g}, #48]",
                    "ldr q21, [{tbl}, #64]",
                    "ldr q22, [{tbl}, #192]",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v22.1q, v20.1d, v22.1d",
                    "pmull v20.1q, v19.1d, v21.1d",
                    "pmull2 v21.1q, v19.2d, v21.2d",
                    "eor3 v23.16b, v23.16b, v26.16b, v20.16b",
                    "eor3 v25.16b, v25.16b, v27.16b, v21.16b",
                    "eor3 v24.16b, v24.16b, v28.16b, v22.16b",
                    "ldr q19, [{g}, #64]",
                    "ldr q21, [{tbl}, #48]",
                    "ldr q22, [{tbl}, #176]",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "aese v11.16b, v7.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v7.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v7.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v7.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v7.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v7.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v7.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v7.16b",
                    "aesmc v18.16b, v18.16b",
                    "pmull2 v27.1q, v19.2d, v21.2d",
                    "pmull v28.1q, v20.1d, v22.1d",
                    "ldr q19, [{g}, #80]",
                    "ldr q21, [{tbl}, #32]",
                    "ldr q22, [{tbl}, #160]",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v22.1q, v20.1d, v22.1d",
                    "pmull v20.1q, v19.1d, v21.1d",
                    "pmull2 v21.1q, v19.2d, v21.2d",
                    "eor3 v23.16b, v23.16b, v26.16b, v20.16b",
                    "eor3 v25.16b, v25.16b, v27.16b, v21.16b",
                    "eor3 v24.16b, v24.16b, v28.16b, v22.16b",
                    "ldr q19, [{g}, #96]",
                    "ldr q21, [{tbl}, #16]",
                    "ldr q22, [{tbl}, #144]",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v27.1q, v19.2d, v21.2d",
                    "pmull v28.1q, v20.1d, v22.1d",
                    "ldr q19, [{g}, #112]",
                    "ldr q21, [{tbl}, #0]",
                    "aese v11.16b, v8.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v8.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v8.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v8.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v8.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v8.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v8.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v8.16b",
                    "aesmc v18.16b, v18.16b",
                    "ldr q22, [{tbl}, #128]",
                    "rbit v19.16b, v19.16b",
                    "ext v20.16b, v19.16b, v19.16b, #8",
                    "eor v20.16b, v20.16b, v19.16b",
                    "pmull v22.1q, v20.1d, v22.1d",
                    "pmull v20.1q, v19.1d, v21.1d",
                    "pmull2 v21.1q, v19.2d, v21.2d",
                    "eor3 v23.16b, v23.16b, v26.16b, v20.16b",
                    "eor3 v25.16b, v25.16b, v27.16b, v21.16b",
                    "eor3 v24.16b, v24.16b, v28.16b, v22.16b",
                    "eor3 v24.16b, v24.16b, v23.16b, v25.16b",
                    "movi v19.2d, #0",
                    "ext v20.16b, v19.16b, v24.16b, #8",
                    "ext v21.16b, v24.16b, v19.16b, #8",
                    "eor v23.16b, v23.16b, v20.16b",
                    "eor v25.16b, v25.16b, v21.16b",
                    "pmull v20.1q, v25.1d, v31.1d",
                    "pmull2 v21.1q, v25.2d, v31.2d",
                    "pmull2 v22.1q, v21.2d, v31.2d",
                    "ext v26.16b, v19.16b, v21.16b, #8",
                    "eor3 v23.16b, v23.16b, v20.16b, v26.16b",
                    "eor v29.16b, v23.16b, v22.16b",
                    "ldp q19, q20, [{p}]",
                    "ldp q21, q22, [{p}, #32]",
                    "ldp q23, q24, [{p}, #64]",
                    "ldp q25, q26, [{p}, #96]",
                    "aese v11.16b, v9.16b",
                    "eor3 v11.16b, v11.16b, v10.16b, v19.16b",
                    "aese v12.16b, v9.16b",
                    "eor3 v12.16b, v12.16b, v10.16b, v20.16b",
                    "aese v13.16b, v9.16b",
                    "eor3 v13.16b, v13.16b, v10.16b, v21.16b",
                    "aese v14.16b, v9.16b",
                    "eor3 v14.16b, v14.16b, v10.16b, v22.16b",
                    "aese v15.16b, v9.16b",
                    "eor3 v15.16b, v15.16b, v10.16b, v23.16b",
                    "aese v16.16b, v9.16b",
                    "eor3 v16.16b, v16.16b, v10.16b, v24.16b",
                    "aese v17.16b, v9.16b",
                    "eor3 v17.16b, v17.16b, v10.16b, v25.16b",
                    "aese v18.16b, v9.16b",
                    "eor3 v18.16b, v18.16b, v10.16b, v26.16b",
                    "stp q11, q12, [{p}]",
                    "stp q13, q14, [{p}, #32]",
                    "stp q15, q16, [{p}, #64]",
                    "stp q17, q18, [{p}, #96]",
                    "add {p}, {p}, #128",
                    "add {g}, {g}, #128",
                    "add {c:w}, {c:w}, #8",
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    rk = inout(reg) rk.keys.as_ptr().wrapping_add(super::AES128_FIRST) => _,
                    tbl = in(reg) tbl.as_ptr(),
                    p = inout(reg) p => _,
                    g = inout(reg) at => _,
                    n = inout(reg) n => _,
                    c = inout(reg) ctr,
                    t0 = out(reg) _,
                    t1 = out(reg) _,
                    inout("v29") y,
                    in("v30") load(block),
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v31") _,
                    options(nostack),
                );
            }
        } else {
            let mut ctrs = Counters([[0; 16]; 8]);
            let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, ..] = *block;
            // rr: escape(unsafe): as above, with AES-256's 15 keys; ctrs
            // takes eight counter blocks a turn.
            unsafe {
                core::arch::asm!(
                    "ldr q0, [{rk}], #80",
                    "ld1 {{v1.16b, v2.16b, v3.16b, v4.16b}}, [{rk}], #64",
                    "ld1 {{v5.16b, v6.16b, v7.16b, v8.16b}}, [{rk}], #64",
                    "ld1 {{v9.16b, v10.16b}}, [{rk}]",
                    "mov {t0}, #0x86",
                    "dup v31.2d, {t0}",
                    "2:",
                    "ldp q19, q20, [{rk}, #-192]",
                    "ldp q21, q22, [{rk}, #-160]",
                    "add {t0:w}, {c:w}, #0",
                    "rev {t0:w}, {t0:w}",
                    "orr {t0}, {bh}, {t0}, lsl #32",
                    "stp {bl}, {t0}, [{ctrs}, #0]",
                    "add {t1:w}, {c:w}, #1",
                    "rev {t1:w}, {t1:w}",
                    "orr {t1}, {bh}, {t1}, lsl #32",
                    "stp {bl}, {t1}, [{ctrs}, #16]",
                    "add {t0:w}, {c:w}, #2",
                    "rev {t0:w}, {t0:w}",
                    "orr {t0}, {bh}, {t0}, lsl #32",
                    "stp {bl}, {t0}, [{ctrs}, #32]",
                    "add {t1:w}, {c:w}, #3",
                    "rev {t1:w}, {t1:w}",
                    "orr {t1}, {bh}, {t1}, lsl #32",
                    "stp {bl}, {t1}, [{ctrs}, #48]",
                    "add {t0:w}, {c:w}, #4",
                    "rev {t0:w}, {t0:w}",
                    "orr {t0}, {bh}, {t0}, lsl #32",
                    "stp {bl}, {t0}, [{ctrs}, #64]",
                    "add {t1:w}, {c:w}, #5",
                    "rev {t1:w}, {t1:w}",
                    "orr {t1}, {bh}, {t1}, lsl #32",
                    "stp {bl}, {t1}, [{ctrs}, #80]",
                    "add {t0:w}, {c:w}, #6",
                    "rev {t0:w}, {t0:w}",
                    "orr {t0}, {bh}, {t0}, lsl #32",
                    "stp {bl}, {t0}, [{ctrs}, #96]",
                    "add {t1:w}, {c:w}, #7",
                    "rev {t1:w}, {t1:w}",
                    "orr {t1}, {bh}, {t1}, lsl #32",
                    "stp {bl}, {t1}, [{ctrs}, #112]",
                    "ldr q11, [{ctrs}, #0]",
                    "aese v11.16b, v0.16b",
                    "aesmc v11.16b, v11.16b",
                    "ldr q12, [{ctrs}, #16]",
                    "aese v12.16b, v0.16b",
                    "aesmc v12.16b, v12.16b",
                    "ldr q13, [{ctrs}, #32]",
                    "aese v13.16b, v0.16b",
                    "aesmc v13.16b, v13.16b",
                    "ldr q14, [{ctrs}, #48]",
                    "aese v14.16b, v0.16b",
                    "aesmc v14.16b, v14.16b",
                    "ldr q15, [{ctrs}, #64]",
                    "aese v15.16b, v0.16b",
                    "aesmc v15.16b, v15.16b",
                    "ldr q16, [{ctrs}, #80]",
                    "aese v16.16b, v0.16b",
                    "aesmc v16.16b, v16.16b",
                    "ldr q17, [{ctrs}, #96]",
                    "aese v17.16b, v0.16b",
                    "aesmc v17.16b, v17.16b",
                    "ldr q18, [{ctrs}, #112]",
                    "aese v18.16b, v0.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v19.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v19.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v19.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v19.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v19.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v19.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v19.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v19.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v20.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v20.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v20.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v20.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v20.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v20.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v20.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v20.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v21.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v21.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v21.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v21.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v21.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v21.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v21.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v21.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v22.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v22.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v22.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v22.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v22.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v22.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v22.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v22.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v1.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v1.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v1.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v1.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v1.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v1.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v1.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v1.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v2.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v2.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v2.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v2.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v2.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v2.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v2.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v2.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v3.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v3.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v3.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v3.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v3.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v3.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v3.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v3.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v4.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v4.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v4.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v4.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v4.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v4.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v4.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v4.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v5.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v5.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v5.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v5.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v5.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v5.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v5.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v5.16b",
                    "aesmc v18.16b, v18.16b",
                    "aese v11.16b, v6.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v6.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v6.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v6.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v6.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v6.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v6.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v6.16b",
                    "aesmc v18.16b, v18.16b",
                    "ldp q19, q20, [{g}, #0]",
                    "ldp q22, q21, [{tbl}, #96]",
                    "ldp q24, q23, [{tbl}, #224]",
                    "rbit v19.16b, v19.16b",
                    "rbit v20.16b, v20.16b",
                    "eor v19.16b, v19.16b, v29.16b",
                    "trn1 v25.2d, v19.2d, v20.2d",
                    "trn2 v26.2d, v19.2d, v20.2d",
                    "eor v25.16b, v25.16b, v26.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v19.1q, v19.2d, v21.2d",
                    "pmull v21.1q, v20.1d, v22.1d",
                    "pmull2 v20.1q, v20.2d, v22.2d",
                    "pmull v22.1q, v25.1d, v23.1d",
                    "pmull2 v25.1q, v25.2d, v24.2d",
                    "eor v27.16b, v26.16b, v21.16b",
                    "eor v28.16b, v19.16b, v20.16b",
                    "eor v30.16b, v22.16b, v25.16b",
                    "ldp q19, q20, [{g}, #32]",
                    "ldp q22, q21, [{tbl}, #64]",
                    "ldp q24, q23, [{tbl}, #192]",
                    "rbit v19.16b, v19.16b",
                    "rbit v20.16b, v20.16b",
                    "trn1 v25.2d, v19.2d, v20.2d",
                    "trn2 v26.2d, v19.2d, v20.2d",
                    "eor v25.16b, v25.16b, v26.16b",
                    "aese v11.16b, v7.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v7.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v7.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v7.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v7.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v7.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v7.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v7.16b",
                    "aesmc v18.16b, v18.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v19.1q, v19.2d, v21.2d",
                    "pmull v21.1q, v20.1d, v22.1d",
                    "pmull2 v20.1q, v20.2d, v22.2d",
                    "pmull v22.1q, v25.1d, v23.1d",
                    "pmull2 v25.1q, v25.2d, v24.2d",
                    "eor3 v27.16b, v27.16b, v26.16b, v21.16b",
                    "eor3 v28.16b, v28.16b, v19.16b, v20.16b",
                    "eor3 v30.16b, v30.16b, v22.16b, v25.16b",
                    "ldp q19, q20, [{g}, #64]",
                    "ldp q22, q21, [{tbl}, #32]",
                    "ldp q24, q23, [{tbl}, #160]",
                    "rbit v19.16b, v19.16b",
                    "rbit v20.16b, v20.16b",
                    "trn1 v25.2d, v19.2d, v20.2d",
                    "trn2 v26.2d, v19.2d, v20.2d",
                    "eor v25.16b, v25.16b, v26.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v19.1q, v19.2d, v21.2d",
                    "pmull v21.1q, v20.1d, v22.1d",
                    "pmull2 v20.1q, v20.2d, v22.2d",
                    "pmull v22.1q, v25.1d, v23.1d",
                    "pmull2 v25.1q, v25.2d, v24.2d",
                    "eor3 v27.16b, v27.16b, v26.16b, v21.16b",
                    "eor3 v28.16b, v28.16b, v19.16b, v20.16b",
                    "eor3 v30.16b, v30.16b, v22.16b, v25.16b",
                    "aese v11.16b, v8.16b",
                    "aesmc v11.16b, v11.16b",
                    "aese v12.16b, v8.16b",
                    "aesmc v12.16b, v12.16b",
                    "aese v13.16b, v8.16b",
                    "aesmc v13.16b, v13.16b",
                    "aese v14.16b, v8.16b",
                    "aesmc v14.16b, v14.16b",
                    "aese v15.16b, v8.16b",
                    "aesmc v15.16b, v15.16b",
                    "aese v16.16b, v8.16b",
                    "aesmc v16.16b, v16.16b",
                    "aese v17.16b, v8.16b",
                    "aesmc v17.16b, v17.16b",
                    "aese v18.16b, v8.16b",
                    "aesmc v18.16b, v18.16b",
                    "ldp q19, q20, [{g}, #96]",
                    "ldp q22, q21, [{tbl}, #0]",
                    "ldp q24, q23, [{tbl}, #128]",
                    "rbit v19.16b, v19.16b",
                    "rbit v20.16b, v20.16b",
                    "trn1 v25.2d, v19.2d, v20.2d",
                    "trn2 v26.2d, v19.2d, v20.2d",
                    "eor v25.16b, v25.16b, v26.16b",
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v19.1q, v19.2d, v21.2d",
                    "pmull v21.1q, v20.1d, v22.1d",
                    "pmull2 v20.1q, v20.2d, v22.2d",
                    "pmull v22.1q, v25.1d, v23.1d",
                    "pmull2 v25.1q, v25.2d, v24.2d",
                    "eor3 v27.16b, v27.16b, v26.16b, v21.16b",
                    "eor3 v28.16b, v28.16b, v19.16b, v20.16b",
                    "eor3 v30.16b, v30.16b, v22.16b, v25.16b",
                    "eor3 v30.16b, v30.16b, v27.16b, v28.16b",
                    "ext v19.16b, v28.16b, v28.16b, #8",
                    "pmull2 v20.1q, v28.2d, v31.2d",
                    "eor3 v30.16b, v30.16b, v19.16b, v20.16b",
                    "ext v19.16b, v30.16b, v30.16b, #8",
                    "pmull2 v20.1q, v30.2d, v31.2d",
                    "eor3 v29.16b, v27.16b, v19.16b, v20.16b",
                    "ldp q19, q20, [{p}]",
                    "ldp q21, q22, [{p}, #32]",
                    "ldp q23, q24, [{p}, #64]",
                    "ldp q25, q26, [{p}, #96]",
                    "aese v11.16b, v9.16b",
                    "eor3 v11.16b, v11.16b, v10.16b, v19.16b",
                    "aese v12.16b, v9.16b",
                    "eor3 v12.16b, v12.16b, v10.16b, v20.16b",
                    "aese v13.16b, v9.16b",
                    "eor3 v13.16b, v13.16b, v10.16b, v21.16b",
                    "aese v14.16b, v9.16b",
                    "eor3 v14.16b, v14.16b, v10.16b, v22.16b",
                    "aese v15.16b, v9.16b",
                    "eor3 v15.16b, v15.16b, v10.16b, v23.16b",
                    "aese v16.16b, v9.16b",
                    "eor3 v16.16b, v16.16b, v10.16b, v24.16b",
                    "aese v17.16b, v9.16b",
                    "eor3 v17.16b, v17.16b, v10.16b, v25.16b",
                    "aese v18.16b, v9.16b",
                    "eor3 v18.16b, v18.16b, v10.16b, v26.16b",
                    "stp q11, q12, [{p}]",
                    "stp q13, q14, [{p}, #32]",
                    "stp q15, q16, [{p}, #64]",
                    "stp q17, q18, [{p}, #96]",
                    "add {p}, {p}, #128",
                    "add {g}, {g}, #128",
                    "add {c:w}, {c:w}, #8",
                    "subs {n}, {n}, #1",
                    "b.ne 2b",
                    rk = inout(reg) rk.keys.as_ptr() => _,
                    tbl = in(reg) tbl.as_ptr(),
                    p = inout(reg) p => _,
                    g = inout(reg) at => _,
                    n = inout(reg) n => _,
                    c = inout(reg) ctr,
                    t0 = out(reg) _,
                    t1 = out(reg) _,
                    bl = in(reg) u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
                    bh = in(reg) u64::from(u32::from_le_bytes([b8, b9, b10, b11])),
                    ctrs = in(reg) ctrs.0.as_mut_ptr(),
                    inout("v29") y,
                    out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                    out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                    out("v8") _, out("v9") _, out("v10") _, out("v11") _,
                    out("v12") _, out("v13") _, out("v14") _, out("v15") _,
                    out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                    out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                    out("v24") _, out("v25") _, out("v26") _, out("v27") _,
                    out("v28") _, out("v30") _, out("v31") _,
                    options(nostack),
                );
            }
        }
        *c = ctr;
        y
    }
}

#[cfg(target_arch = "x86_64")]
mod arch {
    //! GHASH here works on blocks with their bytes reversed and their
    //! bits as they are, as BoringSSL's aes-gcm-avx2-x86_64 does: x86-64
    //! reverses bytes in one instruction and bits in six. A carry-less
    //! product of two such values is the GHASH product times x^-1, so the
    //! table holds H times x (times_x), and each product with it is
    //! GHASH's. Read naturally, the bits are a polynomial modulo x^128 +
    //! x^127 + x^126 + x^121 + 1, whose low 128 bits fold reduces in two
    //! steps of 64. The counter blocks are kept byte-reversed too, the
    //! counter a little-endian number in their first lane.
    //!
    //! Where the CPU has VAES and VPCLMULQDQ on AVX2 (Zen 3, Ice Lake and
    //! later), seal and open take each turn's eight blocks as four 256-bit
    //! vectors, two blocks to each instruction.

    use super::{RoundKeys, Table};
    use core::arch::x86_64::{
        __m128i, __m256i, _mm_add_epi32, _mm_add_epi64, _mm_aesenc_si128, _mm_aesenclast_si128,
        _mm_and_si128, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_set_epi64x,
        _mm_setr_epi8, _mm_setzero_si128, _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_srai_epi32,
        _mm_storeu_si128, _mm_xor_si128, _mm256_add_epi32, _mm256_aesenc_epi128,
        _mm256_aesenclast_epi128, _mm256_broadcastsi128_si256, _mm256_castsi256_si128,
        _mm256_clmulepi64_epi128, _mm256_extracti128_si256, _mm256_loadu_si256, _mm256_set_epi32,
        _mm256_set_m128i, _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_shuffle_epi32,
        _mm256_storeu_si256, _mm256_xor_si256, _mm256_zextsi128_si256,
    };

    type V = __m128i;
    type W = __m256i;

    #[inline(always)]
    fn load(b: &[u8; 16]) -> V {
        // rr: escape(unsafe): b is 16 readable bytes; loadu takes any alignment.
        unsafe { _mm_loadu_si128(b.as_ptr().cast()) }
    }

    #[inline(always)]
    fn store(b: &mut [u8; 16], v: V) {
        // rr: escape(unsafe): b is 16 writable bytes; storeu takes any alignment.
        unsafe { _mm_storeu_si128(b.as_mut_ptr().cast(), v) }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    /// The round keys as vectors, where rk keeps them: loaded into
    /// stack slots instead, x86-64 copies all of them with memcpy.
    fn round_keys(rk: &RoundKeys) -> &[V; 15] {
        // rr: escape(unsafe): RoundKeys starts with 15 blocks of 16 bytes
        // (repr(C)) and is aligned to 16, as [V; 15] is, and every bit
        // pattern is a vector.
        unsafe { &*core::ptr::from_ref(rk).cast::<[V; 15]>() }
    }

    const _: () = assert!(size_of::<RoundKeys>() >= size_of::<[V; 15]>());
    const _: () = assert!(align_of::<RoundKeys>() == align_of::<[V; 15]>());

    /// The key added before the rounds: k[first], which RoundKeys keeps
    /// in range.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn first_key(k: &[V; 15], first: usize) -> V {
        k.get(first).copied().unwrap_or(k[0])
    }

    /// The 16 bytes of v in the other order.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn reflect(v: V) -> V {
        let order = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        _mm_shuffle_epi8(v, order)
    }

    /// Counter blocks from ctr on, one for each of s: base is the block,
    /// which ends in four zero bytes, reflected, so the counter adds to
    /// its first lane and wraps there, as GCM's 32-bit counter does.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn counters(base: V, ctr: u32, s: &mut [V]) {
        let one = _mm_cvtsi32_si128(1);
        let mut next = _mm_add_epi32(base, _mm_cvtsi32_si128(ctr.cast_signed()));
        for x in s.iter_mut() {
            *x = reflect(next);
            next = _mm_add_epi32(next, one);
        }
    }

    /// The first key, added before the rounds.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn first(s: &mut [V], k: V) {
        for x in s.iter_mut() {
            *x = _mm_xor_si128(*x, k);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn round(s: &mut [V], k: V) {
        for x in s.iter_mut() {
            *x = _mm_aesenc_si128(*x, k);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn last(s: &mut [V], k: &[V; 15]) {
        for x in s.iter_mut() {
            *x = _mm_aesenclast_si128(*x, k[14]);
        }
    }

    /// The rounds of the key from k[first] on.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn aes(k: &[V; 15], first_at: usize, s: &mut [V]) {
        first(s, first_key(k, first_at));
        for rk in k.iter().take(14).skip(first_at + 1) {
            round(s, *rk);
        }
        last(s, k);
    }

    /// Each block XORed with its key stream, CTR's last step; s keeps
    /// what was stored, for seal to hash.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn xor_into(blocks: &mut [[u8; 16]], s: &mut [V]) {
        for (b, ks) in blocks.iter_mut().zip(s) {
            *ks = _mm_xor_si128(load(b), *ks);
            store(b, *ks);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn ctr(rk: &RoundKeys, block: &[u8; 16], ctr: u32, data: &mut [u8]) {
        let k = round_keys(rk);
        let base = reflect(load(block));
        let (blocks, tail) = data.as_chunks_mut::<16>();
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        let mut c = ctr;
        let mut s = [_mm_setzero_si128(); 4];
        for four in fours {
            counters(base, c, &mut s);
            c = c.wrapping_add(4);
            aes(k, rk.first, &mut s);
            xor_into(four, &mut s);
        }
        if rest.is_empty() && tail.is_empty() {
            return;
        }
        // Under four blocks and a part: one more batch of key stream.
        counters(base, c, &mut s);
        aes(k, rk.first, &mut s);
        xor_into(rest, &mut s);
        if let Some(ks) = s.get(rest.len()) {
            let mut t = [0; 16];
            store(&mut t, *ks);
            for (d, x) in tail.iter_mut().zip(t) {
                *d ^= x;
            }
        }
    }

    /// x with its halves XORed, in both lanes: Karatsuba's middle factor.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn halves(x: V) -> V {
        _mm_xor_si128(x, _mm_shuffle_epi32::<0x4e>(x))
    }

    /// acc (low, middle, high) += the Karatsuba products of x * h; hk is
    /// halves(h).
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn kmul(acc: &mut [V; 3], x: V, h: V, hk: V) {
        let [lo, mid, hi] = *acc;
        *acc = [
            _mm_xor_si128(lo, _mm_clmulepi64_si128::<0x00>(x, h)),
            _mm_xor_si128(mid, _mm_clmulepi64_si128::<0x00>(halves(x), hk)),
            _mm_xor_si128(hi, _mm_clmulepi64_si128::<0x11>(x, h)),
        ];
    }

    /// x^63 + x^62 + x^57 in the high half, the polynomial's terms below
    /// x^128 that a 64-bit fold multiplies by; 1 in the low half.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn polynomial() -> V {
        _mm_set_epi64x(0xc200_0000_0000_0000_u64.cast_signed(), 1)
    }

    /// The 256-bit sum acc holds, reduced. Karatsuba's middle product
    /// comes first; then the low 64 bits are cancelled twice: x^64 A + B
    /// is x^64 (A + B with its halves swapped + B's low half times x^63 +
    /// x^62 + x^57) modulo the polynomial, folding the low product into
    /// the middle and the middle into the high, which is the product.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn fold(acc: [V; 3]) -> V {
        let [lo, mid, hi] = acc;
        let mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
        let p = polynomial();
        let mid = _mm_xor_si128(
            _mm_xor_si128(mid, _mm_shuffle_epi32::<0x4e>(lo)),
            _mm_clmulepi64_si128::<0x01>(p, lo),
        );
        _mm_xor_si128(
            _mm_xor_si128(hi, _mm_shuffle_epi32::<0x4e>(mid)),
            _mm_clmulepi64_si128::<0x01>(p, mid),
        )
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn gmul(a: V, b: V) -> V {
        let mut acc = [_mm_setzero_si128(); 3];
        kmul(&mut acc, a, b, halves(b));
        fold(acc)
    }

    /// v times x modulo the polynomial: v shifted up a bit, each 64-bit
    /// half doubled and the low half's carry put into the high one, and
    /// the polynomial added if a bit came off the top.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn times_x(v: V) -> V {
        // Lanes 0 and 3 copy bit 127, lane 2 bit 63, each to all its bits.
        let carries = _mm_srai_epi32::<31>(_mm_shuffle_epi32::<0xd3>(v));
        let added = _mm_set_epi64x(0xc200_0000_0000_0001_u64.cast_signed(), 1);
        _mm_xor_si128(_mm_add_epi64(v, v), _mm_and_si128(carries, added))
    }

    /// H to H^8 and their halves, from the table.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn powers(tbl: &Table) -> ([V; 8], [V; 8]) {
        let mut h = [_mm_setzero_si128(); 8];
        let mut hk = h;
        let (hb, kb) = tbl.split_at(8);
        for ((v, w), (b, c)) in h.iter_mut().zip(hk.iter_mut()).zip(hb.iter().zip(kb)) {
            *v = load(b);
            *w = load(c);
        }
        (h, hk)
    }

    /// y, already XORed into x[0], times H^8 .. H for x[0] .. x[7].
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn ghash8(x: &[V; 8], h: &[V; 8], hk: &[V; 8]) -> V {
        let mut acc = [_mm_setzero_si128(); 3];
        for ((xb, hp), kp) in x.iter().zip(h.iter().rev()).zip(hk.iter().rev()) {
            kmul(&mut acc, *xb, *hp, *kp);
        }
        fold(acc)
    }

    /// Eight AES chains, from k[first] on, with ghash8 of x woven between
    /// their first eight rounds.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn aes8_ghash8(
        k: &[V; 15],
        first_at: usize,
        s: &mut [V; 8],
        x: &[V; 8],
        h: &[V; 8],
        hk: &[V; 8],
    ) -> V {
        let mut acc = [_mm_setzero_si128(); 3];
        first(s, first_key(k, first_at));
        let turns = x.iter().zip(k.iter().skip(first_at + 1));
        for ((xb, rk), (hp, kp)) in turns.zip(h.iter().rev().zip(hk.iter().rev())) {
            round(s, *rk);
            kmul(&mut acc, *xb, *hp, *kp);
        }
        for rk in k.iter().take(14).skip(first_at + 9) {
            round(s, *rk);
        }
        last(s, k);
        fold(acc)
    }

    /// H times x, and its powers to the eighth, with their halves.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn ghash_key(h: &[u8; 16], tbl: &mut Table) {
        let hx = times_x(reflect(load(h)));
        let mut p = hx;
        let (pw, ks) = tbl.split_at_mut(8);
        for (i, (t, kt)) in pw.iter_mut().zip(ks).enumerate() {
            if i > 0 {
                p = gmul(p, hx);
            }
            store(t, p);
            store(kt, halves(p));
        }
    }

    /// y continued over blocks, all reflected.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn ghash_reflected(h: &[V; 8], hk: &[V; 8], mut yr: V, blocks: &[[u8; 16]]) -> V {
        let (eights, rest) = blocks.as_chunks::<8>();
        let mut x = [_mm_setzero_si128(); 8];
        for eight in eights {
            for (v, b) in x.iter_mut().zip(eight) {
                *v = reflect(load(b));
            }
            x[0] = _mm_xor_si128(x[0], yr);
            yr = ghash8(&x, h, hk);
        }
        for b in rest {
            let mut acc = [_mm_setzero_si128(); 3];
            kmul(&mut acc, _mm_xor_si128(yr, reflect(load(b))), h[0], hk[0]);
            yr = fold(acc);
        }
        yr
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn ghash(tbl: &Table, y: &mut [u8; 16], blocks: &[[u8; 16]]) {
        let (h, hk) = powers(tbl);
        let yr = ghash_reflected(&h, &hk, reflect(load(y)), blocks);
        store(y, reflect(yr));
    }

    /// Eight blocks a turn; each turn's ciphertext is hashed in the next,
    /// beside its AES, and the last after the loop. wide takes the turns
    /// on 256-bit vectors.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn seal(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
        wide: bool,
    ) {
        // The first round key's place a constant in each copy, as the
        // round count is, so the keys stay in registers.
        match (wide, rk.first == super::AES128_FIRST) {
            // rr: escape(unsafe): the caller found VAES, VPCLMULQDQ and AVX2.
            (true, true) => unsafe {
                seal_wide(rk, super::AES128_FIRST, tbl, block, ctr, blocks, y);
            },
            // rr: escape(unsafe): the caller found VAES, VPCLMULQDQ and AVX2.
            (true, false) => unsafe { seal_wide(rk, 0, tbl, block, ctr, blocks, y) },
            (false, true) => {
                seal_from(rk, super::AES128_FIRST, tbl, block, ctr, blocks, y);
            }
            (false, false) => seal_from(rk, 0, tbl, block, ctr, blocks, y),
        }
    }

    /// seal() with the keys from k[first] on.
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn seal_from(
        rk: &RoundKeys,
        first: usize,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let base = reflect(load(block));
        let mut yr = reflect(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [_mm_setzero_si128(); 8];
        let mut prev: Option<[V; 8]> = None;
        for eight in eights {
            counters(base, c, &mut s);
            c = c.wrapping_add(8);
            match prev {
                Some(mut x) => {
                    x[0] = _mm_xor_si128(x[0], yr);
                    yr = aes8_ghash8(k, first, &mut s, &x, &h, &hk);
                }
                None => aes(k, first, &mut s),
            }
            xor_into(eight, &mut s);
            prev = Some(s.map(|v| reflect(v)));
        }
        if let Some(mut x) = prev {
            x[0] = _mm_xor_si128(x[0], yr);
            yr = ghash8(&x, &h, &hk);
        }
        self::ctr(rk, block, c, rest.as_flattened_mut());
        yr = ghash_reflected(&h, &hk, yr, rest);
        store(y, reflect(yr));
    }

    /// Eight blocks a turn: the ciphertext is hashed beside the AES that
    /// makes the key stream to decrypt it. wide takes the turns on
    /// 256-bit vectors.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn open(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
        wide: bool,
    ) {
        // The first round key's place a constant in each copy, as the
        // round count is, so the keys stay in registers.
        match (wide, rk.first == super::AES128_FIRST) {
            // rr: escape(unsafe): the caller found VAES, VPCLMULQDQ and AVX2.
            (true, true) => unsafe {
                open_wide(rk, super::AES128_FIRST, tbl, block, ctr, blocks, y);
            },
            // rr: escape(unsafe): the caller found VAES, VPCLMULQDQ and AVX2.
            (true, false) => unsafe { open_wide(rk, 0, tbl, block, ctr, blocks, y) },
            (false, true) => {
                open_from(rk, super::AES128_FIRST, tbl, block, ctr, blocks, y);
            }
            (false, false) => open_from(rk, 0, tbl, block, ctr, blocks, y),
        }
    }

    /// open() with the keys from k[first] on.
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn open_from(
        rk: &RoundKeys,
        first: usize,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let base = reflect(load(block));
        let mut yr = reflect(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [_mm_setzero_si128(); 8];
        let mut x = s;
        for eight in eights {
            counters(base, c, &mut s);
            c = c.wrapping_add(8);
            for (v, b) in x.iter_mut().zip(eight.iter()) {
                *v = reflect(load(b));
            }
            x[0] = _mm_xor_si128(x[0], yr);
            yr = aes8_ghash8(k, first, &mut s, &x, &h, &hk);
            xor_into(eight, &mut s);
        }
        yr = ghash_reflected(&h, &hk, yr, rest);
        self::ctr(rk, block, c, rest.as_flattened_mut());
        store(y, reflect(yr));
    }

    #[inline(always)]
    fn wload(b: &[[u8; 16]; 2]) -> W {
        // rr: escape(unsafe): b is 32 readable bytes; loadu takes any alignment.
        unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
    }

    #[inline(always)]
    fn wstore(b: &mut [[u8; 16]; 2], v: W) {
        // rr: escape(unsafe): b is 32 writable bytes; storeu takes any alignment.
        unsafe { _mm256_storeu_si256(b.as_mut_ptr().cast(), v) }
    }

    /// Each 128-bit lane of v reflected.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wreflect(v: W) -> W {
        let order = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        _mm256_shuffle_epi8(v, _mm256_broadcastsi128_si256(order))
    }

    /// The counter blocks from ctr on, two to each of s, as counters()
    /// makes them.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wcounters(base: V, ctr: u32, s: &mut [W; 4]) {
        let first = ctr.cast_signed();
        let second = ctr.wrapping_add(1).cast_signed();
        let two = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2);
        let mut next = _mm256_add_epi32(
            _mm256_broadcastsi128_si256(base),
            _mm256_set_epi32(0, 0, 0, second, 0, 0, 0, first),
        );
        for x in s.iter_mut() {
            *x = wreflect(next);
            next = _mm256_add_epi32(next, two);
        }
    }

    /// A round on both lanes, its key in both.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wround(s: &mut [W; 4], k: V) {
        let key = _mm256_broadcastsi128_si256(k);
        for x in s.iter_mut() {
            *x = _mm256_aesenc_epi128(*x, key);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wfirst(s: &mut [W; 4], k: V) {
        let key = _mm256_broadcastsi128_si256(k);
        for x in s.iter_mut() {
            *x = _mm256_xor_si256(*x, key);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wlast(s: &mut [W; 4], k: &[V; 15]) {
        let key = _mm256_broadcastsi128_si256(k[14]);
        for x in s.iter_mut() {
            *x = _mm256_aesenclast_epi128(*x, key);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn waes(k: &[V; 15], first_at: usize, s: &mut [W; 4]) {
        wfirst(s, first_key(k, first_at));
        for key in k.iter().take(14).skip(first_at + 1) {
            wround(s, *key);
        }
        wlast(s, k);
    }

    /// Both lanes of x with their halves XORed.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn whalves(x: W) -> W {
        _mm256_xor_si256(x, _mm256_shuffle_epi32::<0x4e>(x))
    }

    /// kmul on both lanes.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wkmul(acc: &mut [W; 3], x: W, h: W, hk: W) {
        let [lo, mid, hi] = *acc;
        *acc = [
            _mm256_xor_si256(lo, _mm256_clmulepi64_epi128::<0x00>(x, h)),
            _mm256_xor_si256(mid, _mm256_clmulepi64_epi128::<0x00>(whalves(x), hk)),
            _mm256_xor_si256(hi, _mm256_clmulepi64_epi128::<0x11>(x, h)),
        ];
    }

    /// The lanes' sums added, then reduced: the sum is linear, so one
    /// reduction does for both.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wfold(acc: [W; 3]) -> V {
        let lanes =
            |w: W| _mm_xor_si128(_mm256_castsi256_si128(w), _mm256_extracti128_si256::<1>(w));
        fold(acc.map(lanes))
    }

    /// The powers in pairs for four vectors of two blocks: blocks 2j and
    /// 2j + 1 of eight take H^(8 - 2j) and H^(7 - 2j).
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wpowers(h: &[V; 8], hk: &[V; 8], hw: &mut [W; 4], hkw: &mut [W; 4]) {
        for (j, (p, q)) in hw.iter_mut().zip(hkw.iter_mut()).enumerate() {
            // rr: escape(panic): j is below 4, so 7 - 2j and 6 - 2j are in
            // the eight powers.
            *p = _mm256_set_m128i(h[6 - 2 * j], h[7 - 2 * j]);
            // rr: escape(panic): as above.
            *q = _mm256_set_m128i(hk[6 - 2 * j], hk[7 - 2 * j]);
        }
    }

    /// y, already XORed into x[0]'s first lane, times H^8 .. H for the
    /// eight blocks of x.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wghash(x: &[W; 4], hw: &[W; 4], hkw: &[W; 4]) -> V {
        let mut acc = [_mm256_setzero_si256(); 3];
        for ((xb, hp), kp) in x.iter().zip(hw).zip(hkw) {
            wkmul(&mut acc, *xb, *hp, *kp);
        }
        wfold(acc)
    }

    /// Four vectors of AES chains, from k[first] on, with wghash of x
    /// between their first four rounds.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn waes_wghash(
        k: &[V; 15],
        first_at: usize,
        s: &mut [W; 4],
        x: &[W; 4],
        hw: &[W; 4],
        hkw: &[W; 4],
    ) -> V {
        let mut acc = [_mm256_setzero_si256(); 3];
        wfirst(s, first_key(k, first_at));
        for (((xb, hp), kp), key) in x.iter().zip(hw).zip(hkw).zip(k.iter().skip(first_at + 1)) {
            wround(s, *key);
            wkmul(&mut acc, *xb, *hp, *kp);
        }
        for key in k.iter().take(14).skip(first_at + 5) {
            wround(s, *key);
        }
        wlast(s, k);
        wfold(acc)
    }

    /// The blocks of eight XORed with the key stream in s, two at a time;
    /// s keeps what was stored.
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn wxor_into(eight: &mut [[u8; 16]; 8], s: &mut [W; 4]) {
        for (pair, ks) in eight.as_chunks_mut::<2>().0.iter_mut().zip(s) {
            *ks = _mm256_xor_si256(wload(pair), *ks);
            wstore(pair, *ks);
        }
    }

    /// seal() with each turn on 256-bit vectors; the blocks after the
    /// last whole turn take the 128-bit code.
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn seal_wide(
        rk: &RoundKeys,
        first: usize,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let mut hw = [_mm256_setzero_si256(); 4];
        let mut hkw = hw;
        wpowers(&h, &hk, &mut hw, &mut hkw);
        let base = reflect(load(block));
        let mut yr = reflect(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [_mm256_setzero_si256(); 4];
        let mut prev: Option<[W; 4]> = None;
        for eight in eights {
            wcounters(base, c, &mut s);
            c = c.wrapping_add(8);
            match prev {
                Some(mut x) => {
                    x[0] = _mm256_xor_si256(x[0], _mm256_zextsi128_si256(yr));
                    yr = waes_wghash(k, first, &mut s, &x, &hw, &hkw);
                }
                None => waes(k, first, &mut s),
            }
            wxor_into(eight, &mut s);
            prev = Some(s.map(|v| wreflect(v)));
        }
        if let Some(mut x) = prev {
            x[0] = _mm256_xor_si256(x[0], _mm256_zextsi128_si256(yr));
            yr = wghash(&x, &hw, &hkw);
        }
        self::ctr(rk, block, c, rest.as_flattened_mut());
        yr = ghash_reflected(&h, &hk, yr, rest);
        store(y, reflect(yr));
    }

    /// open() with each turn on 256-bit vectors.
    #[inline]
    #[target_feature(enable = "aes,pclmulqdq,ssse3,avx,avx2,vaes,vpclmulqdq")]
    fn open_wide(
        rk: &RoundKeys,
        first: usize,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let mut hw = [_mm256_setzero_si256(); 4];
        let mut hkw = hw;
        wpowers(&h, &hk, &mut hw, &mut hkw);
        let base = reflect(load(block));
        let mut yr = reflect(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [_mm256_setzero_si256(); 4];
        let mut x = s;
        for eight in eights {
            wcounters(base, c, &mut s);
            c = c.wrapping_add(8);
            for (v, pair) in x.iter_mut().zip(eight.as_chunks::<2>().0) {
                *v = wreflect(wload(pair));
            }
            x[0] = _mm256_xor_si256(x[0], _mm256_zextsi128_si256(yr));
            yr = waes_wghash(k, first, &mut s, &x, &hw, &hkw);
            wxor_into(eight, &mut s);
        }
        yr = ghash_reflected(&h, &hk, yr, rest);
        self::ctr(rk, block, c, rest.as_flattened_mut());
        store(y, reflect(yr));
    }
}

/// No instructions to reach: available() is false, so nothing below runs.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod arch {
    use super::{RoundKeys, Table};

    // rr: escape(unsafe): a stub, the same signature as the real ones.
    pub unsafe fn ctr(_rk: &RoundKeys, _block: &[u8; 16], _ctr: u32, _data: &mut [u8]) {}

    // rr: escape(unsafe): a stub, the same signature as the real ones.
    pub unsafe fn ghash_key(_h: &[u8; 16], _tbl: &mut Table) {}

    // rr: escape(unsafe): a stub, the same signature as the real ones.
    pub unsafe fn ghash(_tbl: &Table, _y: &mut [u8; 16], _blocks: &[[u8; 16]]) {}

    // rr: escape(unsafe): a stub, the same signature as the real ones.
    pub unsafe fn seal(
        _rk: &RoundKeys,
        _tbl: &Table,
        _block: &[u8; 16],
        _ctr: u32,
        _blocks: &mut [[u8; 16]],
        _y: &mut [u8; 16],
        _eor3: bool,
    ) {
    }

    // rr: escape(unsafe): a stub, the same signature as the real ones.
    pub unsafe fn open(
        _rk: &RoundKeys,
        _tbl: &Table,
        _block: &[u8; 16],
        _ctr: u32,
        _blocks: &mut [[u8; 16]],
        _y: &mut [u8; 16],
        _eor3: bool,
    ) {
    }
}

/// What only aarch64 has two of: the asm loop and the intrinsics one.
#[cfg(test)]
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod tests {
    use super::{AES128_FIRST, FASTER, RoundKeys, Table, available, cpu};
    use test::Bencher;

    /// A key schedule and GHASH table of no key in particular, AES-128's
    /// (keys from AES128_FIRST) or AES-256's (from 0).
    fn keys(first: usize) -> (RoundKeys, Table) {
        let rk = RoundKeys {
            keys: core::array::from_fn(|r| {
                core::array::from_fn(|j| u8::try_from(((16 * r + j) * 13 + 5) % 256).unwrap())
            }),
            first,
        };
        let mut tbl: Table = [[0; 16]; 16];
        // rr: escape(unsafe): the callers looked for the instructions.
        unsafe { super::arch::ghash_key(&[0x66; 16], &mut tbl) };
        (rk, tbl)
    }

    /// One 16 KiB record through the one-pass seal loop, the faster one
    /// (aarch64's asm on EOR3, x86_64's on VAES) or the one every CPU
    /// with the instructions takes: where the CPU has both, both run, so
    /// it shows which is faster on it.
    fn bench_loop(b: &mut Bencher, first: usize, faster: bool) {
        if !available() || (faster && !cpu::has(FASTER)) {
            return;
        }
        let (rk, tbl) = keys(first);
        let block = [0x21, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0];
        let mut data = alloc::vec::Vec::new();
        data.resize(1024, [0x17; 16]);
        let mut y = [0; 16];
        // rr: escape(unsafe): the CPU has what each loop runs on.
        b.iter(|| unsafe { super::arch::seal(&rk, &tbl, &block, 2, &mut data, &mut y, faster) });
    }

    #[bench]
    fn seal_loop_16k_faster(b: &mut Bencher) {
        bench_loop(b, AES128_FIRST, true);
    }

    #[bench]
    fn seal_loop_16k_base(b: &mut Bencher) {
        bench_loop(b, AES128_FIRST, false);
    }

    #[bench]
    fn seal_loop_16k_faster_256(b: &mut Bencher) {
        bench_loop(b, 0, true);
    }

    #[bench]
    fn seal_loop_16k_base_256(b: &mut Bencher) {
        bench_loop(b, 0, false);
    }

    /// Where the CPU has the faster loop, both one-pass loops run here:
    /// they agree on every block count to past three turns, from a
    /// counter that wraps, and open undoes seal.
    #[test]
    fn both_loops_agree() {
        loops_agree(AES128_FIRST);
    }

    #[test]
    fn both_loops_agree_256() {
        loops_agree(0);
    }

    fn loops_agree(first: usize) {
        if !cpu::has(FASTER) {
            return;
        }
        let (rk, tbl) = keys(first);
        let mut block = [0x21; 16];
        block[12..].fill(0);
        for n in 0..30 {
            let start = u32::MAX - 20;
            let mut data = [[0u8; 16]; 30];
            for (i, b) in data.iter_mut().flatten().enumerate() {
                *b = u8::try_from(i * 7 % 256).unwrap();
            }
            let plain = data;
            let (mut a, mut b) = (data, data);
            let (mut ya, mut yb, mut yo) = ([3; 16], [3; 16], [3; 16]);
            // rr: escape(unsafe): the CPU has the faster loop's instructions.
            unsafe { super::arch::seal(&rk, &tbl, &block, start, &mut a[..n], &mut ya, true) };
            // rr: escape(unsafe): the CPU has the base loop's instructions.
            unsafe { super::arch::seal(&rk, &tbl, &block, start, &mut b[..n], &mut yb, false) };
            assert_eq!(a, b, "{n} blocks");
            assert_eq!(ya, yb, "{n} blocks");
            // rr: escape(unsafe): the CPU has the faster loop's instructions.
            unsafe { super::arch::open(&rk, &tbl, &block, start, &mut a[..n], &mut yo, true) };
            assert_eq!(yo, ya, "{n} blocks");
            assert_eq!(a, plain);
            // rr: escape(unsafe): the CPU has the base loop's instructions.
            unsafe { super::arch::open(&rk, &tbl, &block, start, &mut b[..n], &mut yo, false) };
            assert_eq!(b, plain);
        }
    }
}
