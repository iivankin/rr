//! AES-128-GCM's CTR and GHASH on the CPU's instructions: AES and PMULL
//! on aarch64, AES-NI, PCLMULQDQ and SSSE3 on x86_64. Each function
//! returns false, having done nothing, where the CPU lacks them;
//! aesgcm.rs then runs its portable code.
//!
//! seal and open take one pass over the record, eight blocks a turn: the
//! eight AES chains of one turn run beside the GHASH of eight ciphertext
//! blocks (seal's from the turn before, open's own input), so the AES and
//! the carry-less multiply units work at once. GHASH folds the eight with
//! H^8..H into one unreduced Karatsuba sum, three products a block and
//! one reduction a turn. The round keys stay in registers for the loop.
//!
//! GHASH here is in the plain polynomial basis: each byte's bits are
//! reversed, so bit i of the little-endian 128-bit value is the
//! coefficient of x^i, and a product is a carry-less multiplication
//! reduced by x^128 = x^7 + x^2 + x + 1 (0x87).

use core::sync::atomic::{AtomicU8, Ordering};

/// H to H^8, then for each the XOR of its halves in both lanes, which
/// Karatsuba's middle product takes.
pub type Table = [[u8; 16]; 16];

/// AES-128's 11 round keys, aligned as a vector register is: the
/// instructions read them where the key keeps them, with no copy.
#[repr(C, align(16))]
pub struct RoundKeys(pub [[u8; 16]; 11]);

/// What the CPU has: 0 before the first look, then 1 + arch::detect():
/// 1 none, 2 the instructions, 3 also SHA3 and SHA512 (Rust's "sha3"
/// feature, which EOR3 is in) for aarch64's asm loop.
// rr: escape(shared): found once, for every thread and every key.
static FOUND: AtomicU8 = AtomicU8::new(0);

fn found() -> u8 {
    match FOUND.load(Ordering::Relaxed) {
        0 => {
            let found = 1 + arch::detect();
            FOUND.store(found, Ordering::Relaxed);
            found
        }
        n => n,
    }
}

/// Whether the CPU has the instructions the functions below need.
pub fn available() -> bool {
    found() >= 2
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
    unsafe { arch::seal(rk, tbl, block, ctr, blocks, y, found() == 3) };
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
    unsafe { arch::open(rk, tbl, block, ctr, blocks, y, found() == 3) };
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

    #[cfg(target_os = "macos")]
    // rr: escape(unsafe): the signature is libSystem's, from sysctlbyname(3).
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const core::ffi::c_char,
            old: *mut core::ffi::c_void,
            oldlen: *mut usize,
            new: *mut core::ffi::c_void,
            newlen: usize,
        ) -> i32;
    }

    /// A 0 or 1 the kernel reports by name; false when it has no such.
    #[cfg(target_os = "macos")]
    fn sysctl_flag(name: &core::ffi::CStr) -> bool {
        let mut v: i32 = 0;
        let mut len = size_of::<i32>();
        // rr: escape(unsafe): name ends in NUL, v and len are this
        // frame's, and len says how much of v there is.
        let r = unsafe {
            sysctlbyname(
                name.as_ptr(),
                (&raw mut v).cast(),
                &raw mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        r == 0 && v != 0
    }

    /// Every Mac on Apple silicon has AES and PMULL (since the A7); SHA3
    /// and SHA512 are asked, as OpenSSL asks them.
    #[cfg(target_os = "macos")]
    pub fn detect() -> u8 {
        let sha3 = sysctl_flag(c"hw.optional.armv8_2_sha3");
        let sha512 = sysctl_flag(c"hw.optional.armv8_2_sha512");
        1 + u8::from(sha3 && sha512)
    }

    /// ID_AA64ISAR0_EL1: the AES field 2 is AES with PMULL, the SHA2
    /// field 2 has SHA512, a SHA3 field above 0 has EOR3.
    #[cfg(target_os = "linux")]
    pub fn detect() -> u8 {
        let isar0: u64;
        // rr: escape(unsafe): Linux emulates this ID register's read for
        // user space (HWCAP_CPUID, since 4.11); it touches no memory.
        unsafe {
            core::arch::asm!(
                "mrs {}, ID_AA64ISAR0_EL1",
                out(reg) isar0,
                options(nomem, nostack, preserves_flags),
            );
        }
        let aes = (isar0 >> 4) & 0xf >= 2;
        let sha512 = (isar0 >> 12) & 0xf >= 2;
        let sha3 = (isar0 >> 32) & 0xf != 0;
        u8::from(aes) + u8::from(aes && sha3 && sha512)
    }

    #[cfg(target_os = "windows")]
    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): the signature is kernel32's, from its documentation.
    unsafe extern "system" {
        // rr: escape(unsafe): it takes a number and only reads the CPU's
        // features.
        safe fn IsProcessorFeaturePresent(feature: u32) -> i32;
    }

    /// PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE (30): AES, PMULL and SHA;
    /// PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE (64) and PF_ARM_SHA512 (65), as
    /// Rust's std_detect asks them. An older Windows answers false to a
    /// number it does not know.
    #[cfg(target_os = "windows")]
    pub fn detect() -> u8 {
        let aes = IsProcessorFeaturePresent(30) != 0;
        let sha3 = IsProcessorFeaturePresent(64) != 0 && IsProcessorFeaturePresent(65) != 0;
        u8::from(aes) + u8::from(aes && sha3)
    }

    /// Elsewhere only what the target promises.
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    pub fn detect() -> u8 {
        let aes = cfg!(target_feature = "aes");
        u8::from(aes) + u8::from(aes && cfg!(target_feature = "sha3"))
    }

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
    /// stack slots instead, x86-64 copies all 176 bytes with memcpy.
    fn round_keys(rk: &RoundKeys) -> &[V; 11] {
        // rr: escape(unsafe): RoundKeys is 11 blocks of 16 bytes aligned
        // to 16, as [V; 11] is, and every bit pattern is a vector.
        unsafe { &*core::ptr::from_ref(rk).cast::<[V; 11]>() }
    }

    const _: () = assert!(size_of::<RoundKeys>() == size_of::<[V; 11]>());
    const _: () = assert!(align_of::<RoundKeys>() == align_of::<[V; 11]>());

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
    fn last(s: &mut [V], k: &[V; 11]) {
        for x in s.iter_mut() {
            *x = veorq_u8(vaeseq_u8(*x, k[9]), k[10]);
        }
    }

    #[target_feature(enable = "aes")]
    fn aes(k: &[V; 11], s: &mut [V]) {
        for rk in k.iter().take(9) {
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
            aes(k, &mut s);
            xor_into(four, &mut s);
        }
        if rest.is_empty() && tail.is_empty() {
            return;
        }
        // Under four blocks and a part: one more batch of key stream.
        counters(base, c, &mut s);
        aes(k, &mut s);
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

    /// Eight AES chains with ghash8 of x woven between their rounds.
    #[target_feature(enable = "aes")]
    fn aes8_ghash8(k: &[V; 11], s: &mut [V; 8], x: &[V; 8], h: &[V; 8], hk: &[V; 8]) -> V {
        let mut acc = [vdupq_n_u8(0); 3];
        let turns = k.iter().zip(x).zip(h.iter().rev()).zip(hk.iter().rev());
        for (((rk, xb), hp), kp) in turns {
            round(s, *rk);
            kmul(&mut acc, *xb, *hp, *kp);
        }
        round(s, k[8]);
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
                    yp = aes8_ghash8(k, &mut s, &x, &h, &hk);
                }
                None => aes(k, &mut s),
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
            yp = aes8_ghash8(k, &mut s, &x, &h, &hk);
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
            aes(k, &mut s);
            xor_into(first, &mut s);
        }
        yp = turns(rk, tbl, base, &mut c, eights, true, yp);
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
        yp = turns(rk, tbl, load(block), &mut c, eights, false, yp);
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
    /// intrinsics, 1450 here; 64 KiB: 6330 ns, 5700. sys/aes-gen.py
    /// writes the body; its header says how, and why this order.
    #[target_feature(enable = "aes,sha3")]
    fn turns(
        rk: &RoundKeys,
        tbl: &Table,
        base: V,
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
        // rr: escape(unsafe): p writes n turns of 128 bytes, all in
        // eights, and g reads n turns from at, which for seal is a turn
        // behind p; rk and tbl are read whole; each vector register the
        // loop writes is named below.
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
                rk = inout(reg) rk.0.as_ptr() => _,
                tbl = in(reg) tbl.as_ptr(),
                p = inout(reg) p => _,
                g = inout(reg) at => _,
                n = inout(reg) n => _,
                c = inout(reg) ctr,
                t0 = out(reg) _,
                t1 = out(reg) _,
                inout("v29") y,
                in("v30") base,
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
        *c = ctr;
        y
    }
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::{RoundKeys, Table};
    use core::arch::x86_64::{
        __cpuid, __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_and_si128,
        _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_or_si128, _mm_set_epi64x,
        _mm_set1_epi8, _mm_setr_epi8, _mm_setzero_si128, _mm_shuffle_epi8, _mm_shuffle_epi32,
        _mm_slli_epi16, _mm_slli_si128, _mm_srli_epi16, _mm_srli_si128, _mm_storeu_si128,
        _mm_xor_si128,
    };

    type V = __m128i;

    /// CPUID leaf 1, ECX: AES (25), PCLMULQDQ (1) and SSSE3 (9).
    pub fn detect() -> u8 {
        let need = (1 << 25) | (1 << 1) | (1 << 9);
        u8::from(__cpuid(1).ecx & need == need)
    }

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
    /// stack slots instead, x86-64 copies all 176 bytes with memcpy.
    fn round_keys(rk: &RoundKeys) -> &[V; 11] {
        // rr: escape(unsafe): RoundKeys is 11 blocks of 16 bytes aligned
        // to 16, as [V; 11] is, and every bit pattern is a vector.
        unsafe { &*core::ptr::from_ref(rk).cast::<[V; 11]>() }
    }

    const _: () = assert!(size_of::<RoundKeys>() == size_of::<[V; 11]>());
    const _: () = assert!(align_of::<RoundKeys>() == align_of::<[V; 11]>());

    /// Counter blocks from ctr on, one for each of s: base, which ends in
    /// four zero bytes, with the counter big-endian there.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn counters(base: V, ctr: u32, s: &mut [V]) {
        for (x, i) in s.iter_mut().zip(0..) {
            let c = _mm_cvtsi32_si128(ctr.wrapping_add(i).to_be().cast_signed());
            *x = _mm_or_si128(base, _mm_slli_si128::<12>(c));
        }
    }

    /// The first key, added before the rounds.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn first(s: &mut [V], k: &[V; 11]) {
        for x in s.iter_mut() {
            *x = _mm_xor_si128(*x, k[0]);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn round(s: &mut [V], k: V) {
        for x in s.iter_mut() {
            *x = _mm_aesenc_si128(*x, k);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn last(s: &mut [V], k: &[V; 11]) {
        for x in s.iter_mut() {
            *x = _mm_aesenclast_si128(*x, k[10]);
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn aes(k: &[V; 11], s: &mut [V]) {
        first(s, k);
        for rk in k.iter().skip(1).take(9) {
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
        let base = load(block);
        let (blocks, tail) = data.as_chunks_mut::<16>();
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        let mut c = ctr;
        let mut s = [_mm_setzero_si128(); 4];
        for four in fours {
            counters(base, c, &mut s);
            c = c.wrapping_add(4);
            aes(k, &mut s);
            xor_into(four, &mut s);
        }
        if rest.is_empty() && tail.is_empty() {
            return;
        }
        // Under four blocks and a part: one more batch of key stream.
        counters(base, c, &mut s);
        aes(k, &mut s);
        xor_into(rest, &mut s);
        if let Some(ks) = s.get(rest.len()) {
            let mut t = [0; 16];
            store(&mut t, *ks);
            for (d, x) in tail.iter_mut().zip(t) {
                *d ^= x;
            }
        }
    }

    /// The bits of each byte reversed, by two nibble lookups.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn rbit(v: V) -> V {
        let lo = _mm_setr_epi8(
            0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b,
            0x07, 0x0f,
        );
        let hi = _mm_slli_epi16::<4>(lo);
        let mask = _mm_set1_epi8(0x0f);
        let l = _mm_and_si128(v, mask);
        let h = _mm_and_si128(_mm_srli_epi16::<4>(v), mask);
        _mm_or_si128(_mm_shuffle_epi8(hi, l), _mm_shuffle_epi8(lo, h))
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

    /// The 256-bit sum acc holds, reduced: the middle product goes to the
    /// middle, then hi * x^128 = hi * 0x87 folds into lo, and then its own
    /// 7-bit overflow.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn fold(acc: [V; 3]) -> V {
        let [lo, mid, hi] = acc;
        let mid = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
        let lo = _mm_xor_si128(lo, _mm_slli_si128::<8>(mid));
        let hi = _mm_xor_si128(hi, _mm_srli_si128::<8>(mid));
        let red = _mm_set_epi64x(0x87, 0x87);
        let f0 = _mm_clmulepi64_si128::<0x00>(hi, red);
        let f1 = _mm_clmulepi64_si128::<0x01>(hi, red);
        let g = _mm_clmulepi64_si128::<0x01>(f1, red);
        _mm_xor_si128(
            _mm_xor_si128(lo, f0),
            _mm_xor_si128(_mm_slli_si128::<8>(f1), g),
        )
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn gmul(a: V, b: V) -> V {
        let mut acc = [_mm_setzero_si128(); 3];
        kmul(&mut acc, a, b, halves(b));
        fold(acc)
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

    /// Eight AES chains with ghash8 of x woven between their rounds.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn aes8_ghash8(k: &[V; 11], s: &mut [V; 8], x: &[V; 8], h: &[V; 8], hk: &[V; 8]) -> V {
        let mut acc = [_mm_setzero_si128(); 3];
        first(s, k);
        let turns = k
            .iter()
            .skip(1)
            .zip(x)
            .zip(h.iter().rev())
            .zip(hk.iter().rev());
        for (((rk, xb), hp), kp) in turns {
            round(s, *rk);
            kmul(&mut acc, *xb, *hp, *kp);
        }
        round(s, k[9]);
        last(s, k);
        fold(acc)
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn ghash_key(h: &[u8; 16], tbl: &mut Table) {
        let hp = rbit(load(h));
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
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    fn ghash_rev(h: &[V; 8], hk: &[V; 8], mut yp: V, blocks: &[[u8; 16]]) -> V {
        let (eights, rest) = blocks.as_chunks::<8>();
        let mut x = [_mm_setzero_si128(); 8];
        for eight in eights {
            for (v, b) in x.iter_mut().zip(eight) {
                *v = rbit(load(b));
            }
            x[0] = _mm_xor_si128(x[0], yp);
            yp = ghash8(&x, h, hk);
        }
        for b in rest {
            let mut acc = [_mm_setzero_si128(); 3];
            kmul(&mut acc, _mm_xor_si128(yp, rbit(load(b))), h[0], hk[0]);
            yp = fold(acc);
        }
        yp
    }

    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn ghash(tbl: &Table, y: &mut [u8; 16], blocks: &[[u8; 16]]) {
        let (h, hk) = powers(tbl);
        let yp = ghash_rev(&h, &hk, rbit(load(y)), blocks);
        store(y, rbit(yp));
    }

    /// Eight blocks a turn; each turn's ciphertext is hashed in the next,
    /// beside its AES, and the last after the loop.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn seal(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
        _eor3: bool,
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let base = load(block);
        let mut yp = rbit(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [_mm_setzero_si128(); 8];
        let mut prev: Option<[V; 8]> = None;
        for eight in eights {
            counters(base, c, &mut s);
            c = c.wrapping_add(8);
            match prev {
                Some(mut x) => {
                    x[0] = _mm_xor_si128(x[0], yp);
                    yp = aes8_ghash8(k, &mut s, &x, &h, &hk);
                }
                None => aes(k, &mut s),
            }
            xor_into(eight, &mut s);
            prev = Some(s.map(|v| rbit(v)));
        }
        if let Some(mut x) = prev {
            x[0] = _mm_xor_si128(x[0], yp);
            yp = ghash8(&x, &h, &hk);
        }
        self::ctr(rk, block, c, rest.as_flattened_mut());
        yp = ghash_rev(&h, &hk, yp, rest);
        store(y, rbit(yp));
    }

    /// Eight blocks a turn: the ciphertext is hashed beside the AES that
    /// makes the key stream to decrypt it.
    #[target_feature(enable = "aes,pclmulqdq,ssse3")]
    pub fn open(
        rk: &RoundKeys,
        tbl: &Table,
        block: &[u8; 16],
        ctr: u32,
        blocks: &mut [[u8; 16]],
        y: &mut [u8; 16],
        _eor3: bool,
    ) {
        let k = round_keys(rk);
        let (h, hk) = powers(tbl);
        let base = load(block);
        let mut yp = rbit(load(y));
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        let mut c = ctr;
        let mut s = [_mm_setzero_si128(); 8];
        let mut x = s;
        for eight in eights {
            counters(base, c, &mut s);
            c = c.wrapping_add(8);
            for (v, b) in x.iter_mut().zip(eight.iter()) {
                *v = rbit(load(b));
            }
            x[0] = _mm_xor_si128(x[0], yp);
            yp = aes8_ghash8(k, &mut s, &x, &h, &hk);
            xor_into(eight, &mut s);
        }
        yp = ghash_rev(&h, &hk, yp, rest);
        self::ctr(rk, block, c, rest.as_flattened_mut());
        store(y, rbit(yp));
    }
}

/// No instructions to reach: available() is false, so nothing below runs.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod arch {
    use super::{RoundKeys, Table};

    pub fn detect() -> u8 {
        0
    }

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
#[cfg(target_arch = "aarch64")]
mod tests {
    use super::{RoundKeys, Table, found};
    use test::Bencher;

    /// A key schedule and GHASH table of no key in particular.
    fn keys() -> (RoundKeys, Table) {
        let rk = RoundKeys(core::array::from_fn(|r| {
            core::array::from_fn(|j| u8::try_from(((16 * r + j) * 13 + 5) % 256).unwrap())
        }));
        let mut tbl: Table = [[0; 16]; 16];
        // rr: escape(unsafe): the callers looked for the instructions.
        unsafe { super::arch::ghash_key(&[0x66; 16], &mut tbl) };
        (rk, tbl)
    }

    /// One 16 KiB record through aarch64's one-pass seal loop, the asm one
    /// or the intrinsics one: where EOR3 is there both run, so a CPU shows
    /// which is faster on it.
    fn bench_loop(b: &mut Bencher, eor3: bool) {
        if found() < 2 + u8::from(eor3) {
            return;
        }
        let (rk, tbl) = keys();
        let block = [0x21, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0];
        let mut data = alloc::vec::Vec::new();
        data.resize(1024, [0x17; 16]);
        let mut y = [0; 16];
        // rr: escape(unsafe): found() saw what each loop runs on.
        b.iter(|| unsafe { super::arch::seal(&rk, &tbl, &block, 2, &mut data, &mut y, eor3) });
    }

    #[bench]
    fn seal_loop_16k_asm(b: &mut Bencher) {
        bench_loop(b, true);
    }

    #[bench]
    fn seal_loop_16k_intrinsics(b: &mut Bencher) {
        bench_loop(b, false);
    }

    /// On aarch64 with EOR3 both one-pass loops run here, the asm and the
    /// intrinsics one other CPUs take: they agree on every block count to
    /// past three turns, from a counter that wraps, and open undoes seal.
    #[test]
    fn both_loops_agree() {
        if found() != 3 {
            return;
        }
        let (rk, tbl) = keys();
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
            // rr: escape(unsafe): found() saw AES, PMULL and EOR3.
            unsafe { super::arch::seal(&rk, &tbl, &block, start, &mut a[..n], &mut ya, true) };
            // rr: escape(unsafe): found() saw AES and PMULL.
            unsafe { super::arch::seal(&rk, &tbl, &block, start, &mut b[..n], &mut yb, false) };
            assert_eq!(a, b, "{n} blocks");
            assert_eq!(ya, yb, "{n} blocks");
            // rr: escape(unsafe): found() saw AES, PMULL and EOR3.
            unsafe { super::arch::open(&rk, &tbl, &block, start, &mut a[..n], &mut yo, true) };
            assert_eq!(yo, ya, "{n} blocks");
            assert_eq!(a, plain);
            // rr: escape(unsafe): found() saw AES and PMULL.
            unsafe { super::arch::open(&rk, &tbl, &block, start, &mut b[..n], &mut yo, false) };
            assert_eq!(b, plain);
        }
    }
}
