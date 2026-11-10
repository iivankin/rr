//! AES-128-GCM and AES-256-GCM (NIST SP 800-38D, TLS 1.3's 12-byte nonce and
//! 16-byte tag), sealed and opened in place, on AES and carry-less multiply
//! instructions where the CPU has them and constant-time portable code
//! elsewhere; a SealingKey and an OpeningKey that number their own nonces (IV
//! XOR the record's number, as TLS 1.3) and refuse past 2^64 - 1,
//! seal_with_nonce and open_with_nonce for a nonce of the caller's, a tag that
//! must be used, key schedules wiped when dropped.
//!
//! AES-128-GCM and AES-256-GCM (FIPS 197, NIST SP 800-38D) as TLS 1.3
//! uses them: a 16- or 32-byte key, a 12-byte nonce and a 16-byte tag,
//! sealed and opened in place.
//!
//! A SealingKey and an OpeningKey number their own nonces, as TLS 1.3
//! does (RFC 9846 5.3): the n-th record's nonce is the IV XOR n, n
//! big-endian in its last eight bytes, so that no nonce seals twice
//! under the key; after 2^64 - 1 records the key is Exhausted. A
//! direction of a connection has one of each, both sides from the same
//! key and IV:
//!
//! ```text
//! let mut sealing = SealingKey::new(&key, &iv);
//! let tag = sealing.seal(&header, &mut record)?;      // number 0, 1, ...
//! send(&header, &record, tag.bytes());
//! let mut opening = OpeningKey::new(&key, &iv);       // the peer's
//! opening.open(&header, &mut record, &tag)?;          // Err(Forged)
//! ```
//!
//! AesGcm, the key alone, takes a nonce of the caller's, by
//! seal_with_nonce and open_with_nonce: a nonce sealed twice under one
//! key gives away the XOR of both plaintexts and lets anyone forge a
//! tag, which is why their names say so. Each key's schedule and hash
//! key are wiped when it is dropped.
//!
//! CTR and GHASH run on the CPU's instructions through sys::aes where it
//! has them. The portable code is constant-time: AES is bitsliced, four
//! blocks at once in eight 64-bit words with the S-box as a circuit, and
//! GHASH multiplies with integer products whose carries fall into holes
//! between the bits; neither indexes memory by a secret. Both follow
//! BearSSL's aes_ct64 and ghash_ctmul64 (Thomas Pornin, MIT licence).

// rr: checked(0.5.2)
// rr: needs(cpu)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
// rr: file(aesgcm-wycheproof.txt, tests = yes)
// rr: option(os, many): Which systems does it build for?
// rr: choice(os = linux, default): Linux
// rr: choice(os = macos, default): macOS
// rr: choice(os = windows, default): Windows
// rr: option(arch, many): Which CPUs does it build for?
// rr: choice(arch = x86_64, default): x86-64
// rr: choice(arch = aarch64, default): AArch64 (ARM64)
// rr: choice(arch = other, default): any other, on portable code

// rr: unless(os = linux)
#[cfg(target_os = "linux")]
compile_error!("rr add cut aesgcm without linux: add it again with linux in --option os");
// rr: end(os = linux)
// rr: unless(os = macos)
#[cfg(target_os = "macos")]
compile_error!("rr add cut aesgcm without macos: add it again with macos in --option os");
// rr: end(os = macos)
// rr: unless(os = windows)
#[cfg(windows)]
compile_error!("rr add cut aesgcm without windows: add it again with windows in --option os");
// rr: end(os = windows)
// rr: unless(arch = x86_64)
#[cfg(target_arch = "x86_64")]
compile_error!("rr add cut aesgcm without x86_64: add it again with x86_64 in --option arch");
// rr: end(arch = x86_64)
// rr: unless(arch = aarch64)
#[cfg(target_arch = "aarch64")]
compile_error!("rr add cut aesgcm without aarch64: add it again with aarch64 in --option arch");
// rr: end(arch = aarch64)
// rr: unless(arch = other)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("rr add cut aesgcm without other: add it again with other in --option arch");
// rr: end(arch = other)

mod sys {
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

    // rr: section(arch = aarch64)
    /// What the faster loop of seal and open runs on besides: SHA3's EOR3
    /// on aarch64, VAES and VPCLMULQDQ on x86_64.
    #[cfg(target_arch = "aarch64")]
    const FASTER: cpu::Features = cpu::AES.and(&cpu::SHA512);
    // rr: end(arch = aarch64)
    // rr: section(arch = x86_64 other)
    #[cfg(not(target_arch = "aarch64"))]
    const FASTER: cpu::Features = cpu::WIDE_AES;
    // rr: end(arch = x86_64 other)

    /// Whether the CPU has the instructions the functions below need.
    pub fn available() -> bool {
        cpu::has(&cpu::AES)
    }

    /// CTR in place over data with round keys rk: the counter blocks are
    /// block (the nonce, then four bytes the counter replaces) with ctr,
    /// ctr + 1, ... big-endian in its last four bytes.
    #[must_use]
    pub fn ctr(rk: &RoundKeys, block: &[u8; 16], ctr: u32, data: &mut [u8]) -> bool {
        if !available() {
            return false;
        }
        // rr: escape(unsafe): available() found the instructions it runs on.
        unsafe { arch::ctr(rk, block, ctr, data) };
        true
    }

    /// The table ghash, seal and open take, from H = E(K, 0).
    #[must_use]
    pub fn ghash_key(h: &[u8; 16], tbl: &mut Table) -> bool {
        if !available() {
            return false;
        }
        // rr: escape(unsafe): available() found the instructions it runs on.
        unsafe { arch::ghash_key(h, tbl) };
        true
    }

    /// y = GHASH of y continued over blocks.
    #[must_use]
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
    #[must_use]
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
        unsafe { arch::seal(rk, tbl, block, ctr, blocks, y, cpu::has(&FASTER)) };
        true
    }

    /// y continued over the ciphertext in blocks, and CTR in place over it.
    #[must_use]
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
        unsafe { arch::open(rk, tbl, block, ctr, blocks, y, cpu::has(&FASTER)) };
        true
    }

    /// Zeros over a key's bytes, each a volatile store, which the compiler
    /// keeps though nothing reads them after; the fence keeps later code
    /// from moving above them.
    pub fn wipe(bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            // rr: escape(unsafe): byte is a place of its own, aligned and
            // borrowed mutably.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// wipe for 32-bit words.
    pub fn wipe_u32(words: &mut [u32]) {
        for word in words.iter_mut() {
            // rr: escape(unsafe): word is a place of its own, aligned and
            // borrowed mutably.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// wipe for 64-bit words.
    pub fn wipe_u64(words: &mut [u64]) {
        for word in words.iter_mut() {
            // rr: escape(unsafe): word is a place of its own, aligned and
            // borrowed mutably.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    // rr: section(arch = aarch64)
    #[cfg(target_arch = "aarch64")]
    mod arch {
        use super::{RoundKeys, Table};
        use core::arch::aarch64::{
            uint8x16_t, uint32x4_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u8, vdupq_n_u64, veorq_u8,
            vextq_u8, vgetq_lane_p64, vld1q_u8, vmull_high_p64, vmull_p64, vrbitq_u8,
            vreinterpretq_p64_u8, vreinterpretq_u8_p128, vreinterpretq_u8_u32,
            vreinterpretq_u8_u64, vreinterpretq_u32_u8, vsetq_lane_u32, vst1q_u8,
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
    // rr: end(arch = aarch64)

    // rr: section(arch = x86_64)
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
            _mm_and_si128, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_loadu_si128,
            _mm_set_epi64x, _mm_setr_epi8, _mm_setzero_si128, _mm_shuffle_epi8, _mm_shuffle_epi32,
            _mm_srai_epi32, _mm_storeu_si128, _mm_xor_si128, _mm256_add_epi32,
            _mm256_aesenc_epi128, _mm256_aesenclast_epi128, _mm256_broadcastsi128_si256,
            _mm256_castsi256_si128, _mm256_clmulepi64_epi128, _mm256_extracti128_si256,
            _mm256_loadu_si256, _mm256_set_epi32, _mm256_set_m128i, _mm256_setzero_si256,
            _mm256_shuffle_epi8, _mm256_shuffle_epi32, _mm256_storeu_si256, _mm256_xor_si256,
            _mm256_zextsi128_si256,
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
            for (((xb, hp), kp), key) in x.iter().zip(hw).zip(hkw).zip(k.iter().skip(first_at + 1))
            {
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
    // rr: end(arch = x86_64)

    // rr: section(arch = other)
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
    // rr: end(arch = other)

    // rr: section(arch = x86_64 aarch64)
    // rr: section(tests = yes)
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
            if !available() || (faster && !cpu::has(&FASTER)) {
                return;
            }
            let (rk, tbl) = keys(first);
            let block = [0x21, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0];
            let mut data = alloc::vec::Vec::new();
            data.resize(1024, [0x17; 16]);
            let mut y = [0; 16];
            // rr: escape(unsafe): the CPU has what each loop runs on.
            b.iter(|| unsafe {
                super::arch::seal(&rk, &tbl, &block, 2, &mut data, &mut y, faster)
            });
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
            if !cpu::has(&FASTER) {
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
    // rr: end(tests = yes)
    // rr: end(arch = x86_64 aarch64)
}

use sys as hw;

pub const KEY_LEN: usize = 16;
/// AES-256's key.
pub const KEY256_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// What one nonce may cover: the 32-bit counter starts at 2, so 2^32 - 2
/// blocks.
const DATA_MAX: u64 = ((1 << 32) - 2) * 16;
/// The AAD's length in bits must fit in 64.
const AAD_MAX: u64 = u64::MAX / 8;
/// Every fourth bit: the bitsliced key's lanes and bmul64's slices.
const M0: u64 = 0x1111_1111_1111_1111;
/// AES-256's round keys; AES-128's 11 are the last of as many places.
const ROUND_KEYS: usize = 15;

/// What went wrong. Only Exhausted ends a key; after TooLong a shorter
/// record goes on, and after Forged the next record (a stream that had a
/// forgery in it is broken, and its owner ends it).
// rr: section(tests = yes)
#[cfg_attr(any(test, fuzzing), derive(Debug))]
// rr: end(tests = yes)
// rr: section(tests = yes)
#[cfg_attr(test, derive(PartialEq))]
// rr: end(tests = yes)
pub enum Error {
    /// The data or the AAD is past GCM's limit; nothing was changed and
    /// no number taken.
    TooLong,
    /// The tag does not match; data is still the ciphertext. An
    /// OpeningKey took the record's number.
    Forged,
    /// The key numbered 2^64 - 1 records: it takes no more, and nothing
    /// was changed.
    Exhausted,
}

/// A tag that authenticates a sealed record: to be sent beside it.
#[must_use]
// rr: section(tests = yes)
#[cfg_attr(any(test, fuzzing), derive(Debug, PartialEq))]
// rr: end(tests = yes)
pub struct Tag([u8; TAG_LEN]);

impl Tag {
    /// The tag's bytes, to send.
    pub fn bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }

    /// The tag's bytes, by value: a record's buffer takes them where it
    /// would take a copy.
    pub fn into_bytes(self) -> [u8; TAG_LEN] {
        self.0
    }
}

/// A key and IV that seal records numbered 0, 1, ... in turn, each
/// under the IV XOR its number: the sending half of a direction.
pub struct SealingKey {
    key: AesGcm,
    iv: [u8; NONCE_LEN],
    next: u64,
}

/// A key and IV that open records numbered 0, 1, ... in turn, as the
/// peer's SealingKey sealed them: the receiving half.
pub struct OpeningKey {
    key: AesGcm,
    iv: [u8; NONCE_LEN],
    next: u64,
}

/// One key, expanded once: round keys and the hash key H in both forms.
pub struct AesGcm {
    /// The round keys as bytes, aligned for the instructions, from
    /// rk.first on.
    rk: hw::RoundKeys,
    /// The same, bitsliced and compressed: one bit of each nibble, which
    /// the portable code spreads to the nibble (spread_key) for its four
    /// blocks, a quarter of the size.
    sk: [[u64; 2]; ROUND_KEYS],
    /// H as two big-endian words, for the portable GHASH.
    h: [u64; 2],
    /// H to H^8 as the instructions' GHASH takes them.
    htbl: hw::Table,
    /// Whether to try the instructions; tests turn them off.
    hw: bool,
}

impl AesGcm {
    /// AES-128-GCM.
    pub fn new(key: &[u8; KEY_LEN]) -> AesGcm {
        AesGcm::with(key, hw::available())
    }

    /// AES-256-GCM.
    pub fn new256(key: &[u8; KEY256_LEN]) -> AesGcm {
        AesGcm::with(key, hw::available())
    }

    /// A key of 16 or 32 bytes: AES-128's 11 round keys go in the last 11
    /// places, so the last rounds take theirs from the same place for both.
    fn with(key: &[u8], hw: bool) -> AesGcm {
        let first = if key.len() == KEY256_LEN {
            0
        } else {
            hw::AES128_FIRST
        };
        let mut w = [[0; 4]; ROUND_KEYS];
        expand(key, w.get_mut(first..).unwrap_or_default());
        let mut g = AesGcm {
            rk: hw::RoundKeys {
                keys: [[0; 16]; ROUND_KEYS],
                first,
            },
            sk: [[0; 2]; ROUND_KEYS],
            h: [0; 2],
            htbl: [[0; 16]; 16],
            hw,
        };
        for ((rk, sk), k) in g.rk.keys.iter_mut().zip(&mut g.sk).zip(w) {
            *rk = block_bytes(k);
            *sk = bitslice_key(k);
        }
        hw::wipe_u32(w.as_flattened_mut());
        let mut h = [0; 16];
        g.ctr(&[0; 16], 0, &mut h);
        let (hi, lo) = words(&h);
        g.h = [hi, lo];
        if !hw::ghash_key(&h, &mut g.htbl) {
            g.hw = false;
        }
        hw::wipe(&mut h);
        g
    }

    /// Encrypts data in place; the tag that authenticates it and aad.
    /// Dangerous: a nonce must never seal twice under one key, which
    /// SealingKey makes sure of; this does not.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<Tag, Error> {
        check(aad, data)?;
        let block = iv(nonce);
        let mut y = [0; 16];
        self.ghash(&mut y, aad);
        self.encrypt(&block, data, &mut y);
        Ok(Tag(self.finish(&block, y, aad.len(), data.len())))
    }

    /// Decrypts data in place when tag authenticates it and aad; a
    /// forgery leaves the ciphertext, and no plaintext, in data. The
    /// nonce is the caller's, to match seal_with_nonce's: OpeningKey
    /// numbers them.
    pub fn open_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Error> {
        check(aad, data)?;
        let block = iv(nonce);
        let mut y = [0; 16];
        self.ghash(&mut y, aad);
        let decrypted = self.decrypt(&block, data, &mut y);
        if !same(&self.finish(&block, y, aad.len(), data.len()), tag) {
            if decrypted {
                // CTR again puts the ciphertext back.
                self.ctr(&block, 2, data);
            }
            return Err(Error::Forged);
        }
        if !decrypted {
            self.ctr(&block, 2, data);
        }
        Ok(())
    }

    /// CTR over data from counter 2, and y continued over the ciphertext:
    /// one pass on the instructions, two in the portable code.
    fn encrypt(&self, block: &[u8; 16], data: &mut [u8], y: &mut [u8; 16]) {
        let (blocks, tail) = data.as_chunks_mut::<16>();
        // The counter after the whole blocks, mod 2^32 as GCM's inc32.
        let c = 2u32.wrapping_add(low32(blocks.len() as u64));
        if self.hw && hw::seal(&self.rk, &self.htbl, block, 2, blocks, y) {
            self.ctr(block, c, tail);
            self.ghash(y, tail);
            return;
        }
        self.ctr(block, 2, data);
        self.ghash(y, data);
    }

    /// y continued over the ciphertext in data; on the instructions, in
    /// the same pass, data decrypted, and then true.
    #[must_use]
    fn decrypt(&self, block: &[u8; 16], data: &mut [u8], y: &mut [u8; 16]) -> bool {
        let (blocks, tail) = data.as_chunks_mut::<16>();
        let c = 2u32.wrapping_add(low32(blocks.len() as u64));
        if self.hw && hw::open(&self.rk, &self.htbl, block, 2, blocks, y) {
            self.ghash(y, tail);
            self.ctr(block, c, tail);
            return true;
        }
        self.ghash(y, data);
        false
    }

    /// The tag: y continued over the lengths in bits, masked with E(K, J0).
    fn finish(&self, block: &[u8; 16], mut y: [u8; 16], alen: usize, n: usize) -> [u8; 16] {
        let bits = (u128::from(alen as u64 * 8) << 64) | u128::from(n as u64 * 8);
        self.ghash_blocks(&mut y, &[bits.to_be_bytes()]);
        self.ctr(block, 1, &mut y);
        y
    }

    /// GHASH over bytes, the last block padded with zeros.
    fn ghash(&self, y: &mut [u8; 16], bytes: &[u8]) {
        let (blocks, tail) = bytes.as_chunks::<16>();
        self.ghash_blocks(y, blocks);
        if !tail.is_empty() {
            // y ^ (tail padded with zeros), times H: the zero block adds
            // nothing, and the tail is never copied.
            for (d, s) in y.iter_mut().zip(tail) {
                *d ^= s;
            }
            self.ghash_blocks(y, &[[0; 16]]);
        }
    }

    fn ghash_blocks(&self, y: &mut [u8; 16], blocks: &[[u8; 16]]) {
        if self.hw && hw::ghash(&self.htbl, y, blocks) {
            return;
        }
        let [h1, h0] = self.h;
        let (h1r, h0r) = (rev64(h1), rev64(h0));
        let (h2, h2r) = (h0 ^ h1, h0r ^ h1r);
        let (mut y1, mut y0) = words(y);
        for b in blocks {
            let (b1, b0) = words(b);
            y1 ^= b1;
            y0 ^= b0;
            let (y1r, y0r) = (rev64(y1), rev64(y0));
            let (y2, y2r) = (y0 ^ y1, y0r ^ y1r);
            let z0 = bmul64(y0, h0);
            let z1 = bmul64(y1, h1);
            let z2 = bmul64(y2, h2) ^ z0 ^ z1;
            let z0h = bmul64(y0r, h0r);
            let z1h = bmul64(y1r, h1r);
            let z2h = bmul64(y2r, h2r) ^ z0h ^ z1h;
            let (z0h, z1h, z2h) = (rev64(z0h) >> 1, rev64(z1h) >> 1, rev64(z2h) >> 1);
            // The 256-bit product, shifted left one for GCM's bit order.
            let (v0, v1, v2, v3) = (z0, z0h ^ z2, z1 ^ z2h, z1h);
            let v3 = (v3 << 1) | (v2 >> 63);
            let v2 = (v2 << 1) | (v1 >> 63);
            let v1 = (v1 << 1) | (v0 >> 63);
            let v0 = v0 << 1;
            let v2 = v2 ^ v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
            let v1 = v1 ^ (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
            y1 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
            y0 = v2 ^ (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        }
        *y = ((u128::from(y1) << 64) | u128::from(y0)).to_be_bytes();
    }

    /// CTR in place from counter ctr of block.
    fn ctr(&self, block: &[u8; 16], ctr: u32, data: &mut [u8]) {
        if self.hw && hw::ctr(&self.rk, block, ctr, data) {
            return;
        }
        let mut sk = [[0; 8]; ROUND_KEYS];
        for (d, k) in sk.iter_mut().zip(&self.sk).skip(self.rk.first) {
            *d = spread_key(*k);
        }
        let [n0, n1, n2, _] = block_words(block);
        let (quads, tail) = data.as_chunks_mut::<64>();
        let mut c = ctr;
        for q in quads {
            let ks = self.keystream(&sk, [n0, n1, n2], c);
            c = c.wrapping_add(4);
            for (d, k) in q.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
        if !tail.is_empty() {
            let ks = self.keystream(&sk, [n0, n1, n2], c);
            for (d, k) in tail.iter_mut().zip(ks) {
                *d ^= k;
            }
        }
    }

    /// Four blocks of key stream, counters c to c + 3, under the round
    /// keys sk spread out.
    fn keystream(&self, sk: &[[u64; 8]; ROUND_KEYS], n: [u32; 3], c: u32) -> [u8; 64] {
        let [n0, n1, n2] = n;
        let mut q = [0; 8];
        let (lo, hi) = q.split_at_mut(4);
        for ((a, b), i) in lo.iter_mut().zip(hi.iter_mut()).zip(0..) {
            let w3 = u32::from_le_bytes(c.wrapping_add(i).to_be_bytes());
            (*a, *b) = interleave_in([n0, n1, n2, w3]);
        }
        ortho(&mut q);
        encrypt(sk, self.rk.first, &mut q);
        ortho(&mut q);
        let mut out = [0; 64];
        let (q03, q47) = q.split_at(4);
        for ((o, a), b) in out.as_chunks_mut::<16>().0.iter_mut().zip(q03).zip(q47) {
            *o = block_bytes(interleave_out(*a, *b));
        }
        out
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        hw::wipe(self.rk.keys.as_flattened_mut());
        hw::wipe_u64(self.sk.as_flattened_mut());
        hw::wipe_u64(&mut self.h);
        hw::wipe(self.htbl.as_flattened_mut());
    }
}

impl SealingKey {
    /// AES-128-GCM under key, nonces from iv.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> SealingKey {
        SealingKey {
            key: AesGcm::new(key),
            iv: *iv,
            next: 0,
        }
    }

    /// AES-256-GCM under key, nonces from iv.
    pub fn new256(key: &[u8; KEY256_LEN], iv: &[u8; NONCE_LEN]) -> SealingKey {
        SealingKey {
            key: AesGcm::new256(key),
            iv: *iv,
            next: 0,
        }
    }

    /// Encrypts data in place under the next number; the tag that
    /// authenticates it and aad. An error takes no number.
    pub fn seal(&mut self, aad: &[u8], data: &mut [u8]) -> Result<Tag, Error> {
        let (nonce, after) = numbered(&self.iv, self.next)?;
        let tag = self.key.seal_with_nonce(&nonce, aad, data)?;
        self.next = after;
        Ok(tag)
    }

    /// The number the next record takes: how many were sealed.
    pub fn sequence(&self) -> u64 {
        self.next
    }

    /// Sets the number the next record takes. Less safe: a number sealed
    /// again seals two records under one nonce. Only for records that
    /// were sealed and then dropped before any byte of them left, whose
    /// numbers the next records take instead, as TLS does when it fails
    /// with records still unsent.
    pub fn set_sequence_less_safe(&mut self, next: u64) {
        self.next = next;
    }
}

impl OpeningKey {
    /// AES-128-GCM under key, nonces from iv.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> OpeningKey {
        OpeningKey {
            key: AesGcm::new(key),
            iv: *iv,
            next: 0,
        }
    }

    /// AES-256-GCM under key, nonces from iv.
    pub fn new256(key: &[u8; KEY256_LEN], iv: &[u8; NONCE_LEN]) -> OpeningKey {
        OpeningKey {
            key: AesGcm::new256(key),
            iv: *iv,
            next: 0,
        }
    }

    /// Decrypts data in place, under the next number, when tag
    /// authenticates it and aad. Forged takes the number and leaves the
    /// ciphertext; TooLong and Exhausted take none.
    pub fn open(&mut self, aad: &[u8], data: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        let (nonce, after) = numbered(&self.iv, self.next)?;
        check(aad, data)?;
        self.next = after;
        self.key.open_with_nonce(&nonce, aad, data, tag)
    }

    /// The number the next record takes: how many were opened.
    pub fn sequence(&self) -> u64 {
        self.next
    }

    // rr: section(tests = yes)
    /// Sets the number the next record takes, as a test reaches the
    /// limit without 2^64 records.
    #[cfg(any(test, fuzzing))]
    pub fn set_sequence_for_tests(&mut self, next: u64) {
        self.next = next;
    }
    // rr: end(tests = yes)
}

/// The nonce of record number n, the IV XOR n big-endian in its last
/// eight bytes (RFC 9846 5.3), and the number after it; Exhausted at
/// the last, which is never used, so that the count never wraps.
fn numbered(iv: &[u8; NONCE_LEN], n: u64) -> Result<([u8; NONCE_LEN], u64), Error> {
    let after = n.checked_add(1).ok_or(Error::Exhausted)?;
    let mut nonce = *iv;
    for (byte, number) in nonce.iter_mut().skip(4).zip(n.to_be_bytes()) {
        *byte ^= number;
    }
    Ok((nonce, after))
}

/// GCM's limits on one record.
fn check(aad: &[u8], data: &[u8]) -> Result<(), Error> {
    if data.len() as u64 > DATA_MAX || aad.len() as u64 > AAD_MAX {
        return Err(Error::TooLong);
    }
    Ok(())
}

/// The nonce with four zero bytes for the counter.
fn iv(nonce: &[u8; NONCE_LEN]) -> [u8; 16] {
    let [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11] = *nonce;
    [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, 0, 0, 0, 0]
}

/// Equal tags, in a time that does not depend on where they differ.
fn same(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let d = a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y));
    core::hint::black_box(d) == 0
}

/// A block as two big-endian words, high first.
fn words(b: &[u8; 16]) -> (u64, u64) {
    let [
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        a6,
        a7,
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
    ] = *b;
    (
        u64::from_be_bytes([a0, a1, a2, a3, a4, a5, a6, a7]),
        u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
    )
}

/// A block as four little-endian words, the order the bitslicing takes.
fn block_words(b: &[u8; 16]) -> [u32; 4] {
    let mut w = [0; 4];
    for (d, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *d = u32::from_le_bytes(*c);
    }
    w
}

fn block_bytes(w: [u32; 4]) -> [u8; 16] {
    let [w0, w1, w2, w3] = w.map(u128::from);
    ((w3 << 96) | (w2 << 64) | (w1 << 32) | w0).to_le_bytes()
}

/// The low half of x.
fn low32(x: u64) -> u32 {
    let [a, b, c, d, ..] = x.to_le_bytes();
    // The high half is zero or not wanted, as each caller says.
    u32::from_le_bytes([a, b, c, d])
}

/// x with its bits in reverse order.
fn rev64(x: u64) -> u64 {
    x.reverse_bits()
}

/// The 64x64 carry-less product, low 64 bits: four integer products of
/// every fourth bit, whose carries land in the three bits between.
fn bmul64(x: u64, y: u64) -> u64 {
    const M1: u64 = M0 << 1;
    const M2: u64 = M0 << 2;
    const M3: u64 = M0 << 3;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = u64::wrapping_mul;
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

/// The key schedule (FIPS 197 5.2) of a 16- or 32-byte key into rk, 11
/// or 15 round keys of little-endian words: Nk words of the key, then
/// each word the one Nk before XORed with the one before, transformed
/// at each multiple of Nk and, for AES-256, halfway too. SubWord goes
/// through the circuit, not a table.
fn expand(key: &[u8], rk: &mut [[u32; 4]]) {
    let w = rk.as_flattened_mut();
    let (words, _) = key.as_chunks::<4>();
    let nk = words.len();
    for (d, c) in w.iter_mut().zip(words) {
        *d = u32::from_le_bytes(*c);
    }
    let mut rcon = 1;
    for i in nk..w.len() {
        let Some((done, [next, ..])) = w.split_at_mut_checked(i) else {
            break;
        };
        let (Some(&back), Some(&prev)) = (done.get(i - nk), done.last()) else {
            break;
        };
        let t = if i % nk == 0 {
            let t = sub_word(prev.rotate_right(8)) ^ rcon;
            rcon = (rcon << 1) ^ ((rcon >> 7) * 0x11b);
            t
        } else if nk > 6 && i % nk == 4 {
            sub_word(prev)
        } else {
            prev
        };
        *next = back ^ t;
    }
}

/// S applied to each byte of x.
fn sub_word(x: u32) -> u32 {
    let mut q = [u64::from(x), 0, 0, 0, 0, 0, 0, 0];
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    // The high half holds S(0) of the zero padding.
    low32(q[0])
}

/// A round key in the bitsliced form, the same in all four blocks, and
/// so one bit of each nibble: those bits, which spread_key spreads.
fn bitslice_key(k: [u32; 4]) -> [u64; 2] {
    let (a, b) = interleave_in(k);
    let mut q = [a, a, a, a, b, b, b, b];
    ortho(&mut q);
    let [q0, q1, q2, q3, q4, q5, q6, q7] = q;
    let c0 = (q0 & M0) | (q1 & (M0 << 1)) | (q2 & (M0 << 2)) | (q3 & (M0 << 3));
    let c1 = (q4 & M0) | (q5 & (M0 << 1)) | (q6 & (M0 << 2)) | (q7 & (M0 << 3));
    [c0, c1]
}

/// The round key for four blocks from bitslice_key's bits.
fn spread_key(c: [u64; 2]) -> [u64; 8] {
    let [c0, c1] = c;
    // Each bit fills its nibble: x * 15 with one bit in four set.
    [
        (c0 & M0) * 15,
        ((c0 >> 1) & M0) * 15,
        ((c0 >> 2) & M0) * 15,
        ((c0 >> 3) & M0) * 15,
        (c1 & M0) * 15,
        ((c1 >> 1) & M0) * 15,
        ((c1 >> 2) & M0) * 15,
        ((c1 >> 3) & M0) * 15,
    ]
}

/// Spreads the 16-bit halves of a word to every other byte of two words.
fn interleave_in(w: [u32; 4]) -> (u64, u64) {
    let [x0, x1, x2, x3] = w.map(|x| {
        let x = u64::from(x);
        let x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
        (x | (x << 8)) & 0x00FF_00FF_00FF_00FF
    });
    (x0 | (x2 << 8), x1 | (x3 << 8))
}

fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    const M: u64 = 0x00FF_00FF_00FF_00FF;
    [q0 & M, q1 & M, (q0 >> 8) & M, (q1 >> 8) & M].map(|x| {
        let x = (x | (x >> 8)) & 0x0000_FFFF_0000_FFFF;
        // The high half is masked out above.
        low32((x | (x >> 16)) & 0xFFFF_FFFF)
    })
}

/// Swaps bits of x and y under masks: the transposition to and from the
/// bitsliced form, its own inverse.
fn ortho(q: &mut [u64; 8]) {
    fn swap(x: u64, y: u64, cl: u64, s: u32) -> (u64, u64) {
        let ch = !cl;
        ((x & cl) | ((y & cl) << s), ((x & ch) >> s) | (y & ch))
    }
    const C2: u64 = 0x5555_5555_5555_5555;
    const C4: u64 = 0x3333_3333_3333_3333;
    const C8: u64 = 0x0F0F_0F0F_0F0F_0F0F;
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let (q0, q1) = swap(q0, q1, C2, 1);
    let (q2, q3) = swap(q2, q3, C2, 1);
    let (q4, q5) = swap(q4, q5, C2, 1);
    let (q6, q7) = swap(q6, q7, C2, 1);
    let (q0, q2) = swap(q0, q2, C4, 2);
    let (q1, q3) = swap(q1, q3, C4, 2);
    let (q4, q6) = swap(q4, q6, C4, 2);
    let (q5, q7) = swap(q5, q7, C4, 2);
    let (q0, q4) = swap(q0, q4, C8, 4);
    let (q1, q5) = swap(q1, q5, C8, 4);
    let (q2, q6) = swap(q2, q6, C8, 4);
    let (q3, q7) = swap(q3, q7, C8, 4);
    *q = [q0, q1, q2, q3, q4, q5, q6, q7];
}

/// Ten or fourteen rounds on four bitsliced blocks, the round keys from
/// sk[first] on.
fn encrypt(sk: &[[u64; 8]; ROUND_KEYS], first: usize, q: &mut [u64; 8]) {
    let [keys @ .., last] = sk;
    let mut keys = keys.iter().skip(first);
    if let Some(k) = keys.next() {
        add_round_key(q, k);
    }
    for k in keys {
        sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, k);
    }
    sbox(q);
    shift_rows(q);
    add_round_key(q, last);
}

fn add_round_key(q: &mut [u64; 8], k: &[u64; 8]) {
    for (x, y) in q.iter_mut().zip(k) {
        *x ^= y;
    }
}

fn shift_rows(q: &mut [u64; 8]) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_FFFF)
            | ((v & 0x0000_0000_FFF0_0000) >> 4)
            | ((v & 0x0000_0000_000F_0000) << 12)
            | ((v & 0x0000_FF00_0000_0000) >> 8)
            | ((v & 0x0000_00FF_0000_0000) << 8)
            | ((v & 0xF000_0000_0000_0000) >> 12)
            | ((v & 0x0FFF_0000_0000_0000) << 4);
    }
}

fn mix_columns(q: &mut [u64; 8]) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let [r0, r1, r2, r3, r4, r5, r6, r7] = q.map(|x| x.rotate_right(16));
    let rot = |x: u64| x.rotate_right(32);
    *q = [
        q7 ^ r7 ^ r0 ^ rot(q0 ^ r0),
        q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rot(q1 ^ r1),
        q1 ^ r1 ^ r2 ^ rot(q2 ^ r2),
        q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rot(q3 ^ r3),
        q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rot(q4 ^ r4),
        q4 ^ r4 ^ r5 ^ rot(q5 ^ r5),
        q5 ^ r5 ^ r6 ^ rot(q6 ^ r6),
        q6 ^ r6 ^ r7 ^ rot(q7 ^ r7),
    ];
}

/// The S-box as Boyar and Peralta's circuit of 113 gates
/// (eprint.iacr.org/2009/191); x0 is the high bit, q[7].
fn sbox(q: &mut [u64; 8]) {
    let [x7, x6, x5, x4, x3, x2, x1, x0] = *q;

    // The top linear layer.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // The nonlinear middle: inversion in GF(2^4)^2.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // The bottom linear layer, with the affine constant 0x63.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

// rr: section(tests = yes)
/// Any bytes as a record: the instructions and the portable code agree,
/// it opens to what was sealed, and a flipped bit does not open.
#[cfg(fuzzing)]
pub fn fuzz_seal_open(input: &[u8]) {
    let Some((&split, rest)) = input.split_first() else {
        return;
    };
    let (aad, msg) = rest.split_at(usize::from(split).min(rest.len()));
    let key = [0x42; KEY_LEN];
    let nonce = [0x24; NONCE_LEN];
    let (fast, slow) = (AesGcm::new(&key), AesGcm::with(&key, false));
    // rr: escape(copy): the record is sealed in place, twice.
    let mut a = msg.to_vec();
    // rr: escape(copy): the record is sealed in place, twice.
    let mut b = msg.to_vec();
    let ta = fast.seal_with_nonce(&nonce, aad, &mut a).unwrap();
    let tb = slow.seal_with_nonce(&nonce, aad, &mut b).unwrap();
    assert_eq!(a, b);
    assert_eq!(ta, tb);
    if let Some(x) = b.first_mut() {
        *x ^= 1;
        let forged = slow.open_with_nonce(&nonce, aad, &mut b, ta.bytes());
        assert!(matches!(forged, Err(Error::Forged)));
    }
    fast.open_with_nonce(&nonce, aad, &mut a, ta.bytes())
        .unwrap();
    assert_eq!(a, msg);
}
// rr: end(tests = yes)

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    use super::{AesGcm, Error, OpeningKey, SealingKey, hw};
    use alloc::vec::Vec;
    use test::Bencher;

    fn unhex(s: &str) -> Vec<u8> {
        let d = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            _ => c - b'a' + 10,
        };
        let mut v = Vec::new();
        for p in s.as_bytes().chunks(2) {
            v.push((d(p[0]) << 4) | d(p[1]));
        }
        v
    }

    /// The instructions where the CPU has them, and the portable code,
    /// for a key of 16 or 32 bytes.
    fn both(k: &str) -> [AesGcm; 2] {
        let key = unhex(k);
        assert!(matches!(key.len(), 16 | 32));
        [
            AesGcm::with(&key, hw::available()),
            AesGcm::with(&key, false),
        ]
    }

    /// Seals pt, checks ct and tag, then opens it back.
    fn vector(g: &AesGcm, nonce: &str, aad: &str, pt: &str, ct: &str, tag: &str) {
        let nonce: [u8; 12] = unhex(nonce).try_into().unwrap();
        let aad = unhex(aad);
        let mut data = unhex(pt);
        let t = g.seal_with_nonce(&nonce, &aad, &mut data).unwrap();
        assert_eq!(data, unhex(ct));
        assert_eq!(t.bytes()[..], unhex(tag)[..]);
        g.open_with_nonce(&nonce, &aad, &mut data, t.bytes())
            .unwrap();
        assert_eq!(data, unhex(pt));
    }

    // rr: section(os = macos)
    // rr: section(arch = aarch64)
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    fn apple_silicon_has_the_instructions() {
        assert!(hw::available());
        assert!(AesGcm::new(&[0; 16]).hw);
        assert!(AesGcm::new256(&[0; 32]).hw);
    }
    // rr: end(arch = aarch64)
    // rr: end(os = macos)

    /// FIPS 197 appendices C.1 and C.3, through the counter: E(K, P) is
    /// the key stream of the counter block P.
    #[test]
    fn fips197() {
        let key128 = "000102030405060708090a0b0c0d0e0f";
        let key256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        for (k, c) in [
            (key128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (key256, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            for g in both(k) {
                let p: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
                    .try_into()
                    .unwrap();
                let counter = u32::from_be_bytes(p[12..].try_into().unwrap());
                let mut block = p;
                block[12..].fill(0);
                let mut out = [0; 16];
                g.ctr(&block, counter, &mut out);
                assert_eq!(out[..], unhex(c)[..]);
            }
        }
    }

    /// FIPS 197 A.3's AES-256 key expansion: the last round key.
    #[test]
    fn key_expansion_256() {
        let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let g = AesGcm::with(&key, false);
        assert_eq!(g.rk.first, 0);
        assert_eq!(
            g.rk.keys[14][..],
            unhex("fe4890d1e6188d0b046df344706c631e")[..]
        );
        let short = AesGcm::with(&key[..16], false);
        assert_eq!(short.rk.first, hw::AES128_FIRST);
    }

    /// McGrew and Viega's test cases 1 to 4, and 13 to 16 of AES-256.
    #[test]
    fn gcm_spec() {
        let z = "00000000000000000000000000000000";
        let n = "000000000000000000000000";
        for g in both(z) {
            vector(&g, n, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
            let ct = "0388dace60b6a392f328c2b971b2fe78";
            vector(&g, n, "", z, ct, "ab6e47d42cec13bdf53a67b21257bddf");
        }
        let pt = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                  1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let ct = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                  21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let pt4 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                   1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let ct4 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                   21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
        let nonce = "cafebabefacedbaddecaf888";
        let aad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        for g in both("feffe9928665731c6d6a8f9467308308") {
            vector(&g, nonce, "", pt, ct, "4d5c2af327cd64a62cf35abd2ba6fab4");
            vector(&g, nonce, aad, pt4, ct4, "5bc94fbc3221a5db94fae95ae7121a47");
        }
        let z256 = "0000000000000000000000000000000000000000000000000000000000000000";
        for g in both(z256) {
            vector(&g, n, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b");
            let zeros = "cea7403d4d606b6e074ec5d3baf39d18";
            vector(&g, n, "", z, zeros, "d0d1c8a799996bf0265b98b5d48ab919");
        }
        let ct15 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad";
        let ct16 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                    8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        for g in both("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308") {
            vector(&g, nonce, "", pt, ct15, "b094dac5d93471bdec1a502270e3cc6c");
            vector(
                &g,
                nonce,
                aad,
                pt4,
                ct16,
                "76fc6ece0f4e1768cddf8853bb2d551b",
            );
        }
    }

    /// A 12-byte nonce with AAD and a partial block: NIST's GCM validation
    /// vectors (gcmEncryptExtIV128 and 256, IVlen 96, PTlen 408, AADlen
    /// 160, Count 0), and one with AAD alone (PTlen 0, AADlen 128, Count
    /// 0).
    #[test]
    fn nist_cavp() {
        for g in both("fe47fcce5fc32665d2ae399e4eec72ba") {
            vector(
                &g,
                "5adb9609dbaeb58cbd6e7275",
                "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
                "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60\
                 e743f1b840382c4bccaf3bafb4ca8429bea063",
                "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf539304373\
                 6365253ddbc5db8778371495da76d269e5db3e",
                "291ef1982e4defedaa2249f898556b47",
            );
        }
        for g in both("77be63708971c4e240d1cb79e8d77feb") {
            vector(
                &g,
                "e0e00f19fed7ba0136a797f3",
                "7a43ec1d9c0a5a78a0b16533a6213cab",
                "",
                "",
                "209fcc8d3675ed938e9c7166709dd946",
            );
        }
        for g in both("24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f") {
            vector(
                &g,
                "9ff18563b978ec281b3f2794",
                "adb5ec720ccf9898500028bf34afccbcaca126ef",
                "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86\
                 757accb158bd9abb3868fdc0d0b074b5f01b2c",
                "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b0614\
                 5dae82057ad55994cf59ad7f67c0fa5e85fab8",
                "bc95c532fecc594c36d1550286a7a3f0",
            );
        }
        for g in both("78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223") {
            vector(
                &g,
                "d79cf22d504cc793c3fb6c8a",
                "b96baa8c1c75a671bfb2d08d06be5f36",
                "",
                "",
                "3e5d486aa2e30b22e040b85723a06e76",
            );
        }
    }

    /// The 8 fields of a case's line, split at spaces.
    fn fields(line: &str) -> [&str; 8] {
        let mut out = [""; 8];
        let mut words = line.split(' ');
        for slot in &mut out {
            *slot = words.next().unwrap();
        }
        assert!(words.next().is_none(), "{line}");
        out
    }

    /// Wycheproof's aes_gcm_test, the cases of a 128- or 256-bit key, a
    /// 96-bit nonce and a 128-bit tag (aesgcm-wycheproof.py), on both paths: a
    /// valid one seals to its ciphertext and tag and opens back; an
    /// invalid one is refused and leaves the ciphertext.
    #[test]
    fn wycheproof() {
        let field = |text: &str| if text == "-" { Vec::new() } else { unhex(text) };
        let mut cases = 0;
        for line in include_str!("aesgcm-wycheproof.txt").lines() {
            if line.starts_with('#') {
                continue;
            }
            let [id, valid, k, nonce, aad, pt, ct, tag] = fields(line);
            let nonce: [u8; 12] = unhex(nonce).try_into().unwrap();
            let tag: [u8; 16] = unhex(tag).try_into().unwrap();
            let aad = field(aad);
            for g in both(k) {
                if valid == "1" {
                    let mut data = field(pt);
                    let sealed = g.seal_with_nonce(&nonce, &aad, &mut data).unwrap();
                    assert_eq!((data, *sealed.bytes()), (field(ct), tag), "tcId {id}");
                }
                let mut data = field(ct);
                let opened = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
                assert_eq!(opened.is_ok(), valid == "1", "tcId {id}");
                let expected = if valid == "1" { field(pt) } else { field(ct) };
                assert_eq!(data, expected, "tcId {id}");
            }
            cases += 1;
        }
        assert_eq!(cases, 133);
    }

    /// A changed tag, ciphertext, AAD or nonce is refused, and the data is
    /// left the ciphertext it came as.
    #[test]
    fn rejects_forgeries() {
        let nonce = [7; 12];
        let mut aad = [0xfe, 0xed, 0xfa, 0xce];
        for g in both("feffe9928665731c6d6a8f9467308308") {
            let mut data = [0x5a; 300];
            let mut tag = *g.seal_with_nonce(&nonce, &aad, &mut data).unwrap().bytes();
            let ct = data;
            tag[3] ^= 1;
            let bad_tag = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_tag, Err(Error::Forged)));
            tag[3] ^= 1;
            data[57] ^= 0x80;
            let bad_ct = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_ct, Err(Error::Forged)));
            data[57] ^= 0x80;
            assert_eq!(data, ct);
            aad[0] ^= 1;
            let bad_aad = g.open_with_nonce(&nonce, &aad, &mut data, &tag);
            assert!(matches!(bad_aad, Err(Error::Forged)));
            aad[0] ^= 1;
            let bad_nonce = g.open_with_nonce(&[8; 12], &aad, &mut data, &tag);
            assert!(matches!(bad_nonce, Err(Error::Forged)));
            assert_eq!(data, ct);
            g.open_with_nonce(&nonce, &aad, &mut data, &tag).unwrap();
            assert_eq!(data, [0x5a; 300]);
        }
    }

    /// The instructions and the portable code agree on every length to
    /// past three eight-block turns, at every alignment, with AAD of each
    /// length to past two blocks.
    #[test]
    fn paths_agree() {
        paths_agree_key(&[0x5a; 16]);
        paths_agree_key(&[0x5a; 32]);
    }

    fn paths_agree_key(k: &[u8]) {
        let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
        let mut aad = [0; 41];
        for (i, a) in aad.iter_mut().enumerate() {
            *a = u8::try_from(i).unwrap();
        }
        let mut buf = [0u8; 800];
        let mut x = 3u8;
        for b in &mut buf {
            *b = x;
            x = x.wrapping_add(7);
        }
        let mut other = buf;
        for n in 0..400 {
            let at = n % 17;
            let aad = &aad[..n % 41];
            let nonce = [u8::try_from(n % 256).unwrap(); 12];
            let a = &mut buf[at..at + n];
            let b = &mut other[at + 1..at + 1 + n];
            b.copy_from_slice(a);
            let ta = fast.seal_with_nonce(&nonce, aad, a).unwrap();
            let tb = slow.seal_with_nonce(&nonce, aad, b).unwrap();
            assert_eq!(a, b, "length {n}");
            assert_eq!(ta, tb, "length {n}");
            slow.open_with_nonce(&nonce, aad, a, ta.bytes()).unwrap();
            fast.open_with_nonce(&nonce, aad, b, tb.bytes()).unwrap();
            assert_eq!(a, b);
        }
    }

    /// The 32-bit counter wraps the same way on both paths, and only the
    /// counter: block 6 of a run from 2^32 - 6 is counter 0.
    #[test]
    fn counter_wraps() {
        for k in [&[0x11; 16][..], &[0x11; 32]] {
            let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
            let mut block = [0x33; 16];
            block[12..].fill(0);
            let mut a = [0; 200];
            let mut b = [0; 200];
            fast.ctr(&block, u32::MAX - 5, &mut a);
            slow.ctr(&block, u32::MAX - 5, &mut b);
            assert_eq!(a, b);
            let mut c = [0; 16];
            slow.ctr(&block, 0, &mut c);
            assert_eq!(a[96..112], c);
        }
    }

    /// CTR alone, as tag masks and a refused open use it, agrees on every
    /// length: whole groups of four blocks, the blocks after, a part.
    #[test]
    fn ctr_paths_agree() {
        for k in [&[0x77; 16][..], &[0x77; 32]] {
            let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
            let block = [
                0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0, 0, 0, 0,
            ];
            for n in 0..200 {
                let mut a = [0; 200];
                let mut b = [0; 200];
                fast.ctr(&block, 2, &mut a[..n]);
                slow.ctr(&block, 2, &mut b[..n]);
                assert_eq!(a, b, "length {n}");
            }
        }
    }

    /// The one-pass seal and open wrap the 32-bit counter as CTR does, and
    /// agree with the portable CTR and GHASH: two eight-block turns and
    /// five blocks after.
    #[test]
    fn stitched_counter_wraps() {
        if !hw::available() {
            return;
        }
        for k in [&[0x11; 16][..], &[0x11; 32]] {
            stitched_counter_wraps_key(k);
        }
    }

    fn stitched_counter_wraps_key(k: &[u8]) {
        let [fast, slow] = [AesGcm::with(k, true), AesGcm::with(k, false)];
        let mut block = [0x33; 16];
        block[12..].fill(0);
        let start = u32::MAX - 9;
        let mut a = [[0x5a; 16]; 21];
        let mut b = a;
        let (mut ya, mut yb, mut yo) = ([1; 16], [1; 16], [1; 16]);
        assert!(hw::seal(
            &fast.rk, &fast.htbl, &block, start, &mut a, &mut ya
        ));
        slow.ctr(&block, start, b.as_flattened_mut());
        slow.ghash(&mut yb, b.as_flattened());
        assert_eq!(a, b);
        assert_eq!(ya, yb);
        assert!(hw::open(
            &fast.rk, &fast.htbl, &block, start, &mut a, &mut yo
        ));
        assert_eq!(yo, yb);
        assert_eq!(a, [[0x5a; 16]; 21]);
    }

    /// A whole TLS record, past the strides many times, agrees as well.
    #[test]
    fn long_records() {
        long_record(&[0x42; 16]);
        long_record(&[0x42; 32]);
    }

    fn long_record(k: &[u8]) {
        let [fast, slow] = [AesGcm::with(k, hw::available()), AesGcm::with(k, false)];
        let mut a = Vec::new();
        a.resize(16384 + 5, 0x91);
        // rr: escape(copy): the same record, sealed by the other path.
        let mut b = a.clone();
        let aad = [0x17; 13];
        let ta = fast.seal_with_nonce(&[1; 12], &aad, &mut a).unwrap();
        let tb = slow.seal_with_nonce(&[1; 12], &aad, &mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(ta, tb);
    }

    /// As TLS uses the keys: one side seals records in turn and the other
    /// opens them, each under the next number; a record opened out of
    /// turn, or twice, is Forged; TooLong takes no number; Exhausted at
    /// the last number, on both sides.
    #[test]
    fn numbered_loop() {
        let iv = [0xa0; 12];
        numbered(
            SealingKey::new(&[0x3c; 16], &iv),
            OpeningKey::new(&[0x3c; 16], &iv),
            &iv,
        );
        numbered(
            SealingKey::new256(&[0x3c; 32], &iv),
            OpeningKey::new256(&[0x3c; 32], &iv),
            &iv,
        );
        let mut sealing = SealingKey::new(&[1; 16], &[2; 12]);
        let mut opening = OpeningKey::new(&[1; 16], &[2; 12]);
        sealing.set_sequence_less_safe(u64::MAX - 1);
        opening.set_sequence_for_tests(u64::MAX - 1);
        let mut data = [9; 20];
        let tag = sealing.seal(&[], &mut data).unwrap();
        assert_eq!(opening.open(&[], &mut data, tag.bytes()), Ok(()));
        assert_eq!(data, [9; 20]);
        assert_eq!(sealing.seal(&[], &mut data), Err(Error::Exhausted));
        assert_eq!(data, [9; 20]);
        assert_eq!(
            opening.open(&[], &mut data, tag.bytes()),
            Err(Error::Exhausted)
        );
        assert_eq!(sealing.sequence(), u64::MAX);
        assert_eq!(opening.sequence(), u64::MAX);
    }

    /// Five records sealed in turn, and opened by the other side.
    fn numbered(mut sealing: SealingKey, mut opening: OpeningKey, iv: &[u8; 12]) {
        let mut records = Vec::new();
        for n in 0..5_u8 {
            let mut data = [n; 33];
            let tag = sealing.seal(&[n], &mut data).unwrap();
            records.push((data, tag));
        }
        assert_eq!(sealing.sequence(), 5);
        // Number n is the IV XOR n: what seal_with_nonce gives.
        let mut nonce = *iv;
        nonce[11] ^= 3;
        let mut third = [3; 33];
        let again = sealing
            .key
            .seal_with_nonce(&nonce, &[3], &mut third)
            .unwrap();
        assert_eq!((third, &again), (records[3].0, &records[3].1));
        // Out of turn: record 1 under number 0.
        let mut early = records[1].0;
        let forged = opening.open(&[1], &mut early, records[1].1.bytes());
        assert_eq!(forged, Err(Error::Forged));
        assert_eq!(early, records[1].0);
        assert_eq!(opening.sequence(), 1);
        for (n, (data, tag)) in records.iter_mut().enumerate().skip(1) {
            let n = u8::try_from(n).unwrap();
            assert_eq!(opening.open(&[n], data, tag.bytes()), Ok(()));
            assert_eq!(*data, [n; 33]);
        }
        assert_eq!(opening.sequence(), 5);
    }

    /// One TLS record of 16 KiB with its 5-byte header as AAD.
    fn seal_record(b: &mut Bencher, g: &AesGcm) {
        let mut record = Vec::new();
        record.resize(16384, 0x17);
        let aad = [0x17, 3, 3, 0x40, 0x11];
        b.iter(|| g.seal_with_nonce(&[9; 12], &aad, &mut record).unwrap());
    }

    #[bench]
    fn seal_16k(b: &mut Bencher) {
        seal_record(b, &AesGcm::new(&[7; 16]));
    }

    #[bench]
    fn seal_16k_256(b: &mut Bencher) {
        seal_record(b, &AesGcm::new256(&[7; 32]));
    }

    /// The portable code, which a CPU without the instructions takes.
    #[bench]
    fn seal_16k_portable(b: &mut Bencher) {
        seal_record(b, &AesGcm::with(&[7; 16], false));
    }

    /// A record sealed and opened again, as one side of a connection
    /// sends and the other receives it, each key numbering its nonces.
    #[bench]
    fn seal_open_16k(b: &mut Bencher) {
        let mut sealing = SealingKey::new(&[7; 16], &[9; 12]);
        let mut opening = OpeningKey::new(&[7; 16], &[9; 12]);
        let mut record = Vec::new();
        record.resize(16384, 0x17);
        let aad = [0x17, 3, 3, 0x40, 0x11];
        b.iter(|| {
            let tag = sealing.seal(&aad, &mut record).unwrap();
            opening.open(&aad, &mut record, tag.bytes()).unwrap();
        });
    }
}
// rr: end(tests = yes)
