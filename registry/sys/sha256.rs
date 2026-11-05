//! SHA-256 compression on the CPU's own instructions: the Armv8 SHA2
//! extension on aarch64, SHA-NI on x86_64. Not every CPU has them, so
//! compress says whether it ran and the caller keeps its portable rounds.

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use crate::sys::cpu;

/// Compresses blocks into state, true when the instructions ran; false,
/// and state untouched, on a CPU without them.
#[cfg(target_arch = "aarch64")]
pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) -> bool {
    if !cpu::has(cpu::SHA256) {
        return false;
    }
    // rr: escape(unsafe): the CPU has the SHA2 extension.
    unsafe { arm::compress(state, blocks) };
    true
}

/// Compresses blocks into state, true when the instructions ran; false,
/// and state untouched, on a CPU without them.
#[cfg(target_arch = "x86_64")]
pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) -> bool {
    if !cpu::has(cpu::SHA256) {
        return false;
    }
    // rr: escape(unsafe): the CPU has SHA-NI, SSSE3 and SSE4.1.
    unsafe { x86::compress(state, blocks) };
    true
}

/// No SHA-256 instructions this code knows on this architecture.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub fn compress(_state: &mut [u32; 8], _blocks: &[[u8; 64]]) -> bool {
    false
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use crate::sha256::ROUND;
    use core::arch::aarch64::{
        uint32x4_t, vaddq_u32, vld1q_u8, vld1q_u32, vreinterpretq_u32_u8, vrev32q_u8,
        vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };

    /// Four rounds a step; the schedule runs four groups of four words
    /// ahead, so each step makes the group a later step takes.
    #[target_feature(enable = "sha2")]
    // rr: escape(unsafe): the caller must have found the SHA2 extension.
    pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        let (halves, _) = state.as_chunks_mut::<4>();
        let [low, high] = halves else {
            return;
        };
        let mut abcd = load_words(low);
        let mut efgh = load_words(high);
        for block in blocks {
            let (abcd_start, efgh_start) = (abcd, efgh);
            let [g0, g1, g2, g3] = block.as_chunks::<16>().0 else {
                return;
            };
            let (mut w0, mut w1) = (message(g0), message(g1));
            let (mut w2, mut w3) = (message(g2), message(g3));
            for constants in ROUND.as_chunks::<4>().0 {
                let sum = vaddq_u32(w0, load_words(constants));
                rounds(&mut abcd, &mut efgh, sum);
                let next = vsha256su1q_u32(vsha256su0q_u32(w0, w1), w2, w3);
                (w0, w1, w2, w3) = (w1, w2, w3, next);
            }
            abcd = vaddq_u32(abcd, abcd_start);
            efgh = vaddq_u32(efgh, efgh_start);
        }
        // rr: escape(unsafe): low is four words of the caller's state.
        unsafe { vst1q_u32(low.as_mut_ptr(), abcd) };
        // rr: escape(unsafe): high is the other four.
        unsafe { vst1q_u32(high.as_mut_ptr(), efgh) };
    }

    /// Four rounds: SHA256H on abcd in place, SHA256H2 on a copy of the
    /// abcd it read. With vsha256hq_u32, LLVM copies abcd into the
    /// register SHA256H then overwrites, which puts the copy between one
    /// SHA256H and the next: 6.3 us for 16 KiB on an M4 Pro, 5.4 us so.
    #[target_feature(enable = "sha2")]
    fn rounds(abcd: &mut uint32x4_t, efgh: &mut uint32x4_t, sum: uint32x4_t) {
        // rr: escape(unsafe): registers only; SHA2 is enabled here.
        unsafe {
            core::arch::asm!(
                "mov {before:v}.16b, {abcd:v}.16b",
                "sha256h {abcd:q}, {efgh:q}, {sum:v}.4s",
                "sha256h2 {efgh:q}, {before:q}, {sum:v}.4s",
                abcd = inout(vreg) *abcd,
                efgh = inout(vreg) *efgh,
                sum = in(vreg) sum,
                before = out(vreg) _,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
    }

    #[target_feature(enable = "neon")]
    fn load_words(words: &[u32; 4]) -> uint32x4_t {
        // rr: escape(unsafe): words is four u32s.
        unsafe { vld1q_u32(words.as_ptr()) }
    }

    /// Four big-endian words of a block.
    #[target_feature(enable = "neon")]
    fn message(group: &[u8; 16]) -> uint32x4_t {
        // rr: escape(unsafe): group is sixteen bytes.
        let bytes = unsafe { vld1q_u8(group.as_ptr()) };
        vreinterpretq_u32_u8(vrev32q_u8(bytes))
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use crate::sha256::ROUND;
    use core::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
        _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
        _mm_shuffle_epi32, _mm_storeu_si128,
    };

    /// SHA-NI keeps the state as ABEF and CDGH, two rounds a call; the
    /// shuffles at entry and exit turn the a..h order into those and back.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    // rr: escape(unsafe): the caller must have found SHA-NI and SSE4.1.
    pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        let (halves, _) = state.as_chunks_mut::<4>();
        let [low, high] = halves else {
            return;
        };
        let dcba = load_words(low);
        let hgfe = load_words(high);
        let cdab = _mm_shuffle_epi32::<0xb1>(dcba);
        let efgh = _mm_shuffle_epi32::<0x1b>(hgfe);
        let mut abef = _mm_alignr_epi8::<8>(cdab, efgh);
        let mut cdgh = _mm_blend_epi16::<0xf0>(efgh, cdab);
        for block in blocks {
            let (abef_start, cdgh_start) = (abef, cdgh);
            let [g0, g1, g2, g3] = block.as_chunks::<16>().0 else {
                return;
            };
            let (mut w0, mut w1) = (message(g0), message(g1));
            let (mut w2, mut w3) = (message(g2), message(g3));
            for constants in ROUND.as_chunks::<4>().0 {
                let sum = _mm_add_epi32(w0, load_words(constants));
                // Each call makes the new ABEF; the old one is the new CDGH.
                cdgh = _mm_sha256rnds2_epu32(cdgh, abef, sum);
                abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32::<0x0e>(sum));
                let early = _mm_sha256msg1_epu32(w0, w1);
                let next = _mm_add_epi32(early, _mm_alignr_epi8::<4>(w3, w2));
                (w0, w1, w2, w3) = (w1, w2, w3, _mm_sha256msg2_epu32(next, w3));
            }
            abef = _mm_add_epi32(abef, abef_start);
            cdgh = _mm_add_epi32(cdgh, cdgh_start);
        }
        let feba = _mm_shuffle_epi32::<0x1b>(abef);
        let dchg = _mm_shuffle_epi32::<0xb1>(cdgh);
        let low_words = _mm_blend_epi16::<0xf0>(feba, dchg);
        let high_words = _mm_alignr_epi8::<8>(dchg, feba);
        // rr: escape(unsafe): low is four words of the caller's state.
        unsafe { _mm_storeu_si128(low.as_mut_ptr().cast(), low_words) };
        // rr: escape(unsafe): high is the other four.
        unsafe { _mm_storeu_si128(high.as_mut_ptr().cast(), high_words) };
    }

    #[target_feature(enable = "sse2")]
    fn load_words(words: &[u32; 4]) -> __m128i {
        // rr: escape(unsafe): words is sixteen bytes; loadu takes any
        // alignment.
        unsafe { _mm_loadu_si128(words.as_ptr().cast()) }
    }

    /// Four big-endian words of a block.
    #[target_feature(enable = "sse2,ssse3")]
    fn message(group: &[u8; 16]) -> __m128i {
        let swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
        // rr: escape(unsafe): group is sixteen bytes; loadu takes any
        // alignment.
        let bytes = unsafe { _mm_loadu_si128(group.as_ptr().cast()) };
        _mm_shuffle_epi8(bytes, swap)
    }
}
