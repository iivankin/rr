//! SHA-512 compression, SHA-384's too, on Armv8.2's SHA512
//! instructions. Not every CPU has them, so compress says whether it ran
//! and the caller keeps its portable rounds. x86_64 has such
//! instructions only on its newest CPUs, which this code does not reach.

#[cfg(target_arch = "aarch64")]
use crate::base::cpu;

/// Compresses blocks into state, true when the instructions ran; false,
/// and state untouched, on a CPU without them.
#[cfg(target_arch = "aarch64")]
pub fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) -> bool {
    if !cpu::has(&cpu::SHA512) {
        return false;
    }
    // rr: escape(unsafe): the CPU has SHA512.
    unsafe { arm::compress(state, blocks) };
    true
}

/// No SHA-512 instructions this code knows on this architecture.
#[cfg(not(target_arch = "aarch64"))]
pub fn compress(_state: &mut [u64; 8], _blocks: &[[u8; 128]]) -> bool {
    false
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use crate::base::sha384::ROUND;
    use core::arch::aarch64::{
        uint64x2_t, vaddq_u64, vextq_u64, vld1q_u8, vld1q_u64, vreinterpretq_u64_u8, vrev64q_u8,
        vsha512h2q_u64, vsha512hq_u64, vsha512su0q_u64, vsha512su1q_u64, vst1q_u64,
    };

    type V = uint64x2_t;

    /// Two rounds a step, as the Linux kernel's sha512-ce-core.S takes
    /// them: the state is four pairs, ab, cd, ef and gh, whose roles move
    /// on by one each step and come back after four. The schedule runs
    /// eight pairs of words ahead, so each step makes the pair the step
    /// eight later takes. Eight steps, a whole turn of the schedule, are
    /// written out: kept in an array moved on a step at a time, the pairs
    /// and the roles were copied between registers every step.
    #[target_feature(enable = "sha3")]
    // rr: escape(unsafe): the caller must have found SHA512.
    pub(super) unsafe fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
        let (pairs, _) = state.as_chunks_mut::<2>();
        let [p0, p1, p2, p3] = pairs else {
            return;
        };
        let (mut ab, mut cd, mut ef, mut gh) = (load(p0), load(p1), load(p2), load(p3));
        for block in blocks {
            let start = (ab, cd, ef, gh);
            let [g0, g1, g2, g3, g4, g5, g6, g7] = block.as_chunks::<16>().0 else {
                return;
            };
            let (mut w0, mut w1, mut w2, mut w3) =
                (message(g0), message(g1), message(g2), message(g3));
            let (mut w4, mut w5, mut w6, mut w7) =
                (message(g4), message(g5), message(g6), message(g7));
            for constants in ROUND.as_chunks::<16>().0 {
                let [k0, k1, k2, k3, k4, k5, k6, k7] = constants.as_chunks::<2>().0 else {
                    return;
                };
                rounds(&mut cd, &mut gh, ab, ef, vaddq_u64(w0, load(k0)));
                w0 = schedule(w0, w1, w7, w4, w5);
                rounds(&mut ab, &mut ef, gh, cd, vaddq_u64(w1, load(k1)));
                w1 = schedule(w1, w2, w0, w5, w6);
                rounds(&mut gh, &mut cd, ef, ab, vaddq_u64(w2, load(k2)));
                w2 = schedule(w2, w3, w1, w6, w7);
                rounds(&mut ef, &mut ab, cd, gh, vaddq_u64(w3, load(k3)));
                w3 = schedule(w3, w4, w2, w7, w0);
                rounds(&mut cd, &mut gh, ab, ef, vaddq_u64(w4, load(k4)));
                w4 = schedule(w4, w5, w3, w0, w1);
                rounds(&mut ab, &mut ef, gh, cd, vaddq_u64(w5, load(k5)));
                w5 = schedule(w5, w6, w4, w1, w2);
                rounds(&mut gh, &mut cd, ef, ab, vaddq_u64(w6, load(k6)));
                w6 = schedule(w6, w7, w5, w2, w3);
                rounds(&mut ef, &mut ab, cd, gh, vaddq_u64(w7, load(k7)));
                w7 = schedule(w7, w0, w6, w3, w4);
            }
            ab = vaddq_u64(ab, start.0);
            cd = vaddq_u64(cd, start.1);
            ef = vaddq_u64(ef, start.2);
            gh = vaddq_u64(gh, start.3);
        }
        for (pair, h) in [p0, p1, p2, p3].into_iter().zip([ab, cd, ef, gh]) {
            // rr: escape(unsafe): pair is two words of the caller's state.
            unsafe { vst1q_u64(pair.as_mut_ptr(), h) };
        }
    }

    /// The pair eight steps after oldest: from it and the pair after it,
    /// the newest, and the two four and five steps on.
    #[target_feature(enable = "sha3")]
    fn schedule(oldest: V, next: V, newest: V, fourth: V, fifth: V) -> V {
        let early = vsha512su0q_u64(oldest, next);
        vsha512su1q_u64(early, newest, vextq_u64::<1>(fourth, fifth))
    }

    /// Two rounds on the state in the roles this step gives it: a, c, e
    /// and g, of which c and g change. words is the step's two message
    /// words with their constants added.
    #[target_feature(enable = "sha3")]
    fn rounds(c: &mut V, g: &mut V, a: V, e: V, words: V) {
        let sum = vaddq_u64(vextq_u64::<1>(words, words), *g);
        let partial = vsha512hq_u64(sum, vextq_u64::<1>(e, *g), vextq_u64::<1>(*c, e));
        *g = vsha512h2q_u64(partial, *c, a);
        *c = vaddq_u64(*c, partial);
    }

    #[target_feature(enable = "neon")]
    fn load(words: &[u64; 2]) -> V {
        // rr: escape(unsafe): words is two u64s.
        unsafe { vld1q_u64(words.as_ptr()) }
    }

    /// Two big-endian words of a block.
    #[target_feature(enable = "neon")]
    fn message(group: &[u8; 16]) -> V {
        // rr: escape(unsafe): group is sixteen bytes.
        vreinterpretq_u64_u8(vrev64q_u8(unsafe { vld1q_u8(group.as_ptr()) }))
    }
}
