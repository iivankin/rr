//! SHA-384 and SHA-512 (FIPS 180-4) as digest384 and digest512, HMAC-SHA384
//! and HMAC-SHA512 (RFC 2104) with a constant-time verify, and HKDF-SHA384
//! (RFC 5869) whose Expand takes only its Prk; with SHA512 instructions where
//! the CPU has them.
//!
//! SHA-384 and SHA-512 (FIPS 180-4: one compression, from other initial
//! values, SHA-384's digest cut to 48 bytes), HMAC-SHA384 and
//! HMAC-SHA512 (RFC 2104) and HKDF-SHA384 (RFC 5869).
//! Whole blocks are compressed straight from the caller's input; only a
//! part block waits in the state. The rounds run on SHA512 instructions
//! where sys finds them, as portable code elsewhere.
//!
//! Each name says its hash: digest384 and digest512, SHA384_BYTES and
//! SHA512_BYTES. A MAC received is checked by verify, in constant time;
//! HKDF-Extract gives a Prk, the only key HKDF-Expand takes, not Copy,
//! Clone or Debug and wiped when dropped, as sha256's.

// rr: checked(0.5.2)
// rr: needs(cpu)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
// rr: file(sha384-wycheproof.txt, tests = yes)
// rr: option(arch, many): Which CPUs does it build for?
// rr: choice(arch = x86_64, default): x86-64
// rr: choice(arch = aarch64, default): AArch64 (ARM64)
// rr: choice(arch = other, default): any other, on portable code

// rr: unless(arch = x86_64)
#[cfg(target_arch = "x86_64")]
compile_error!("rr add cut sha384 without x86_64: add it again with x86_64 in --option arch");
// rr: end(arch = x86_64)
// rr: unless(arch = aarch64)
#[cfg(target_arch = "aarch64")]
compile_error!("rr add cut sha384 without aarch64: add it again with aarch64 in --option arch");
// rr: end(arch = aarch64)
// rr: unless(arch = other)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("rr add cut sha384 without other: add it again with other in --option arch");
// rr: end(arch = other)

mod sys {
    //! SHA-512 compression, SHA-384's too, on Armv8.2's SHA512
    //! instructions. Not every CPU has them, so compress says whether it ran
    //! and the caller keeps its portable rounds. x86_64 has such
    //! instructions only on its newest CPUs, which this code does not reach.

    // rr: section(arch = aarch64)
    #[cfg(target_arch = "aarch64")]
    use crate::base::cpu;
    // rr: end(arch = aarch64)

    // rr: section(arch = aarch64)
    /// Compresses blocks into state, true when the instructions ran; false,
    /// and state untouched, on a CPU without them.
    #[cfg(target_arch = "aarch64")]
    #[must_use]
    pub fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) -> bool {
        if !cpu::has(&cpu::SHA512) {
            return false;
        }
        // rr: escape(unsafe): the CPU has SHA512.
        unsafe { arm::compress(state, blocks) };
        true
    }
    // rr: end(arch = aarch64)

    // rr: section(arch = x86_64 other)
    /// No SHA-512 instructions this code knows on this architecture.
    #[cfg(not(target_arch = "aarch64"))]
    #[must_use]
    pub fn compress(_state: &mut [u64; 8], _blocks: &[[u8; 128]]) -> bool {
        false
    }
    // rr: end(arch = x86_64 other)

    // rr: section(arch = aarch64)
    #[cfg(target_arch = "aarch64")]
    mod arm {
        use crate::base::sha384::ROUND;
        use core::arch::aarch64::{
            uint64x2_t, vaddq_u64, vextq_u64, vld1q_u8, vld1q_u64, vreinterpretq_u64_u8,
            vrev64q_u8, vsha512h2q_u64, vsha512hq_u64, vsha512su0q_u64, vsha512su1q_u64, vst1q_u64,
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
    // rr: end(arch = aarch64)
}

/// The bytes of a SHA-384 digest.
pub const SHA384_BYTES: usize = 48;
/// The bytes of a SHA-512 digest.
pub const SHA512_BYTES: usize = 64;
/// The bytes of one block the compression takes.
pub const BLOCK_BYTES: usize = 128;
/// The most bytes Prk::expand writes: its counter is one byte.
pub const EXPAND_BYTES_MAX: usize = 255 * SHA384_BYTES;
/// The bytes the padding gives the message's length in bits.
const LENGTH_BYTES: usize = 16;

/// What went wrong; nothing is left changed by either.
// rr: section(tests = yes)
#[cfg_attr(test, derive(Debug, PartialEq))]
// rr: end(tests = yes)
pub enum Error {
    /// The tag is not the MAC of the message.
    Mismatch,
    /// More than EXPAND_BYTES_MAX asked of HKDF-Expand.
    TooLong,
}

const INITIAL: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// The round constants, which sys loads too.
pub const ROUND: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512's initial values.
const INITIAL512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// SHA-512 or SHA-384 in progress, which differ only in their initial
/// values and in how much of the state the digest keeps: the chaining
/// state and the part block not yet compressed.
#[derive(Clone)]
struct Hash {
    state: [u64; 8],
    block: [u8; BLOCK_BYTES],
    /// The bytes of block that hold message; always under BLOCK_BYTES.
    buffered: usize,
    /// The message's bytes so far.
    length: u64,
}

impl Hash {
    const fn new(initial: [u64; 8]) -> Self {
        Self {
            state: initial,
            block: [0; BLOCK_BYTES],
            buffered: 0,
            length: 0,
        }
    }

    #[cfg_attr(rr, rr::hot)]
    fn update(&mut self, data: &[u8]) {
        // 2^64 bytes take centuries to hash; the count wraps there.
        self.length = self.length.wrapping_add(data.len() as u64);
        let mut rest = data;
        if self.buffered > 0 {
            let taken = (BLOCK_BYTES - self.buffered).min(rest.len());
            let (head, tail) = rest.split_at(taken);
            let end = self.buffered + taken;
            // rr: escape(copy, panic): a part block waits for the rest of
            // it, and taken is at most what is free there.
            self.block[self.buffered..end].copy_from_slice(head);
            self.buffered = end;
            if end < BLOCK_BYTES {
                return;
            }
            compress(&mut self.state, core::slice::from_ref(&self.block));
            rest = tail;
        }
        let (blocks, tail) = rest.as_chunks::<BLOCK_BYTES>();
        compress(&mut self.state, blocks);
        // rr: escape(copy, panic): the part block must outlive the caller's
        // buffer; as_chunks leaves fewer than BLOCK_BYTES.
        self.block[..tail.len()].copy_from_slice(tail);
        self.buffered = tail.len();
    }

    /// The whole final state, of which SHA-384 keeps the first 48 bytes.
    fn finish(mut self) -> [u8; SHA512_BYTES] {
        assert!(self.buffered < BLOCK_BYTES);
        // rr: escape(panic): buffered is under BLOCK_BYTES after update.
        self.block[self.buffered] = 0x80;
        // rr: escape(panic): buffered + 1 is at most BLOCK_BYTES.
        self.block[self.buffered + 1..].fill(0);
        if self.buffered >= BLOCK_BYTES - LENGTH_BYTES {
            compress(&mut self.state, core::slice::from_ref(&self.block));
            self.block = [0; BLOCK_BYTES];
        }
        let bits = (u128::from(self.length) << 3).to_be_bytes();
        for (byte, length) in self.block.iter_mut().rev().zip(bits.iter().rev()) {
            *byte = *length;
        }
        compress(&mut self.state, core::slice::from_ref(&self.block));
        let mut digest = [0; SHA512_BYTES];
        for (bytes, word) in digest.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            *bytes = word.to_be_bytes();
        }
        digest
    }
}

/// A SHA-384 hash in progress.
pub struct Sha384(Hash);

impl Sha384 {
    pub const fn new() -> Self {
        Self(Hash::new(INITIAL))
    }

    /// A hash in progress that goes on from the same message, as a
    /// transcript's hash so far is taken while the transcript goes on.
    /// A method, not a derived Clone: a derive nothing in the program
    /// uses is refused, and only some programs take one.
    pub fn fork(&self) -> Self {
        // rr: escape(copy): the state goes on in both.
        Self(self.0.clone())
    }

    /// Adds data to the message; any split of it gives the same digest.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of the message. It takes the hash, which padding ends.
    pub fn finish(self) -> [u8; SHA384_BYTES] {
        let mut digest = [0; SHA384_BYTES];
        for (byte, word) in digest.iter_mut().zip(self.0.finish()) {
            *byte = word;
        }
        digest
    }
}

/// A SHA-512 hash in progress.
pub struct Sha512(Hash);

impl Sha512 {
    pub const fn new() -> Self {
        Self(Hash::new(INITIAL512))
    }

    /// Adds data to the message; any split of it gives the same digest.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of the message. It takes the hash, which padding ends.
    pub fn finish(self) -> [u8; SHA512_BYTES] {
        self.0.finish()
    }
}

/// The SHA-384 digest of data in one call.
pub fn digest384(data: &[u8]) -> [u8; SHA384_BYTES] {
    let mut hash = Sha384::new();
    hash.update(data);
    hash.finish()
}

/// The SHA-512 digest of data in one call.
pub fn digest512(data: &[u8]) -> [u8; SHA512_BYTES] {
    let mut hash = Sha512::new();
    hash.update(data);
    hash.finish()
}

/// HMAC in progress over SHA-512 or SHA-384: both hashes keyed, so that
/// one keyed value can be cloned for each message under the same key.
#[derive(Clone)]
struct Keyed {
    inner: Hash,
    outer: Hash,
    /// The digest's bytes: 48 or 64.
    bytes: usize,
}

impl Keyed {
    fn new(initial: [u64; 8], bytes: usize, key: &[u8]) -> Self {
        // A key longer than a block is hashed first, as RFC 2104 says.
        let hashed;
        let key = if key.len() > BLOCK_BYTES {
            let mut hash = Hash::new(initial);
            hash.update(key);
            hashed = hash.finish();
            // rr: escape(panic): bytes is 48 or 64, within the digest.
            &hashed[..bytes]
        } else {
            key
        };
        let mut pad = [0x36; BLOCK_BYTES];
        for (byte, secret) in pad.iter_mut().zip(key) {
            *byte ^= secret;
        }
        let mut inner = Hash::new(initial);
        inner.update(&pad);
        for byte in &mut pad {
            *byte ^= 0x36 ^ 0x5c;
        }
        let mut outer = Hash::new(initial);
        outer.update(&pad);
        wipe(&mut pad);
        Self {
            inner,
            outer,
            bytes,
        }
    }

    /// The tag in the first bytes of the result.
    fn finish(mut self) -> [u8; SHA512_BYTES] {
        let inner = self.inner.finish();
        // rr: escape(panic): bytes is 48 or 64, within the digest.
        self.outer.update(&inner[..self.bytes]);
        self.outer.finish()
    }
}

/// HMAC-SHA384 in progress.
#[derive(Clone)]
pub struct Hmac384(Keyed);

impl Hmac384 {
    pub fn new(key: &[u8]) -> Self {
        Self(Keyed::new(INITIAL, SHA384_BYTES, key))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.inner.update(data);
    }

    /// The MAC, to send.
    pub fn finish(self) -> [u8; SHA384_BYTES] {
        let mut tag = [0; SHA384_BYTES];
        for (byte, word) in tag.iter_mut().zip(self.0.finish()) {
            *byte = word;
        }
        tag
    }

    /// Whether tag, received, is the MAC: every byte is compared, so the
    /// time does not say where they differ.
    pub fn verify(self, tag: &[u8; SHA384_BYTES]) -> Result<(), Error> {
        same(&self.finish(), tag)
    }
}

/// HMAC-SHA512 in progress.
pub struct Hmac512(Keyed);

impl Hmac512 {
    pub fn new(key: &[u8]) -> Self {
        Self(Keyed::new(INITIAL512, SHA512_BYTES, key))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.inner.update(data);
    }

    /// The MAC, to send.
    pub fn finish(self) -> [u8; SHA512_BYTES] {
        self.0.finish()
    }

    /// Whether tag, received, is the MAC, as Hmac384::verify.
    pub fn verify(self, tag: &[u8; SHA512_BYTES]) -> Result<(), Error> {
        same(&self.finish(), tag)
    }
}

/// Ok when a and b, of one length, are equal: every byte is compared,
/// and black_box keeps the compiler from ending at the first that
/// differs.
fn same(a: &[u8], b: &[u8]) -> Result<(), Error> {
    let differ = a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y));
    if core::hint::black_box(differ) == 0 && a.len() == b.len() {
        Ok(())
    } else {
        Err(Error::Mismatch)
    }
}

/// A pseudorandom key of HKDF-SHA384 (RFC 5869 2.2), which HKDF-Expand
/// takes: hkdf_extract makes one. Not Copy, Clone or Debug; wiped when
/// dropped.
pub struct Prk {
    bytes: [u8; SHA384_BYTES],
}

/// HKDF-Extract: the pseudorandom key from salt and input keying
/// material. An empty salt stands for a block of zeros, as HMAC pads it.
pub fn hkdf_extract(salt: &[u8], input: &[u8]) -> Prk {
    let mut hmac = Hmac384::new(salt);
    hmac.update(input);
    Prk {
        bytes: hmac.finish(),
    }
}

impl Prk {
    /// A secret that is already a pseudorandom key of the hash's length,
    /// as a protocol's key schedule makes one by HKDF-Expand (TLS 1.3's
    /// Derive-Secret). Less safe than hkdf_extract: bytes of a password
    /// or of a shared secret would be taken as they are, not extracted.
    pub fn new_less_safe(secret: &[u8; SHA384_BYTES]) -> Prk {
        Prk { bytes: *secret }
    }

    /// HKDF-Expand: fills out from the key and info; TooLong, and out
    /// untouched, when out is longer than EXPAND_BYTES_MAX.
    pub fn expand(&self, info: &[u8], out: &mut [u8]) -> Result<(), Error> {
        if out.len() > EXPAND_BYTES_MAX {
            return Err(Error::TooLong);
        }
        let keyed = Hmac384::new(&self.bytes);
        let mut previous = [0; SHA384_BYTES];
        for (counter, chunk) in (1..=u8::MAX).zip(out.chunks_mut(SHA384_BYTES)) {
            // rr: escape(copy): each block starts from the keyed hashes,
            // which spares compressing the two key blocks again.
            let mut hmac = keyed.clone();
            if counter > 1 {
                hmac.update(&previous);
            }
            hmac.update(info);
            hmac.update(&[counter]);
            previous = hmac.finish();
            // rr: escape(panic): chunks_mut gives at most SHA384_BYTES.
            chunk.copy_from_slice(&previous[..chunk.len()]);
        }
        wipe(&mut previous);
        Ok(())
    }

    /// The key's bytes: a salt for the next HKDF-Extract, or an HMAC key.
    pub fn bytes(&self) -> &[u8; SHA384_BYTES] {
        &self.bytes
    }
}

impl Drop for Prk {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

/// Overwrites a secret with zeros. black_box makes the compiler take
/// the bytes as read after, so it keeps the writes though nothing reads
/// them.
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

fn compress(state: &mut [u64; 8], blocks: &[[u8; BLOCK_BYTES]]) {
    if sys::compress(state, blocks) {
        return;
    }
    for block in blocks {
        let mut schedule = [0_u64; 80];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
            *word = u64::from_be_bytes(*bytes);
        }
        for at in 16..schedule.len() {
            // rr: escape(panic): at runs 16..80, so at - 16 to at are in the
            // 80-word schedule.
            let early = schedule[at - 15];
            // rr: escape(panic): as above.
            let late = schedule[at - 2];
            // rr: escape(panic): as above.
            let sum = schedule[at - 16].wrapping_add(schedule[at - 7]);
            let small0 = early.rotate_right(1) ^ early.rotate_right(8) ^ (early >> 7);
            let small1 = late.rotate_right(19) ^ late.rotate_right(61) ^ (late >> 6);
            // rr: escape(panic): as above.
            schedule[at] = sum.wrapping_add(small0).wrapping_add(small1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for (word, constant) in schedule.iter().zip(&ROUND) {
            let big1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(*word);
            let big0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(big0).wrapping_add(majority);
        }
        for (word, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(add);
        }
    }
}

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    use super::{
        BLOCK_BYTES, EXPAND_BYTES_MAX, Error, Hmac384, Hmac512, Prk, SHA384_BYTES, SHA512_BYTES,
        Sha384, Sha512, digest384, digest512, hkdf_extract,
    };
    use alloc::vec::Vec;
    use test::Bencher;

    fn hex(text: &str) -> Vec<u8> {
        let nibble = |c: u8| char::from(c).to_digit(16).unwrap();
        let mut bytes = Vec::new();
        for pair in text.as_bytes().as_chunks::<2>().0 {
            let [high, low] = *pair;
            bytes.push(u8::try_from((nibble(high) << 4) | nibble(low)).unwrap());
        }
        bytes
    }

    /// Bytes start, start + 1 and on, as RFC 5869's case 2 has them.
    fn counting(start: u8) -> [u8; 80] {
        let mut bytes = [start; 80];
        for (byte, step) in bytes.iter_mut().zip(0..) {
            *byte = byte.wrapping_add(step);
        }
        bytes
    }

    /// FIPS 180-4's examples and the million a's, whole and in pieces.
    #[test]
    fn fips_vectors() {
        let mut million = Vec::new();
        million.resize(1_000_000, b'a');
        for (data, expected) in [
            (
                &b""[..],
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
                 4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                b"abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163\
                 1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05ab\
                 fe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2\
                 2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
            ),
            (
                &million[..],
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852\
                 7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
            ),
        ] {
            let expected = hex(expected);
            assert_eq!(digest384(data)[..], expected[..]);
            let mut hash = Sha384::new();
            for piece in data.chunks(997) {
                hash.update(piece);
            }
            assert_eq!(hash.finish()[..], expected[..]);
        }
    }

    /// FIPS 180-4's SHA-512 examples and the million a's, whole and in
    /// pieces.
    #[test]
    fn sha512_vectors() {
        let mut million = Vec::new();
        million.resize(1_000_000, b'a');
        for (data, expected) in [
            (
                &b""[..],
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                b"abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                 501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
            (
                &million[..],
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
                 de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
            ),
        ] {
            let expected = hex(expected);
            assert_eq!(digest512(data)[..], expected[..]);
            let mut hash = Sha512::new();
            for piece in data.chunks(997) {
                hash.update(piece);
            }
            assert_eq!(hash.finish()[..], expected[..]);
        }
    }

    /// Every length over two blocks, split everywhere, gives the digest
    /// of one update: the part block and the padding at each offset.
    #[test]
    fn splits_agree() {
        let mut data = [0_u8; 2 * BLOCK_BYTES + 1];
        let mut byte = 1_u8;
        for slot in &mut data {
            byte = byte.wrapping_mul(73).wrapping_add(19);
            *slot = byte;
        }
        for length in 0..=data.len() {
            let data = &data[..length];
            let whole = digest384(data);
            for split in 0..=length {
                let (head, tail) = data.split_at(split);
                let mut hash = Sha384::new();
                hash.update(head);
                hash.update(&[]);
                hash.update(tail);
                assert_eq!(hash.finish(), whole);
            }
        }
    }

    /// RFC 4231's cases 1 to 7: short, long and hashed keys, and case 5
    /// cut to 128 bits.
    #[test]
    fn hmac_vectors() {
        let key4 = hex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        for (key, data, expected) in [
            (
                &[0x0b; 20][..],
                &b"Hi There"[..],
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6\
                 82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47\
                 e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9feb\
                 e83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            ),
            (
                &key4,
                &[0xcd; 50],
                "3e8a69b7783c25851933ab6290af6ca77a9981480850009c\
                 c5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            ),
            (
                &[0x0c; 20],
                b"Test With Truncation",
                "3abf34c3503b2a23a46efc619baef897",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f\
                 3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a \
                  larger than block-size data. The key needs to be hashed \
                  before being used by the HMAC algorithm.",
                "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9a\
                 dccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            ),
        ] {
            let expected = hex(expected);
            let mut hmac = Hmac384::new(key);
            hmac.update(data);
            assert_eq!(hmac.finish()[..expected.len()], expected[..]);
        }
    }

    /// Keys one byte short of a block, a block and a block and a byte:
    /// padded, padded exactly, and hashed first. Python's hmac gave the
    /// tags.
    #[test]
    fn block_size_keys() {
        let mut key = [0; BLOCK_BYTES + 1];
        for (byte, value) in key.iter_mut().zip(0..) {
            *byte = value;
        }
        for (length, tag384, tag512) in [
            (
                BLOCK_BYTES - 1,
                "dbebb7841ea8e2cb6180cc85d28f99f2247bb2666e9949b129a0f73e8ce33132\
                 2c148cf5ad7c00d03cff7234dac5fb43",
                "b165030069f5631883a89fb0bb02a9b41c71bf6334b6fd9c70dcd3f89a8e1bb9\
                 d9c19363c8f6a242ee545884553242204756035bc2aa8c32d6b22bc21d3a10e0",
            ),
            (
                BLOCK_BYTES,
                "0534177b30cf3f731c5e94f988d86dba6ca5e2496ac14e278e5bc62a7cb08b8c\
                 fe47b7e5884ab04bb5ceb3e6fde1dc08",
                "695dc10b6e2b7f95bf21d58d04e30fb4f75b54f4701452b10e13694adcda2240\
                 f63c91a3915c90203ae5f29596b4fc3f8d9b67455a2eb2719658f2b85aace95c",
            ),
            (
                BLOCK_BYTES + 1,
                "41b716fdc05cdbf749230caf91f627050721a28e40b90425a4df345942d10aac\
                 ee2c122099f1ecd3be945871b8ae6a0e",
                "935db917a886dc2d99263737db8f72ab7f71ec96bcad62cee9486d41cd7b4732\
                 9c529c5514705ba6a2d88ca3f2f219d446bd74102869794c01e70a98ef2681bf",
            ),
        ] {
            let mut short = Hmac384::new(&key[..length]);
            short.update(b"block-size key");
            assert_eq!(short.finish()[..], hex(tag384)[..]);
            let mut long = Hmac512::new(&key[..length]);
            long.update(b"block-size key");
            assert_eq!(long.finish()[..], hex(tag512)[..]);
        }
    }

    /// A line's eight fields, or seven and an empty one.
    fn fields(line: &str) -> [&str; 8] {
        let mut out = [""; 8];
        let mut words = line.split(' ');
        for (slot, word) in out.iter_mut().zip(&mut words) {
            *slot = word;
        }
        assert!(words.next().is_none(), "{line}");
        out
    }

    /// Wycheproof's hmac_sha384_test, hmac_sha512_test and
    /// hkdf_sha384_test, every case (sha384-wycheproof.py): a MAC whose
    /// first tag bytes match exactly when the case is valid, and HKDF's
    /// output, or a refusal past 255 blocks.
    #[test]
    fn wycheproof() {
        let field = |text: &str| if text == "-" { Vec::new() } else { hex(text) };
        let (mut macs, mut keys) = (0, 0);
        let mut out = Vec::new();
        for line in include_str!("sha384-wycheproof.txt").lines() {
            if line.starts_with('#') {
                continue;
            }
            match fields(line) {
                ["hmac", bits, id, valid, size, key, message, tag] => {
                    let size: usize = size.parse().unwrap();
                    let (key, message) = (field(key), field(message));
                    let mut mac = [0; 64];
                    if bits == "384" {
                        let mut hmac = Hmac384::new(&key);
                        hmac.update(&message);
                        mac[..SHA384_BYTES].copy_from_slice(&hmac.finish());
                    } else {
                        let mut hmac = Hmac512::new(&key);
                        hmac.update(&message);
                        mac = hmac.finish();
                    }
                    let tag = field(tag);
                    let matches = mac[..size] == tag[..];
                    assert_eq!(matches, valid == "1", "hmac {bits} tcId {id}");
                    let verified = match bits {
                        "384" => <&[u8; SHA384_BYTES]>::try_from(&tag[..])
                            .ok()
                            .map(|full| verify384(&key, &message, full)),
                        _ => <&[u8; SHA512_BYTES]>::try_from(&tag[..])
                            .ok()
                            .map(|full| verify512(&key, &message, full)),
                    };
                    if let Some(verified) = verified {
                        assert_eq!(verified, valid == "1", "hmac {bits} tcId {id}");
                    }
                    macs += 1;
                }
                ["hkdf", id, input, salt, info, size, okm, ""] => {
                    let key = hkdf_extract(&field(salt), &field(input));
                    out.clear();
                    out.resize(size.parse().unwrap(), 0);
                    let expected = field(okm);
                    let done = key.expand(&field(info), &mut out);
                    assert_eq!(done.is_ok(), !expected.is_empty(), "hkdf tcId {id}");
                    if done.is_ok() {
                        assert_eq!(out, expected, "hkdf tcId {id}");
                    }
                    keys += 1;
                }
                _ => panic!("{line}"),
            }
        }
        assert_eq!((macs, keys), (348, 83));
    }

    /// RFC 5869's three inputs under SHA-384, whose results Python's
    /// hmac and hashlib gave: one and two output blocks, a long salt and
    /// info, and none at all.
    #[test]
    fn hkdf_vectors() {
        let short = [0x0b; 22];
        let (long, long_salt, long_info) = (counting(0x00), counting(0x60), counting(0xb0));
        for (input, salt, info, key, expected) in [
            (
                &short[..],
                &hex("000102030405060708090a0b0c")[..],
                &hex("f0f1f2f3f4f5f6f7f8f9")[..],
                "704b39990779ce1dc548052c7dc39f303570dd13fb39f7ac\
                 c564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade",
                "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7\
                 48b6457763e4f0204fc5",
            ),
            (
                &long,
                &long_salt,
                &long_info,
                "b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c\
                 901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb",
                "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649ee\
                 bf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6\
                 f4c09c5500dca24a56222fea53d8967a8b2e",
            ),
            (
                &short,
                b"",
                b"",
                "10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cb\
                 c8e45b40068f8f0ba57cdb598af9dfa6963a96899af047e5",
                "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daa\
                 cc1cea5670415b52849c",
            ),
        ] {
            let derived = hkdf_extract(salt, input);
            assert_eq!(derived.bytes()[..], hex(key)[..]);
            let expected = hex(expected);
            let mut out = [0; 82];
            let out = &mut out[..expected.len()];
            assert_eq!(derived.expand(info, out), Ok(()));
            assert_eq!(out[..], expected[..]);
        }
    }

    /// An output past 255 blocks is refused before any byte is written;
    /// one at the limit is filled.
    #[test]
    fn hkdf_expand_limit() {
        let key = Prk::new_less_safe(&[0x42; SHA384_BYTES]);
        let mut out = [0xa5; EXPAND_BYTES_MAX + 1];
        assert_eq!(key.expand(b"", &mut out), Err(Error::TooLong));
        assert!(out.iter().all(|byte| *byte == 0xa5));
        assert_eq!(key.expand(b"", &mut out[..EXPAND_BYTES_MAX]), Ok(()));
        assert_eq!(out[EXPAND_BYTES_MAX], 0xa5);
        let mut first = [0; SHA384_BYTES];
        assert_eq!(key.expand(b"", &mut first), Ok(()));
        assert_eq!(out[..SHA384_BYTES], first);
    }

    fn verify384(key: &[u8], message: &[u8], tag: &[u8; SHA384_BYTES]) -> bool {
        let mut hmac = Hmac384::new(key);
        hmac.update(message);
        hmac.verify(tag).is_ok()
    }

    fn verify512(key: &[u8], message: &[u8], tag: &[u8; SHA512_BYTES]) -> bool {
        let mut hmac = Hmac512::new(key);
        hmac.update(message);
        hmac.verify(tag).is_ok()
    }

    /// As a protocol uses it: a key extracted and expanded into a MAC
    /// key, a MAC sent and checked by the peer, any byte changed a
    /// Mismatch; and SHA-384 and SHA-512 told apart by name and length.
    #[test]
    fn mac_loop() {
        let prk = hkdf_extract(b"salt", b"shared secret");
        let mut key = [0; SHA384_BYTES];
        assert_eq!(prk.expand(b"mac key", &mut key), Ok(()));
        let mut sender = Hmac384::new(&key);
        sender.update(b"a message");
        let tag = sender.finish();
        assert!(verify384(&key, b"a message", &tag));
        assert!(!verify384(&key, b"a messagE", &tag));
        for at in 0..SHA384_BYTES {
            let mut forged = tag;
            forged[at] ^= 0x80;
            assert!(!verify384(&key, b"a message", &forged));
        }
        let mut long = Hmac512::new(&key);
        long.update(b"a message");
        let tag512 = long.finish();
        assert!(verify512(&key, b"a message", &tag512));
        assert!(!verify512(b"another key", b"a message", &tag512));
        let (short, wide) = (digest384(b"abc"), digest512(b"abc"));
        assert_eq!((short.len(), wide.len()), (48, 64));
        assert_ne!(short[..], wide[..48]);
        let next = Prk::new_less_safe(&key);
        let mut out = [0; 16];
        assert_eq!(next.expand(b"next", &mut out), Ok(()));
        assert_ne!(out, [0; 16]);
    }

    /// One 16 KiB buffer, as a file or a record is hashed.
    #[bench]
    fn digest_16k(b: &mut Bencher) {
        let data = [0x5a; 16 * 1024];
        b.iter(|| digest384(&data));
    }

    /// The same under SHA-512: the same rounds, a wider digest.
    #[bench]
    fn digest512_16k(b: &mut Bencher) {
        let data = [0x5a; 16 * 1024];
        b.iter(|| digest512(&data));
    }
}
// rr: end(tests = yes)
