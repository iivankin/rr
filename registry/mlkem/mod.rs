//! ML-KEM-768 (FIPS 203): a key encapsulation that a quantum computer
//! is not known to break, for TLS's hybrid X25519MLKEM768. The
//! decapsulation key keeps its expanded form, as Go's does: the matrix A
//! sampled once, the vectors in the NTT domain. SHA3-256, SHA3-512,
//! SHAKE128 and SHAKE256 (FIPS 202) are here too, on one Keccak-f[1600].
//!
//! Everything a secret reaches is constant time: coefficients are
//! reduced by Barrett multiplication, not division; compression rounds
//! by masks; decapsulation compares the ciphertexts by folding every
//! byte and picks its result by a mask. Only the sampling of A, from the
//! public seed rho, and the parsing of a key loop or branch on data.

/// Bytes of the seed generate takes: d, then z (FIPS 203 Algorithm 19).
pub const SEED_BYTES: usize = 64;
/// Bytes of an encapsulation key.
pub const ENCAPSULATION_KEY_BYTES: usize = K * POLY_BYTES + 32;
/// Bytes of a ciphertext.
pub const CIPHERTEXT_BYTES: usize = K * U_BYTES + V_BYTES;
/// Bytes of the shared secret.
// rr: escape(duplicate): each component stands alone; ecdh's is P-256's
// x-coordinate, a size of its own.
pub const SHARED_BYTES: usize = 32;
/// Bytes of the randomness m an encapsulation takes.
pub const MESSAGE_BYTES: usize = 32;
/// Bytes of a decapsulation key in FIPS 203's expanded encoding.
pub const DECAPSULATION_KEY_BYTES: usize = K * POLY_BYTES + ENCAPSULATION_KEY_BYTES + 64;

/// Coefficients of a polynomial.
const N: usize = 256;
/// The modulus of the coefficients.
const Q: u16 = 3329;
/// The module's rank for ML-KEM-768.
const K: usize = 3;
/// Bytes of a polynomial at 12 bits a coefficient (ByteEncode12).
const POLY_BYTES: usize = N * 12 / 8;
/// Bytes of a polynomial of u, compressed to du = 10 bits.
const U_BYTES: usize = N * 10 / 8;
/// Bytes of v, compressed to dv = 4 bits.
const V_BYTES: usize = N * 4 / 8;
/// Bytes PRF gives SamplePolyCBD for eta = 2.
const CBD_BYTES: usize = 64 * 2;
/// floor(2^24 / q): Barrett reduction's multiplier.
const BARRETT: u64 = 5039;
/// 128^-1 mod q, which ends the inverse NTT.
const INVERSE_128: u16 = 3303;

/// Bytes of Keccak's state.
const WIDTH: usize = 200;
/// The rates of the four functions, 200 bytes less twice the security.
const RATE_SHA3_256: usize = 136;
const RATE_SHA3_512: usize = 72;
const RATE_SHAKE128: usize = 168;
const RATE_SHAKE256: usize = 136;
/// The domain bits and the first bit of the padding: 01 for SHA-3,
/// 1111 for SHAKE.
const SUFFIX_SHA3: u8 = 0x06;
const SUFFIX_SHAKE: u8 = 0x1f;

/// A polynomial, or its NTT: coefficients below q.
type Poly = [u16; N];

/// Keccak-f[1600]'s round constants.
const ROUND: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The lanes rho and pi visit, from lane 1, and each one's rotation.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// zeta^BitRev7(k) mod q (FIPS 203 Appendix A), for the NTT.
const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// zeta^(2 BitRev7(i) + 1) mod q (FIPS 203 Appendix A), for the
/// products of the NTT's pairs.
const GAMMAS: [u16; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409,
    1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626,
    1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390,
    2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298,
    1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319,
    3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117,
    1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

/// An encapsulation key, parsed: t in the NTT domain, the matrix A
/// sampled from rho, and H(ek) for the encapsulation.
pub struct EncapsulationKey {
    t: [Poly; K],
    /// a[i][j] = SampleNTT(rho, j, i).
    a: [[Poly; K]; K],
    rho: [u8; 32],
    h: [u8; 32],
}

/// A decapsulation key: the encapsulation key it answers, the secret s
/// in the NTT domain, and z for the implicit rejection.
pub struct DecapsulationKey {
    ek: EncapsulationKey,
    s: [Poly; K],
    z: [u8; 32],
}

/// ML-KEM.KeyGen_internal (FIPS 203 Algorithms 16 and 13) from the
/// seed d || z, 64 bytes of the system's randomness.
pub fn generate(seed: &[u8; SEED_BYTES]) -> DecapsulationKey {
    let (d, z) = halves(seed);
    let g = sha3_512(&[&d, &[3]]);
    let (rho, sigma) = halves(&g);
    let a = matrix(&rho);
    let mut s = [[0; N]; K];
    let mut t = [[0; N]; K];
    for (si, n) in s.iter_mut().zip(0..) {
        *si = cbd(&sigma, n);
        ntt(si);
    }
    // t = A s + e, e from the PRF's next three counters.
    for ((ti, row), n) in t.iter_mut().zip(&a).zip(3..) {
        *ti = cbd(&sigma, n);
        ntt(ti);
        for (aij, sj) in row.iter().zip(&s) {
            multiply_add(ti, aij, sj);
        }
    }
    let mut ek = EncapsulationKey {
        t,
        a,
        rho,
        h: [0; 32],
    };
    ek.h = sha3_256(&[&ek.bytes()]);
    DecapsulationKey { ek, s, z }
}

/// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17) to the key's bytes,
/// m being 32 bytes of the system's randomness: the ciphertext and the
/// shared secret. None when the key fails FIPS 203's check (7.2): a
/// coefficient of q or more.
pub fn encapsulate(
    key: &[u8; ENCAPSULATION_KEY_BYTES],
    m: &[u8; MESSAGE_BYTES],
) -> Option<([u8; CIPHERTEXT_BYTES], [u8; SHARED_BYTES])> {
    Some(EncapsulationKey::parse(key)?.encapsulate(m))
}

impl EncapsulationKey {
    /// The key's bytes parsed, A sampled; None when a coefficient is q
    /// or more (FIPS 203 7.2, the modulus check).
    pub fn parse(bytes: &[u8; ENCAPSULATION_KEY_BYTES]) -> Option<Self> {
        let (polys, _) = bytes.as_chunks::<POLY_BYTES>();
        let mut t = [[0; N]; K];
        for (ti, chunk) in t.iter_mut().zip(polys) {
            *ti = decode12(chunk)?;
        }
        let rho = *bytes.last_chunk::<32>()?;
        Some(Self {
            t,
            a: matrix(&rho),
            rho,
            h: sha3_256(&[bytes]),
        })
    }

    /// The key's encoding: ByteEncode12(t) || rho.
    pub fn bytes(&self) -> [u8; ENCAPSULATION_KEY_BYTES] {
        let mut out = [0; ENCAPSULATION_KEY_BYTES];
        let (polys, rest) = out.as_chunks_mut::<POLY_BYTES>();
        for (chunk, ti) in polys.iter_mut().zip(&self.t) {
            encode12(ti, chunk);
        }
        for (byte, r) in rest.iter_mut().zip(self.rho) {
            *byte = r;
        }
        out
    }

    /// Encaps_internal with m: the ciphertext and the shared secret.
    pub fn encapsulate(
        &self,
        m: &[u8; MESSAGE_BYTES],
    ) -> ([u8; CIPHERTEXT_BYTES], [u8; SHARED_BYTES]) {
        let g = sha3_512(&[m, &self.h]);
        let (shared, r) = halves(&g);
        (self.encrypt(m, &r), shared)
    }

    /// K-PKE.Encrypt (FIPS 203 Algorithm 14), A and t already parsed.
    fn encrypt(&self, m: &[u8; MESSAGE_BYTES], r: &[u8; 32]) -> [u8; CIPHERTEXT_BYTES] {
        let mut y = [[0; N]; K];
        for (yi, n) in y.iter_mut().zip(0..) {
            *yi = cbd(r, n);
            ntt(yi);
        }
        let mut out = [0; CIPHERTEXT_BYTES];
        let (us, rest) = out.as_chunks_mut::<U_BYTES>();
        // u = NTT^-1(A^T y) + e1, e1 from counters 3, 4 and 5.
        for ((chunk, i), n) in us.iter_mut().zip(0..K).zip(3..) {
            let mut u = [0; N];
            for (row, yj) in self.a.iter().zip(&y) {
                // rr: escape(panic): i < K, a row's length.
                multiply_add(&mut u, &row[i], yj);
            }
            inverse_ntt(&mut u);
            add(&mut u, &cbd(r, n));
            compress_encode10(&u, chunk);
        }
        // v = NTT^-1(t^T y) + e2 + Decompress1(m), e2 from counter 6.
        let mut v = [0; N];
        for (ti, yi) in self.t.iter().zip(&y) {
            multiply_add(&mut v, ti, yi);
        }
        inverse_ntt(&mut v);
        add(&mut v, &cbd(r, 6));
        add(&mut v, &decompress1(m));
        compress_encode4(&v, rest);
        out
    }
}

impl DecapsulationKey {
    /// The encapsulation key's bytes, for the peer.
    pub fn encapsulation_key(&self) -> [u8; ENCAPSULATION_KEY_BYTES] {
        self.ek.bytes()
    }

    /// ML-KEM.Decaps_internal (FIPS 203 Algorithm 18): the shared secret.
    /// A ciphertext that does not re-encrypt to itself gives
    /// J(z || c), a secret the peer cannot know, in the same time.
    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> [u8; SHARED_BYTES] {
        let m = self.decrypt(ciphertext);
        let g = sha3_512(&[&m, &self.ek.h]);
        let (shared, r) = halves(&g);
        let mut rejected = [0; SHARED_BYTES];
        shake256(&[&self.z, ciphertext], &mut rejected);
        let again = self.ek.encrypt(&m, &r);
        let differ = ciphertext
            .iter()
            .zip(&again)
            .fold(0, |acc, (x, y)| acc | (x ^ y));
        // 0xff when the ciphertexts are equal, 0 when not, by arithmetic.
        let mask = core::hint::black_box(u16::from(differ).wrapping_sub(1) >> 8);
        let mut out = [0; SHARED_BYTES];
        for ((o, k), j) in out.iter_mut().zip(shared).zip(rejected) {
            *o = narrow((u16::from(k) & mask) | (u16::from(j) & !mask));
        }
        out
    }

    /// K-PKE.Decrypt (FIPS 203 Algorithm 15): the message m'.
    fn decrypt(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> [u8; MESSAGE_BYTES] {
        let (us, rest) = ciphertext.as_chunks::<U_BYTES>();
        // s^T NTT(u).
        let mut w = [0; N];
        for (chunk, si) in us.iter().zip(&self.s) {
            let mut u = decompress10(chunk);
            ntt(&mut u);
            multiply_add(&mut w, si, &u);
        }
        inverse_ntt(&mut w);
        let mut v = decompress4(rest);
        for (vi, wi) in v.iter_mut().zip(w) {
            *vi = sub(*vi, wi);
        }
        compress1(&v)
    }

    /// The expanded encoding (FIPS 203 Algorithm 16's dk):
    /// ByteEncode12(s) || ek || H(ek) || z.
    pub fn expanded(&self) -> [u8; DECAPSULATION_KEY_BYTES] {
        let mut out = [0; DECAPSULATION_KEY_BYTES];
        let (s_bytes, rest) = out.split_at_mut(K * POLY_BYTES);
        for (chunk, si) in s_bytes
            .as_chunks_mut::<POLY_BYTES>()
            .0
            .iter_mut()
            .zip(&self.s)
        {
            encode12(si, chunk);
        }
        let ek = self.ek.bytes();
        for (byte, value) in rest
            .iter_mut()
            .zip(ek.iter().chain(&self.ek.h).chain(&self.z))
        {
            *byte = *value;
        }
        out
    }

    /// A key in the expanded encoding, checked as FIPS 203's 7.3 asks:
    /// H of the encapsulation key inside it is the H that follows it.
    /// The encapsulation key passes the modulus check, and s too.
    pub fn from_expanded(bytes: &[u8; DECAPSULATION_KEY_BYTES]) -> Option<Self> {
        let (s_bytes, rest) = bytes.split_first_chunk::<{ K * POLY_BYTES }>()?;
        let (ek_bytes, rest) = rest.split_first_chunk::<ENCAPSULATION_KEY_BYTES>()?;
        let (h, z) = rest.split_first_chunk::<32>()?;
        let ek = EncapsulationKey::parse(ek_bytes)?;
        if ek.h != *h {
            return None;
        }
        let mut s = [[0; N]; K];
        for (si, chunk) in s.iter_mut().zip(s_bytes.as_chunks::<POLY_BYTES>().0) {
            *si = decode12(chunk)?;
        }
        Some(Self {
            ek,
            s,
            z: *z.first_chunk::<32>()?,
        })
    }
}

/// The two 32-byte halves of 64 bytes.
fn halves(bytes: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0; 32];
    let mut b = [0; 32];
    for (out, byte) in a.iter_mut().chain(&mut b).zip(bytes) {
        *out = *byte;
    }
    (a, b)
}

/// A, a[i][j] = SampleNTT(rho || j || i) (FIPS 203 Algorithm 13 step 4).
fn matrix(rho: &[u8; 32]) -> [[Poly; K]; K] {
    let mut a = [[[0; N]; K]; K];
    for (row, i) in a.iter_mut().zip(0..) {
        for (aij, j) in row.iter_mut().zip(0..) {
            *aij = sample_ntt(rho, j, i);
        }
    }
    a
}

/// SampleNTT (FIPS 203 Algorithm 7): 12-bit values from SHAKE128,
/// those below q kept, until there are N. The seed is public.
fn sample_ntt(rho: &[u8; 32], j: u8, i: u8) -> Poly {
    let mut xof = Sponge::new(RATE_SHAKE128);
    xof.absorb(rho);
    xof.absorb(&[j, i]);
    xof.pad(SUFFIX_SHAKE);
    let mut f = [0; N];
    let mut slots = f.iter_mut();
    let mut block = [0; RATE_SHAKE128];
    // About 3 blocks; rejection makes more, rarely (CCTV's unlucky).
    'sample: loop {
        xof.squeeze(&mut block);
        for &[b0, b1, b2] in block.as_chunks::<3>().0 {
            let d1 = u16::from(b0) | ((u16::from(b1) & 0xf) << 8);
            let d2 = (u16::from(b1) >> 4) | (u16::from(b2) << 4);
            for d in [d1, d2] {
                if d < Q
                    && let Some(slot) = slots.next()
                {
                    *slot = d;
                }
                if slots.len() == 0 {
                    break 'sample;
                }
            }
        }
    }
    f
}

/// SamplePolyCBD with eta = 2 (FIPS 203 Algorithm 8) of PRF(seed, n):
/// each coefficient the sum of two bits less the sum of two others.
fn cbd(seed: &[u8; 32], n: u8) -> Poly {
    let mut bytes = [0; CBD_BYTES];
    shake256(&[seed, &[n]], &mut bytes);
    let mut f = [0; N];
    for (pair, byte) in f.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
        let b = u16::from(byte);
        let bit = |k: u16| (b >> k) & 1;
        *pair = [
            sub(bit(0) + bit(1), bit(2) + bit(3)),
            sub(bit(4) + bit(5), bit(6) + bit(7)),
        ];
    }
    f
}

/// The NTT (FIPS 203 Algorithm 9), in place.
fn ntt(f: &mut Poly) {
    let mut zetas = ZETAS.iter().skip(1);
    for len in [128, 64, 32, 16, 8, 4, 2] {
        for (block, &zeta) in f.chunks_exact_mut(2 * len).zip(&mut zetas) {
            let (low, high) = block.split_at_mut(len);
            for (x, y) in low.iter_mut().zip(high) {
                let t = multiply(zeta, *y);
                *y = sub(*x, t);
                *x = reduce_once(*x + t);
            }
        }
    }
}

/// The inverse NTT (FIPS 203 Algorithm 10), in place.
fn inverse_ntt(f: &mut Poly) {
    let mut zetas = ZETAS.iter().rev();
    for len in [2, 4, 8, 16, 32, 64, 128] {
        for (block, &zeta) in f.chunks_exact_mut(2 * len).zip(&mut zetas) {
            let (low, high) = block.split_at_mut(len);
            for (x, y) in low.iter_mut().zip(high) {
                let t = *x;
                *x = reduce_once(t + *y);
                *y = multiply(zeta, *y + Q - t);
            }
        }
    }
    for x in f {
        *x = multiply(*x, INVERSE_128);
    }
}

/// acc += f g in the NTT domain (FIPS 203 Algorithms 11 and 12): the
/// pairs multiplied modulo X^2 - gamma.
fn multiply_add(acc: &mut Poly, f: &Poly, g: &Poly) {
    let pairs = acc.as_chunks_mut::<2>().0.iter_mut();
    let factors = f.as_chunks::<2>().0.iter().zip(g.as_chunks::<2>().0);
    for ((out, (&[a0, a1], &[b0, b1])), &gamma) in pairs.zip(factors).zip(&GAMMAS) {
        let [c0, c1] = *out;
        let h0 =
            barrett(u64::from(a0) * u64::from(b0) + u64::from(multiply(a1, b1)) * u64::from(gamma));
        let h1 = barrett(u64::from(a0) * u64::from(b1) + u64::from(a1) * u64::from(b0));
        *out = [reduce_once(c0 + h0), reduce_once(c1 + h1)];
    }
}

/// f += g.
fn add(f: &mut Poly, g: &Poly) {
    for (x, y) in f.iter_mut().zip(g) {
        *x = reduce_once(*x + y);
    }
}

/// a - q when a is q or more; a below 2q. A mask from the sign of the
/// difference picks, not a branch.
const fn reduce_once(a: u16) -> u16 {
    let x = a.wrapping_sub(Q);
    x.wrapping_add((x >> 15) * Q)
}

/// a - b mod q, both below q.
const fn sub(a: u16, b: u16) -> u16 {
    reduce_once(a + Q - b)
}

/// a b mod q, both below q.
fn multiply(a: u16, b: u16) -> u16 {
    barrett(u64::from(a) * u64::from(b))
}

/// a mod q for a below 2q^2: Barrett's quotient is floor(a / q) or one
/// less, so the remainder is below 2q, reduced once more.
fn barrett(a: u64) -> u16 {
    let quotient = (a * BARRETT) >> 24;
    reduce_once(short(a - quotient * u64::from(Q)))
}

/// The low 16 bits of a value its caller knows below 2^16.
const fn short(x: u64) -> u16 {
    // rr: escape(cast): callers reduce below 2q or mask to under 16 bits.
    x as u16
}

/// The low 8 bits of a value its caller knows below 2^8.
const fn narrow(x: u16) -> u8 {
    // rr: escape(cast): callers mask to 8 bits.
    x as u8
}

/// Compress_d (FIPS 203 4.7): round(2^d x / q) mod 2^d, the division by
/// Barrett's quotient and two corrections from the remainder's spans.
fn compress(x: u16, d: u32) -> u16 {
    let dividend = u64::from(x) << d;
    let mut quotient = (dividend * BARRETT) >> 24;
    let remainder = dividend - quotient * u64::from(Q);
    // remainder is below 2q: past q/2 rounds up once, past 3q/2 twice.
    let half = u64::from(Q / 2);
    quotient += (half.wrapping_sub(remainder) >> 63) & 1;
    quotient += ((u64::from(Q) + half).wrapping_sub(remainder) >> 63) & 1;
    short(quotient & ((1 << d) - 1))
}

/// Decompress_d (FIPS 203 4.8): round(q y / 2^d), y below 2^d.
fn decompress(y: u64, d: u32) -> u16 {
    let dividend = y * u64::from(Q);
    short((dividend >> d) + ((dividend >> (d - 1)) & 1))
}

/// ByteEncode12 (FIPS 203 Algorithm 5): two coefficients in 3 bytes.
fn encode12(f: &Poly, out: &mut [u8; POLY_BYTES]) {
    for (bytes, &[a, b]) in out
        .as_chunks_mut::<3>()
        .0
        .iter_mut()
        .zip(f.as_chunks::<2>().0)
    {
        let x = u32::from(a) | (u32::from(b) << 12);
        // x has 24 bits: its three low bytes.
        let [b0, b1, b2, _] = x.to_le_bytes();
        *bytes = [b0, b1, b2];
    }
}

/// ByteDecode12 (FIPS 203 Algorithm 6); None for a coefficient of q or
/// more, which the modulus check refuses.
fn decode12(bytes: &[u8; POLY_BYTES]) -> Option<Poly> {
    let mut f = [0; N];
    for (pair, &[b0, b1, b2]) in f
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(bytes.as_chunks::<3>().0)
    {
        let a = u16::from(b0) | ((u16::from(b1) & 0xf) << 8);
        let b = (u16::from(b1) >> 4) | (u16::from(b2) << 4);
        if a >= Q || b >= Q {
            return None;
        }
        *pair = [a, b];
    }
    Some(f)
}

/// Compress10 then ByteEncode10: four coefficients in 5 bytes.
fn compress_encode10(f: &Poly, out: &mut [u8; U_BYTES]) {
    for (bytes, coefficients) in out
        .as_chunks_mut::<5>()
        .0
        .iter_mut()
        .zip(f.as_chunks::<4>().0)
    {
        let x = coefficients
            .iter()
            .zip([0, 10, 20, 30])
            .fold(0, |acc, (&c, shift)| {
                acc | (u64::from(compress(c, 10)) << shift)
            });
        // x has 40 bits: its five low bytes.
        let [b0, b1, b2, b3, b4, ..] = x.to_le_bytes();
        *bytes = [b0, b1, b2, b3, b4];
    }
}

/// ByteDecode10 then Decompress10.
fn decompress10(bytes: &[u8; U_BYTES]) -> Poly {
    let mut f = [0; N];
    for (coefficients, &[b0, b1, b2, b3, b4]) in f
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(bytes.as_chunks::<5>().0)
    {
        let x = u64::from_le_bytes([b0, b1, b2, b3, b4, 0, 0, 0]);
        for (c, shift) in coefficients.iter_mut().zip([0, 10, 20, 30]) {
            *c = decompress((x >> shift) & 0x3ff, 10);
        }
    }
    f
}

/// Compress4 then ByteEncode4: two coefficients a byte.
fn compress_encode4(f: &Poly, out: &mut [u8]) {
    for (byte, &[a, b]) in out.iter_mut().zip(f.as_chunks::<2>().0) {
        *byte = narrow(compress(a, 4) | (compress(b, 4) << 4));
    }
}

/// ByteDecode4 then Decompress4.
fn decompress4(bytes: &[u8]) -> Poly {
    let mut f = [0; N];
    for (pair, &byte) in f.as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
        let b = u64::from(byte);
        *pair = [decompress(b & 0xf, 4), decompress(b >> 4, 4)];
    }
    f
}

/// Compress1 then ByteEncode1: a bit a coefficient, the message.
fn compress1(f: &Poly) -> [u8; MESSAGE_BYTES] {
    let mut out = [0; MESSAGE_BYTES];
    for (byte, coefficients) in out.iter_mut().zip(f.as_chunks::<8>().0) {
        let bits = coefficients
            .iter()
            .zip(0..)
            .fold(0, |acc, (&c, k)| acc | (compress(c, 1) << k));
        *byte = narrow(bits);
    }
    out
}

/// ByteDecode1 then Decompress1: each bit of m to 0 or (q + 1) / 2, by
/// a product, not a branch.
fn decompress1(m: &[u8; MESSAGE_BYTES]) -> Poly {
    let mut f = [0; N];
    for (coefficients, &byte) in f.as_chunks_mut::<8>().0.iter_mut().zip(m) {
        for (c, k) in coefficients.iter_mut().zip(0..) {
            *c = ((u16::from(byte) >> k) & 1) * Q.div_ceil(2);
        }
    }
    f
}

/// A Keccak sponge: the state as bytes, lanes little-endian, and how
/// far into the rate it has absorbed or squeezed.
struct Sponge {
    bytes: [u8; WIDTH],
    rate: usize,
    /// Below rate while absorbing; at most rate while squeezing, rate
    /// when the block is used up.
    at: usize,
}

impl Sponge {
    const fn new(rate: usize) -> Self {
        Self {
            bytes: [0; WIDTH],
            rate,
            at: 0,
        }
    }

    /// XORs data into the state, permuting at each full rate.
    fn absorb(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            // rr: escape(panic): at < rate <= WIDTH while absorbing.
            let room = &mut self.bytes[self.at..self.rate];
            let taken = room.len().min(rest.len());
            let (head, tail) = rest.split_at(taken);
            for (byte, value) in room.iter_mut().zip(head) {
                *byte ^= value;
            }
            rest = tail;
            self.at += taken;
            if self.at == self.rate {
                self.permute();
                self.at = 0;
            }
        }
    }

    /// Ends the input: the suffix, the padding's last bit, a permutation.
    fn pad(&mut self, suffix: u8) {
        // rr: escape(panic): at < rate while absorbing.
        self.bytes[self.at] ^= suffix;
        // rr: escape(panic): the rate is 72 bytes or more.
        self.bytes[self.rate - 1] ^= 0x80;
        self.permute();
        self.at = 0;
    }

    /// The next bytes of output, after pad.
    fn squeeze(&mut self, out: &mut [u8]) {
        let mut rest = out;
        while !rest.is_empty() {
            if self.at == self.rate {
                self.permute();
                self.at = 0;
            }
            // rr: escape(panic): at < rate here.
            let ready = &self.bytes[self.at..self.rate];
            let taken = ready.len().min(rest.len());
            let (head, tail) = core::mem::take(&mut rest).split_at_mut(taken);
            for (byte, value) in head.iter_mut().zip(ready) {
                *byte = *value;
            }
            rest = tail;
            self.at += taken;
        }
    }

    /// Keccak-f[1600] on the state.
    fn permute(&mut self) {
        let mut lanes = [0; 25];
        let (words, _) = self.bytes.as_chunks_mut::<8>();
        for (lane, word) in lanes.iter_mut().zip(words.iter()) {
            *lane = u64::from_le_bytes(*word);
        }
        keccak(&mut lanes);
        for (word, lane) in words.iter_mut().zip(lanes) {
            *word = lane.to_le_bytes();
        }
    }
}

/// The 24 rounds of Keccak-f[1600] (FIPS 202 3.3), lanes at x + 5y.
fn keccak(a: &mut [u64; 25]) {
    for round in ROUND {
        // Theta: each column's parity into its neighbours.
        let mut c = [0; 5];
        for row in a.as_chunks::<5>().0 {
            for (parity, lane) in c.iter_mut().zip(row) {
                *parity ^= lane;
            }
        }
        let [c0, c1, c2, c3, c4] = c;
        let d = [
            c4 ^ c1.rotate_left(1),
            c0 ^ c2.rotate_left(1),
            c1 ^ c3.rotate_left(1),
            c2 ^ c4.rotate_left(1),
            c3 ^ c0.rotate_left(1),
        ];
        for row in a.as_chunks_mut::<5>().0 {
            for (lane, dx) in row.iter_mut().zip(d) {
                *lane ^= dx;
            }
        }
        // Rho and pi: each lane rotated into its place along one cycle.
        let mut carry = a[1];
        for (&lane, &rotation) in PI.iter().zip(&RHO) {
            // rr: escape(panic): PI's entries are lanes, below 25.
            carry = core::mem::replace(&mut a[lane], carry.rotate_left(rotation));
        }
        // Chi: each row.
        for row in a.as_chunks_mut::<5>().0 {
            let [a0, a1, a2, a3, a4] = *row;
            *row = [
                a0 ^ (!a1 & a2),
                a1 ^ (!a2 & a3),
                a2 ^ (!a3 & a4),
                a3 ^ (!a4 & a0),
                a4 ^ (!a0 & a1),
            ];
        }
        // Iota.
        a[0] ^= round;
    }
}

/// A sponge that has absorbed parts and is padded, ready to squeeze.
fn sponge(rate: usize, suffix: u8, parts: &[&[u8]]) -> Sponge {
    let mut s = Sponge::new(rate);
    for part in parts {
        s.absorb(part);
    }
    s.pad(suffix);
    s
}

/// SHA3-256 of the parts, one after another: H.
fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0; 32];
    sponge(RATE_SHA3_256, SUFFIX_SHA3, parts).squeeze(&mut out);
    out
}

/// SHA3-512 of the parts: G.
fn sha3_512(parts: &[&[u8]]) -> [u8; 64] {
    let mut out = [0; 64];
    sponge(RATE_SHA3_512, SUFFIX_SHA3, parts).squeeze(&mut out);
    out
}

/// SHAKE256 of the parts into out: J and PRF.
fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    sponge(RATE_SHAKE256, SUFFIX_SHAKE, parts).squeeze(out);
}

#[cfg(test)]
mod tests {
    use super::{
        CIPHERTEXT_BYTES, DECAPSULATION_KEY_BYTES, DecapsulationKey, ENCAPSULATION_KEY_BYTES,
        EncapsulationKey, K, MESSAGE_BYTES, N, POLY_BYTES, Q, RATE_SHAKE128, SEED_BYTES,
        SHARED_BYTES, SUFFIX_SHAKE, Sponge, decode12, encapsulate, encode12, generate, sha3_256,
        sha3_512, shake256, sponge,
    };
    use test::Bencher;

    /// Wycheproof's and NIST ACVP's vectors; mlkem-tests.py
    /// says what each line asks.
    const TESTS: &str = include_str!("mlkem-tests.txt");

    fn hex(s: &str, out: &mut [u8]) {
        assert_eq!(s.len(), 2 * out.len(), "{s}");
        for (byte, pair) in out.iter_mut().zip(s.as_bytes().as_chunks::<2>().0) {
            let digit = |c: u8| match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("not hex"),
            };
            *byte = (digit(pair[0]) << 4) | digit(pair[1]);
        }
    }

    fn h32(s: &str) -> [u8; 32] {
        let mut out = [0; 32];
        hex(s, &mut out);
        out
    }

    fn h64(s: &str) -> [u8; 64] {
        let mut out = [0; 64];
        hex(s, &mut out);
        out
    }

    fn ciphertext(s: &str) -> [u8; CIPHERTEXT_BYTES] {
        let mut out = [0; CIPHERTEXT_BYTES];
        hex(s, &mut out);
        out
    }

    fn encapsulation_key(s: &str) -> [u8; ENCAPSULATION_KEY_BYTES] {
        let mut out = [0; ENCAPSULATION_KEY_BYTES];
        hex(s, &mut out);
        out
    }

    /// FIPS 202's functions on the empty message, "abc", and 400 bytes
    /// that cross the rates (hashlib's answers).
    #[test]
    fn sha3() {
        let long: [u8; 400] = core::array::from_fn(|i| u8::try_from(i % 200).unwrap_or(0));
        assert_eq!(
            sha3_256(&[]),
            h32("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            sha3_512(&[b"abc"]),
            h64(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
        assert_eq!(
            sha3_256(&[&long[..7], &long[7..]]),
            h32("867625599c629bd53b9bdacd751e116cf146fe89a0bf9aa46cba9e94b2159c40")
        );
        assert_eq!(
            sha3_512(&[&long]),
            h64(
                "9e3f99ac2a8ad8ec744e6fbf84f35dfa542e884902dfa2d8e75dd26ab88d10db\
                 51f8e08218edf4d7bb2dc73499654bab10e556feadbb88479dd1b8f5684486a3"
            )
        );
        let mut out = [0; 32];
        shake256(&[], &mut out);
        assert_eq!(
            out,
            h32("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
        sponge(RATE_SHAKE128, SUFFIX_SHAKE, &[]).squeeze(&mut out);
        assert_eq!(
            out,
            h32("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
        // The last 32 of 400 bytes of output, squeezed in uneven pieces.
        let mut xof = sponge(RATE_SHAKE128, SUFFIX_SHAKE, &[&long]);
        let mut skip = [0; 123];
        xof.squeeze(&mut skip);
        xof.squeeze(&mut skip);
        xof.squeeze(&mut skip[..122]);
        xof.squeeze(&mut out);
        assert_eq!(
            out,
            h32("26aa6f3f97509f5bd076596977d768896ac7a719bbfc2d67b13223969d2e86e0")
        );
        let mut long_out = [0; 300];
        shake256(&[&long], &mut long_out);
        assert_eq!(
            long_out[268..],
            h32("33458d3ff9fa3307823f58e07743a8b1ce661387cac7d65ae9bedf8388b4cd3d")
        );
    }

    /// The key generated from seed, with the SHA3-256 of its encodings.
    fn check_keygen(seed: &str, ekh: &str, dkh: &str) -> DecapsulationKey {
        let dk = generate(&h64(seed));
        assert_eq!(sha3_256(&[&dk.encapsulation_key()]), h32(ekh), "{seed}");
        if dkh != "-" {
            assert_eq!(sha3_256(&[&dk.expanded()]), h32(dkh), "{seed}");
        }
        dk
    }

    /// Every line of mlkem-tests.txt.
    #[test]
    fn vectors() {
        let mut base = [0; ENCAPSULATION_KEY_BYTES];
        let mut last = [0; DECAPSULATION_KEY_BYTES];
        let mut count = 0;
        for line in TESTS.lines().filter(|line| !line.starts_with('#')) {
            let f: [&str; 7] = {
                let mut fields = [""; 7];
                for (field, word) in fields.iter_mut().zip(line.split(' ')) {
                    *field = word;
                }
                fields
            };
            match f[0] {
                "kem" => {
                    let dk = check_keygen(f[1], f[3], f[4]);
                    let (c, k) = encapsulate(&dk.encapsulation_key(), &h32(f[2]))
                        .expect("a generated key is valid");
                    assert_eq!(sha3_256(&[&c]), h32(f[5]), "{line}");
                    assert_eq!(k, h32(f[6]), "{line}");
                    assert_eq!(dk.decapsulate(&c), k, "{line}");
                }
                "keygen" => {
                    check_keygen(f[1], f[2], f[3]);
                }
                "decaps" => {
                    let dk = generate(&h64(f[1]));
                    assert_eq!(dk.decapsulate(&ciphertext(f[2])), h32(f[3]), "{line}");
                }
                "flip" => {
                    let dk = generate(&h64(f[1]));
                    let (mut c, k) = encapsulate(&dk.encapsulation_key(), &h32(f[2]))
                        .expect("a generated key is valid");
                    let at: usize = f[3].parse().expect("a position");
                    c[at] ^= u8::from_str_radix(f[4], 16).expect("a byte");
                    let rejected = dk.decapsulate(&c);
                    assert_ne!(rejected, k, "{line}");
                    assert_eq!(rejected, h32(f[5]), "{line}");
                }
                "unreduced" => {
                    let ek = generate(&h64(f[1])).encapsulation_key();
                    let mut bad = ek;
                    let (polys, _) = bad.as_chunks_mut::<POLY_BYTES>();
                    for chunk in polys {
                        let mut t = raw12(chunk);
                        for c in &mut t {
                            if *c + Q < 4096 {
                                *c += Q;
                            }
                        }
                        encode12(&t, chunk);
                    }
                    assert!(encapsulate(&bad, &[0; MESSAGE_BYTES]).is_none(), "{line}");
                }
                "base" => {
                    hex(f[1], &mut base);
                    assert!(EncapsulationKey::parse(&base).is_some());
                }
                "overflow" => {
                    let at: usize = f[1].parse().expect("a position");
                    let value: u16 = f[2].parse().expect("a value");
                    assert!(
                        encapsulate(&set(&base, at, value), &[0; 32]).is_none(),
                        "{line}"
                    );
                }
                "encaps" => {
                    let (c, k) =
                        encapsulate(&encapsulation_key(f[1]), &h32(f[2])).expect("a valid key");
                    assert_eq!(sha3_256(&[&c]), h32(f[3]), "{line}");
                    assert_eq!(k, h32(f[4]), "{line}");
                }
                "expanded" => {
                    hex(f[1], &mut last);
                    let dk = DecapsulationKey::from_expanded(&last).expect("a valid key");
                    assert_eq!(dk.expanded(), last);
                    assert_eq!(dk.decapsulate(&ciphertext(f[2])), h32(f[3]), "{line}");
                }
                "corrupt" => {
                    let mut bad = last;
                    let at: usize = f[1].parse().expect("a position");
                    bad[at] ^= u8::from_str_radix(f[2], 16).expect("a byte");
                    assert!(DecapsulationKey::from_expanded(&bad).is_none(), "{line}");
                }
                "ekcheck" => {
                    let ek = encapsulation_key(f[1]);
                    assert_eq!(EncapsulationKey::parse(&ek).is_some(), f[2] == "1");
                }
                "dkcheck" => {
                    let mut dk = [0; DECAPSULATION_KEY_BYTES];
                    hex(f[1], &mut dk);
                    assert_eq!(DecapsulationKey::from_expanded(&dk).is_some(), f[2] == "1");
                }
                other => panic!("unknown line {other}"),
            }
            count += 1;
        }
        assert_eq!(count, 316);
    }

    /// The coefficients of a 12-bit encoding, unchecked.
    fn raw12(chunk: &[u8; POLY_BYTES]) -> [u16; N] {
        let mut f = [0; N];
        for (pair, &[b0, b1, b2]) in f
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(chunk.as_chunks::<3>().0)
        {
            *pair = [
                u16::from(b0) | ((u16::from(b1) & 0xf) << 8),
                (u16::from(b1) >> 4) | (u16::from(b2) << 4),
            ];
        }
        f
    }

    /// ek with coefficient at (of K N) set to value.
    fn set(
        ek: &[u8; ENCAPSULATION_KEY_BYTES],
        at: usize,
        value: u16,
    ) -> [u8; ENCAPSULATION_KEY_BYTES] {
        let mut out = *ek;
        let chunk = &mut out.as_chunks_mut::<POLY_BYTES>().0[at / N];
        let mut t = raw12(chunk);
        t[at % N] = value;
        encode12(&t, chunk);
        out
    }

    /// CCTV's modulus check, all of it: every position of a key and every
    /// value from q to 2^12 - 1, each alone, is refused.
    #[test]
    fn modulus() {
        let ek = generate(&[7; SEED_BYTES]).encapsulation_key();
        assert!(encapsulate(&ek, &[0; 32]).is_some());
        let values = 4096 - usize::from(Q);
        for at in 0..K * N {
            let value = Q + u16::try_from(at % values).unwrap_or(0);
            assert!(
                EncapsulationKey::parse(&set(&ek, at, value)).is_none(),
                "{at}"
            );
        }
        // And a coefficient of q - 1 is taken.
        assert!(EncapsulationKey::parse(&set(&ek, 5, Q - 1)).is_some());
        let mut chunk = [0; POLY_BYTES];
        encode12(&[Q - 1; N], &mut chunk);
        assert!(decode12(&chunk).is_some());
    }

    /// Go's accumulated vectors (crypto/mlkem's TestAccumulated, at
    /// 06fcd67cc3371f8b5c8b577a650afd123ab9dad4): n tests whose inputs
    /// come from SHAKE128 of nothing and whose outputs go into another;
    /// C2SP/CCTV's are FIPS 203 ipd's, whose KeyGen differs.
    fn accumulated(n: u32) -> [u8; 32] {
        let mut rng = sponge(RATE_SHAKE128, SUFFIX_SHAKE, &[]);
        let mut acc = Sponge::new(RATE_SHAKE128);
        let mut seed = [0; SEED_BYTES];
        let mut m = [0; MESSAGE_BYTES];
        let mut random = [0; CIPHERTEXT_BYTES];
        for _ in 0..n {
            rng.squeeze(&mut seed);
            let dk = generate(&seed);
            let ek = dk.encapsulation_key();
            acc.absorb(&ek);
            rng.squeeze(&mut m);
            let (c, k) = encapsulate(&ek, &m).expect("a generated key is valid");
            acc.absorb(&c);
            acc.absorb(&k);
            assert_eq!(dk.decapsulate(&c), k);
            rng.squeeze(&mut random);
            acc.absorb(&dk.decapsulate(&random));
        }
        acc.pad(SUFFIX_SHAKE);
        let mut out = [0; 32];
        acc.squeeze(&mut out);
        out
    }

    #[test]
    fn accumulated_10k() {
        assert_eq!(
            accumulated(10_000),
            h32("8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc")
        );
    }

    /// A minute or so at -O: rr test always skips it; drop #[ignore] to run.
    #[test]
    #[ignore]
    fn accumulated_million() {
        assert_eq!(
            accumulated(1_000_000),
            h32("424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0")
        );
    }

    #[bench]
    fn keygen(b: &mut Bencher) {
        let seed = [42; SEED_BYTES];
        b.iter(|| generate(core::hint::black_box(&seed)).z);
    }

    #[bench]
    fn encaps(b: &mut Bencher) {
        let ek = generate(&[42; SEED_BYTES]).encapsulation_key();
        let m = [3; MESSAGE_BYTES];
        b.iter(|| encapsulate(core::hint::black_box(&ek), &m).map(|(_, k)| k));
    }

    #[bench]
    fn decaps(b: &mut Bencher) {
        let dk = generate(&[42; SEED_BYTES]);
        let (c, _) = encapsulate(&dk.encapsulation_key(), &[3; MESSAGE_BYTES])
            .expect("a generated key is valid");
        b.iter(|| -> [u8; SHARED_BYTES] { dk.decapsulate(core::hint::black_box(&c)) });
    }
}
