//! What the CPU has of the instructions the components use, asked once
//! for the process: what the target promises, and on aarch64 Linux and
//! Windows and on x86_64 what the CPU says it has besides. A component
//! asks has() before it runs code built for more than its target.

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use core::sync::atomic::{AtomicU32, Ordering};

/// AES with the carry-less multiply GHASH takes: AES and PMULL on
/// aarch64; AES-NI, PCLMULQDQ and SSSE3 on x86_64.
pub const AES: u32 = 1 << 0;
/// SHA-256's rounds: SHA2 on aarch64; SHA-NI, SSSE3 and SSE4.1 on x86_64.
pub const SHA256: u32 = 1 << 1;
/// SHA-512's rounds and SHA3's EOR3 on aarch64, which Rust enables as one
/// feature, "sha3".
pub const SHA512: u32 = 1 << 2;
/// AES and carry-less multiply on 256-bit vectors on x86_64: VAES,
/// VPCLMULQDQ and AVX2, with the YMM registers the OS saves.
pub const WIDE_AES: u32 = 1 << 3;

/// Set in FOUND once the CPU was asked.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const ASKED: u32 = 1 << 31;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
// rr: escape(shared): the CPU's answer, the same for every thread; a race
// only asks it twice.
static FOUND: AtomicU32 = AtomicU32::new(0);

/// Whether the CPU has every feature in want.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub fn has(want: u32) -> bool {
    let mut found = FOUND.load(Ordering::Relaxed);
    if found & ASKED == 0 {
        found = detect() | ASKED;
        FOUND.store(found, Ordering::Relaxed);
    }
    found & want == want
}

/// No instructions this code knows on this architecture.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub fn has(want: u32) -> bool {
    want == 0
}

/// What the target promises: on macOS every one of them, as every Mac
/// on Apple silicon has them.
#[cfg(target_arch = "aarch64")]
fn promised() -> u32 {
    let mut found = 0;
    if cfg!(target_feature = "aes") {
        found |= AES;
    }
    if cfg!(target_feature = "sha2") {
        found |= SHA256;
    }
    if cfg!(target_feature = "sha3") {
        found |= SHA512;
    }
    found
}

/// ID_AA64ISAR0_EL1: the AES field (bits 7:4) 2 is AES with PMULL; the
/// SHA2 field (15:12) 1 is SHA-256 and 2 adds SHA-512; the SHA3 field
/// (35:32) above 0 has EOR3. Linux traps the read at EL0 and answers
/// it, since 4.11 (HWCAP_CPUID).
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn detect() -> u32 {
    let isar0: u64;
    // rr: escape(unsafe): mrs of an ID register only reads it; the kernel
    // emulates it for user space.
    unsafe {
        core::arch::asm!(
            "mrs {}, ID_AA64ISAR0_EL1",
            out(reg) isar0,
            options(nomem, nostack, preserves_flags),
        );
    }
    let aes = (isar0 >> 4) & 0xf;
    let sha2 = (isar0 >> 12) & 0xf;
    let sha3 = (isar0 >> 32) & 0xf;
    let mut found = promised();
    if aes >= 2 {
        found |= AES;
    }
    if sha2 >= 1 {
        found |= SHA256;
    }
    if sha2 >= 2 && sha3 >= 1 {
        found |= SHA512;
    }
    found
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
#[link(name = "kernel32", kind = "raw-dylib")]
// rr: escape(unsafe): the signature is kernel32's, from its documentation.
unsafe extern "system" {
    // rr: escape(unsafe): it takes a number and only reads the CPU's
    // features.
    safe fn IsProcessorFeaturePresent(feature: u32) -> i32;
}

/// PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE (30) is AES, PMULL, SHA-1
/// and SHA-256; PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE (64) and
/// PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE (65), from Windows 11 24H2 on: an
/// older Windows answers false to a number it does not know.
#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
fn detect() -> u32 {
    const CRYPTO: u32 = 30;
    const SHA3: u32 = 64;
    const SHA512: u32 = 65;
    let mut found = promised();
    if IsProcessorFeaturePresent(CRYPTO) != 0 {
        found |= AES | SHA256;
    }
    if IsProcessorFeaturePresent(SHA3) != 0 && IsProcessorFeaturePresent(SHA512) != 0 {
        found |= self::SHA512;
    }
    found
}

/// Elsewhere, macOS among them, what the target promises.
#[cfg(all(
    target_arch = "aarch64",
    not(any(target_os = "linux", target_os = "windows"))
))]
fn detect() -> u32 {
    promised()
}

/// CPUID leaf 1, ECX: PCLMULQDQ (1), SSSE3 (9), SSE4.1 (19), AES (25),
/// OSXSAVE (27) and AVX (28). Leaf 7, EBX: AVX2 (5) and SHA (29); ECX:
/// VAES (9) and VPCLMULQDQ (10). AVX's registers are there to use only
/// when the OS saves them: XCR0's bits 1 and 2.
#[cfg(target_arch = "x86_64")]
fn detect() -> u32 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    const PCLMULQDQ: u32 = 1 << 1;
    const SSSE3: u32 = 1 << 9;
    const SSE41: u32 = 1 << 19;
    const AESNI: u32 = 1 << 25;
    const OSXSAVE: u32 = 1 << 27;
    const AVX: u32 = 1 << 28;
    const AVX2: u32 = 1 << 5;
    const SHA: u32 = 1 << 29;
    const VAES: u32 = 1 << 9;
    const VPCLMULQDQ: u32 = 1 << 10;
    const XCR0_SSE_AVX: u64 = 0b110;
    let leaf1 = __cpuid(1).ecx;
    let (leaf7_ebx, leaf7_ecx) = if __cpuid(0).eax >= 7 {
        let leaf7 = __cpuid_count(7, 0);
        (leaf7.ebx, leaf7.ecx)
    } else {
        (0, 0)
    };
    let all = |bits: u32, of: u32| of & bits == bits;
    let mut found = 0;
    if all(AESNI | PCLMULQDQ | SSSE3, leaf1) {
        found |= AES;
    }
    if all(SSSE3 | SSE41, leaf1) && all(SHA, leaf7_ebx) {
        found |= SHA256;
    }
    // rr: escape(unsafe): OSXSAVE says XGETBV runs and reads XCR0.
    let ymm = all(OSXSAVE | AVX, leaf1) && unsafe { xcr0() } & XCR0_SSE_AVX == XCR0_SSE_AVX;
    if found & AES != 0 && ymm && all(AVX2, leaf7_ebx) && all(VAES | VPCLMULQDQ, leaf7_ecx) {
        found |= WIDE_AES;
    }
    found
}

/// The state components the OS saves: XCR0.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "xsave")]
fn xcr0() -> u64 {
    // rr: escape(unsafe): register 0, XCR0, is there wherever XGETBV is.
    unsafe { core::arch::x86_64::_xgetbv(0) }
}
