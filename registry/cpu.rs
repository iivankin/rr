//! What the CPU has of the instructions the components use (AES, carry-less
//! multiply, SHA-256, SHA-512, VAES), asked once for the process, as Features
//! only it names.
//!
//! What the CPU has of the instructions the components use, asked once
//! for the process: what the target promises, and on aarch64 Linux and
//! Windows and on x86_64 what the CPU says it has besides. A component
//! asks has() before it runs code built for more than its target, of
//! Features that only the constants here name (AES, SHA256, SHA512,
//! WIDE_AES, and sets of them by and).

// rr: checked(0.5.2)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
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
compile_error!("rr add cut cpu without linux: add it again with linux in --option os");
// rr: end(os = linux)
// rr: unless(os = macos)
#[cfg(target_os = "macos")]
compile_error!("rr add cut cpu without macos: add it again with macos in --option os");
// rr: end(os = macos)
// rr: unless(os = windows)
#[cfg(windows)]
compile_error!("rr add cut cpu without windows: add it again with windows in --option os");
// rr: end(os = windows)
// rr: unless(arch = x86_64)
#[cfg(target_arch = "x86_64")]
compile_error!("rr add cut cpu without x86_64: add it again with x86_64 in --option arch");
// rr: end(arch = x86_64)
// rr: unless(arch = aarch64)
#[cfg(target_arch = "aarch64")]
compile_error!("rr add cut cpu without aarch64: add it again with aarch64 in --option arch");
// rr: end(arch = aarch64)
// rr: unless(arch = other)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("rr add cut cpu without other: add it again with other in --option arch");
// rr: end(arch = other)

mod sys {
    //! The system side of cpu: what the top of the file says it is, for each system.

    // rr: section(arch = x86_64 aarch64)
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    use core::sync::atomic::{AtomicU32, Ordering};
    // rr: end(arch = x86_64 aarch64)

    /// Features of the CPU, one or more of the constants below. Only cpu
    /// makes one, so a bit it keeps for itself cannot be asked.
    pub struct Features(u32);

    /// AES with the carry-less multiply GHASH takes: AES and PMULL on
    /// aarch64; AES-NI, PCLMULQDQ and SSSE3 on x86_64.
    pub const AES: Features = Features(1 << 0);
    /// SHA-256's rounds: SHA2 on aarch64; SHA-NI, SSSE3 and SSE4.1 on x86_64.
    pub const SHA256: Features = Features(1 << 1);
    /// SHA-512's rounds and SHA3's EOR3 on aarch64, which Rust enables as one
    /// feature, "sha3".
    pub const SHA512: Features = Features(1 << 2);
    /// AES and carry-less multiply on 256-bit vectors on x86_64: VAES,
    /// VPCLMULQDQ and AVX2, with the YMM registers the OS saves.
    pub const WIDE_AES: Features = Features(1 << 3);

    impl Features {
        /// These and other, for one has().
        #[must_use]
        pub const fn and(&self, other: &Features) -> Features {
            Features(self.0 | other.0)
        }
    }

    // rr: section(arch = x86_64 aarch64)
    /// Set in FOUND once the CPU was asked.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    const ASKED: u32 = 1 << 31;
    // rr: end(arch = x86_64 aarch64)

    // rr: section(arch = x86_64 aarch64)
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    // rr: escape(shared): the CPU's answer, the same for every thread; a race
    // only asks it twice.
    static FOUND: AtomicU32 = AtomicU32::new(0);
    // rr: end(arch = x86_64 aarch64)

    // rr: section(arch = x86_64 aarch64)
    /// Whether the CPU has every feature in want.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub fn has(want: &Features) -> bool {
        let mut found = FOUND.load(Ordering::Relaxed);
        if found & ASKED == 0 {
            found = detect() | ASKED;
            FOUND.store(found, Ordering::Relaxed);
        }
        found & want.0 == want.0
    }
    // rr: end(arch = x86_64 aarch64)

    // rr: section(arch = other)
    /// No instructions this code knows on this architecture.
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub fn has(want: &Features) -> bool {
        want.0 == 0
    }
    // rr: end(arch = other)

    // rr: section(arch = aarch64)
    /// What the target promises: on macOS every one of them, as every Mac
    /// on Apple silicon has them.
    #[cfg(target_arch = "aarch64")]
    fn promised() -> u32 {
        let mut found = 0;
        if cfg!(target_feature = "aes") {
            found |= AES.0;
        }
        if cfg!(target_feature = "sha2") {
            found |= SHA256.0;
        }
        if cfg!(target_feature = "sha3") {
            found |= SHA512.0;
        }
        found
    }
    // rr: end(arch = aarch64)

    // rr: section(os = linux)
    // rr: section(arch = aarch64)
    /// What the kernel says the CPU has, in the auxiliary vector's HWCAP
    /// (asm/hwcap.h): AES and PMULL for AES, SHA2 for SHA-256, SHA512 and
    /// SHA3 (its EOR3) for SHA-512.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[must_use]
    fn detect() -> u32 {
        const AT_HWCAP: core::ffi::c_ulong = 16;
        const HWCAP_AES: core::ffi::c_ulong = 1 << 3;
        const HWCAP_PMULL: core::ffi::c_ulong = 1 << 4;
        const HWCAP_SHA2: core::ffi::c_ulong = 1 << 6;
        const HWCAP_SHA3: core::ffi::c_ulong = 1 << 17;
        const HWCAP_SHA512: core::ffi::c_ulong = 1 << 21;
        #[link(name = "c")]
        // rr: escape(unsafe): its signature is the C library's, from sys/auxv.h.
        unsafe extern "C" {
            #[must_use]
            fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
        }
        // rr: escape(unsafe): getauxval only reads the process's vector.
        let hwcap = unsafe { getauxval(AT_HWCAP) };
        let has = |bits: core::ffi::c_ulong| hwcap & bits == bits;
        let mut found = promised();
        if has(HWCAP_AES | HWCAP_PMULL) {
            found |= AES.0;
        }
        if has(HWCAP_SHA2) {
            found |= SHA256.0;
        }
        if has(HWCAP_SHA512 | HWCAP_SHA3) {
            found |= SHA512.0;
        }
        found
    }
    // rr: end(arch = aarch64)
    // rr: end(os = linux)

    // rr: section(os = windows)
    // rr: section(arch = aarch64)
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): the signature is kernel32's, from its documentation.
    unsafe extern "system" {
        #[must_use]
        // rr: escape(unsafe): it takes a number and only reads the CPU's
        // features.
        safe fn IsProcessorFeaturePresent(feature: u32) -> i32;
    }
    // rr: end(arch = aarch64)
    // rr: end(os = windows)

    // rr: section(os = windows)
    // rr: section(arch = aarch64)
    /// PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE (30) is AES, PMULL, SHA-1
    /// and SHA-256; PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE (64) and
    /// PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE (65), from Windows 11 24H2 on: an
    /// older Windows answers false to a number it does not know.
    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    #[must_use]
    fn detect() -> u32 {
        const CRYPTO: u32 = 30;
        const SHA3: u32 = 64;
        const SHA512: u32 = 65;
        let mut found = promised();
        if IsProcessorFeaturePresent(CRYPTO) != 0 {
            found |= AES.0 | SHA256.0;
        }
        if IsProcessorFeaturePresent(SHA3) != 0 && IsProcessorFeaturePresent(SHA512) != 0 {
            found |= self::SHA512.0;
        }
        found
    }
    // rr: end(arch = aarch64)
    // rr: end(os = windows)

    // rr: section(os = macos)
    // rr: section(arch = aarch64)
    /// Elsewhere, macOS among them, what the target promises.
    #[cfg(all(
        target_arch = "aarch64",
        not(any(target_os = "linux", target_os = "windows"))
    ))]
    fn detect() -> u32 {
        promised()
    }
    // rr: end(arch = aarch64)
    // rr: end(os = macos)

    // rr: section(arch = x86_64)
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
            found |= AES.0;
        }
        if all(SSSE3 | SSE41, leaf1) && all(SHA, leaf7_ebx) {
            found |= SHA256.0;
        }
        // rr: escape(unsafe): OSXSAVE says XGETBV runs and reads XCR0.
        let ymm = all(OSXSAVE | AVX, leaf1) && unsafe { xcr0() } & XCR0_SSE_AVX == XCR0_SSE_AVX;
        if found & AES.0 != 0 && ymm && all(AVX2, leaf7_ebx) && all(VAES | VPCLMULQDQ, leaf7_ecx) {
            found |= WIDE_AES.0;
        }
        found
    }
    // rr: end(arch = x86_64)

    // rr: section(arch = x86_64)
    /// The state components the OS saves: XCR0.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "xsave")]
    fn xcr0() -> u64 {
        // rr: escape(unsafe): register 0, XCR0, is there wherever XGETBV is.
        unsafe { core::arch::x86_64::_xgetbv(0) }
    }
    // rr: end(arch = x86_64)
}

pub use sys::*;

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    use super::{AES, SHA256, SHA512, WIDE_AES, has};

    /// As a component asks: the same answer every time, and a set of
    /// features is had when each of them is.
    #[test]
    fn asks() {
        for feature in [&AES, &SHA256, &SHA512, &WIDE_AES] {
            assert_eq!(has(feature), has(feature));
        }
        assert_eq!(has(&AES.and(&SHA512)), has(&AES) && has(&SHA512));
        assert_eq!(has(&SHA256.and(&WIDE_AES)), has(&SHA256) && has(&WIDE_AES));
        // What the target promises, the CPU has.
        if cfg!(all(target_arch = "aarch64", target_feature = "aes")) {
            assert!(has(&AES));
        }
    }
}
// rr: end(tests = yes)
