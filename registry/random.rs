//! The system's randomness: arc4random_buf on macOS, getrandom(2) on Linux
//! (/dev/urandom before 3.17), ProcessPrng on Windows; seeds of 32 and 64
//! bytes that only it makes, which keys are made from, wiped when dropped.
//!
//! The system's randomness, as Go's crypto/rand and BoringSSL take it:
//! arc4random_buf on macOS, getrandom(2) on Linux, ProcessPrng on
//! Windows (its sys module says why each). It never fails: a system that cannot
//! give randomness stops the program, as Go 1.24's Read and BoringSSL's
//! RAND_bytes do, rather than hand out bytes that are not random.
//!
//! A key is made from a Seed32 or a Seed64, which only seed32 and
//! seed64 make from the system (and for_tests in a test): a constant, a
//! counter or a test array cannot stand in for one where a key is made.
//! A seed is not Copy, Clone or Debug, is used once (the key takes it by
//! value, and into_bytes uses it up), and is wiped when dropped.
//!
//! The intended use:
//!
//! ```text
//! let secret = x25519::Secret::new(random::seed32());
//! let key = mlkem::DecapsulationKey::generate(random::seed64());
//! let mut nonce = [0; 12];
//! random::fill(&mut nonce);
//! ```

// rr: checked(0.5.2)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
// rr: option(os, many): Which systems does it build for?
// rr: choice(os = linux, default): Linux
// rr: choice(os = macos, default): macOS
// rr: choice(os = windows, default): Windows

// rr: unless(os = linux)
#[cfg(target_os = "linux")]
compile_error!("rr add cut random without linux: add it again with linux in --option os");
// rr: end(os = linux)
// rr: unless(os = macos)
#[cfg(target_os = "macos")]
compile_error!("rr add cut random without macos: add it again with macos in --option os");
// rr: end(os = macos)
// rr: unless(os = windows)
#[cfg(windows)]
compile_error!("rr add cut random without windows: add it again with windows in --option os");
// rr: end(os = windows)

mod sys {
    //! The system side of random: what the top of the file says it is, for each system.
    //!
    //! - macOS: arc4random_buf, as Go's crypto/internal/sysrand takes it on
    //!   Darwin: the C library's generator over the kernel's, for any length,
    //!   and it never fails. (BoringSSL and the getrandom crate ask
    //!   getentropy, the same kernel source, 256 bytes a call.)
    //! - Linux: getrandom(2) with no flags, as Go, BoringSSL and the
    //!   getrandom crate (ring's and rustls's) ask it: it blocks only until
    //!   the kernel's pool is first ready at boot, and then never. A signal
    //!   (EINTR) asks again; a short read goes on from where it stopped. A
    //!   kernel before 3.17, which glibc 2.31 still runs on, or a seccomp
    //!   filter, answers ENOSYS: then /dev/urandom, as Go and BoringSSL fall
    //!   back to it.
    //! - Windows: ProcessPrng from bcryptprimitives.dll, as Go (since 1.22),
    //!   BoringSSL and the getrandom crate take it on Windows 10 and later:
    //!   the process's generator, which never fails and always answers TRUE.
    //!
    //! Any other answer is a system without randomness: the program stops.

    use core::sync::atomic::{Ordering, compiler_fence};

    // rr: section(os = macos)
    /// Fills out with the system's randomness.
    #[cfg(target_os = "macos")]
    pub fn fill(out: &mut [u8]) {
        #[link(name = "c")]
        // rr: escape(unsafe): its signature is the C library's, from stdlib.h.
        unsafe extern "C" {
            fn arc4random_buf(buffer: *mut core::ffi::c_void, length: usize);
        }
        // rr: escape(unsafe): it writes length bytes at buffer, which out has.
        unsafe { arc4random_buf(out.as_mut_ptr().cast(), out.len()) };
    }
    // rr: end(os = macos)

    // rr: section(os = linux)
    /// The C library's calls, and what errno says of one that failed.
    #[cfg(target_os = "linux")]
    mod linux {
        use core::ffi::{c_char, c_int, c_uint, c_void};

        /// open's flags for /dev/urandom: O_RDONLY (0) and O_CLOEXEC, fcntl.h's
        /// on x86_64 and aarch64.
        pub const URANDOM_FLAGS: c_int = 0o2_000_000;

        /// Why a call failed, by errno.h's numbers on x86_64 and aarch64.
        pub enum Failure {
            /// EINTR (4): a signal came; the call goes again.
            Interrupted,
            /// ENOSYS (38): a kernel without the call.
            Missing,
            /// Anything else.
            Other,
        }

        #[link(name = "c")]
        // rr: escape(unsafe): their signatures are the C library's, from
        // sys/random.h, fcntl.h, unistd.h and errno.h.
        unsafe extern "C" {
            #[must_use]
            pub fn getrandom(buffer: *mut c_void, length: usize, flags: c_uint) -> isize;
            #[must_use]
            pub fn open(path: *const c_char, flags: c_int, ...) -> c_int;
            #[must_use]
            pub fn read(fd: c_int, buffer: *mut c_void, length: usize) -> isize;
            #[must_use]
            pub fn close(fd: c_int) -> c_int;
            fn __errno_location() -> *mut c_int;
        }

        /// Why the last call of this thread failed, from errno as the C
        /// library keeps it.
        pub fn failure() -> Failure {
            // rr: escape(unsafe): the C library's thread-local errno.
            let place = unsafe { __errno_location() };
            // rr: escape(unsafe): the place is this thread's errno.
            match unsafe { place.read() } {
                4 => Failure::Interrupted,
                38 => Failure::Missing,
                _ => Failure::Other,
            }
        }
    }
    // rr: end(os = linux)

    // rr: section(os = linux)
    /// Fills out with the system's randomness.
    #[cfg(target_os = "linux")]
    pub fn fill(out: &mut [u8]) {
        use linux::{Failure, failure, getrandom};
        let mut at = 0;
        while let Some(rest) = out.get_mut(at..)
            && !rest.is_empty()
        {
            // rr: escape(unsafe): it writes at most length bytes at buffer,
            // which rest has.
            let got = unsafe { getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
            match usize::try_from(got) {
                Ok(count) => at += count,
                Err(_) => match failure() {
                    Failure::Interrupted => {}
                    Failure::Missing => return urandom(rest),
                    Failure::Other => none(),
                },
            }
        }
    }
    // rr: end(os = linux)

    // rr: section(os = linux)
    /// Fills out from /dev/urandom, for a kernel without getrandom.
    #[cfg(target_os = "linux")]
    fn urandom(out: &mut [u8]) {
        use core::ffi::c_int;
        use linux::{Failure, URANDOM_FLAGS, close, failure, open, read};
        // rr: escape(unsafe): the path ends in its NUL; no mode is read
        // without O_CREAT.
        let fd = unsafe { open(c"/dev/urandom".as_ptr(), URANDOM_FLAGS) };
        if fd < 0 {
            none();
        }
        let mut at = 0;
        while let Some(rest) = out.get_mut(at..)
            && !rest.is_empty()
        {
            // rr: escape(unsafe): it writes at most length bytes at buffer,
            // which rest has.
            let got = unsafe { read(fd, rest.as_mut_ptr().cast(), rest.len()) };
            match usize::try_from(got) {
                Ok(0) => none(),
                Ok(count) => at += count,
                Err(_) if matches!(failure(), Failure::Interrupted) => {}
                Err(_) => none(),
            }
        }
        // rr: escape(unsafe): fd is the descriptor open gave, closed once.
        unsafe {
            // rr: escape(discard): close releases the descriptor whatever it
            // answers; no one is left to tell.
            let _: c_int = close(fd);
        }
    }
    // rr: end(os = linux)

    // rr: section(os = windows)
    /// Fills out with the system's randomness.
    #[cfg(target_os = "windows")]
    pub fn fill(out: &mut [u8]) {
        #[link(name = "bcryptprimitives", kind = "raw-dylib")]
        // rr: escape(unsafe): the signature is bcryptprimitives.dll's, as Go's
        // and BoringSSL's declare it.
        unsafe extern "system" {
            #[must_use]
            fn ProcessPrng(data: *mut u8, length: usize) -> i32;
        }
        // rr: escape(unsafe): it writes length bytes at data, which out has.
        if unsafe { ProcessPrng(out.as_mut_ptr(), out.len()) } == 0 {
            none();
        }
    }
    // rr: end(os = windows)

    // rr: section(os = linux windows)
    /// The system gave no randomness: nothing can go on that needs it.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn none() -> ! {
        // rr: escape(panic): a key or a nonce of bytes that are not random
        // would fail silently; Go and BoringSSL stop the program here too.
        panic!("random: the system gave no randomness");
    }
    // rr: end(os = linux windows)

    /// Zeros over bytes, each written as a volatile store, which the
    /// compiler keeps; the fence keeps later code from moving above them.
    pub fn wipe(bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            // rr: escape(unsafe): byte is a place of its own, aligned and
            // borrowed mutably.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// wipe for 16-bit words.
    pub fn wipe_u16(words: &mut [u16]) {
        for word in words.iter_mut() {
            // rr: escape(unsafe): word is a place of its own, aligned and
            // borrowed mutably.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Bytes of a Seed32.
pub const SEED32_BYTES: usize = 32;
/// Bytes of a Seed64.
pub const SEED64_BYTES: usize = 64;

/// 32 bytes of the system's randomness, for one key.
pub struct Seed32 {
    bytes: [u8; SEED32_BYTES],
}

/// 64 bytes of the system's randomness, for one key.
pub struct Seed64 {
    bytes: [u8; SEED64_BYTES],
}

/// Fills out with the system's randomness.
pub fn fill(out: &mut [u8]) {
    sys::fill(out);
}

/// A new Seed32 from the system.
#[must_use]
pub fn seed32() -> Seed32 {
    let mut bytes = [0; SEED32_BYTES];
    sys::fill(&mut bytes);
    Seed32 { bytes }
}

/// A new Seed64 from the system.
#[must_use]
pub fn seed64() -> Seed64 {
    let mut bytes = [0; SEED64_BYTES];
    sys::fill(&mut bytes);
    Seed64 { bytes }
}

/// Overwrites a secret with zeros, by writes the compiler keeps though
/// nothing reads the bytes after them.
pub fn wipe(bytes: &mut [u8]) {
    sys::wipe(bytes);
}

/// wipe for 16-bit words, as a key's polynomials are.
pub fn wipe_u16(words: &mut [u16]) {
    sys::wipe_u16(words);
}

impl Seed32 {
    /// The bytes, for the key that takes the seed, which is used up:
    /// the key keeps them and wipes them.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SEED32_BYTES] {
        self.bytes
    }

    // rr: section(tests = yes)
    /// Given bytes as a seed: a standard's test vector. Only tests and
    /// fuzz targets have it.
    #[cfg(any(test, fuzzing))]
    pub fn for_tests(bytes: [u8; SEED32_BYTES]) -> Seed32 {
        Seed32 { bytes }
    }
    // rr: end(tests = yes)
}

impl Seed64 {
    /// The bytes, for the key that takes the seed, which is used up:
    /// the key keeps them and wipes them.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SEED64_BYTES] {
        self.bytes
    }

    // rr: section(tests = yes)
    /// Given bytes as a seed: a standard's test vector. Only tests and
    /// fuzz targets have it.
    #[cfg(any(test, fuzzing))]
    pub fn for_tests(bytes: [u8; SEED64_BYTES]) -> Seed64 {
        Seed64 { bytes }
    }
    // rr: end(tests = yes)
}

impl Drop for Seed32 {
    fn drop(&mut self) {
        sys::wipe(&mut self.bytes);
    }
}

impl Drop for Seed64 {
    fn drop(&mut self) {
        sys::wipe(&mut self.bytes);
    }
}

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    use super::{SEED32_BYTES, fill, seed32, seed64, wipe, wipe_u16};
    use alloc::vec::Vec;
    use test::Bencher;

    /// Bits set in bytes.
    fn ones(bytes: &[u8]) -> u32 {
        bytes.iter().map(|byte| byte.count_ones()).sum()
    }

    /// As a program uses it: seeds and buffers of every size from 0 to a
    /// megabyte (past getrandom's 32 MiB - 1 a call is not needed to show
    /// the loop: any short read goes round it), each different from the
    /// last and about half ones.
    #[test]
    fn fills() {
        let mut last = Vec::new();
        let mut buffer = Vec::new();
        for length in [0, 1, 7, 32, 255, 256, 257, 4096, 1 << 20] {
            buffer.clear();
            buffer.resize(length, 0);
            fill(&mut buffer);
            if length >= 32 {
                assert_ne!(buffer, last, "{length}");
                let bits = u32::try_from(8 * length).unwrap();
                let set = ones(&buffer);
                // Eight standard deviations of a fair coin's count.
                let spread = 4 * bits.isqrt() + 8;
                assert!(set.abs_diff(bits / 2) < spread, "{length}: {set} of {bits}");
            }
            core::mem::swap(&mut last, &mut buffer);
        }
        // A fill that covers part of a buffer leaves the rest.
        let mut part = [0; 64];
        fill(&mut part[..32]);
        assert_eq!(part[32..], [0; 32]);
    }

    /// Two seeds are never the same, and a seed is all its bytes.
    #[test]
    fn seeds() {
        let (a, b) = (seed32().into_bytes(), seed32().into_bytes());
        assert_ne!(a, b);
        assert_ne!(a, [0; SEED32_BYTES]);
        let (c, d) = (seed64().into_bytes(), seed64().into_bytes());
        assert_ne!(c, d);
        assert!(ones(&c) > 128);
    }

    #[test]
    fn wipes() {
        let mut bytes = [0xa5; 100];
        wipe(&mut bytes[1..]);
        assert_eq!(bytes[0], 0xa5);
        assert_eq!(bytes[1..], [0; 99]);
        let mut words = [0xa5a5; 9];
        wipe_u16(&mut words);
        assert_eq!(words, [0; 9]);
    }

    /// One seed for a key, from the system.
    #[bench]
    fn one_seed32(b: &mut Bencher) {
        b.iter(seed32);
    }
}
// rr: end(tests = yes)
