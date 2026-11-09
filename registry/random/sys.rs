//! The system side of random: what mod.rs says it is, for each system.
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
        pub fn getrandom(buffer: *mut c_void, length: usize, flags: c_uint) -> isize;
        pub fn open(path: *const c_char, flags: c_int, ...) -> c_int;
        pub fn read(fd: c_int, buffer: *mut c_void, length: usize) -> isize;
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

/// Fills out from /dev/urandom, for a kernel without getrandom.
#[cfg(target_os = "linux")]
fn urandom(out: &mut [u8]) {
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
    unsafe { close(fd) };
}

/// Fills out with the system's randomness.
#[cfg(target_os = "windows")]
pub fn fill(out: &mut [u8]) {
    #[link(name = "bcryptprimitives", kind = "raw-dylib")]
    // rr: escape(unsafe): the signature is bcryptprimitives.dll's, as Go's
    // and BoringSSL's declare it.
    unsafe extern "system" {
        fn ProcessPrng(data: *mut u8, length: usize) -> i32;
    }
    // rr: escape(unsafe): it writes length bytes at data, which out has.
    if unsafe { ProcessPrng(out.as_mut_ptr(), out.len()) } == 0 {
        none();
    }
}

/// The system gave no randomness: nothing can go on that needs it.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn none() -> ! {
    // rr: escape(panic): a key or a nonce of bytes that are not random
    // would fail silently; Go and BoringSSL stop the program here too.
    panic!("random: the system gave no randomness");
}

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
