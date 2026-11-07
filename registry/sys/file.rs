//! Files on Linux, for the components that read the system's
//! configuration there (resolve, trust): open a path, read a file whole up
//! to a limit, and a descriptor closed on drop; and the kernel's calls by
//! number, through the C library's syscall, for them and for this. macOS
//! and Windows read their configuration through the system's own
//! libraries, and have nothing here.
#![cfg(target_os = "linux")]

use alloc::vec::Vec;
use core::ffi::c_long;

#[link(name = "c")]
// rr: escape(unsafe): each signature is the C library's, from its headers.
unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn __errno_location() -> *mut i32;
}

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: usize = 0;
    pub const CLOSE: usize = 3;
    pub const OPENAT: usize = 257;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: usize = 63;
    pub const CLOSE: usize = 57;
    pub const OPENAT: usize = 56;
}

const AT_FDCWD: isize = -100;
const O_CLOEXEC: usize = 0o2_000_000;
const EINTR: i32 = 4;
const EINVAL: i32 = 22;
/// The longest path opened, the kernel's PATH_MAX with its NUL.
const PATH_BYTES_MAX: usize = 4096;
/// What one read takes of a file.
const CHUNK_BYTES: usize = 64 << 10;

/// System call n on plain numbers and memory the caller vouches for;
/// its result, or the error number.
pub fn call(n: usize, args: [usize; 6]) -> Result<usize, i32> {
    // The calls' numbers are small; a larger one is no call.
    let Ok(n) = c_long::try_from(n) else {
        return Err(EINVAL);
    };
    let [a, b, c, d, e, f] = args;
    // rr: escape(unsafe): each caller passes the call's own arguments,
    // pointers to memory it holds for the call's length.
    let r = unsafe { syscall(n, a, b, c, d, e, f) };
    if let Ok(r) = usize::try_from(r) {
        return Ok(r);
    }
    // rr: escape(unsafe): the C library gives each thread its errno.
    let errno = unsafe { __errno_location() };
    // rr: escape(unsafe): errno is the calling thread's, set by the call
    // that failed.
    Err(unsafe { *errno })
}

/// A descriptor, closed on drop.
pub struct Descriptor(usize);

impl Descriptor {
    /// Takes fd, which a system call opened, to close.
    pub fn new(fd: usize) -> Descriptor {
        Descriptor(fd)
    }

    pub fn raw(&self) -> usize {
        self.0
    }

    /// The descriptor as poll takes it.
    pub fn fd(&self) -> i32 {
        i32::try_from(self.0).unwrap_or(-1)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // rr: escape(discard): nothing is left to do when close fails.
        let _closed = call(nr::CLOSE, [self.0, 0, 0, 0, 0, 0]);
    }
}

/// Opens path (without its NUL) for reading: a file or a directory.
pub fn open(path: &[u8]) -> Result<Descriptor, i32> {
    if path.contains(&0) || path.len() >= PATH_BYTES_MAX {
        return Err(EINVAL);
    }
    let mut c_path = [0u8; PATH_BYTES_MAX];
    c_path
        .get_mut(..path.len())
        .ok_or(EINVAL)?
        .copy_from_slice(path);
    let at = AT_FDCWD.cast_unsigned();
    let p = c_path.as_ptr().expose_provenance();
    call(nr::OPENAT, [at, p, O_CLOEXEC, 0, 0, 0]).map(Descriptor)
}

/// The file at path into text, which it clears first, up to limit
/// bytes: whether that was the whole file, or the error number.
pub fn read(path: &[u8], limit: usize, text: &mut Vec<u8>) -> Result<bool, i32> {
    text.clear();
    let file = open(path)?;
    // Each turn reads more of the file, or ends.
    for _ in 0..=limit / CHUNK_BYTES + 1 {
        let start = text.len();
        let chunk = (limit - start).min(CHUNK_BYTES);
        if chunk == 0 {
            return Ok(false);
        }
        text.resize(start + chunk, 0);
        let into = text.get_mut(start..).unwrap_or_default();
        let p = into.as_mut_ptr().expose_provenance();
        match call(nr::READ, [file.raw(), p, chunk, 0, 0, 0]) {
            Ok(0) => {
                text.truncate(start);
                return Ok(true);
            }
            Ok(n) => text.truncate(start + n.min(chunk)),
            Err(EINTR) => text.truncate(start),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}
