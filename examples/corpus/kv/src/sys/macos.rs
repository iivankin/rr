//! What the program needs of macOS: the heap, files, output, arguments
//! and an end on a bug, through the C library, as Apple requires. The
//! rest of the crate calls only this; unsafe stays here.

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

#[link(name = "c")]
// rr: escape(unsafe): each signature is the C library's, from its headers.
unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn calloc(n: usize, size: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn posix_memalign(p: &mut *mut c_void, align: usize, size: usize) -> c_int;
    fn write(fd: c_int, p: *const c_void, n: usize) -> isize;
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn pread(fd: c_int, p: *mut c_void, n: usize, off: i64) -> isize;
    fn pwrite(fd: c_int, p: *const c_void, n: usize, off: i64) -> isize;
    fn lseek(fd: c_int, off: i64, whence: c_int) -> i64;
    fn ftruncate(fd: c_int, len: i64) -> c_int;
    fn fsync(fd: c_int) -> c_int;
    fn rename(from: *const c_char, to: *const c_char) -> c_int;
    fn unlink(path: *const c_char) -> c_int;
    fn strlen(s: *const c_char) -> usize;
    fn abort() -> !;
}

/// The alignment malloc gives every block.
const MALLOC_ALIGN: usize = 16;

/// The global allocator: the C library's malloc, as std's System is on
/// Unix. An alignment above malloc's goes through posix_memalign.
pub struct Heap;

fn aligned(l: Layout) -> *mut u8 {
    let mut p = null_mut();
    let align = l.align().max(size_of::<usize>());
    // rr: escape(unsafe): p is a local out-parameter; align is a power of two.
    let r = unsafe { posix_memalign(&mut p, align, l.size()) };
    if r != 0 { null_mut() } else { p.cast() }
}

// Blocks come from malloc, calloc and posix_memalign, all freed by free,
// and realloc keeps malloc's alignment: GlobalAlloc's contract holds.
// rr: escape(unsafe): GlobalAlloc is unsafe to implement.
unsafe impl GlobalAlloc for Heap {
    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.align() > MALLOC_ALIGN || l.align() > l.size() {
            return aligned(l);
        }
        // rr: escape(unsafe): malloc takes a plain size.
        unsafe { malloc(l.size()) }.cast()
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if l.align() > MALLOC_ALIGN || l.align() > l.size() {
            let p = aligned(l);
            if !p.is_null() {
                // rr: escape(unsafe): p is a fresh block of l.size() bytes.
                unsafe { core::ptr::write_bytes(p, 0, l.size()) };
            }
            return p;
        }
        // rr: escape(unsafe): calloc takes plain sizes.
        unsafe { calloc(l.size(), 1) }.cast()
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn dealloc(&self, p: *mut u8, _l: Layout) {
        // rr: escape(unsafe): p came from this heap.
        unsafe { free(p.cast()) };
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
        if l.align() <= MALLOC_ALIGN && l.align() <= size {
            // rr: escape(unsafe): p is a live block of this heap.
            return unsafe { realloc(p.cast(), size) }.cast();
        }
        let q = aligned(Layout::from_size_align(size, l.align()).unwrap_or(l));
        if !q.is_null() {
            // rr: escape(unsafe): both blocks are live and hold at least this much.
            unsafe { core::ptr::copy_nonoverlapping(p, q, l.size().min(size)) };
            // rr: escape(unsafe): p came from this heap and is not used after.
            unsafe { free(p.cast()) };
        }
        q
    }
}

fn write_all(fd: c_int, mut p: &[u8]) {
    while !p.is_empty() {
        // rr: escape(unsafe): p is readable memory of its length.
        let n = unsafe { write(fd, p.as_ptr().cast(), p.len()) };
        // An error, or nothing written: give up.
        let Some(n) = usize::try_from(n).ok().filter(|n| *n > 0) else {
            return;
        };
        p = &p[n..];
    }
}

pub fn stdout(p: &[u8]) {
    write_all(1, p);
}

pub fn stderr(p: &[u8]) {
    write_all(2, p);
}

/// main's arguments as byte strings.
///
/// # Safety
/// argv must hold argc NUL-terminated strings that live as long as the
/// process, as main's own do.
// rr: escape(unsafe): the caller vouches for argv, which only main can.
pub unsafe fn args(argc: i32, argv: *const *const c_char) -> Vec<&'static [u8]> {
    let argc = usize::try_from(argc).unwrap_or(0);
    let mut out = Vec::with_capacity(argc);
    // rr: escape(unsafe): argv holds argc of main's strings, per the contract.
    let argv = unsafe { core::slice::from_raw_parts(argv, argc) };
    for &s in argv {
        // rr: escape(unsafe): s is NUL-terminated.
        let n = unsafe { strlen(s) };
        // rr: escape(unsafe): s holds n bytes that live as long as the process.
        out.push(unsafe { core::slice::from_raw_parts(s.cast(), n) });
    }
    out
}

/// End the process at once: a bug was found.
pub fn die() -> ! {
    // rr: escape(unsafe): abort ends the process.
    unsafe { abort() }
}

/// A failed call to the system.
pub struct Error;

/// A number the system cannot take or give: the call fails.
impl From<core::num::TryFromIntError> for Error {
    fn from(_: core::num::TryFromIntError) -> Error {
        Error
    }
}

const O_RDWR: c_int = 0x0002;
const O_CREAT: c_int = 0x0200;
const O_TRUNC: c_int = 0x0400;
const O_CLOEXEC: c_int = 0x0100_0000;
const SEEK_END: c_int = 2;
/// The longest path the program names.
pub const PATH_MAX: usize = 1024;

/// path with a NUL after it, on the stack; Error when it is too long or
/// holds a NUL.
fn c_path(path: &[u8], buf: &mut [u8; PATH_MAX + 1]) -> Result<(), Error> {
    if path.len() > PATH_MAX || path.contains(&0) {
        return Err(Error);
    }
    buf[..path.len()].copy_from_slice(path);
    buf[path.len()] = 0;
    Ok(())
}

/// An open file, closed on drop.
pub struct File {
    fd: c_int,
}

impl File {
    /// Open path for reading and writing, creating it if it is missing;
    /// emptied first when fresh.
    pub fn open(path: &[u8], fresh: bool) -> Result<File, Error> {
        let mut buf = [0u8; PATH_MAX + 1];
        c_path(path, &mut buf)?;
        let flags = O_RDWR | O_CREAT | O_CLOEXEC | if fresh { O_TRUNC } else { 0 };
        // rr: escape(unsafe): buf is NUL-terminated.
        let fd = unsafe { open(buf.as_ptr().cast(), flags, 0o600) };
        if fd < 0 {
            return Err(Error);
        }
        Ok(File { fd })
    }

    /// The file's length in bytes.
    pub fn size(&self) -> Result<u64, Error> {
        // rr: escape(unsafe): the descriptor is this file's.
        let n = unsafe { lseek(self.fd, 0, SEEK_END) };
        Ok(u64::try_from(n)?)
    }

    /// Read up to buf's length at offset off: how many bytes came, 0 at
    /// the end.
    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let off = i64::try_from(off)?;
        // rr: escape(unsafe): buf is writable memory of its length.
        let n = unsafe { pread(self.fd, buf.as_mut_ptr().cast(), buf.len(), off) };
        Ok(usize::try_from(n)?)
    }

    /// Write all of p at offset off.
    pub fn write_at(&self, mut off: u64, mut p: &[u8]) -> Result<(), Error> {
        while !p.is_empty() {
            let at = i64::try_from(off)?;
            // rr: escape(unsafe): p is readable memory of its length.
            let n = unsafe { pwrite(self.fd, p.as_ptr().cast(), p.len(), at) };
            let n = usize::try_from(n).ok().filter(|n| *n > 0).ok_or(Error)?;
            p = &p[n..];
            off += n as u64;
        }
        Ok(())
    }

    /// Cut the file to len bytes.
    pub fn truncate(&self, len: u64) -> Result<(), Error> {
        let len = i64::try_from(len)?;
        // rr: escape(unsafe): the descriptor is this file's.
        if unsafe { ftruncate(self.fd, len) } != 0 {
            return Err(Error);
        }
        Ok(())
    }

    /// Wait until what was written is on the disk.
    pub fn sync(&self) -> Result<(), Error> {
        // rr: escape(unsafe): the descriptor is this file's.
        if unsafe { fsync(self.fd) } != 0 {
            return Err(Error);
        }
        Ok(())
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // rr: escape(unsafe): the descriptor is this file's, and closed once.
        unsafe { close(self.fd) };
    }
}

/// Give the file at from the name to, replacing what had it.
pub fn rename_to(from: &[u8], to: &[u8]) -> Result<(), Error> {
    let (mut a, mut b) = ([0u8; PATH_MAX + 1], [0u8; PATH_MAX + 1]);
    c_path(from, &mut a)?;
    c_path(to, &mut b)?;
    // rr: escape(unsafe): both are NUL-terminated.
    if unsafe { rename(a.as_ptr().cast(), b.as_ptr().cast()) } != 0 {
        return Err(Error);
    }
    Ok(())
}

/// Remove the file at path.
pub fn remove(path: &[u8]) -> Result<(), Error> {
    let mut buf = [0u8; PATH_MAX + 1];
    c_path(path, &mut buf)?;
    // rr: escape(unsafe): buf is NUL-terminated.
    if unsafe { unlink(buf.as_ptr().cast()) } != 0 {
        return Err(Error);
    }
    Ok(())
}
