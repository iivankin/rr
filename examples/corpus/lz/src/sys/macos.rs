//! What the program needs of macOS: the heap, input, output, arguments
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
    fn read(fd: c_int, p: *mut c_void, n: usize) -> isize;
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

/// Standard input, all of it up to max bytes, onto out; false when it
/// holds more or cannot be read.
pub fn stdin(out: &mut Vec<u8>, max: usize) -> bool {
    let mut buf = [0u8; 16384];
    loop {
        // rr: escape(unsafe): buf is writable memory of its length.
        let n = unsafe { read(0, buf.as_mut_ptr().cast(), buf.len()) };
        let Ok(n) = usize::try_from(n) else {
            return false;
        };
        if n == 0 {
            return true;
        }
        if out.len() + n > max {
            return false;
        }
        out.extend_from_slice(&buf[..n]);
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
