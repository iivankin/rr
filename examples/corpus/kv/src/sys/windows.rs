//! What the program needs of Windows: the heap, files, output, arguments
//! and an end on a bug, through kernel32.dll; there is no C runtime. The rest of
//! the crate calls only this; unsafe stays here.

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

#[link(name = "kernel32", kind = "raw-dylib")]
// rr: escape(unsafe): each signature is kernel32's, from its documentation.
unsafe extern "system" {
    fn GetProcessHeap() -> *mut c_void;
    fn HeapAlloc(heap: *mut c_void, flags: u32, size: usize) -> *mut c_void;
    fn HeapReAlloc(heap: *mut c_void, flags: u32, p: *mut c_void, size: usize) -> *mut c_void;
    fn HeapFree(heap: *mut c_void, flags: u32, p: *mut c_void) -> i32;
    fn GetStdHandle(which: u32) -> *mut c_void;
    fn WriteFile(
        file: *mut c_void,
        p: *const u8,
        n: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn ReadFile(
        file: *mut c_void,
        p: *mut u8,
        n: u32,
        read: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        attributes: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetFileSizeEx(file: *mut c_void, size: *mut i64) -> i32;
    fn SetFileInformationByHandle(
        file: *mut c_void,
        class: u32,
        info: *const c_void,
        size: u32,
    ) -> i32;
    fn FlushFileBuffers(file: *mut c_void) -> i32;
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    fn DeleteFileW(path: *const u16) -> i32;
    fn MultiByteToWideChar(
        page: u32,
        flags: u32,
        s: *const u8,
        n: i32,
        wide: *mut u16,
        wide_n: i32,
    ) -> i32;
    fn GetLastError() -> u32;
}

/// The alignment HeapAlloc gives every block.
const HEAP_ALIGN: usize = 16;
const HEAP_ZERO_MEMORY: u32 = 8;
const STD_OUTPUT_HANDLE: u32 = (-11i32).cast_unsigned();
const STD_ERROR_HANDLE: u32 = (-12i32).cast_unsigned();

/// The global allocator: the process heap, as std's System is on
/// Windows. A block aligned beyond the heap's is taken larger and
/// aligned inside, with the heap's own pointer kept just before it.
pub struct Heap;

/// The process's heap.
fn heap() -> *mut c_void {
    // rr: escape(unsafe): the process heap is always there.
    unsafe { GetProcessHeap() }
}

/// A block for l, zeroed or not.
fn block(l: Layout, flags: u32) -> *mut u8 {
    let heap = heap();
    if l.align() <= HEAP_ALIGN {
        // rr: escape(unsafe): HeapAlloc takes a plain size.
        return unsafe { HeapAlloc(heap, flags, l.size()) }.cast();
    }
    let Some(total) = l.size().checked_add(l.align()) else {
        return null_mut();
    };
    // rr: escape(unsafe): HeapAlloc takes a plain size.
    let p = unsafe { HeapAlloc(heap, flags, total) }.cast::<u8>();
    if p.is_null() {
        return p;
    }
    // p is aligned to 16, l to more: the aligned block starts 16 bytes or
    // more into p's, which leaves room for the pointer before it.
    let offset = match p.align_offset(l.align()) {
        0 => l.align(),
        o => o,
    };
    let aligned = p.wrapping_add(offset);
    // rr: escape(unsafe, cast): the word before aligned lies within the block, past p.
    unsafe { aligned.cast::<*mut u8>().wrapping_sub(1).write_unaligned(p) };
    aligned
}

/// The heap's own pointer of a block of l.
fn origin(p: *mut u8, l: Layout) -> *mut c_void {
    if l.align() <= HEAP_ALIGN {
        return p.cast();
    }
    // rr: escape(unsafe, cast): block kept the heap's pointer just before p.
    unsafe { p.cast::<*mut u8>().wrapping_sub(1).read_unaligned() }.cast()
}

// Blocks come from the process heap and go back to it by the pointer
// it gave; an aligned block keeps that pointer before it: GlobalAlloc's
// contract holds.
// rr: escape(unsafe): GlobalAlloc is unsafe to implement.
unsafe impl GlobalAlloc for Heap {
    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        block(l, 0)
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        block(l, HEAP_ZERO_MEMORY)
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // rr: escape(unsafe): the block came from the process heap.
        unsafe { HeapFree(heap(), 0, origin(p, l)) };
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
        if l.align() <= HEAP_ALIGN {
            // rr: escape(unsafe): p is a live block of the process heap.
            return unsafe { HeapReAlloc(heap(), 0, p.cast(), size) }.cast();
        }
        let q = block(Layout::from_size_align(size, l.align()).unwrap_or(l), 0);
        if !q.is_null() {
            // rr: escape(unsafe): both blocks are live and hold at least this much.
            unsafe { core::ptr::copy_nonoverlapping(p, q, l.size().min(size)) };
            // rr: escape(unsafe): p came from this heap and is not used after.
            unsafe { HeapFree(heap(), 0, origin(p, l)) };
        }
        q
    }
}

fn write_all(which: u32, mut p: &[u8]) {
    // rr: escape(unsafe): the standard handles are the process's own.
    let handle = unsafe { GetStdHandle(which) };
    while !p.is_empty() {
        let n = u32::try_from(p.len()).unwrap_or(u32::MAX);
        let mut written = 0;
        // rr: escape(unsafe): p is readable memory of at least n bytes.
        let ok = unsafe { WriteFile(handle, p.as_ptr(), n, &raw mut written, null_mut()) };
        // An error, or nothing written: give up.
        if ok == 0 || written == 0 {
            return;
        }
        p = &p[written as usize..];
    }
}

pub fn stdout(p: &[u8]) {
    write_all(STD_OUTPUT_HANDLE, p);
}

pub fn stderr(p: &[u8]) {
    write_all(STD_ERROR_HANDLE, p);
}

/// main's arguments as byte strings, in UTF-8.
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
        // rr: escape(unsafe): s is NUL-terminated and lives as long as the process.
        out.push(unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes());
    }
    out
}

/// End the process at once, as abort does: a bug was found. Windows's
/// fast fail ends it without running anything more.
pub fn die() -> ! {
    // FAST_FAIL_FATAL_APP_EXIT.
    #[cfg(target_arch = "x86_64")]
    // rr: escape(unsafe): __fastfail does not return.
    unsafe {
        core::arch::asm!("int 0x29", in("ecx") 7, options(noreturn, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    // rr: escape(unsafe): __fastfail does not return.
    unsafe {
        core::arch::asm!("brk #0xf003", in("x0") 7, options(noreturn, nostack));
    }
}

/// A failed call to the system.
pub struct Error;

/// A number the system cannot take or give: the call fails.
impl From<core::num::TryFromIntError> for Error {
    fn from(_: core::num::TryFromIntError) -> Error {
        Error
    }
}

/// Where a read or write starts in its file, as kernel32 takes it.
#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut c_void,
}

impl Overlapped {
    fn at(off: u64) -> Overlapped {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: (off & 0xffff_ffff) as u32,
            offset_high: (off >> 32) as u32,
            event: null_mut(),
        }
    }
}

const GENERIC_READ_WRITE: u32 = 0xC000_0000;
/// Others may read, write, and rename or remove the file while it is open,
/// as on Unix.
const FILE_SHARE_ALL: u32 = 7;
const CREATE_ALWAYS: u32 = 2;
const OPEN_ALWAYS: u32 = 4;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_END_OF_FILE_INFO: u32 = 6;
const MOVEFILE_REPLACE_EXISTING: u32 = 1;
const MOVEFILE_WRITE_THROUGH: u32 = 8;
const ERROR_HANDLE_EOF: u32 = 38;
const CP_UTF8: u32 = 65001;
/// The longest path the program names.
pub const PATH_MAX: usize = 1024;

/// path in UTF-16 with a NUL after it, on the stack; Error when it is
/// too long, holds a NUL or is not UTF-8.
fn wide_path(path: &[u8], buf: &mut [u16; PATH_MAX + 1]) -> Result<(), Error> {
    if path.len() > PATH_MAX || path.contains(&0) {
        return Err(Error);
    }
    let n = i32::try_from(path.len())?;
    let room = i32::try_from(PATH_MAX)?;
    // rr: escape(unsafe): path holds n bytes, buf room for PATH_MAX units.
    let wide = unsafe { MultiByteToWideChar(CP_UTF8, 0, path.as_ptr(), n, buf.as_mut_ptr(), room) };
    let wide = usize::try_from(wide)?;
    if wide == 0 && !path.is_empty() {
        return Err(Error);
    }
    buf[wide] = 0;
    Ok(())
}

/// Whether a call that returns nonzero on success succeeded.
fn ok(r: i32) -> Result<(), Error> {
    if r == 0 { Err(Error) } else { Ok(()) }
}

/// An open file, closed on drop.
pub struct File {
    handle: *mut c_void,
}

impl File {
    /// Open path for reading and writing, creating it if it is missing;
    /// emptied first when fresh.
    pub fn open(path: &[u8], fresh: bool) -> Result<File, Error> {
        let mut buf = [0u16; PATH_MAX + 1];
        wide_path(path, &mut buf)?;
        let disposition = if fresh { CREATE_ALWAYS } else { OPEN_ALWAYS };
        // rr: escape(unsafe): buf is NUL-terminated.
        let handle = unsafe {
            CreateFileW(
                buf.as_ptr(),
                GENERIC_READ_WRITE,
                FILE_SHARE_ALL,
                null_mut(),
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle.addr() == usize::MAX {
            return Err(Error);
        }
        Ok(File { handle })
    }

    /// The file's length in bytes.
    pub fn size(&self) -> Result<u64, Error> {
        let mut size = 0;
        // rr: escape(unsafe): the handle is this file's.
        ok(unsafe { GetFileSizeEx(self.handle, &raw mut size) })?;
        Ok(u64::try_from(size)?)
    }

    /// Read up to buf's length at offset off: how many bytes came, 0 at
    /// the end.
    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let n = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut at = Overlapped::at(off);
        let mut read = 0;
        // rr: escape(unsafe): buf is writable memory of at least n bytes.
        let r = unsafe { ReadFile(self.handle, buf.as_mut_ptr(), n, &raw mut read, &raw mut at) };
        // rr: escape(unsafe): GetLastError reads this thread's last error.
        if r == 0 && unsafe { GetLastError() } != ERROR_HANDLE_EOF {
            return Err(Error);
        }
        Ok(read as usize)
    }

    /// Write all of p at offset off.
    pub fn write_at(&self, mut off: u64, mut p: &[u8]) -> Result<(), Error> {
        while !p.is_empty() {
            let n = u32::try_from(p.len()).unwrap_or(u32::MAX);
            let mut at = Overlapped::at(off);
            let mut written = 0;
            let place = (&raw mut at).cast::<c_void>();
            // rr: escape(unsafe): p is readable memory of at least n bytes.
            ok(unsafe { WriteFile(self.handle, p.as_ptr(), n, &raw mut written, place) })?;
            if written == 0 {
                return Err(Error);
            }
            p = &p[written as usize..];
            off += u64::from(written);
        }
        Ok(())
    }

    /// Cut the file to len bytes.
    pub fn truncate(&self, len: u64) -> Result<(), Error> {
        let end = i64::try_from(len)?;
        let info = (&raw const end).cast::<c_void>();
        // rr: escape(unsafe): info is the eight bytes FILE_END_OF_FILE_INFO takes.
        ok(unsafe { SetFileInformationByHandle(self.handle, FILE_END_OF_FILE_INFO, info, 8) })
    }

    /// Wait until what was written is on the disk.
    pub fn sync(&self) -> Result<(), Error> {
        // rr: escape(unsafe): the handle is this file's.
        ok(unsafe { FlushFileBuffers(self.handle) })
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // rr: escape(unsafe): the handle is this file's, and closed once.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Give the file at from the name to, replacing what had it.
pub fn rename_to(from: &[u8], to: &[u8]) -> Result<(), Error> {
    let (mut a, mut b) = ([0u16; PATH_MAX + 1], [0u16; PATH_MAX + 1]);
    wide_path(from, &mut a)?;
    wide_path(to, &mut b)?;
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // rr: escape(unsafe): both are NUL-terminated.
    ok(unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), flags) })
}

/// Remove the file at path.
pub fn remove(path: &[u8]) -> Result<(), Error> {
    let mut buf = [0u16; PATH_MAX + 1];
    wide_path(path, &mut buf)?;
    // rr: escape(unsafe): buf is NUL-terminated.
    ok(unsafe { DeleteFileW(buf.as_ptr()) })
}
