//! What the program needs of Linux: the heap, files, output, arguments
//! and an end on a bug, by system calls; there is no C library. The rest of the
//! crate calls only this; unsafe stays here.

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_char;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

/// The system call numbers this file uses, which differ by architecture.
#[cfg(target_arch = "x86_64")]
mod nr {
    pub const WRITE: usize = 1;
    pub const MMAP: usize = 9;
    pub const MUNMAP: usize = 11;
    pub const GETPID: usize = 39;
    pub const KILL: usize = 62;
    pub const EXIT_GROUP: usize = 231;
    pub const CLOSE: usize = 3;
    pub const LSEEK: usize = 8;
    pub const PREAD64: usize = 17;
    pub const PWRITE64: usize = 18;
    pub const FSYNC: usize = 74;
    pub const FTRUNCATE: usize = 77;
    pub const OPENAT: usize = 257;
    pub const UNLINKAT: usize = 263;
    pub const RENAMEAT2: usize = 316;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const WRITE: usize = 64;
    pub const MMAP: usize = 222;
    pub const MUNMAP: usize = 215;
    pub const GETPID: usize = 172;
    pub const KILL: usize = 129;
    pub const EXIT_GROUP: usize = 94;
    pub const CLOSE: usize = 57;
    pub const LSEEK: usize = 62;
    pub const PREAD64: usize = 67;
    pub const PWRITE64: usize = 68;
    pub const FSYNC: usize = 82;
    pub const FTRUNCATE: usize = 46;
    pub const OPENAT: usize = 56;
    pub const UNLINKAT: usize = 35;
    pub const RENAMEAT2: usize = 276;
}

/// System call n; its result, or a negative error number.
///
/// # Safety
/// The arguments are those system call n takes, and memory it reads or
/// writes is valid for it.
// rr: escape(unsafe): the caller vouches for the arguments, which only it knows.
unsafe fn syscall(n: usize, args: [usize; 6]) -> isize {
    let r: isize;
    #[cfg(target_arch = "x86_64")]
    // rr: escape(unsafe): the Linux system call convention for x86_64.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => r,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // rr: escape(unsafe): the Linux system call convention for aarch64.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") args[0] => r,
            in("x1") args[1],
            in("x2") args[2],
            in("x3") args[3],
            in("x4") args[4],
            in("x5") args[5],
            options(nostack),
        );
    }
    r
}

const PAGE: usize = 4096;
const PROT_READ_WRITE: usize = 3;
const MAP_PRIVATE_ANONYMOUS: usize = 0x22;
const SIGABRT: usize = 6;

/// Fresh zeroed pages, size bytes of them, or null.
fn map(size: usize) -> *mut u8 {
    let none = usize::MAX;
    // rr: escape(unsafe): an anonymous private mapping touches no memory of ours.
    let r = unsafe {
        syscall(
            nr::MMAP,
            [0, size, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, none, 0],
        )
    };
    match usize::try_from(r) {
        Ok(at) => core::ptr::with_exposed_provenance_mut(at),
        Err(_) => null_mut(),
    }
}

/// Give back the pages at p, size bytes, from map.
fn unmap(p: *mut u8, size: usize) {
    // rr: escape(unsafe): p and size are a mapping of ours, unused from here.
    unsafe { syscall(nr::MUNMAP, [p.expose_provenance(), size, 0, 0, 0, 0]) };
}

/// The block sizes the heap keeps lists of: 16 bytes to a page.
const CLASSES: usize = 9;
/// The pages taken at once for small blocks.
const CHUNK: usize = 64 * PAGE;

/// The global allocator. Blocks up to a page come in sizes of powers of
/// two, each size aligned to itself, carved from chunks of pages and kept
/// on a list when freed; a larger block is pages of its own. One lock
/// keeps the lists whole when threads share the heap.
pub struct Heap;

// The heap's state is the process's: GlobalAlloc gives Heap's methods
// only &self, of a static every allocation reaches.
// rr: escape(shared): the global allocator's lock.
static LOCK: AtomicBool = AtomicBool::new(false);
/// The free blocks of each size, each holding a pointer to the next.
// rr: escape(shared): the global allocator's free lists, under LOCK.
static FREE: [AtomicPtr<u8>; CLASSES] = [const { AtomicPtr::new(null_mut()) }; CLASSES];
/// What is left of the chunk being carved.
// rr: escape(shared): the global allocator's chunk, under LOCK.
static NEXT: AtomicPtr<u8> = AtomicPtr::new(null_mut());
// rr: escape(shared): the global allocator's chunk, under LOCK.
static LEFT: AtomicUsize = AtomicUsize::new(0);

/// The size class of l, or None when it takes pages of its own.
fn class(l: Layout) -> Option<usize> {
    let size = l
        .size()
        .max(l.align())
        .max(16)
        .checked_next_power_of_two()?;
    if size > PAGE {
        return None;
    }
    Some(size.trailing_zeros() as usize - 4)
}

fn lock() {
    // rr: escape(loop): another thread holds the lock for one allocation,
    // a few instructions; a program of one thread never waits here.
    while LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn unlock() {
    LOCK.store(false, Ordering::Release);
}

/// A block of class c: a freed one, or the next from the chunk.
fn small(c: usize) -> *mut u8 {
    let size = 16 << c;
    // rr: escape(panic): class gives an index below CLASSES, for sizes up to a page.
    let list = &FREE[c];
    let head = list.load(Ordering::Relaxed);
    if !head.is_null() {
        // rr: escape(unsafe, cast): a free block, aligned to 16 at least, holds the next one's address.
        let next = unsafe { head.cast::<*mut u8>().read() };
        list.store(next, Ordering::Relaxed);
        return head;
    }
    let mut at = NEXT.load(Ordering::Relaxed);
    let mut left = LEFT.load(Ordering::Relaxed);
    let pad = at.align_offset(size);
    if at.is_null() || pad.saturating_add(size) > left {
        // The rest of the chunk is too small for this size: a new chunk.
        at = map(CHUNK);
        if at.is_null() {
            return null_mut();
        }
        left = CHUNK;
    } else {
        at = at.wrapping_add(pad);
        left -= pad;
    }
    NEXT.store(at.wrapping_add(size), Ordering::Relaxed);
    LEFT.store(left - size, Ordering::Relaxed);
    at
}

/// Pages for a block of l's size, at l's alignment.
fn large(l: Layout) -> *mut u8 {
    let size = l.size().next_multiple_of(PAGE);
    if l.align() <= PAGE {
        return map(size);
    }
    // Map more, then give back what is before and after the aligned part.
    let total = size + l.align();
    let p = map(total);
    if p.is_null() {
        return p;
    }
    let head = p.align_offset(l.align());
    if head > 0 {
        unmap(p, head);
    }
    let tail = total - head - size;
    if tail > 0 {
        unmap(p.wrapping_add(head + size), tail);
    }
    p.wrapping_add(head)
}

// Every block is its class's size or whole pages, at l's alignment, and
// dealloc finds the same class from the same layout: GlobalAlloc's
// contract holds.
// rr: escape(unsafe): GlobalAlloc is unsafe to implement.
unsafe impl GlobalAlloc for Heap {
    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let Some(c) = class(l) else {
            return large(l);
        };
        lock();
        let p = small(c);
        unlock();
        p
    }

    // rr: escape(unsafe): the signature GlobalAlloc requires.
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let Some(c) = class(l) else {
            let size = l.size().next_multiple_of(PAGE);
            unmap(p, size);
            return;
        };
        // rr: escape(panic): class gives an index below CLASSES, for sizes up to a page.
        let list = &FREE[c];
        lock();
        // rr: escape(unsafe, cast): p is a block of class c, aligned to 16 at least, no longer used.
        unsafe { p.cast::<*mut u8>().write(list.load(Ordering::Relaxed)) };
        list.store(p, Ordering::Relaxed);
        unlock();
    }
}

fn write_all(fd: usize, mut p: &[u8]) {
    while !p.is_empty() {
        // rr: escape(unsafe): p is readable memory of its length.
        let n = unsafe {
            syscall(
                nr::WRITE,
                [fd, p.as_ptr().expose_provenance(), p.len(), 0, 0, 0],
            )
        };
        // An error, or nothing written: give up.
        let Some(n) = usize::try_from(n).ok().filter(|n| *n > 0) else {
            return;
        };
        // More than was asked: the system broke its contract; give up.
        let Some(rest) = p.get(n..) else { return };
        p = rest;
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
        // rr: escape(unsafe): s is NUL-terminated and lives as long as the process.
        out.push(unsafe { core::ffi::CStr::from_ptr(s) }.to_bytes());
    }
    out
}

/// End the process at once, as abort does: a bug was found.
pub fn die() -> ! {
    // rr: escape(unsafe): getpid takes nothing.
    let pid = unsafe { syscall(nr::GETPID, [0; 6]) };
    // rr: escape(unsafe): kill takes no memory of ours.
    unsafe { syscall(nr::KILL, [pid.cast_unsigned(), SIGABRT, 0, 0, 0, 0]) };
    // rr: escape(unsafe): exit_group takes no memory of ours.
    unsafe { syscall(nr::EXIT_GROUP, [134, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop();
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

/// A system call's result: what it returned, or Error for an error number.
fn checked(r: isize) -> Result<usize, Error> {
    Ok(usize::try_from(r)?)
}

const AT_FDCWD: usize = (-100isize).cast_unsigned();
const O_RDWR: usize = 0o2;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;
const O_CLOEXEC: usize = 0o2_000_000;
const SEEK_END: usize = 2;
/// The longest path the program names.
pub const PATH_MAX: usize = 1024;

/// path with a NUL after it, on the stack; Error when it is too long or
/// holds a NUL.
fn c_path(path: &[u8], buf: &mut [u8; PATH_MAX + 1]) -> Result<(), Error> {
    if path.len() > PATH_MAX || path.contains(&0) {
        return Err(Error);
    }
    buf.get_mut(..path.len())
        .ok_or(Error)?
        .copy_from_slice(path);
    *buf.get_mut(path.len()).ok_or(Error)? = 0;
    Ok(())
}

/// An open file, closed on drop.
pub struct File {
    fd: usize,
}

impl File {
    /// Open path for reading and writing, creating it if it is missing;
    /// emptied first when fresh.
    pub fn open(path: &[u8], fresh: bool) -> Result<File, Error> {
        let mut buf = [0u8; PATH_MAX + 1];
        c_path(path, &mut buf)?;
        let flags = O_RDWR | O_CREAT | O_CLOEXEC | if fresh { O_TRUNC } else { 0 };
        let at = buf.as_ptr().expose_provenance();
        // rr: escape(unsafe): buf is NUL-terminated.
        let fd = checked(unsafe { syscall(nr::OPENAT, [AT_FDCWD, at, flags, 0o600, 0, 0]) })?;
        Ok(File { fd })
    }

    /// The file's length in bytes.
    pub fn size(&self) -> Result<u64, Error> {
        // rr: escape(unsafe): the descriptor is this file's.
        let n = checked(unsafe { syscall(nr::LSEEK, [self.fd, 0, SEEK_END, 0, 0, 0]) })?;
        Ok(u64::try_from(n)?)
    }

    /// Read up to buf's length at offset off: how many bytes came, 0 at
    /// the end.
    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let off = usize::try_from(off)?;
        let at = buf.as_mut_ptr().expose_provenance();
        // rr: escape(unsafe): buf is writable memory of its length.
        checked(unsafe { syscall(nr::PREAD64, [self.fd, at, buf.len(), off, 0, 0]) })
    }

    /// Write all of p at offset off.
    pub fn write_at(&self, mut off: u64, mut p: &[u8]) -> Result<(), Error> {
        while !p.is_empty() {
            let to = usize::try_from(off)?;
            let at = p.as_ptr().expose_provenance();
            // rr: escape(unsafe): p is readable memory of its length.
            let n = checked(unsafe { syscall(nr::PWRITE64, [self.fd, at, p.len(), to, 0, 0]) })?;
            if n == 0 {
                return Err(Error);
            }
            // More than was asked: the system broke its contract.
            p = p.get(n..).ok_or(Error)?;
            off += n as u64;
        }
        Ok(())
    }

    /// Cut the file to len bytes.
    pub fn truncate(&self, len: u64) -> Result<(), Error> {
        let len = usize::try_from(len)?;
        // rr: escape(unsafe): the descriptor is this file's.
        checked(unsafe { syscall(nr::FTRUNCATE, [self.fd, len, 0, 0, 0, 0]) })?;
        Ok(())
    }

    /// Wait until what was written is on the disk.
    pub fn sync(&self) -> Result<(), Error> {
        // rr: escape(unsafe): the descriptor is this file's.
        checked(unsafe { syscall(nr::FSYNC, [self.fd, 0, 0, 0, 0, 0]) })?;
        Ok(())
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // rr: escape(unsafe): the descriptor is this file's, and closed once.
        unsafe { syscall(nr::CLOSE, [self.fd, 0, 0, 0, 0, 0]) };
    }
}

/// Give the file at from the name to, replacing what had it.
pub fn rename_to(from: &[u8], to: &[u8]) -> Result<(), Error> {
    let (mut a, mut b) = ([0u8; PATH_MAX + 1], [0u8; PATH_MAX + 1]);
    c_path(from, &mut a)?;
    c_path(to, &mut b)?;
    let (a, b) = (
        a.as_ptr().expose_provenance(),
        b.as_ptr().expose_provenance(),
    );
    // rr: escape(unsafe): both are NUL-terminated.
    checked(unsafe { syscall(nr::RENAMEAT2, [AT_FDCWD, a, AT_FDCWD, b, 0, 0]) })?;
    Ok(())
}

/// Remove the file at path.
pub fn remove(path: &[u8]) -> Result<(), Error> {
    let mut buf = [0u8; PATH_MAX + 1];
    c_path(path, &mut buf)?;
    let at = buf.as_ptr().expose_provenance();
    // rr: escape(unsafe): buf is NUL-terminated.
    checked(unsafe { syscall(nr::UNLINKAT, [AT_FDCWD, at, 0, 0, 0, 0]) })?;
    Ok(())
}
