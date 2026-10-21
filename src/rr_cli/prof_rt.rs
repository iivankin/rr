//! rr prof's runtime, linked into a program built with `rr build --prof`.
//! There rr renames the `__rust_*` allocator functions that
//! `#[global_allocator]` defines to `__rg_*`, and the rr_prof_rust_* here
//! to the `__rust_*` the program calls: each counts the call by the stack
//! it came from, then hands it to the program's own allocator. The
//! `memcpy` and `memmove` here are the program's too, since the linker
//! prefers a definition in the program to the C library's: each counts the
//! bytes copied by stack, then hands the copy to the C library; on rr's
//! Linux and Windows targets, which have none, it copies itself. Counts go
//! to a file mapped shared, one per process image, so that they survive
//! exec and crashes. Nothing here allocates or copies through memcpy.
//! Off unless RR_PROF_DIR names a directory.

#![no_std]
#![feature(rustc_attrs)]
#![allow(internal_features)]

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, Ordering};

/// Frames kept per stack.
const DEPTH: usize = 16;
/// Distinct stacks; more are counted as lost.
const SLOTS: usize = 16384;
const MAGIC: [u8; 8] = *b"RRPROF2\0";
/// What a slot counts.
const ALLOC: u64 = 0;
const COPY: u64 = 1;
const PATH: usize = 1024;

#[repr(C)]
struct Header {
    magic: [u8; 8],
    depth: u32,
    slots: u32,
    /// The runtime address of rr_prof_anchor, for the load slide.
    anchor: u64,
    lost: u64,
    exe: [u8; PATH],
}

#[repr(C)]
struct Slot {
    what: u64,
    count: u64,
    bytes: u64,
    pcs: [u64; DEPTH],
}

const SIZE: usize = size_of::<Header>() + SLOTS * size_of::<Slot>();

unsafe extern "Rust" {
    #[rustc_std_internal_symbol]
    fn __rg_alloc(size: usize, align: usize) -> *mut u8;
    #[rustc_std_internal_symbol]
    fn __rg_dealloc(ptr: *mut u8, size: usize, align: usize);
    #[rustc_std_internal_symbol]
    fn __rg_realloc(ptr: *mut u8, old: usize, align: usize, new: usize) -> *mut u8;
    #[rustc_std_internal_symbol]
    fn __rg_alloc_zeroed(size: usize, align: usize) -> *mut u8;
}

/// The system, as each reaches it: macOS through its C library, Linux by
/// system calls, Windows through kernel32.dll.
/// The system, as each reaches it: macOS through its C library, Linux by
/// system calls, Windows through kernel32.dll.
#[cfg(target_os = "macos")]
mod os {
    use core::ffi::{c_char, c_int, c_void};
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicPtr, Ordering};

    unsafe extern "C" {
        fn getenv(name: *const c_char) -> *const c_char;
        fn getpid() -> c_int;
        fn open(path: *const c_char, flags: c_int, ...) -> c_int;
        fn ftruncate(fd: c_int, len: i64) -> c_int;
        fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void;
        fn close(fd: c_int) -> c_int;
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
        fn abort() -> !;
        fn _NSGetExecutablePath(buf: *mut c_char, size: *mut u32) -> c_int;
    }

    /// RDWR CREAT EXCL CLOEXEC.
    const O_FLAGS: c_int = 0x0002 | 0x0200 | 0x0800 | 0x0100_0000;
    /// For dlsym: the libraries loaded after the program.
    const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

    type Copy = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;

    /// The C library's memcpy and memmove, once found.
    static MEMCPY: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static MEMMOVE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

    /// The C library's function of this name, found at the first call. The
    /// C library is always loaded, so it is always there.
    fn libc(slot: &AtomicPtr<c_void>, name: &core::ffi::CStr) -> Copy {
        let mut f = slot.load(Ordering::Acquire);
        if f.is_null() {
            f = unsafe { dlsym(RTLD_NEXT, name.as_ptr()) };
            if f.is_null() {
                unsafe { abort() };
            }
            slot.store(f, Ordering::Release);
        }
        unsafe { core::mem::transmute::<*mut c_void, Copy>(f) }
    }

    pub unsafe fn copy(dst: *mut c_void, src: *const c_void, n: usize) {
        unsafe { libc(&MEMCPY, c"memcpy")(dst, src, n) };
    }

    pub unsafe fn moved(dst: *mut c_void, src: *const c_void, n: usize) {
        unsafe { libc(&MEMMOVE, c"memmove")(dst, src, n) };
    }

    /// RR_PROF_DIR into out; its length, 0 when unset.
    pub fn env_dir(out: &mut [u8]) -> usize {
        let dir = unsafe { getenv(c"RR_PROF_DIR".as_ptr()) };
        if dir.is_null() {
            return 0;
        }
        super::c_string(dir.cast(), out)
    }

    pub fn pid() -> u64 {
        unsafe { getpid() as u64 }
    }

    /// A new file at path, NUL-terminated, of size bytes, mapped shared;
    /// null when it cannot be made.
    pub fn create_mapped(path: &[u8], size: usize) -> *mut u8 {
        let fd = unsafe { open(path.as_ptr().cast(), O_FLAGS, 0o600) };
        if fd < 0 {
            return null_mut();
        }
        if unsafe { ftruncate(fd, size as i64) } != 0 {
            unsafe { close(fd) };
            return null_mut();
        }
        let p = unsafe { mmap(null_mut(), size, 3, 1, fd, 0) };
        unsafe { close(fd) };
        if p as isize == -1 { null_mut() } else { p.cast() }
    }

    /// The executable's path into out, NUL-terminated.
    pub fn executable(out: &mut [u8]) {
        let mut size = (out.len() - 1) as u32;
        unsafe { _NSGetExecutablePath(out.as_mut_ptr().cast(), &mut size) };
    }
}

#[cfg(target_os = "linux")]
mod os {
    use core::ffi::{c_char, c_void};
    use core::ptr::null_mut;

    #[cfg(target_arch = "x86_64")]
    mod nr {
        pub const CLOSE: usize = 3;
        pub const MMAP: usize = 9;
        pub const GETPID: usize = 39;
        pub const FTRUNCATE: usize = 77;
        pub const OPENAT: usize = 257;
        pub const READLINKAT: usize = 267;
    }
    #[cfg(target_arch = "aarch64")]
    mod nr {
        pub const CLOSE: usize = 57;
        pub const MMAP: usize = 222;
        pub const GETPID: usize = 172;
        pub const FTRUNCATE: usize = 46;
        pub const OPENAT: usize = 56;
        pub const READLINKAT: usize = 78;
    }

    unsafe extern "C" {
        /// rr_crt's: the environment, as the kernel gave it.
        fn rr_crt_environ() -> *const *const c_char;
    }

    fn syscall(n: usize, a: [usize; 6]) -> isize {
        let r: isize;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") n => r, in("rdi") a[0], in("rsi") a[1],
                in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5],
                lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("svc #0", in("x8") n, inlateout("x0") a[0] => r, in("x1") a[1],
                in("x2") a[2], in("x3") a[3], in("x4") a[4], in("x5") a[5], options(nostack));
        }
        r
    }

    const AT_FDCWD: usize = -100isize as usize;
    /// RDWR CREAT EXCL CLOEXEC.
    const O_FLAGS: usize = 0o2 | 0o100 | 0o200 | 0o2_000_000;

    pub unsafe fn copy(dst: *mut c_void, src: *const c_void, n: usize) {
        unsafe { super::forward(dst.cast(), src.cast(), n) };
    }

    pub unsafe fn moved(dst: *mut c_void, src: *const c_void, n: usize) {
        unsafe { super::overlapping(dst.cast(), src.cast(), n) };
    }

    /// RR_PROF_DIR into out; its length, 0 when unset.
    pub fn env_dir(out: &mut [u8]) -> usize {
        let mut env = unsafe { rr_crt_environ() };
        if env.is_null() {
            return 0;
        }
        let name = b"RR_PROF_DIR=";
        loop {
            let entry = unsafe { *env };
            if entry.is_null() {
                return 0;
            }
            let mut k = 0;
            while k < name.len() && unsafe { *entry.add(k) } as u8 == name[k] {
                k += 1;
            }
            if k == name.len() {
                return super::c_string(unsafe { entry.add(k) }.cast(), out);
            }
            env = unsafe { env.add(1) };
        }
    }

    pub fn pid() -> u64 {
        syscall(nr::GETPID, [0; 6]) as u64
    }

    /// A new file at path, NUL-terminated, of size bytes, mapped shared;
    /// null when it cannot be made.
    pub fn create_mapped(path: &[u8], size: usize) -> *mut u8 {
        let fd = syscall(nr::OPENAT, [AT_FDCWD, path.as_ptr() as usize, O_FLAGS, 0o600, 0, 0]);
        if fd < 0 {
            return null_mut();
        }
        let fd = fd as usize;
        if syscall(nr::FTRUNCATE, [fd, size, 0, 0, 0, 0]) != 0 {
            syscall(nr::CLOSE, [fd, 0, 0, 0, 0, 0]);
            return null_mut();
        }
        let p = syscall(nr::MMAP, [0, size, 3, 1, fd, 0]);
        syscall(nr::CLOSE, [fd, 0, 0, 0, 0, 0]);
        if p < 0 { null_mut() } else { p as usize as *mut u8 }
    }

    /// The executable's path into out, NUL-terminated.
    pub fn executable(out: &mut [u8]) {
        let path = c"/proc/self/exe";
        let to = out.as_mut_ptr() as usize;
        syscall(
            nr::READLINKAT,
            [AT_FDCWD, path.as_ptr() as usize, to, out.len() - 1, 0, 0],
        );
    }
}

#[cfg(target_os = "windows")]
mod os {
    use core::ffi::c_void;
    use core::ptr::null_mut;

    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        fn GetEnvironmentVariableA(name: *const u8, buf: *mut u8, size: u32) -> u32;
        fn GetCurrentProcessId() -> u32;
        fn CreateFileA(
            path: *const u8,
            access: u32,
            share: u32,
            security: *mut c_void,
            disposition: u32,
            attributes: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn CreateFileMappingA(
            file: *mut c_void,
            security: *mut c_void,
            protect: u32,
            high: u32,
            low: u32,
            name: *const u8,
        ) -> *mut c_void;
        fn MapViewOfFile(mapping: *mut c_void, access: u32, high: u32, low: u32, size: usize) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetModuleFileNameA(module: *mut c_void, name: *mut u8, size: u32) -> u32;
        pub fn RtlCaptureStackBackTrace(skip: u32, count: u32, frames: *mut *mut c_void, hash: *mut u32) -> u16;
    }

    const GENERIC_READ_WRITE: u32 = 0xC000_0000;
    const FILE_SHARE_READ_WRITE: u32 = 3;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const PAGE_READWRITE: u32 = 4;
    const FILE_MAP_ALL_ACCESS: u32 = 0xF001F;

    pub unsafe fn copy(dst: *mut c_void, src: *const c_void, n: usize) {
        unsafe { super::forward(dst.cast(), src.cast(), n) };
    }

    pub unsafe fn moved(dst: *mut c_void, src: *const c_void, n: usize) {
        unsafe { super::overlapping(dst.cast(), src.cast(), n) };
    }

    /// RR_PROF_DIR into out; its length, 0 when unset.
    pub fn env_dir(out: &mut [u8]) -> usize {
        let name = c"RR_PROF_DIR".as_ptr().cast();
        let n = unsafe { GetEnvironmentVariableA(name, out.as_mut_ptr(), out.len() as u32) } as usize;
        if n >= out.len() { 0 } else { n }
    }

    pub fn pid() -> u64 {
        u64::from(unsafe { GetCurrentProcessId() })
    }

    /// A new file at path, NUL-terminated, of size bytes, mapped shared;
    /// null when it cannot be made.
    pub fn create_mapped(path: &[u8], size: usize) -> *mut u8 {
        let file = unsafe {
            CreateFileA(
                path.as_ptr(),
                GENERIC_READ_WRITE,
                FILE_SHARE_READ_WRITE,
                null_mut(),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if file as isize == -1 {
            return null_mut();
        }
        let mapping =
            unsafe { CreateFileMappingA(file, null_mut(), PAGE_READWRITE, 0, size as u32, core::ptr::null()) };
        unsafe { CloseHandle(file) };
        if mapping.is_null() {
            return null_mut();
        }
        // The view keeps the mapping, and the mapping the file.
        let p = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size) };
        unsafe { CloseHandle(mapping) };
        p.cast()
    }

    /// The executable's path into out, NUL-terminated.
    pub fn executable(out: &mut [u8]) {
        unsafe { GetModuleFileNameA(null_mut(), out.as_mut_ptr(), (out.len() - 1) as u32) };
    }
}

/// The NUL-terminated string at s into out, cut to fit; its length.
#[cfg(not(target_os = "windows"))]
fn c_string(s: *const u8, out: &mut [u8]) -> usize {
    let mut n = 0;
    while n < out.len() {
        let c = unsafe { *s.add(n) };
        if c == 0 {
            break;
        }
        out[n] = c;
        n += 1;
    }
    n
}

/// n bytes from src to dst, which do not overlap. The writes are
/// volatile, so that the loop stays a loop, not a call to memcpy, which
/// is this.
#[cfg(not(target_os = "macos"))]
unsafe fn forward(dst: *mut u8, src: *const u8, n: usize) {
    for i in 0..n {
        unsafe { dst.add(i).write_volatile(src.add(i).read()) };
    }
}

/// n bytes from src to dst, which may overlap.
#[cfg(not(target_os = "macos"))]
unsafe fn overlapping(dst: *mut u8, src: *const u8, n: usize) {
    if dst.addr() <= src.addr() {
        unsafe { forward(dst, src, n) };
        return;
    }
    let mut i = n;
    while i > 0 {
        i -= 1;
        unsafe { dst.add(i).write_volatile(src.add(i).read()) };
    }
}

/// Allocations and bytes copied since the program started, whether or
/// not RR_PROF_DIR is set: what rr bench reads around a measured loop.
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static COPIED: AtomicU64 = AtomicU64::new(0);

/// The counts so far, for rr bench.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rr_prof_counts(allocations: *mut u64, copied: *mut u64) {
    unsafe {
        *allocations = ALLOCATIONS.load(Ordering::Relaxed);
        *copied = COPIED.load(Ordering::Relaxed);
    }
}

/// 0 not yet looked at, 1 on, 2 off, 3 being set up.
static STATE: AtomicU8 = AtomicU8::new(0);
static BASE: AtomicPtr<u8> = AtomicPtr::new(null_mut());
static LOCK: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rr_prof_anchor() {}

#[inline(never)]
pub unsafe fn rr_prof_rust_alloc(size: usize, align: usize) -> *mut u8 {
    note(ALLOC, size);
    unsafe { __rg_alloc(size, align) }
}

#[inline(never)]
pub unsafe fn rr_prof_rust_dealloc(ptr: *mut u8, size: usize, align: usize) {
    unsafe { __rg_dealloc(ptr, size, align) }
}

#[inline(never)]
pub unsafe fn rr_prof_rust_realloc(ptr: *mut u8, old: usize, align: usize, new: usize) -> *mut u8 {
    note(ALLOC, new);
    unsafe { __rg_realloc(ptr, old, align, new) }
}

#[inline(never)]
pub unsafe fn rr_prof_rust_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    note(ALLOC, size);
    unsafe { __rg_alloc_zeroed(size, align) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe { os::copy(dst, src, n) };
    note(COPY, n);
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe { os::moved(dst, src, n) };
    note(COPY, n);
    dst
}

/// The stack of this call by its frame pointers, innermost first. On
/// Windows a frame pointer need not point at the caller's, so there the
/// system walks the stack by its unwind tables.
#[cfg(not(target_os = "windows"))]
#[inline(always)]
fn stack(pcs: &mut [u64; DEPTH]) {
    let mut fp: usize;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) fp, options(nomem, nostack, preserves_flags));
    }
    for pc in pcs.iter_mut() {
        if fp == 0 || fp % size_of::<usize>() != 0 {
            break;
        }
        // A frame record: the caller's frame pointer, then the return address.
        let (next, ret) = unsafe { (*(fp as *const usize), *((fp + size_of::<usize>()) as *const usize)) };
        if ret == 0 {
            break;
        }
        *pc = ret as u64;
        // Frames go up the stack; anything else ends the chain.
        if next <= fp || next - fp > 1 << 24 {
            break;
        }
        fp = next;
    }
}

#[cfg(target_os = "windows")]
#[inline(always)]
fn stack(pcs: &mut [u64; DEPTH]) {
    let mut frames = [null_mut::<c_void>(); DEPTH];
    let n = unsafe { os::RtlCaptureStackBackTrace(0, DEPTH as u32, frames.as_mut_ptr(), null_mut()) };
    for (pc, frame) in pcs.iter_mut().zip(&frames[..usize::from(n)]) {
        *pc = frame.addr() as u64;
    }
}

fn note(what: u64, size: usize) {
    if what == ALLOC {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    } else {
        COPIED.fetch_add(size as u64, Ordering::Relaxed);
    }
    let base = match STATE.load(Ordering::Acquire) {
        1 => BASE.load(Ordering::Acquire),
        0 if STATE
            .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire)
            .is_ok() =>
        {
            start()
        },
        // Off, or another thread is mapping the file: this one goes uncounted.
        _ => return,
    };
    if base.is_null() {
        return;
    }
    let mut pcs = [0u64; DEPTH];
    stack(&mut pcs);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ what;
    for pc in pcs {
        h = (h ^ pc).wrapping_mul(0x0100_0000_01b3);
    }
    while LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let header = base.cast::<Header>();
    let slots = unsafe { base.add(size_of::<Header>()).cast::<Slot>() };
    let mut i = (h as usize) % SLOTS;
    let mut placed = false;
    for _ in 0..64 {
        let s = unsafe { &mut *slots.add(i) };
        if s.count == 0 {
            s.what = what;
            // One volatile word at a time: an array assigned whole, or a
            // plain loop, may become a call to memcpy, which comes here.
            for d in 0..DEPTH {
                unsafe { (&raw mut s.pcs[d]).write_volatile(pcs[d]) };
            }
        }
        if s.what == what && s.pcs == pcs {
            s.count += 1;
            s.bytes += size as u64;
            placed = true;
            break;
        }
        i = (i + 1) % SLOTS;
    }
    if !placed {
        unsafe { (*header).lost += 1 };
    }
    LOCK.store(false, Ordering::Release);
}

/// Map this image's file, or switch off: once, at the first count.
#[cold]
fn start() -> *mut u8 {
    let base = map();
    BASE.store(base, Ordering::Release);
    STATE.store(if base.is_null() { 2 } else { 1 }, Ordering::Release);
    base
}

fn map() -> *mut u8 {
    let mut path = [0u8; PATH + 32];
    let mut n = os::env_dir(&mut path[..PATH]);
    if n == 0 {
        return null_mut();
    }
    path[n] = b'/';
    n += 1;
    n = put_num(&mut path, n, os::pid());
    path[n] = b'.';
    n += 1;
    // An exec keeps the PID: the next image takes the next number.
    let mut base = null_mut();
    for k in 0..1000u64 {
        let end = put_num(&mut path, n, k);
        path[end] = 0;
        base = os::create_mapped(&path[..=end], SIZE);
        if !base.is_null() {
            break;
        }
    }
    if base.is_null() {
        return base;
    }
    let header = unsafe { &mut *base.cast::<Header>() };
    header.magic = MAGIC;
    header.depth = DEPTH as u32;
    header.slots = SLOTS as u32;
    header.anchor = rr_prof_anchor as *const () as usize as u64;
    os::executable(&mut header.exe);
    base
}

fn put_num(buf: &mut [u8], at: usize, mut v: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut k = 0;
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for j in 0..k {
        buf[at + j] = digits[k - 1 - j];
    }
    at + k
}
