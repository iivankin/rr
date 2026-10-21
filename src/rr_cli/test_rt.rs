//! rr test's runtime, built as the crate `test` and linked into a crate
//! built with `--test`: the part of libtest that rustc's expansion of
//! `#[test]` and `#[bench]` and its test harness name, without std.
//!
//! Each test runs in a child process, as libtest runs tests under
//! panic=abort: a test that panics ends its child, not the run, and
//! `#[should_panic]` is a child that ended so. On macOS and Linux the
//! child is a fork; Windows has none, so there the executable runs again
//! with `--rr-one=N` and runs the Nth test alone. Each system is reached
//! as an rr program reaches it: macOS through its C library, Linux by
//! system calls, Windows through kernel32.dll. A bench run measures each
//! `#[bench]` in this process, with the time, and under rr bench the
//! allocations and bytes copied, of one iteration; a test run runs each
//! bench once, as a test.
//!
//! Arguments: `--bench` to measure the benches, and filters: a test or
//! bench runs when its name holds one of them, every one when none is
//! given. Nothing here allocates.

#![no_std]
// The runtime implements a compiler interface.
#![allow(internal_features)]

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use os::{exit, now_ns, out};

#[cfg(rr_counts)]
unsafe extern "C" {
    /// rr prof's runtime: allocations and bytes copied so far.
    fn rr_prof_counts(allocations: *mut u64, copied: *mut u64);
}

#[cfg(target_os = "macos")]
mod os {
    use core::ffi::c_int;

    #[link(name = "c")]
    unsafe extern "C" {
        fn fork() -> c_int;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn write(fd: c_int, p: *const u8, n: usize) -> isize;
        fn clock_gettime(clock: c_int, t: *mut [i64; 2]) -> c_int;
        fn _exit(code: c_int) -> !;
    }

    const CLOCK_MONOTONIC: c_int = 6;

    pub fn out(p: &[u8]) {
        // SAFETY: p is readable memory of its length.
        unsafe { write(1, p.as_ptr(), p.len()) };
    }

    pub fn now_ns() -> u64 {
        let mut t = [0i64; 2];
        // SAFETY: t is a valid out-parameter.
        unsafe { clock_gettime(CLOCK_MONOTONIC, &raw mut t) };
        (t[0] as u64).wrapping_mul(1_000_000_000).wrapping_add(t[1] as u64)
    }

    pub fn exit(code: i32) -> ! {
        // SAFETY: the process ends here.
        unsafe { _exit(code) }
    }

    /// Run test in a child; whether it returned.
    pub fn in_child(_: usize, test: &dyn Fn()) -> bool {
        // SAFETY: fork has no preconditions; the child only runs the test
        // and exits.
        let pid = unsafe { fork() };
        if pid == 0 {
            test();
            exit(0);
        }
        let mut status = 0;
        // SAFETY: status is a valid out-parameter.
        unsafe { waitpid(pid, &raw mut status, 0) };
        pid > 0 && status == 0
    }
}

#[cfg(target_os = "linux")]
mod os {
    #[cfg(target_arch = "x86_64")]
    mod nr {
        pub const WRITE: usize = 1;
        pub const CLONE: usize = 56;
        pub const WAIT4: usize = 61;
        pub const CLOCK_GETTIME: usize = 228;
        pub const EXIT_GROUP: usize = 231;
    }
    #[cfg(target_arch = "aarch64")]
    mod nr {
        pub const WRITE: usize = 64;
        pub const CLONE: usize = 220;
        pub const WAIT4: usize = 260;
        pub const CLOCK_GETTIME: usize = 113;
        pub const EXIT_GROUP: usize = 94;
    }

    /// System call n with four arguments; its result.
    fn syscall(n: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
        let r: isize;
        #[cfg(target_arch = "x86_64")]
        // SAFETY: each call below passes what its system call takes.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") n as isize => r, in("rdi") a, in("rsi") b,
                in("rdx") c, in("r10") d, lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: each call below passes what its system call takes.
        unsafe {
            core::arch::asm!("svc #0", in("x8") n, inlateout("x0") a as isize => r, in("x1") b,
                in("x2") c, in("x3") d, options(nostack));
        }
        r
    }

    const SIGCHLD: usize = 17;
    const CLOCK_MONOTONIC: usize = 1;

    pub fn out(p: &[u8]) {
        syscall(nr::WRITE, 1, p.as_ptr() as usize, p.len(), 0);
    }

    pub fn now_ns() -> u64 {
        let mut t = [0i64; 2];
        syscall(nr::CLOCK_GETTIME, CLOCK_MONOTONIC, (&raw mut t) as usize, 0, 0);
        (t[0] as u64).wrapping_mul(1_000_000_000).wrapping_add(t[1] as u64)
    }

    pub fn exit(code: i32) -> ! {
        syscall(nr::EXIT_GROUP, code as usize, 0, 0, 0);
        loop {}
    }

    /// Run test in a child, a fork; whether it returned.
    pub fn in_child(_: usize, test: &dyn Fn()) -> bool {
        // clone with no new stack and SIGCHLD to the parent is fork.
        let pid = syscall(nr::CLONE, SIGCHLD, 0, 0, 0);
        if pid == 0 {
            test();
            exit(0);
        }
        let mut status: i32 = 0;
        syscall(nr::WAIT4, pid as usize, (&raw mut status) as usize, 0, 0);
        pid > 0 && status == 0
    }
}

#[cfg(target_os = "windows")]
mod os {
    use core::ffi::c_void;
    use core::ptr::null_mut;

    #[repr(C)]
    struct StartupInfo {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        geometry: [u32; 8],
        show_window: u16,
        reserved2: u16,
        reserved3: *mut u8,
        handles: [*mut c_void; 3],
    }

    #[repr(C)]
    struct ProcessInformation {
        process: *mut c_void,
        thread: *mut c_void,
        pid: u32,
        tid: u32,
    }

    #[link(name = "kernel32", kind = "raw-dylib")]
    unsafe extern "system" {
        fn GetStdHandle(n: u32) -> *mut c_void;
        fn WriteFile(h: *mut c_void, p: *const u8, n: u32, written: *mut u32, o: *mut c_void) -> i32;
        fn QueryPerformanceCounter(count: *mut i64) -> i32;
        fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
        fn ExitProcess(code: u32) -> !;
        fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
        fn CreateProcessW(
            application: *const u16,
            command: *mut u16,
            process_attributes: *mut c_void,
            thread_attributes: *mut c_void,
            inherit: i32,
            flags: u32,
            environment: *mut c_void,
            directory: *const u16,
            startup: *mut StartupInfo,
            information: *mut ProcessInformation,
        ) -> i32;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(process: *mut c_void, code: *mut u32) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }

    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const INFINITE: u32 = u32::MAX;

    pub fn out(p: &[u8]) {
        let mut written = 0;
        let n = u32::try_from(p.len()).unwrap_or(u32::MAX);
        // SAFETY: p is readable memory of its length.
        unsafe {
            WriteFile(
                GetStdHandle(STD_OUTPUT_HANDLE),
                p.as_ptr(),
                n,
                &raw mut written,
                null_mut(),
            )
        };
    }

    pub fn now_ns() -> u64 {
        let (mut count, mut frequency) = (0i64, 1i64);
        // SAFETY: both are valid out-parameters.
        unsafe {
            QueryPerformanceCounter(&raw mut count);
            QueryPerformanceFrequency(&raw mut frequency);
        }
        ((count as u128) * 1_000_000_000 / (frequency.max(1) as u128)) as u64
    }

    pub fn exit(code: i32) -> ! {
        // SAFETY: the process ends here.
        unsafe { ExitProcess(code as u32) }
    }

    /// Run test number index in a child: this executable again, with
    /// --rr-one=index; whether it returned.
    pub fn in_child(index: usize, _: &dyn Fn()) -> bool {
        let mut line = [0u16; 1200];
        line[0] = u16::from(b'"');
        // SAFETY: line has room for the name, past the quote.
        let n = unsafe { GetModuleFileNameW(null_mut(), line.as_mut_ptr().add(1), 1024) } as usize;
        if n == 0 || n >= 1024 {
            return false;
        }
        let mut at = n + 1;
        let mut digits = [0u8; 20];
        let mut k = 0;
        let mut v = index;
        loop {
            digits[k] = b'0' + (v % 10) as u8;
            k += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for b in b"\" --rr-one=".iter().chain(digits[..k].iter().rev()) {
            line[at] = u16::from(*b);
            at += 1;
        }
        line[at] = 0;
        // SAFETY: the structures are zeroed as their documentation allows,
        // with their sizes set; line is a writable command line.
        unsafe {
            let mut startup: StartupInfo = core::mem::zeroed();
            startup.cb = size_of::<StartupInfo>() as u32;
            let mut info: ProcessInformation = core::mem::zeroed();
            let made = CreateProcessW(
                core::ptr::null(),
                line.as_mut_ptr(),
                null_mut(),
                null_mut(),
                1,
                0,
                null_mut(),
                core::ptr::null(),
                &raw mut startup,
                &raw mut info,
            );
            if made == 0 {
                return false;
            }
            WaitForSingleObject(info.process, INFINITE);
            let mut code = 1;
            GetExitCodeProcess(info.process, &raw mut code);
            CloseHandle(info.thread);
            CloseHandle(info.process);
            code == 0
        }
    }
}

pub enum TestName {
    StaticTestName(&'static str),
}
pub use TestName::StaticTestName;

pub enum ShouldPanic {
    No,
    Yes,
    YesWithMessage(&'static str),
}

pub enum TestType {
    UnitTest,
    IntegrationTest,
    Unknown,
}

pub enum TestFn {
    StaticTestFn(fn() -> Result<(), &'static str>),
    StaticBenchFn(fn(&mut Bencher) -> Result<(), &'static str>),
}
pub use TestFn::{StaticBenchFn, StaticTestFn};

pub struct TestDesc {
    pub name: TestName,
    pub ignore: bool,
    pub ignore_message: Option<&'static str>,
    pub source_file: &'static str,
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub compile_fail: bool,
    pub no_run: bool,
    pub should_panic: ShouldPanic,
    pub test_type: TestType,
}

pub struct TestDescAndFn {
    pub desc: TestDesc,
    pub testfn: TestFn,
}

/// What a test returned: tests return nothing.
pub fn assert_test_result(_: ()) -> Result<(), &'static str> {
    Ok(())
}

/// What a bench measures with.
pub struct Bencher {
    /// Measure, or run the body once, as a test.
    measure: bool,
    /// Per iteration: nanoseconds, allocations, bytes copied.
    ns: u64,
    allocations: u64,
    copied: u64,
}

fn counts() -> (u64, u64) {
    #[cfg(rr_counts)]
    {
        let (mut a, mut c) = (0, 0);
        // SAFETY: both are valid out-parameters.
        unsafe { rr_prof_counts(&raw mut a, &raw mut c) };
        (a, c)
    }
    #[cfg(not(rr_counts))]
    {
        (0, 0)
    }
}

impl Bencher {
    /// Run f again and again, as many times as take about a second, and
    /// keep the cost of one run.
    pub fn iter<T, F: FnMut() -> T>(&mut self, mut f: F) {
        core::hint::black_box(f());
        if !self.measure {
            return;
        }
        let mut n: u64 = 1;
        loop {
            let (a0, c0) = counts();
            let t0 = now_ns();
            for _ in 0..n {
                core::hint::black_box(f());
            }
            let elapsed = now_ns() - t0;
            let (a1, c1) = counts();
            if elapsed >= 1_000_000_000 || n >= 1 << 30 {
                self.ns = elapsed / n;
                self.allocations = (a1 - a0) / n;
                self.copied = (c1 - c0) / n;
                return;
            }
            n *= 2;
        }
    }
}

static ARGC: AtomicUsize = AtomicUsize::new(0);
static ARGV: AtomicPtr<*const c_char> = AtomicPtr::new(core::ptr::null_mut());

/// The arguments the test executable was given, from its entry.
pub fn start(argc: c_int, argv: *const *const c_char) {
    ARGC.store(usize::try_from(argc).unwrap_or(0), Ordering::Relaxed);
    ARGV.store(argv.cast_mut(), Ordering::Relaxed);
}

/// Argument i, past the program's name.
fn arg(i: usize) -> Option<&'static [u8]> {
    if i + 1 >= ARGC.load(Ordering::Relaxed) {
        return None;
    }
    let argv = ARGV.load(Ordering::Relaxed);
    // SAFETY: argv holds argc strings, each ending in a NUL, that live as
    // long as the process.
    unsafe {
        let s = *argv.add(i + 1);
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        Some(core::slice::from_raw_parts(s.cast(), n))
    }
}

fn num(mut v: u64) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out(&d[i..]);
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether name passes the filters.
fn chosen(name: &str) -> bool {
    let mut any = false;
    let mut i = 0;
    while let Some(a) = arg(i) {
        i += 1;
        if a.starts_with(b"--") {
            continue;
        }
        any = true;
        if contains(name.as_bytes(), a) {
            return true;
        }
    }
    !any
}

fn bench_mode() -> bool {
    let mut i = 0;
    while let Some(a) = arg(i) {
        if a == b"--bench" {
            return true;
        }
        i += 1;
    }
    false
}

/// The test --rr-one=N names: the child that runs it alone, on Windows.
fn one() -> Option<usize> {
    let mut i = 0;
    while let Some(a) = arg(i) {
        if let Some(digits) = a.strip_prefix(b"--rr-one=") {
            let mut n: usize = 0;
            for d in digits {
                n = n.checked_mul(10)?.checked_add(usize::from(d.checked_sub(b'0')?))?;
            }
            return Some(n);
        }
        i += 1;
    }
    None
}

/// Run t's body once, as a test.
fn run(t: &TestDescAndFn) {
    match t.testfn {
        TestFn::StaticTestFn(f) => {
            let _ = f();
        },
        TestFn::StaticBenchFn(f) => {
            let mut b = Bencher {
                measure: false,
                ns: 0,
                allocations: 0,
                copied: 0,
            };
            let _ = f(&mut b);
        },
    }
}

/// Run each chosen test in a child, or under --bench measure each chosen
/// bench; exit 0 when all passed, 101 when one failed.
pub fn test_main_static_abort(tests: &[&TestDescAndFn]) {
    if let Some(i) = one() {
        if let Some(t) = tests.get(i) {
            run(t);
        }
        exit(0);
    }
    let bench = bench_mode();
    let (mut passed, mut failed, mut ignored) = (0u64, 0u64, 0u64);
    for (index, t) in tests.iter().enumerate() {
        let TestName::StaticTestName(name) = t.desc.name;
        if !chosen(name) {
            continue;
        }
        match (&t.testfn, bench) {
            (TestFn::StaticTestFn(_), true) => continue,
            (TestFn::StaticBenchFn(f), true) => {
                let mut b = Bencher {
                    measure: true,
                    ns: 0,
                    allocations: 0,
                    copied: 0,
                };
                let _ = f(&mut b);
                out(b"bench ");
                out(name.as_bytes());
                out(b" ... ");
                num(b.ns);
                out(b" ns/iter");
                if cfg!(rr_counts) {
                    out(b", ");
                    num(b.allocations);
                    out(b" allocations/iter, ");
                    num(b.copied);
                    out(b" bytes copied/iter");
                }
                out(b"\n");
                passed += 1;
                continue;
            },
            (_, false) => {},
        }
        out(b"test ");
        out(name.as_bytes());
        out(b" ... ");
        if t.desc.ignore {
            out(b"ignored\n");
            ignored += 1;
            continue;
        }
        let finished = os::in_child(index, &|| run(t));
        let want_panic = !matches!(t.desc.should_panic, ShouldPanic::No);
        if finished == want_panic {
            out(b"FAILED\n");
            failed += 1;
        } else {
            out(b"ok\n");
            passed += 1;
        }
    }
    out(b"\n");
    num(passed);
    out(if bench { b" measured" } else { b" passed" });
    if !bench {
        out(b", ");
        num(failed);
        out(b" failed, ");
        num(ignored);
        out(b" ignored");
    }
    out(b"\n");
    exit(if failed == 0 { 0 } else { 101 })
}
