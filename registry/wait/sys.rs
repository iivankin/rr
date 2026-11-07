//! The system side of wait: what mod.rs says it is, for each system.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

#[cfg(test)]
pub(super) use os::net;
/// Linux's close-on-exec flag, which epoll, eventfd and open take.
#[cfg(target_os = "linux")]
pub use poller::O_CLOEXEC;
pub(super) use poller::{Poller, Wake, monotonic_ns};

/// poll's events, the same on Linux and macOS.
#[cfg(unix)]
pub const POLLIN: i16 = 1;
#[cfg(unix)]
pub const POLLOUT: i16 = 4;
#[cfg(unix)]
pub const POLLERR: i16 = 8;
#[cfg(unix)]
pub const POLLHUP: i16 = 16;

/// WSAPoll's events: POLLIN is POLLRDNORM | POLLRDBAND.
#[cfg(target_os = "windows")]
pub const POLLIN: i16 = 0x0300;
#[cfg(target_os = "windows")]
pub const POLLOUT: i16 = 0x0010;
#[cfg(target_os = "windows")]
pub const POLLERR: i16 = 0x0001;
#[cfg(target_os = "windows")]
pub const POLLHUP: i16 = 0x0002;

/// Winsock's IPv4 family, which the signal's pair and resolve's lookup
/// both name.
#[cfg(target_os = "windows")]
pub const AF_INET: u16 = 2;
/// Stream sockets: 1 in Winsock and in the C libraries of Linux and
/// macOS, for the signal's pair, resolve's lookups and the tests.
pub const SOCK_STREAM: i32 = 1;

/// A descriptor as the system names it: a file descriptor on Linux and
/// macOS, a SOCKET on Windows.
#[cfg(unix)]
pub type Raw = i32;
#[cfg(target_os = "windows")]
pub type Raw = usize;

/// A descriptor to wait on, and for what (POLLIN or POLLOUT).
#[cfg(unix)]
pub struct Fd {
    pub fd: Raw,
    pub events: i16,
}

#[cfg(unix)]
impl Fd {
    pub const NONE: Fd = Fd { fd: -1, events: 0 };
}

/// A socket (a SOCKET, as WSAPoll takes it) to wait on, and for what
/// (POLLIN or POLLOUT).
#[cfg(target_os = "windows")]
pub struct Fd {
    pub fd: Raw,
    pub events: i16,
}

#[cfg(target_os = "windows")]
impl Fd {
    /// INVALID_SOCKET, which WSAPoll passes over.
    pub const NONE: Fd = Fd {
        fd: usize::MAX,
        events: 0,
    };
}

/// Wait on the first count of fds, at most timeout_ms (None: no
/// limit); Fd::NONE is none.
pub struct Wait {
    pub fds: [Fd; 2],
    pub count: usize,
    pub timeout_ms: Option<u64>,
}

impl Wait {
    /// Nothing to wait on: poll again now.
    pub const READY: Wait = Wait {
        fds: [Fd::NONE; 2],
        count: 0,
        timeout_ms: Some(0),
    };
}

/// Waits as wait says.
pub fn block(wait: &Wait) {
    // The caller polls whatever woke it.
    ready(wait);
}

/// Waits as wait says; what happened on each of its fds (revents).
pub fn ready(wait: &Wait) -> [i16; 2] {
    os::ready(wait)
}

/// Winsock, started once for the process: WSAPoll and the sockets
/// need it.
#[cfg(target_os = "windows")]
pub fn startup() {
    os::startup();
}

/// Set when a thread's work is done; what waits on it is readable then.
pub struct Signal {
    os: os::Signal,
}

impl Signal {
    pub fn new() -> Option<Signal> {
        os::Signal::new().map(|os| Signal { os })
    }

    /// Says the work is done.
    pub fn set(&self) {
        self.os.set();
    }

    /// What waits until set.
    pub fn wait(&self) -> Wait {
        let mut wait = Wait::READY;
        wait.fds[0] = Fd {
            fd: self.os.read_end(),
            events: POLLIN,
        };
        wait.count = 1;
        wait.timeout_ms = None;
        wait
    }
}

/// The most threads spawn runs at once; more work waits its turn.
pub const THREADS_MAX: usize = 32;

/// Work's states: in line, taken by a thread, or cancelled first.
const QUEUED: u8 = 0;
const STARTED: u8 = 1;
const CANCELLED: u8 = 2;

/// Work spawn took: what runs, on what, the next in line, its state,
/// and its two holders, the line or thread and the Ticket.
struct Start {
    work: fn(*mut c_void),
    argument: *mut c_void,
    next: *mut Start,
    state: AtomicU8,
    holders: AtomicUsize,
}

/// Lets go of start; the last holder frees it.
fn release(start: *mut Start) {
    // rr: escape(unsafe): start lives until its holders let go.
    let holders = unsafe { &(*start).holders };
    if holders.fetch_sub(1, Ordering::AcqRel) == 1 {
        // rr: escape(unsafe): no one else holds it now.
        drop(unsafe { Box::from_raw(start) });
    }
}

/// Work spawn took, which cancel keeps from starting.
pub struct Ticket(*mut Start);

impl Ticket {
    /// Keeps the work from starting, when it has not: then it never
    /// runs, and its argument is the caller's again. False when a
    /// thread took it.
    pub fn cancel(&self) -> bool {
        // rr: escape(unsafe): the ticket holds its Start.
        let state = unsafe { &(*self.0).state };
        state
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        release(self.0);
    }
}

/// The line of work waiting for a thread, and the threads running.
struct Line {
    running: usize,
    first: *mut Start,
    last: *mut Start,
}

/// The process's line, under its lock: the threads spawn starts reach
/// it from outside any caller's call tree, as a signal handler would.
struct Queue {
    lock: os::Lock,
    line: UnsafeCell<Line>,
}

// rr: escape(unsafe): Queue's line is only reached under its lock.
unsafe impl Sync for Queue {}

// rr: escape(shared): one line for the process, which the worker threads
// reach without a caller to lend it to them.
static QUEUE: Queue = Queue {
    lock: os::Lock::new(),
    // rr: escape(shared): the line, under the lock.
    line: UnsafeCell::new(Line {
        running: 0,
        first: null_mut(),
        last: null_mut(),
    }),
};

/// Runs f on the line under its lock. f never calls locked: the lock
/// is not taken twice by one thread, which POSIX leaves undefined for
/// the mutex PTHREAD_MUTEX_INITIALIZER makes.
fn locked(f: impl FnOnce(&mut Line)) {
    QUEUE.lock.lock();
    // rr: escape(unsafe): the lock is held: no one else touches the line.
    f(unsafe { &mut *QUEUE.line.get() });
    QUEUE.lock.unlock();
}

/// Runs work(argument) on a thread: a new one while fewer than
/// THREADS_MAX run, else the first to finish its work, in the order
/// spawn was called. None when no thread could be started.
pub fn spawn(work: fn(*mut c_void), argument: *mut c_void) -> Option<Ticket> {
    let start = Box::new(Start {
        work,
        argument,
        next: null_mut(),
        // rr: escape(shared): the ticket and the thread race to it.
        state: AtomicU8::new(QUEUED),
        // rr: escape(shared): the ticket and the line or thread hold it.
        holders: AtomicUsize::new(2),
    });
    // rr: escape(leak): its holders let go of it, and release frees it.
    let raw = Box::into_raw(start);
    let mut queued = false;
    locked(|line| {
        if line.running < THREADS_MAX {
            line.running += 1;
            return;
        }
        if line.last.is_null() {
            line.first = raw;
        } else {
            // rr: escape(unsafe): the last is in the line, under the lock.
            unsafe { (*line.last).next = raw };
        }
        line.last = raw;
        queued = true;
    });
    if queued || os::thread(raw.cast()) {
        return Some(Ticket(raw));
    }
    locked(|line| line.running -= 1);
    // Neither a thread nor a ticket holds it.
    release(raw);
    release(raw);
    None
}

/// A thread's life: its work, then the line's first while there is one;
/// work cancelled in line is passed over.
fn begin(first: *mut c_void) {
    let mut next = first.cast::<Start>();
    // Each turn takes one work off the line, which is finite.
    loop {
        // rr: escape(unsafe): this thread holds next.
        let start = unsafe { &*next };
        let taken = start
            .state
            .compare_exchange(QUEUED, STARTED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if taken {
            (start.work)(start.argument);
        }
        release(next);
        let mut head = null_mut();
        locked(|line| {
            head = line.first;
            if head.is_null() {
                line.running -= 1;
            } else {
                // rr: escape(unsafe): head is in the line, under the lock.
                line.first = unsafe { (*head).next };
                if line.first.is_null() {
                    line.last = null_mut();
                }
            }
        });
        if head.is_null() {
            return;
        }
        next = head;
    }
}

#[cfg(unix)]
mod os {
    use super::Wait;
    use core::cell::UnsafeCell;
    use core::ffi::{c_int, c_void};

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    /// pthread_t: a pointer on macOS, an unsigned long in glibc and musl.
    #[cfg(target_os = "macos")]
    type Thread = *mut c_void;
    #[cfg(not(target_os = "macos"))]
    type Thread = core::ffi::c_ulong;

    /// nfds_t: an unsigned int on macOS, an unsigned long on Linux.
    #[cfg(target_os = "macos")]
    type Count = core::ffi::c_uint;
    #[cfg(not(target_os = "macos"))]
    type Count = core::ffi::c_ulong;

    // glibc before 2.34 keeps the threads in libpthread; later ones and
    // musl keep them in libc, and glibc's libpthread is then empty.
    #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "pthread"))]
    // rr: escape(unsafe): each signature is the C library's, from its headers.
    unsafe extern "C" {
        fn pthread_create(
            thread: *mut Thread,
            attributes: *const c_void,
            start: extern "C" fn(*mut c_void) -> *mut c_void,
            argument: *mut c_void,
        ) -> c_int;
        fn pthread_detach(thread: Thread) -> c_int;
        fn pthread_mutex_lock(mutex: *mut u64) -> c_int;
        fn pthread_mutex_unlock(mutex: *mut u64) -> c_int;
        fn abort() -> !;
        fn pipe(fds: *mut c_int) -> c_int;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        fn write(fd: c_int, buffer: *const c_void, size: usize) -> isize;
        fn close(fd: c_int) -> c_int;
        fn poll(fds: *mut PollFd, count: Count, timeout: c_int) -> c_int;
    }

    // fcntl.h's, the same on macOS and Linux.
    pub const F_SETFD: c_int = 2;
    #[cfg(test)]
    const F_GETFD: c_int = 1;
    pub const FD_CLOEXEC: c_int = 1;

    pub fn ready(wait: &Wait) -> [i16; 2] {
        let [one, two] = &wait.fds;
        let mut fds = [
            PollFd {
                fd: one.fd,
                events: one.events,
                revents: 0,
            },
            PollFd {
                fd: two.fd,
                events: two.events,
                revents: 0,
            },
        ];
        let count = Count::try_from(wait.count.min(2)).unwrap_or(0);
        let timeout = wait
            .timeout_ms
            .map_or(-1, |ms| c_int::try_from(ms).unwrap_or(c_int::MAX));
        // rr: escape(unsafe): fds holds count entries.
        if unsafe { poll(fds.as_mut_ptr(), count, timeout) } <= 0 {
            return [0, 0];
        }
        let [first, second] = fds;
        [first.revents, second.revents]
    }

    extern "C" fn run(start: *mut c_void) -> *mut c_void {
        super::begin(start);
        core::ptr::null_mut()
    }

    /// PTHREAD_MUTEX_INITIALIZER's first word: macOS's
    /// _PTHREAD_MUTEX_SIG_init (its SDK's pthread/pthread_impl.h); glibc's
    /// (sysdeps/nptl/bits/struct_mutex.h, whose kind PTHREAD_MUTEX_TIMED_NP
    /// is 0) and musl's (include/pthread.h) are all zeros.
    #[cfg(target_os = "macos")]
    const MUTEX_INIT: u64 = 0x32AA_ABA7;
    #[cfg(not(target_os = "macos"))]
    const MUTEX_INIT: u64 = 0;

    /// A pthread_mutex_t, made as PTHREAD_MUTEX_INITIALIZER makes it: a
    /// long and 56 bytes on macOS (sys/_pthread/_pthread_types.h), 40
    /// bytes in musl (include/alltypes.h.in) and in glibc on x86_64, 48 in
    /// glibc on aarch64 (sysdeps/*/nptl/bits/pthreadtypes-arch.h). Eight
    /// words hold each.
    pub struct Lock(UnsafeCell<[u64; 8]>);

    impl Lock {
        pub const fn new() -> Lock {
            // rr: escape(shared): the C library's mutex, which threads
            // share to take turns.
            Lock(UnsafeCell::new([MUTEX_INIT, 0, 0, 0, 0, 0, 0, 0]))
        }

        /// Takes the mutex. It fails only on a mutex never made or
        /// taken twice, which leaves the line in no known state: the
        /// process stops there.
        pub fn lock(&self) {
            // rr: escape(unsafe): the mutex lives as long as self, which
            // is never moved once shared (a static).
            if unsafe { pthread_mutex_lock(self.0.get().cast()) } != 0 {
                // rr: escape(unsafe): abort takes nothing and never returns.
                unsafe { abort() }
            }
        }

        pub fn unlock(&self) {
            // rr: escape(unsafe): this thread locked the mutex.
            if unsafe { pthread_mutex_unlock(self.0.get().cast()) } != 0 {
                // rr: escape(unsafe): abort takes nothing and never returns.
                unsafe { abort() }
            }
        }
    }

    /// Starts a detached thread on start; whether it did.
    pub fn thread(start: *mut c_void) -> bool {
        // rr: escape(unsafe): an integer or a null pointer, which
        // pthread_create fills before it is read.
        let mut thread: Thread = unsafe { core::mem::zeroed() };
        // rr: escape(unsafe): run takes the Start passed to it.
        let code = unsafe { pthread_create(&raw mut thread, core::ptr::null(), run, start) };
        if code != 0 {
            return false;
        }
        // rr: escape(unsafe): thread was just made, and is detached once.
        unsafe { pthread_detach(thread) };
        true
    }

    /// A pipe a byte is written to when the work is done; both ends
    /// close on exec, and with it.
    pub struct Signal {
        pipe: [c_int; 2],
    }

    impl Signal {
        pub fn new() -> Option<Signal> {
            let mut pipe_fds: [c_int; 2] = [-1, -1];
            // rr: escape(unsafe): pipe fills the two fds.
            if unsafe { pipe(pipe_fds.as_mut_ptr()) } != 0 {
                return None;
            }
            let signal = Signal { pipe: pipe_fds };
            for fd in signal.pipe {
                // rr: escape(unsafe): fd is the pipe's, open.
                if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } != 0 {
                    return None;
                }
            }
            Some(signal)
        }

        /// Says the work is done; the pipe is then readable.
        pub fn set(&self) {
            // rr: escape(unsafe): the pipe is open while self lives.
            unsafe { write(self.pipe[1], b"!".as_ptr().cast(), 1) };
        }

        pub fn read_end(&self) -> c_int {
            self.pipe[0]
        }

        /// Whether both ends close on exec.
        #[cfg(test)]
        pub fn cloexec(&self) -> bool {
            self.pipe.iter().all(|fd| {
                // rr: escape(unsafe): fd is the pipe's, open.
                let flags = unsafe { fcntl(*fd, F_GETFD) };
                flags >= 0 && flags & FD_CLOEXEC != 0
            })
        }
    }

    impl Drop for Signal {
        fn drop(&mut self) {
            for fd in self.pipe {
                // rr: escape(unsafe): the pipe is this value's own.
                unsafe { close(fd) };
            }
        }
    }

    /// TCP over loopback for the tests: non-blocking sockets, as a
    /// server and its clients use them.
    #[cfg(test)]
    pub mod net {
        use super::{F_SETFD, FD_CLOEXEC, fcntl};
        use crate::base::wait::SOCK_STREAM;
        use core::ffi::{c_int, c_void};

        /// struct rlimit: two rlim_t, 64 bits on both.
        #[repr(C)]
        struct Rlimit {
            current: u64,
            most: u64,
        }

        #[link(name = "c")]
        // rr: escape(unsafe): each signature is the C library's, from its
        // headers.
        unsafe extern "C" {
            fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
            fn bind(fd: c_int, address: *const u8, length: u32) -> c_int;
            fn listen(fd: c_int, backlog: c_int) -> c_int;
            fn accept(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            fn connect(fd: c_int, address: *const u8, length: u32) -> c_int;
            fn getsockname(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            fn getsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *mut c_void,
                length: *mut u32,
            ) -> c_int;
            fn setsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *const c_void,
                length: u32,
            ) -> c_int;
            fn send(fd: c_int, buffer: *const c_void, length: usize, flags: c_int) -> isize;
            fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
            fn getrlimit(resource: c_int, limit: *mut Rlimit) -> c_int;
            fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
            #[cfg(target_os = "macos")]
            fn __error() -> *mut c_int;
            #[cfg(target_os = "linux")]
            fn __errno_location() -> *mut c_int;
        }

        // sys/socket.h's, errno.h's, fcntl.h's and sys/resource.h's: macOS's
        // from its SDK, Linux's from asm-generic, as x86_64 and aarch64 have.
        const AF_INET: c_int = 2;
        const F_GETFL: c_int = 3;
        const F_SETFL: c_int = 4;
        #[cfg(target_os = "macos")]
        const SOL_SOCKET: c_int = 0xffff;
        #[cfg(target_os = "linux")]
        const SOL_SOCKET: c_int = 1;
        #[cfg(target_os = "macos")]
        const SO_ERROR: c_int = 0x1007;
        #[cfg(target_os = "linux")]
        const SO_ERROR: c_int = 4;
        #[cfg(target_os = "macos")]
        const SO_LINGER: c_int = 0x80;
        #[cfg(target_os = "linux")]
        const SO_LINGER: c_int = 13;
        #[cfg(target_os = "macos")]
        const SO_NOSIGPIPE: c_int = 0x1022;
        #[cfg(target_os = "linux")]
        const MSG_NOSIGNAL: c_int = 0x4000;
        #[cfg(target_os = "macos")]
        const SEND_FLAGS: c_int = 0;
        #[cfg(target_os = "linux")]
        const SEND_FLAGS: c_int = MSG_NOSIGNAL;
        #[cfg(target_os = "macos")]
        const O_NONBLOCK: c_int = 0x4;
        #[cfg(target_os = "linux")]
        use super::super::poller::O_NONBLOCK;
        #[cfg(target_os = "macos")]
        const EAGAIN: c_int = 35;
        #[cfg(target_os = "linux")]
        const EAGAIN: c_int = 11;
        #[cfg(target_os = "macos")]
        const EINPROGRESS: c_int = 36;
        #[cfg(target_os = "linux")]
        const EINPROGRESS: c_int = 115;
        #[cfg(target_os = "macos")]
        pub const REFUSED: i32 = 61;
        #[cfg(target_os = "linux")]
        pub const REFUSED: i32 = 111;
        #[cfg(target_os = "macos")]
        pub const RESET: i32 = 54;
        #[cfg(target_os = "linux")]
        pub const RESET: i32 = 104;
        #[cfg(target_os = "macos")]
        const RLIMIT_NOFILE: c_int = 8;
        #[cfg(target_os = "linux")]
        const RLIMIT_NOFILE: c_int = 7;
        const ADDRESS_BYTES: u32 = 16;

        /// What a read or write did.
        #[derive(Debug, PartialEq)]
        pub enum Io {
            /// So many bytes; a read of 0 is the peer's end.
            Done(usize),
            /// It would block: wait for readiness.
            Blocked,
            Failed(i32),
        }

        #[cfg(target_os = "macos")]
        fn errno_place() -> *mut c_int {
            // rr: escape(unsafe): the C library's thread-local errno.
            unsafe { __error() }
        }

        #[cfg(target_os = "linux")]
        fn errno_place() -> *mut c_int {
            // rr: escape(unsafe): the C library's thread-local errno.
            unsafe { __errno_location() }
        }

        fn errno() -> i32 {
            let place = errno_place();
            // rr: escape(unsafe): the place is this thread's errno.
            unsafe { place.read() }
        }

        /// sockaddr_in for 127.0.0.1 and port: macOS's starts with its
        /// length, Linux's family is a u16 in the host's order, little on
        /// both targets.
        fn address(port: u16) -> [u8; 16] {
            let [high, low] = port.to_be_bytes();
            #[cfg(target_os = "macos")]
            let [first, second] = [16, 2];
            #[cfg(target_os = "linux")]
            let [first, second] = 2u16.to_le_bytes();
            [
                first, second, high, low, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        }

        /// A socket that does not block or outlive exec, and does not
        /// raise SIGPIPE on macOS.
        fn prepare(fd: c_int) -> c_int {
            // rr: escape(unsafe): fd is open.
            let flags = unsafe { fcntl(fd, F_GETFL) };
            // rr: escape(unsafe): fd is open.
            assert_eq!(unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) }, 0);
            // rr: escape(unsafe): fd is open.
            assert_eq!(unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) }, 0);
            #[cfg(target_os = "macos")]
            set(fd, SO_NOSIGPIPE, &1i32.to_le_bytes());
            fd
        }

        fn set(fd: c_int, name: c_int, value: &[u8]) {
            let length = u32::try_from(value.len()).unwrap();
            // rr: escape(unsafe): value holds length bytes.
            let done = unsafe { setsockopt(fd, SOL_SOCKET, name, value.as_ptr().cast(), length) };
            assert_eq!(done, 0);
        }

        fn stream() -> c_int {
            // rr: escape(unsafe): socket takes plain numbers.
            let fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
            assert!(fd >= 0);
            prepare(fd)
        }

        /// A listener on a free port of 127.0.0.1, and the port.
        pub fn listener() -> (i32, u16) {
            let fd = stream();
            let any = address(0);
            // rr: escape(unsafe): any is a sockaddr_in of its length.
            assert_eq!(unsafe { bind(fd, any.as_ptr(), ADDRESS_BYTES) }, 0);
            // rr: escape(unsafe): fd is bound.
            assert_eq!(unsafe { listen(fd, 1024) }, 0);
            let mut bound = [0u8; 16];
            let mut length = ADDRESS_BYTES;
            // rr: escape(unsafe): bound holds length bytes.
            let named = unsafe { getsockname(fd, bound.as_mut_ptr(), &raw mut length) };
            assert_eq!(named, 0);
            (fd, u16::from_be_bytes([bound[2], bound[3]]))
        }

        /// A connection to port begun; Err with the error when it failed
        /// at once.
        pub fn dial(port: u16) -> Result<i32, i32> {
            let fd = stream();
            let peer = address(port);
            // rr: escape(unsafe): peer is a sockaddr_in of its length.
            if unsafe { connect(fd, peer.as_ptr(), ADDRESS_BYTES) } == 0 {
                return Ok(fd);
            }
            match errno() {
                EINPROGRESS => Ok(fd),
                error => {
                    close(fd);
                    Err(error)
                }
            }
        }

        /// The next connection waiting on listener.
        pub fn take(listener: i32) -> Option<i32> {
            // rr: escape(unsafe): no address is asked for.
            let fd = unsafe { accept(listener, core::ptr::null_mut(), core::ptr::null_mut()) };
            (fd >= 0).then(|| prepare(fd))
        }

        fn io(done: isize) -> Io {
            match usize::try_from(done) {
                Ok(count) => Io::Done(count),
                Err(_) => match errno() {
                    EAGAIN => Io::Blocked,
                    error => Io::Failed(error),
                },
            }
        }

        pub fn write(fd: i32, bytes: &[u8]) -> Io {
            // rr: escape(unsafe): bytes holds its length.
            io(unsafe { send(fd, bytes.as_ptr().cast(), bytes.len(), SEND_FLAGS) })
        }

        pub fn read(fd: i32, bytes: &mut [u8]) -> Io {
            // rr: escape(unsafe): bytes holds its length.
            io(unsafe { recv(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) })
        }

        pub fn close(fd: i32) {
            // rr: escape(unsafe): the tests close each socket once.
            unsafe { super::close(fd) };
        }

        /// Closes with a reset, as linger 0 makes it.
        pub fn reset(fd: i32) {
            // struct linger: l_onoff 1, l_linger 0, two ints.
            let [a, b, c, d] = 1i32.to_le_bytes();
            set(fd, SO_LINGER, &[a, b, c, d, 0, 0, 0, 0]);
            close(fd);
        }

        /// The socket's pending error, as SO_ERROR reads and clears it.
        pub fn error(fd: i32) -> i32 {
            let mut error = [0u8; 4];
            let mut length = 4u32;
            // rr: escape(unsafe): error holds length bytes.
            let done = unsafe {
                getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    error.as_mut_ptr().cast(),
                    &raw mut length,
                )
            };
            assert_eq!(done, 0);
            i32::from_le_bytes(error)
        }

        /// Raises this process's descriptors to want, or as many as the
        /// system lets it; how many it has.
        pub fn files(want: u64) -> u64 {
            let mut limit = Rlimit {
                current: 0,
                most: 0,
            };
            // rr: escape(unsafe): limit is a local rlimit.
            assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &raw mut limit) }, 0);
            if limit.current < want {
                let raised = Rlimit {
                    current: want.min(limit.most),
                    most: limit.most,
                };
                // rr: escape(unsafe): raised is a local rlimit.
                if unsafe { setrlimit(RLIMIT_NOFILE, &raw const raised) } == 0 {
                    limit.current = raised.current;
                }
            }
            limit.current
        }
    }
}

#[cfg(target_os = "windows")]
mod os {
    use super::{AF_INET, SOCK_STREAM, Wait};
    use core::cell::UnsafeCell;
    use core::ffi::c_void;
    use core::ptr::{null, null_mut, without_provenance_mut};
    use core::sync::atomic::{AtomicBool, Ordering};

    /// WSAPOLLFD.
    #[repr(C)]
    pub struct PollFd {
        pub fd: usize,
        pub events: i16,
        pub revents: i16,
    }

    /// SOCKADDR_IN.
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        address: [u8; 4],
        zero: [u8; 8],
    }

    #[link(name = "ws2_32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is ws2_32's, from its documentation.
    unsafe extern "system" {
        fn WSAStartup(version: u16, data: *mut u8) -> i32;
        fn WSASocketW(
            family: i32,
            kind: i32,
            protocol: i32,
            info: *const c_void,
            group: u32,
            flags: u32,
        ) -> usize;
        fn bind(socket: usize, address: *const SockaddrIn, length: i32) -> i32;
        fn listen(socket: usize, backlog: i32) -> i32;
        fn getsockname(socket: usize, address: *mut SockaddrIn, length: *mut i32) -> i32;
        fn connect(socket: usize, address: *const SockaddrIn, length: i32) -> i32;
        fn accept(socket: usize, address: *mut SockaddrIn, length: *mut i32) -> usize;
        fn send(socket: usize, buffer: *const u8, length: i32, flags: i32) -> i32;
        fn closesocket(socket: usize) -> i32;
        fn WSAPoll(fds: *mut PollFd, count: u32, timeout: i32) -> i32;
        fn recv(socket: usize, buffer: *mut u8, length: i32, flags: i32) -> i32;
        fn ioctlsocket(socket: usize, command: i32, argument: *mut u32) -> i32;
    }

    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is kernel32's, from its documentation.
    unsafe extern "system" {
        fn CreateThread(
            attributes: *const c_void,
            stack: usize,
            start: extern "system" fn(*mut c_void) -> u32,
            argument: *mut c_void,
            flags: u32,
            id: *mut u32,
        ) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
        fn Sleep(milliseconds: u32);
        fn AcquireSRWLockExclusive(lock: *mut *mut c_void);
        fn ReleaseSRWLockExclusive(lock: *mut *mut c_void);
    }

    const IPPROTO_TCP: i32 = 6;
    const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
    const HANDLE_FLAG_INHERIT: u32 = 1;
    const INVALID_SOCKET: usize = usize::MAX;
    pub const INFINITE: u32 = u32::MAX;
    /// winsock2.h's _IOW('f', 126, u_long).
    const FIONBIO: i32 = 0x8004_667E_u32.cast_signed();

    // rr: escape(shared): Winsock is started once for the process; a race
    // only starts it twice, which it counts.
    static STARTED: AtomicBool = AtomicBool::new(false);

    pub fn startup() {
        if STARTED.load(Ordering::Acquire) {
            return;
        }
        let mut data = [0u8; 512];
        // rr: escape(unsafe): WSADATA is 408 bytes at most; data holds 512.
        if unsafe { WSAStartup(0x0202, data.as_mut_ptr()) } == 0 {
            STARTED.store(true, Ordering::Release);
        }
    }

    pub fn ready(wait: &Wait) -> [i16; 2] {
        let milliseconds = wait
            .timeout_ms
            .map_or(INFINITE, |ms| u32::try_from(ms).unwrap_or(INFINITE - 1));
        // WSAPoll refuses an empty set: nothing to wait on is a sleep.
        if wait.count == 0 {
            // rr: escape(unsafe): Sleep takes a plain number.
            unsafe { Sleep(milliseconds) };
            return [0, 0];
        }
        startup();
        let [one, two] = &wait.fds;
        let mut fds = [
            PollFd {
                fd: one.fd,
                events: one.events,
                revents: 0,
            },
            PollFd {
                fd: two.fd,
                events: two.events,
                revents: 0,
            },
        ];
        let count = u32::try_from(wait.count.min(2)).unwrap_or(0);
        let timeout = i32::try_from(milliseconds).unwrap_or(-1);
        // rr: escape(unsafe): fds holds count entries.
        if unsafe { WSAPoll(fds.as_mut_ptr(), count, timeout) } <= 0 {
            return [0, 0];
        }
        let [first, second] = fds;
        [first.revents, second.revents]
    }

    extern "system" fn run(start: *mut c_void) -> u32 {
        super::begin(start);
        0
    }

    /// An SRWLOCK, one pointer, made as SRWLOCK_INIT makes it: null
    /// (synchapi.h). Taken only exclusive: the shared mode's bug that
    /// Rust's std left SRWLOCK for (rust-lang/rust#121949) is not met.
    /// Acquire and Release return nothing, and cannot fail.
    pub struct Lock(UnsafeCell<*mut c_void>);

    impl Lock {
        pub const fn new() -> Lock {
            // rr: escape(shared): the system's lock, which threads share
            // to take turns.
            Lock(UnsafeCell::new(null_mut()))
        }

        pub fn lock(&self) {
            // rr: escape(unsafe): the lock lives as long as self, which is
            // never moved once shared (a static).
            unsafe { AcquireSRWLockExclusive(self.0.get()) };
        }

        pub fn unlock(&self) {
            // rr: escape(unsafe): this thread holds the lock.
            unsafe { ReleaseSRWLockExclusive(self.0.get()) };
        }
    }

    /// Starts a detached thread on start; whether it did.
    pub fn thread(start: *mut c_void) -> bool {
        // rr: escape(unsafe): run takes the Start passed to it.
        let thread = unsafe { CreateThread(null(), 0, run, start, 0, null_mut()) };
        if thread.is_null() {
            return false;
        }
        // rr: escape(unsafe): the thread runs on without its handle.
        unsafe { CloseHandle(thread) };
        true
    }

    /// A socket of ours, closed on drop.
    struct Socket(usize);

    impl Drop for Socket {
        fn drop(&mut self) {
            if self.0 != INVALID_SOCKET {
                // rr: escape(unsafe): the socket is ours and unused from here.
                unsafe { closesocket(self.0) };
            }
        }
    }

    /// A TCP socket that no child process inherits.
    fn tcp() -> Option<Socket> {
        let flags = WSA_FLAG_NO_HANDLE_INHERIT;
        let family = i32::from(AF_INET);
        // rr: escape(unsafe): WSASocketW takes plain numbers.
        let socket = unsafe { WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, null(), 0, flags) };
        if socket == INVALID_SOCKET {
            None
        } else {
            Some(Socket(socket))
        }
    }

    /// The socket's own address.
    fn name(socket: &Socket) -> Option<SockaddrIn> {
        let mut address = loopback(0);
        let mut length = i32::try_from(size_of::<SockaddrIn>()).ok()?;
        // rr: escape(unsafe): address and length are locals of their size.
        let failed = unsafe { getsockname(socket.0, &raw mut address, &raw mut length) };
        if failed == 0 { Some(address) } else { None }
    }

    fn loopback(port: u16) -> SockaddrIn {
        SockaddrIn {
            family: AF_INET,
            port,
            address: [127, 0, 0, 1],
            zero: [0; 8],
        }
    }

    fn same(a: &SockaddrIn, b: &SockaddrIn) -> bool {
        a.family == b.family && a.port == b.port && a.address == b.address
    }

    /// A connected pair: what was written to the second is read from
    /// the first. The listener lives only until it accepted the second,
    /// whose address the accepted peer must have: another process's
    /// connection is refused.
    fn pair() -> Option<(Socket, Socket)> {
        startup();
        let listener = tcp()?;
        let size = i32::try_from(size_of::<SockaddrIn>()).ok()?;
        let any = loopback(0);
        // rr: escape(unsafe): any is a local SOCKADDR_IN of size bytes.
        if unsafe { bind(listener.0, &raw const any, size) } != 0 {
            return None;
        }
        // rr: escape(unsafe): listen takes plain numbers.
        if unsafe { listen(listener.0, 1) } != 0 {
            return None;
        }
        let bound = name(&listener)?;
        let writer = tcp()?;
        // rr: escape(unsafe): bound is a local SOCKADDR_IN of size bytes.
        if unsafe { connect(writer.0, &raw const bound, size) } != 0 {
            return None;
        }
        let mut peer = loopback(0);
        let mut length = size;
        // rr: escape(unsafe): peer and length are locals of their size.
        let reader = Socket(unsafe { accept(listener.0, &raw mut peer, &raw mut length) });
        if reader.0 == INVALID_SOCKET || !same(&peer, &name(&writer)?) {
            return None;
        }
        // rr: escape(unsafe): the accepted socket is ours; a SOCKET is a
        // handle.
        let kept = unsafe {
            SetHandleInformation(without_provenance_mut(reader.0), HANDLE_FLAG_INHERIT, 0)
        };
        if kept == 0 {
            return None;
        }
        let mut on = 1u32;
        // rr: escape(unsafe): on is a local u_long; the reader is drained
        // without blocking.
        if unsafe { ioctlsocket(reader.0, FIONBIO, &raw mut on) } != 0 {
            return None;
        }
        Some((reader, writer))
    }

    /// WSAPoll on fds, up to timeout milliseconds (-1: no limit); how
    /// many have events.
    pub fn poll(fds: &mut [PollFd], timeout: i32) -> i32 {
        let Ok(count) = u32::try_from(fds.len()) else {
            return 0;
        };
        // rr: escape(unsafe): fds holds count entries.
        unsafe { WSAPoll(fds.as_mut_ptr(), count, timeout) }
    }

    /// A pair of loopback sockets: the thread sends a byte on one when
    /// the work is done, and the other is then readable.
    pub struct Signal {
        reader: Socket,
        writer: Socket,
    }

    impl Signal {
        pub fn new() -> Option<Signal> {
            let (reader, writer) = pair()?;
            Some(Signal { reader, writer })
        }

        /// Says the work is done.
        pub fn set(&self) {
            // rr: escape(unsafe): the socket is open while self lives.
            unsafe { send(self.writer.0, b"!".as_ptr(), 1, 0) };
        }

        pub fn read_end(&self) -> usize {
            self.reader.0
        }
    }

    /// Reads what a signal's set sent to its reader, so that the reader
    /// is not ready: 64 bytes at a time, as often as 64 times, and what
    /// is left the next time.
    pub fn drain(reader: usize) {
        let mut bytes = [0u8; 64];
        let length = i32::try_from(bytes.len()).unwrap_or(0);
        for _ in 0..64 {
            // rr: escape(unsafe): bytes is a local of length bytes; the
            // reader does not block.
            if unsafe { recv(reader, bytes.as_mut_ptr(), length, 0) } <= 0 {
                return;
            }
        }
    }

    /// TCP over loopback for the tests: non-blocking sockets, as a
    /// server and its clients use them.
    #[cfg(test)]
    pub mod net {
        use super::{
            FIONBIO, INVALID_SOCKET, IPPROTO_TCP, SockaddrIn, WSA_FLAG_NO_HANDLE_INHERIT,
            WSASocketW, accept, bind, closesocket, connect, getsockname, ioctlsocket, listen,
            loopback, recv, send, startup,
        };
        use crate::base::wait::{AF_INET, SOCK_STREAM};
        use core::ptr::null;

        #[link(name = "ws2_32", kind = "raw-dylib")]
        // rr: escape(unsafe): each signature is ws2_32's, from its
        // documentation.
        unsafe extern "system" {
            fn WSAGetLastError() -> i32;
            fn getsockopt(
                socket: usize,
                level: i32,
                name: i32,
                value: *mut u8,
                length: *mut i32,
            ) -> i32;
            fn setsockopt(
                socket: usize,
                level: i32,
                name: i32,
                value: *const u8,
                length: i32,
            ) -> i32;
        }

        // winsock2.h's and winerror.h's.
        const SOL_SOCKET: i32 = 0xffff;
        const SO_ERROR: i32 = 0x1007;
        const SO_LINGER: i32 = 0x80;
        const WSAEWOULDBLOCK: i32 = 10035;
        pub const REFUSED: i32 = 10061;
        pub const RESET: i32 = 10054;

        /// What a read or write did.
        #[derive(Debug, PartialEq)]
        pub enum Io {
            /// So many bytes; a read of 0 is the peer's end.
            Done(usize),
            /// It would block: wait for readiness.
            Blocked,
            Failed(i32),
        }

        fn last() -> i32 {
            // rr: escape(unsafe): the thread's last Winsock error.
            unsafe { WSAGetLastError() }
        }

        fn prepare(socket: usize) -> usize {
            let mut on = 1u32;
            // rr: escape(unsafe): on is a local u_long.
            assert_eq!(unsafe { ioctlsocket(socket, FIONBIO, &raw mut on) }, 0);
            socket
        }

        fn stream() -> usize {
            startup();
            let family = i32::from(AF_INET);
            let flags = WSA_FLAG_NO_HANDLE_INHERIT;
            // rr: escape(unsafe): WSASocketW takes plain numbers.
            let socket = unsafe { WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, null(), 0, flags) };
            assert_ne!(socket, INVALID_SOCKET);
            prepare(socket)
        }

        fn size() -> i32 {
            i32::try_from(size_of::<SockaddrIn>()).unwrap()
        }

        /// A listener on a free port of 127.0.0.1, and the port.
        pub fn listener() -> (usize, u16) {
            let socket = stream();
            let any = loopback(0);
            // rr: escape(unsafe): any is a local SOCKADDR_IN of its size.
            assert_eq!(unsafe { bind(socket, &raw const any, size()) }, 0);
            // rr: escape(unsafe): the socket is bound.
            assert_eq!(unsafe { listen(socket, 1024) }, 0);
            let mut bound = loopback(0);
            let mut length = size();
            // rr: escape(unsafe): bound and length are locals of their size.
            let named = unsafe { getsockname(socket, &raw mut bound, &raw mut length) };
            assert_eq!(named, 0);
            (socket, u16::from_be(bound.port))
        }

        /// A connection to port begun; Err with the error when it failed
        /// at once.
        pub fn dial(port: u16) -> Result<usize, i32> {
            let socket = stream();
            let peer = loopback(port.to_be());
            // rr: escape(unsafe): peer is a local SOCKADDR_IN of its size.
            if unsafe { connect(socket, &raw const peer, size()) } == 0 {
                return Ok(socket);
            }
            match last() {
                WSAEWOULDBLOCK => Ok(socket),
                error => {
                    close(socket);
                    Err(error)
                }
            }
        }

        /// The next connection waiting on listener.
        pub fn take(listener: usize) -> Option<usize> {
            let mut peer = loopback(0);
            let mut length = size();
            // rr: escape(unsafe): peer and length are locals of their size.
            let socket = unsafe { accept(listener, &raw mut peer, &raw mut length) };
            (socket != INVALID_SOCKET).then(|| prepare(socket))
        }

        fn io(done: i32) -> Io {
            match usize::try_from(done) {
                Ok(count) => Io::Done(count),
                Err(_) => match last() {
                    WSAEWOULDBLOCK => Io::Blocked,
                    error => Io::Failed(error),
                },
            }
        }

        pub fn write(socket: usize, bytes: &[u8]) -> Io {
            let length = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
            // rr: escape(unsafe): bytes holds at least length bytes.
            io(unsafe { send(socket, bytes.as_ptr(), length, 0) })
        }

        pub fn read(socket: usize, bytes: &mut [u8]) -> Io {
            let length = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
            // rr: escape(unsafe): bytes holds at least length bytes.
            io(unsafe { recv(socket, bytes.as_mut_ptr(), length, 0) })
        }

        pub fn close(socket: usize) {
            // rr: escape(unsafe): the tests close each socket once.
            unsafe { closesocket(socket) };
        }

        /// Closes with a reset, as linger 0 makes it.
        pub fn reset(socket: usize) {
            // struct linger: l_onoff 1, l_linger 0, two u_shorts.
            let [a, b] = 1u16.to_le_bytes();
            let linger = [a, b, 0, 0];
            // rr: escape(unsafe): linger holds 4 bytes.
            let done = unsafe { setsockopt(socket, SOL_SOCKET, SO_LINGER, linger.as_ptr(), 4) };
            assert_eq!(done, 0);
            close(socket);
        }

        /// The socket's pending error, as SO_ERROR reads it.
        pub fn error(socket: usize) -> i32 {
            let mut error = [0u8; 4];
            let mut length = 4i32;
            // rr: escape(unsafe): error holds length bytes.
            let done = unsafe {
                getsockopt(
                    socket,
                    SOL_SOCKET,
                    SO_ERROR,
                    error.as_mut_ptr(),
                    &raw mut length,
                )
            };
            assert_eq!(done, 0);
            i32::from_le_bytes(error)
        }

        /// Windows has no limit to raise: as many as asked.
        pub fn files(want: u64) -> u64 {
            want
        }
    }
}

/// Linux: epoll, level-triggered: the system keeps each descriptor's
/// interest, and a wait costs what is ready, not what is watched. An
/// eventfd wakes it. Time is CLOCK_MONOTONIC, which epoll's timeout
/// counts on too; the timeout is in milliseconds, rounded up.
#[cfg(target_os = "linux")]
mod poller {
    use crate::base::wait::{ERROR, HUP, READ, WRITE};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::ffi::{c_int, c_void};

    /// struct epoll_event, packed on x86_64 alone (linux/eventpoll.h and
    /// musl's sys/epoll.h): 12 bytes there, 16 on aarch64.
    #[cfg_attr(target_arch = "x86_64", repr(C, packed))]
    #[cfg_attr(not(target_arch = "x86_64"), repr(C))]
    struct Event {
        events: u32,
        data: u64,
    }

    /// struct timespec: a time_t and a long, 64 bits on both targets.
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    #[link(name = "c")]
    // rr: escape(unsafe): each signature is the C library's, from its headers.
    unsafe extern "C" {
        fn epoll_create1(flags: c_int) -> c_int;
        fn epoll_ctl(epoll: c_int, operation: c_int, fd: c_int, event: *mut Event) -> c_int;
        fn epoll_wait(epoll: c_int, events: *mut Event, count: c_int, timeout: c_int) -> c_int;
        fn eventfd(initial: u32, flags: c_int) -> c_int;
        fn read(fd: c_int, buffer: *mut c_void, size: usize) -> isize;
        fn write(fd: c_int, buffer: *const c_void, size: usize) -> isize;
        fn close(fd: c_int) -> c_int;
        fn clock_gettime(clock: c_int, time: *mut Timespec) -> c_int;
    }

    // linux/eventpoll.h's operations and events; asm-generic/fcntl.h's
    // flags, which x86_64 and aarch64 share: EPOLL_CLOEXEC and EFD_CLOEXEC
    // are O_CLOEXEC, EFD_NONBLOCK is O_NONBLOCK; linux/time.h's clock.
    const EPOLL_CTL_ADD: c_int = 1;
    const EPOLL_CTL_DEL: c_int = 2;
    const EPOLL_CTL_MOD: c_int = 3;
    const EPOLLIN: u32 = 0x1;
    const EPOLLOUT: u32 = 0x4;
    const EPOLLERR: u32 = 0x8;
    const EPOLLHUP: u32 = 0x10;
    const EPOLLRDHUP: u32 = 0x2000;
    pub(super) const O_NONBLOCK: c_int = 0x800;
    /// Also what trust opens its files with.
    pub const O_CLOEXEC: c_int = 0x8_0000;
    const CLOCK_MONOTONIC: c_int = 1;
    /// The events one wait takes; the rest, still ready, the next.
    const BATCH: usize = 256;

    pub fn monotonic_ns() -> u64 {
        let mut time = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        // rr: escape(unsafe): time is a local timespec.
        unsafe { clock_gettime(CLOCK_MONOTONIC, &raw mut time) };
        let seconds = u64::try_from(time.seconds).unwrap_or(0);
        let nanoseconds = u64::try_from(time.nanoseconds).unwrap_or(0);
        seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(nanoseconds)
    }

    /// The eventfd: a write wakes the epoll it is in.
    pub struct Wake {
        fd: c_int,
    }

    impl Wake {
        pub fn wake(&self) {
            // eventfd adds a u64 in the host's order: little on both targets.
            let one = 1u64.to_le_bytes();
            // rr: escape(unsafe): one is a local of 8 bytes, as eventfd takes.
            unsafe { write(self.fd, one.as_ptr().cast(), one.len()) };
        }

        /// Reads the count back to 0, so that the eventfd is not ready.
        fn drain(&self) {
            let mut count = [0u8; 8];
            // rr: escape(unsafe): count is a local of 8 bytes; the eventfd
            // does not block.
            unsafe { read(self.fd, count.as_mut_ptr().cast(), count.len()) };
        }
    }

    impl Drop for Wake {
        fn drop(&mut self) {
            // rr: escape(unsafe): the eventfd is this value's own.
            unsafe { close(self.fd) };
        }
    }

    pub struct Poller {
        epoll: c_int,
        wake: Arc<Wake>,
        events: [Event; BATCH],
    }

    impl Poller {
        pub fn new() -> Option<Poller> {
            // rr: escape(unsafe): epoll_create1 takes a flag.
            let epoll = unsafe { epoll_create1(O_CLOEXEC) };
            if epoll < 0 {
                return None;
            }
            // rr: escape(unsafe): eventfd takes a count and flags.
            let fd = unsafe { eventfd(0, O_CLOEXEC | O_NONBLOCK) };
            if fd < 0 {
                // rr: escape(unsafe): the epoll is this call's.
                unsafe { close(epoll) };
                return None;
            }
            let poller = Poller {
                epoll,
                // rr: escape(shared): the poller and each Waker hold the
                // eventfd.
                wake: Arc::new(Wake { fd }),
                events: [const { Event { events: 0, data: 0 } }; BATCH],
            };
            // The eventfd's key is 0, which names the waker.
            poller
                .control(EPOLL_CTL_ADD, fd, 0, EPOLLIN)
                .then_some(poller)
        }

        fn control(&self, operation: c_int, fd: c_int, key: u64, events: u32) -> bool {
            let mut event = Event { events, data: key };
            // rr: escape(unsafe): event is a local epoll_event, which the
            // kernel copies.
            unsafe { epoll_ctl(self.epoll, operation, fd, &raw mut event) == 0 }
        }

        pub fn add(&self, fd: c_int, key: u64, interest: u8) -> bool {
            self.control(EPOLL_CTL_ADD, fd, key, events(interest))
        }

        pub fn modify(&self, fd: c_int, key: u64, _old: u8, interest: u8) -> bool {
            self.control(EPOLL_CTL_MOD, fd, key, events(interest))
        }

        pub fn remove(&self, fd: c_int, key: u64, _interest: u8) {
            // A descriptor already closed is already out: no error to act on.
            self.control(EPOLL_CTL_DEL, fd, key, 0);
        }

        pub fn waker(&self) -> Arc<Wake> {
            // rr: escape(copy): a Waker's holder of the eventfd.
            Arc::clone(&self.wake)
        }

        /// Waits up to timeout nanoseconds (None: no limit); what is
        /// ready goes to found by key, 0 for a wake.
        pub fn wait(&mut self, timeout: Option<u64>, found: &mut Vec<(u64, u8)>) {
            let ms = timeout.map_or(-1, |ns| {
                c_int::try_from(ns.div_ceil(1_000_000)).unwrap_or(c_int::MAX)
            });
            let room = c_int::try_from(BATCH).unwrap_or(0);
            // rr: escape(unsafe): events holds room entries.
            let got = unsafe { epoll_wait(self.epoll, self.events.as_mut_ptr(), room, ms) };
            // -1 is an interrupted wait: nothing is ready.
            let got = usize::try_from(got).unwrap_or(0);
            for event in self.events.iter().take(got) {
                let (key, events) = (event.data, event.events);
                if key == 0 {
                    self.wake.drain();
                    found.push((0, 0));
                } else {
                    found.push((key, ready(events)));
                }
            }
        }
    }

    impl Drop for Poller {
        fn drop(&mut self) {
            // rr: escape(unsafe): the epoll is this value's own.
            unsafe { close(self.epoll) };
        }
    }

    fn events(interest: u8) -> u32 {
        let read = if interest & READ == 0 {
            0
        } else {
            EPOLLIN | EPOLLRDHUP
        };
        let write = if interest & WRITE == 0 { 0 } else { EPOLLOUT };
        read | write
    }

    fn ready(events: u32) -> u8 {
        flag(events, EPOLLIN, READ)
            | flag(events, EPOLLOUT, WRITE)
            | flag(events, EPOLLHUP | EPOLLRDHUP, HUP)
            | flag(events, EPOLLERR, ERROR)
    }

    fn flag(events: u32, mask: u32, ready: u8) -> u8 {
        if events & mask == 0 { 0 } else { ready }
    }
}

/// macOS: kqueue, level-triggered (no EV_CLEAR): a filter for reading
/// and one for writing, each added while the interest holds. An
/// EVFILT_USER event wakes it. Time is CLOCK_UPTIME_RAW, as Rust's std
/// reads it on macOS; kevent's timeout is in nanoseconds.
#[cfg(target_os = "macos")]
mod poller {
    use super::os::{F_SETFD, FD_CLOEXEC};
    use crate::base::wait::{ERROR, HUP, READ, WRITE};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::ffi::{c_int, c_void};
    use core::ptr::{null, null_mut, without_provenance_mut};

    /// struct kevent, which sys/event.h declares under #pragma pack(4):
    /// 32 bytes, aligned to 4.
    #[repr(C, packed(4))]
    struct Kevent {
        ident: usize,
        filter: i16,
        flags: u16,
        fflags: u32,
        data: isize,
        udata: *mut c_void,
    }

    /// struct timespec: a time_t and a long.
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    #[link(name = "c")]
    // rr: escape(unsafe): each signature is the C library's, from its headers.
    unsafe extern "C" {
        fn kqueue() -> c_int;
        fn kevent(
            kq: c_int,
            changes: *const Kevent,
            change_count: c_int,
            events: *mut Kevent,
            event_count: c_int,
            timeout: *const Timespec,
        ) -> c_int;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        fn close(fd: c_int) -> c_int;
        /// clockid_t is an enum, an int.
        fn clock_gettime_nsec_np(clock: c_int) -> u64;
    }

    // sys/event.h's filters, flags and notes; _time.h's clock.
    const EVFILT_READ: i16 = -1;
    const EVFILT_WRITE: i16 = -2;
    const EVFILT_USER: i16 = -10;
    const EV_ADD: u16 = 0x1;
    const EV_DELETE: u16 = 0x2;
    const EV_CLEAR: u16 = 0x20;
    const EV_ERROR: u16 = 0x4000;
    const EV_EOF: u16 = 0x8000;
    const NOTE_TRIGGER: u32 = 0x0100_0000;
    const CLOCK_UPTIME_RAW: c_int = 8;
    /// The waker's identifier, in EVFILT_USER's own namespace.
    const WAKE: usize = 0;
    /// The events one wait takes; the rest, still ready, the next.
    const BATCH: usize = 256;

    pub fn monotonic_ns() -> u64 {
        // rr: escape(unsafe): the call takes a clock's number.
        unsafe { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
    }

    fn change(ident: usize, filter: i16, flags: u16, key: u64) -> Kevent {
        Kevent {
            ident,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: without_provenance_mut(usize::try_from(key).unwrap_or(0)),
        }
    }

    /// The kqueue: the poller and each Waker hold it.
    pub struct Wake {
        kq: c_int,
    }

    impl Wake {
        pub fn wake(&self) {
            let mut trigger = change(WAKE, EVFILT_USER, 0, 0);
            trigger.fflags = NOTE_TRIGGER;
            self.apply(&[trigger]);
        }

        /// Makes the changes; false when the system refused one.
        fn apply(&self, changes: &[Kevent]) -> bool {
            let Ok(count) = c_int::try_from(changes.len()) else {
                return false;
            };
            // rr: escape(unsafe): changes holds count entries; no events
            // are asked for, so an error is the call's result.
            let done = unsafe { kevent(self.kq, changes.as_ptr(), count, null_mut(), 0, null()) };
            done == 0
        }
    }

    impl Drop for Wake {
        fn drop(&mut self) {
            // rr: escape(unsafe): the kqueue is this value's own.
            unsafe { close(self.kq) };
        }
    }

    pub struct Poller {
        queue: Arc<Wake>,
        events: [Kevent; BATCH],
    }

    impl Poller {
        pub fn new() -> Option<Poller> {
            // rr: escape(unsafe): kqueue takes nothing.
            let kq = unsafe { kqueue() };
            if kq < 0 {
                return None;
            }
            // rr: escape(shared): the poller and each Waker hold the kqueue.
            let queue = Arc::new(Wake { kq });
            // rr: escape(unsafe): kq is open; fork drops a kqueue, exec
            // does not.
            if unsafe { fcntl(kq, F_SETFD, FD_CLOEXEC) } != 0 {
                return None;
            }
            if !queue.apply(&[change(WAKE, EVFILT_USER, EV_ADD | EV_CLEAR, 0)]) {
                return None;
            }
            Some(Poller {
                queue,
                events: [const {
                    Kevent {
                        ident: 0,
                        filter: 0,
                        flags: 0,
                        fflags: 0,
                        data: 0,
                        udata: null_mut(),
                    }
                }; BATCH],
            })
        }

        pub fn add(&self, fd: c_int, key: u64, interest: u8) -> bool {
            self.modify(fd, key, 0, interest)
        }

        /// Adds the filters the interest gained, deletes those it lost.
        pub fn modify(&self, fd: c_int, key: u64, old: u8, interest: u8) -> bool {
            let ident = usize::try_from(fd).unwrap_or(usize::MAX);
            let mut changes = [change(ident, 0, 0, key), change(ident, 0, 0, key)];
            let mut count = 0;
            for (bit, filter) in [(READ, EVFILT_READ), (WRITE, EVFILT_WRITE)] {
                let flags = match (old & bit != 0, interest & bit != 0) {
                    (false, true) => EV_ADD,
                    (true, false) => EV_DELETE,
                    (true, true) | (false, false) => continue,
                };
                if let Some(slot) = changes.get_mut(count) {
                    slot.filter = filter;
                    slot.flags = flags;
                    count += 1;
                }
            }
            self.queue.apply(changes.get(..count).unwrap_or_default())
        }

        pub fn remove(&self, fd: c_int, key: u64, interest: u8) {
            // A descriptor already closed lost its filters with it.
            self.modify(fd, key, interest, 0);
        }

        pub fn waker(&self) -> Arc<Wake> {
            // rr: escape(copy): a Waker's holder of the kqueue.
            Arc::clone(&self.queue)
        }

        /// Waits up to timeout nanoseconds (None: no limit); what is
        /// ready goes to found by key, 0 for a wake.
        pub fn wait(&mut self, timeout: Option<u64>, found: &mut Vec<(u64, u8)>) {
            let time = timeout.map(|ns| Timespec {
                seconds: i64::try_from(ns / 1_000_000_000).unwrap_or(i64::MAX),
                nanoseconds: i64::try_from(ns % 1_000_000_000).unwrap_or(0),
            });
            let limit = time.as_ref().map_or(null(), core::ptr::from_ref);
            let room = c_int::try_from(BATCH).unwrap_or(0);
            // rr: escape(unsafe): events holds room entries; limit is null
            // or a local timespec.
            let got = unsafe {
                kevent(
                    self.queue.kq,
                    null(),
                    0,
                    self.events.as_mut_ptr(),
                    room,
                    limit,
                )
            };
            // -1 is an interrupted wait: nothing is ready.
            let got = usize::try_from(got).unwrap_or(0);
            for event in self.events.iter().take(got) {
                let (filter, flags, fflags) = (event.filter, event.flags, event.fflags);
                let key = u64::try_from(event.udata.addr()).unwrap_or(0);
                if filter == EVFILT_USER {
                    found.push((0, 0));
                } else {
                    found.push((key, ready(filter, flags, fflags)));
                }
            }
        }
    }

    /// A filter's event: EV_EOF is the peer's hangup, with the socket's
    /// error in fflags when there is one.
    fn ready(filter: i16, flags: u16, fflags: u32) -> u8 {
        let side = match filter {
            EVFILT_READ => READ,
            EVFILT_WRITE => WRITE,
            _ => 0,
        };
        let hup = if flags & EV_EOF == 0 { 0 } else { HUP };
        let error = if flags & EV_ERROR != 0 || (flags & EV_EOF != 0 && fflags != 0) {
            ERROR
        } else {
            0
        };
        side | hup | error
    }
}

/// Windows: socket notifications (ProcessSocketNotifications, Windows 11
/// and Server 2022, build 20348) where the system has them: readiness
/// through a completion port, as epoll has it, level-triggered and
/// one-shot as Microsoft recommends, each registration enabled again
/// with the interest of the time once its notification is taken; a
/// packet posted to the port wakes it. Elsewhere WSAPoll, whose wait
/// costs every socket watched; the signal's pair of sockets wakes it.
/// Time is QueryPerformanceCounter, as Rust's std reads it; both waits
/// take milliseconds, rounded up.
#[cfg(target_os = "windows")]
mod poller {
    use super::os::{self, INFINITE, PollFd, Signal};
    use super::{POLLERR, POLLHUP};
    use crate::base::wait::{ERROR, HUP, READ, WRITE};
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::ffi::{c_char, c_void};
    use core::ptr::{null_mut, without_provenance_mut};

    /// SOCK_NOTIFY_REGISTRATION, from winsock2.h.
    #[repr(C)]
    struct Registration {
        socket: usize,
        key: *mut c_void,
        filter: u16,
        operation: u8,
        trigger: u8,
        result: u32,
    }

    /// OVERLAPPED_ENTRY, from minwinbase.h; for a notification, bytes is
    /// the mask of its events.
    #[repr(C)]
    struct Entry {
        key: usize,
        overlapped: *mut c_void,
        internal: usize,
        bytes: u32,
    }

    /// ProcessSocketNotifications, which ws2_32 exports from build 20348:
    /// found at run time, so that the program still starts before it.
    type Notify = unsafe extern "system" fn(
        port: *mut c_void,
        count: u32,
        registrations: *mut Registration,
        timeout: u32,
        room: u32,
        entries: *mut Entry,
        received: *mut u32,
    ) -> u32;

    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is kernel32's, from its documentation.
    unsafe extern "system" {
        fn CreateIoCompletionPort(
            file: *mut c_void,
            existing: *mut c_void,
            key: usize,
            threads: u32,
        ) -> *mut c_void;
        fn PostQueuedCompletionStatus(
            port: *mut c_void,
            bytes: u32,
            key: usize,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        fn QueryPerformanceCounter(count: *mut i64) -> i32;
        fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
    }

    // winsock2.h's SOCK_NOTIFY_* values; winerror.h's WAIT_TIMEOUT.
    const REGISTER_IN: u16 = 0x1;
    const REGISTER_OUT: u16 = 0x2;
    const REGISTER_HANGUP: u16 = 0x4;
    const EVENT_ERR: u32 = 0x40;
    const EVENT_REMOVE: u32 = 0x80;
    const OP_ENABLE: u8 = 0x1;
    const OP_REMOVE: u8 = 0x4;
    const TRIGGER_ONESHOT: u8 = 0x1;
    const TRIGGER_LEVEL: u8 = 0x4;
    const WAIT_TIMEOUT: u32 = 258;
    // winsock2.h's WSAPoll events.
    const POLLRDNORM: i16 = 0x100;
    const POLLRDBAND: i16 = 0x200;
    const POLLWRNORM: i16 = 0x10;
    const POLLNVAL: i16 = 0x4;
    /// The notifications one wait takes; the rest, still ready, the next.
    const BATCH: usize = 256;

    pub fn monotonic_ns() -> u64 {
        let (mut count, mut frequency) = (0i64, 0i64);
        // rr: escape(unsafe): count is a local; the call cannot fail since
        // Windows XP.
        unsafe { QueryPerformanceCounter(&raw mut count) };
        // rr: escape(unsafe): frequency is a local, fixed at boot.
        unsafe { QueryPerformanceFrequency(&raw mut frequency) };
        let count = u64::try_from(count).unwrap_or(0);
        let Some(frequency) = u64::try_from(frequency).ok().filter(|&f| f > 0) else {
            return 0;
        };
        // Whole seconds, then the rest, so that nothing overflows: the
        // rest is under frequency, some MHz, times 10^9.
        let seconds = count / frequency;
        let rest = (count % frequency).saturating_mul(1_000_000_000) / frequency;
        seconds.saturating_mul(1_000_000_000).saturating_add(rest)
    }

    /// Milliseconds as both waits take them, rounded up; INFINITE for
    /// no limit.
    fn milliseconds(timeout: Option<u64>) -> u32 {
        timeout.map_or(INFINITE, |ns| {
            u32::try_from(ns.div_ceil(1_000_000))
                .unwrap_or(INFINITE - 1)
                .min(INFINITE - 1)
        })
    }

    /// What wakes a Set: a packet on its completion port, or a byte on
    /// its signal.
    pub enum Wake {
        Port(Port),
        Signal(Signal),
    }

    impl Wake {
        pub fn wake(&self) {
            match self {
                Wake::Port(port) => {
                    // rr: escape(unsafe): the port lives as long as self;
                    // key 0 names the waker.
                    unsafe { PostQueuedCompletionStatus(port.handle, 0, 0, null_mut()) };
                }
                Wake::Signal(signal) => signal.set(),
            }
        }
    }

    /// A completion port, closed on drop.
    pub struct Port {
        handle: *mut c_void,
    }

    // rr: escape(unsafe): a completion port is a kernel handle, which any
    // thread may post to while it is open.
    unsafe impl Send for Port {}
    // rr: escape(unsafe): posting takes no state of the value but the handle.
    unsafe impl Sync for Port {}

    impl Drop for Port {
        fn drop(&mut self) {
            // rr: escape(unsafe): the port is this value's own.
            unsafe { CloseHandle(self.handle) };
        }
    }

    pub enum Poller {
        Notified(Notified),
        Polled(Polled),
    }

    impl Poller {
        pub fn new() -> Option<Poller> {
            os::startup();
            match notifier() {
                Some(notify) => Notified::new(notify).map(Poller::Notified),
                None => Polled::new().map(Poller::Polled),
            }
        }

        #[cfg(test)]
        pub fn polled() -> Option<Poller> {
            os::startup();
            Polled::new().map(Poller::Polled)
        }

        pub fn add(&mut self, socket: usize, key: u64, interest: u8) -> bool {
            match self {
                Poller::Notified(notified) => notified.add(socket, key, interest),
                Poller::Polled(polled) => polled.add(socket, key, interest),
            }
        }

        pub fn modify(&mut self, _socket: usize, key: u64, _old: u8, interest: u8) -> bool {
            match self {
                Poller::Notified(notified) => notified.modify(key, interest),
                Poller::Polled(polled) => polled.modify(key, interest),
            }
        }

        pub fn remove(&mut self, socket: usize, key: u64, _interest: u8) {
            match self {
                Poller::Notified(notified) => notified.remove(socket, key),
                Poller::Polled(polled) => polled.remove(key),
            }
        }

        /// The system dropped a closed socket itself: closesocket ends its
        /// registration; the poller forgets its own record.
        pub fn forget(&mut self, key: u64) {
            match self {
                Poller::Notified(notified) => {
                    notified.sockets.remove(&key);
                }
                Poller::Polled(polled) => polled.remove(key),
            }
        }

        pub fn waker(&self) -> Arc<Wake> {
            match self {
                // rr: escape(copy): a Waker's holder of the port.
                Poller::Notified(notified) => Arc::clone(&notified.wake),
                // rr: escape(copy): a Waker's holder of the signal.
                Poller::Polled(polled) => Arc::clone(&polled.wake),
            }
        }

        /// Waits up to timeout nanoseconds (None: no limit); what is
        /// ready goes to found by key, 0 for a wake.
        pub fn wait(&mut self, timeout: Option<u64>, found: &mut Vec<(u64, u8)>) {
            match self {
                Poller::Notified(notified) => notified.wait(timeout, found),
                Poller::Polled(polled) => polled.wait(timeout, found),
            }
        }
    }

    /// ProcessSocketNotifications, where ws2_32 has it.
    fn notifier() -> Option<Notify> {
        let name = b"ws2_32.dll\0".map(u16::from);
        // rr: escape(unsafe): name is NUL-terminated; ws2_32 is loaded,
        // as the program imports it.
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        if module.is_null() {
            return None;
        }
        // rr: escape(unsafe): the name is NUL-terminated.
        let address = unsafe { GetProcAddress(module, c"ProcessSocketNotifications".as_ptr()) };
        if address.is_null() {
            return None;
        }
        // rr: escape(unsafe): the export is the function Notify
        // declares, from winsock2.h.
        Some(unsafe { core::mem::transmute::<*mut c_void, Notify>(address) })
    }

    /// A socket's registration: what the loop wants of it, and whether
    /// it is enabled, as a one-shot one is until its notification.
    struct Watched {
        socket: usize,
        interest: u8,
        armed: bool,
    }

    pub struct Notified {
        notify: Notify,
        /// The port's handle, which wake keeps open.
        port: *mut c_void,
        wake: Arc<Wake>,
        // rr: escape(bound): one for each socket the Set watches.
        sockets: BTreeMap<u64, Watched>,
        /// The registrations that delivered and wait to be enabled again.
        // rr: escape(bound): no more than the sockets.
        spent: Vec<u64>,
        // rr: escape(bound): no more than the sockets.
        enable: Vec<Registration>,
        /// What a wait takes from the port: BATCH entries.
        entries: Vec<Entry>,
    }

    impl Notified {
        fn new(notify: Notify) -> Option<Notified> {
            let invalid = without_provenance_mut(usize::MAX);
            // rr: escape(unsafe): a new port, for one thread.
            let handle = unsafe { CreateIoCompletionPort(invalid, null_mut(), 0, 1) };
            if handle.is_null() {
                return None;
            }
            let mut entries = Vec::with_capacity(BATCH);
            entries.resize_with(BATCH, || Entry {
                key: 0,
                overlapped: null_mut(),
                internal: 0,
                bytes: 0,
            });
            Some(Notified {
                notify,
                port: handle,
                // rr: escape(shared): the poller and each Waker hold the port.
                wake: Arc::new(Wake::Port(Port { handle })),
                sockets: BTreeMap::new(),
                spent: Vec::new(),
                enable: Vec::new(),
                entries,
            })
        }

        /// Makes one registration now; whether the system took it.
        fn register(&self, mut registration: Registration) -> bool {
            // rr: escape(unsafe): registration is a local; no entries are
            // asked for.
            let done = unsafe {
                (self.notify)(
                    self.port,
                    1,
                    &raw mut registration,
                    0,
                    0,
                    null_mut(),
                    null_mut(),
                )
            };
            done == 0 && registration.result == 0
        }

        fn add(&mut self, socket: usize, key: u64, interest: u8) -> bool {
            if !self.register(enable(socket, key, interest)) {
                return false;
            }
            let watched = Watched {
                socket,
                interest,
                armed: true,
            };
            self.sockets.insert(key, watched);
            true
        }

        /// An enabled registration is enabled again with the new
        /// interest; a spent one takes it when it is.
        fn modify(&mut self, key: u64, interest: u8) -> bool {
            let Some(watched) = self.sockets.get_mut(&key) else {
                return false;
            };
            watched.interest = interest;
            if !watched.armed {
                return true;
            }
            let registration = enable(watched.socket, key, interest);
            self.register(registration)
        }

        fn remove(&mut self, socket: usize, key: u64) {
            self.sockets.remove(&key);
            let registration = Registration {
                socket,
                key: key_pointer(key),
                filter: 0,
                operation: OP_REMOVE,
                trigger: 0,
                result: 0,
            };
            // A socket already closed lost its registration with it; what
            // the port still holds for it the Set drops by its key.
            self.register(registration);
        }

        fn wait(&mut self, timeout: Option<u64>, found: &mut Vec<(u64, u8)>) {
            self.enable.clear();
            while let Some(key) = self.spent.pop() {
                if let Some(watched) = self.sockets.get_mut(&key) {
                    watched.armed = true;
                    self.enable
                        .push(enable(watched.socket, key, watched.interest));
                }
            }
            let count = u32::try_from(self.enable.len()).unwrap_or(0);
            let registrations = if count == 0 {
                null_mut()
            } else {
                self.enable.as_mut_ptr()
            };
            let room = u32::try_from(self.entries.len()).unwrap_or(0);
            let mut received = 0u32;
            // rr: escape(unsafe): registrations holds count entries or is
            // null for none; entries holds room.
            let done = unsafe {
                (self.notify)(
                    self.port,
                    count,
                    registrations,
                    milliseconds(timeout),
                    room,
                    self.entries.as_mut_ptr(),
                    &raw mut received,
                )
            };
            let made = done == 0 || done == WAIT_TIMEOUT;
            let enabled = core::mem::take(&mut self.enable);
            for registration in &enabled {
                let key = u64::try_from(registration.key.addr()).unwrap_or(0);
                match (made, registration.result) {
                    (true, 0) => {}
                    // Nothing was made: enabled at the next wait.
                    (false, _) => self.disarm(key),
                    // Refused, as for a socket closed: reported, and tried
                    // again at the next wait until the Set removes it.
                    (true, _) => {
                        self.disarm(key);
                        found.push((key, ERROR));
                    }
                }
            }
            self.enable = enabled;
            if !made {
                return;
            }
            let received = usize::try_from(received).unwrap_or(0);
            for at in 0..received {
                let Some(entry) = self.entries.get(at) else {
                    break;
                };
                let (key, events) = (u64::try_from(entry.key).unwrap_or(0), entry.bytes);
                if key == 0 {
                    found.push((0, 0));
                } else if events & EVENT_REMOVE == 0 {
                    self.disarm(key);
                    found.push((key, ready(events)));
                } else {
                    // A removed registration's last word.
                }
            }
        }

        /// The registration delivered, or was not made: it waits to be
        /// enabled again.
        fn disarm(&mut self, key: u64) {
            if let Some(watched) = self.sockets.get_mut(&key)
                && watched.armed
            {
                watched.armed = false;
                self.spent.push(key);
            }
        }
    }

    fn key_pointer(key: u64) -> *mut c_void {
        without_provenance_mut(usize::try_from(key).unwrap_or(0))
    }

    /// Enables a socket's registration, one-shot and level-triggered,
    /// for its interest and its hangup.
    fn enable(socket: usize, key: u64, interest: u8) -> Registration {
        let read = if interest & READ == 0 { 0 } else { REGISTER_IN };
        let write = if interest & WRITE == 0 {
            0
        } else {
            REGISTER_OUT
        };
        Registration {
            socket,
            key: key_pointer(key),
            filter: read | write | REGISTER_HANGUP,
            operation: OP_ENABLE,
            trigger: TRIGGER_ONESHOT | TRIGGER_LEVEL,
            result: 0,
        }
    }

    /// A notification's events.
    fn ready(events: u32) -> u8 {
        flag(events, u32::from(REGISTER_IN), READ)
            | flag(events, u32::from(REGISTER_OUT), WRITE)
            | flag(events, u32::from(REGISTER_HANGUP), HUP)
            | flag(events, EVENT_ERR, ERROR)
    }

    fn flag(events: u32, mask: u32, ready: u8) -> u8 {
        if events & mask == 0 { 0 } else { ready }
    }

    pub struct Polled {
        /// The signal's reader, which wake keeps open.
        reader: usize,
        wake: Arc<Wake>,
        /// The sockets, the signal's reader first, and each one's key.
        fds: Vec<PollFd>,
        // rr: escape(bound): as many as fds.
        keys: Vec<u64>,
        // rr: escape(bound): as many as fds.
        places: BTreeMap<u64, usize>,
        /// The sockets a wait found closed, to drop after it.
        // rr: escape(bound): no more than fds.
        closed: Vec<u64>,
    }

    impl Polled {
        fn new() -> Option<Polled> {
            let signal = Signal::new()?;
            let reader = signal.read_end();
            Some(Polled {
                reader,
                // rr: escape(shared): the poller and each Waker hold the
                // signal.
                wake: Arc::new(Wake::Signal(signal)),
                fds: Vec::from([PollFd {
                    fd: reader,
                    events: POLLRDNORM,
                    revents: 0,
                }]),
                keys: Vec::from([0]),
                places: BTreeMap::new(),
                closed: Vec::new(),
            })
        }

        fn add(&mut self, socket: usize, key: u64, interest: u8) -> bool {
            self.places.insert(key, self.fds.len());
            self.fds.push(PollFd {
                fd: socket,
                events: poll_events(interest),
                revents: 0,
            });
            self.keys.push(key);
            true
        }

        fn modify(&mut self, key: u64, interest: u8) -> bool {
            let Some(fd) = self.places.get(&key).and_then(|&at| self.fds.get_mut(at)) else {
                return false;
            };
            fd.events = poll_events(interest);
            true
        }

        fn remove(&mut self, key: u64) {
            let Some(at) = self.places.remove(&key) else {
                return;
            };
            if at >= self.fds.len() {
                return;
            }
            self.fds.swap_remove(at);
            self.keys.swap_remove(at);
            // The last took its place.
            if let Some(&moved) = self.keys.get(at) {
                self.places.insert(moved, at);
            }
        }

        fn wait(&mut self, timeout: Option<u64>, found: &mut Vec<(u64, u8)>) {
            let ms = i32::try_from(milliseconds(timeout)).unwrap_or(-1);
            if os::poll(&mut self.fds, ms) <= 0 {
                return;
            }
            for (fd, &key) in self.fds.iter_mut().zip(&self.keys) {
                let revents = fd.revents;
                fd.revents = 0;
                match (revents, key) {
                    (0, _) => {}
                    (_, 0) => {
                        os::drain(self.reader);
                        found.push((0, 0));
                    }
                    // Closed here before it was removed (WSAPoll's remarks):
                    // dropped, as epoll, kqueue and the port drop it.
                    (revents, key) if revents & POLLNVAL != 0 => self.closed.push(key),
                    (revents, key) => found.push((key, poll_ready(revents))),
                }
            }
            while let Some(key) = self.closed.pop() {
                self.remove(key);
            }
        }
    }

    fn poll_events(interest: u8) -> i16 {
        let read = if interest & READ == 0 { 0 } else { POLLRDNORM };
        let write = if interest & WRITE == 0 { 0 } else { POLLWRNORM };
        read | write
    }

    fn poll_ready(revents: i16) -> u8 {
        let read = if revents & (POLLRDNORM | POLLRDBAND) == 0 {
            0
        } else {
            READ
        };
        let write = if revents & POLLWRNORM == 0 { 0 } else { WRITE };
        let hup = if revents & POLLHUP == 0 { 0 } else { HUP };
        let error = if revents & POLLERR == 0 { 0 } else { ERROR };
        read | write | hup | error
    }
}

#[cfg(test)]
mod tests {
    use super::{POLLIN, Signal, THREADS_MAX, Wait, ready, spawn};
    use crate::base::wait::{Instant, Set, WOKEN, Waker};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const JOBS: usize = THREADS_MAX + 8;

    // The jobs' record, which their threads write.
    // rr: escape(shared): the jobs running now.
    static NOW: AtomicUsize = AtomicUsize::new(0);
    // rr: escape(shared): the most that ran at once.
    static MOST: AtomicUsize = AtomicUsize::new(0);
    // rr: escape(shared): the jobs done.
    static DONE: AtomicUsize = AtomicUsize::new(0);
    // rr: escape(shared): lets the jobs end.
    static OPEN: AtomicBool = AtomicBool::new(false);
    // rr: escape(shared): which jobs ran.
    static RAN: [AtomicBool; JOBS] = [const { AtomicBool::new(false) }; JOBS];

    /// Waits a millisecond.
    fn nap() {
        let mut wait = Wait::READY;
        wait.timeout_ms = Some(1);
        ready(&wait);
    }

    /// Waits up to five seconds for done.
    fn until(done: impl Fn() -> bool) -> bool {
        (0..5000).any(|_| {
            nap();
            done()
        })
    }

    fn job(argument: *mut c_void) {
        RAN[argument.addr()].store(true, Ordering::SeqCst);
        let now = NOW.fetch_add(1, Ordering::SeqCst) + 1;
        MOST.fetch_max(now, Ordering::SeqCst);
        while !OPEN.load(Ordering::SeqCst) {
            nap();
        }
        NOW.fetch_sub(1, Ordering::SeqCst);
        DONE.fetch_add(1, Ordering::SeqCst);
    }

    /// More jobs than threads: THREADS_MAX run, the rest wait in line
    /// and run as threads free; one cancelled in line never runs.
    #[test]
    fn queue() {
        let mut tickets = Vec::new();
        for index in 0..JOBS {
            tickets.push(spawn(job, core::ptr::without_provenance_mut(index)).unwrap());
        }
        assert!(until(|| NOW.load(Ordering::SeqCst) == THREADS_MAX));
        nap();
        assert_eq!(NOW.load(Ordering::SeqCst), THREADS_MAX);
        assert!(tickets[JOBS - 1].cancel());
        assert!(!tickets[0].cancel());
        OPEN.store(true, Ordering::SeqCst);
        assert!(until(|| DONE.load(Ordering::SeqCst) == JOBS - 1));
        for _ in 0..50 {
            nap();
        }
        assert_eq!(DONE.load(Ordering::SeqCst), JOBS - 1);
        assert_eq!(MOST.load(Ordering::SeqCst), THREADS_MAX);
        assert!(!RAN[JOBS - 1].load(Ordering::SeqCst));
    }

    /// A signal's descriptor joins a poll beside one that stays quiet,
    /// and only it wakes the poll.
    #[test]
    fn joins_a_poll() {
        let quiet = Signal::new().unwrap();
        let signal = Signal::new().unwrap();
        let Wait {
            fds: [other, _], ..
        } = quiet.wait();
        let Wait { fds: [own, _], .. } = signal.wait();
        let mut wait = Wait {
            fds: [other, own],
            count: 2,
            timeout_ms: Some(0),
        };
        assert_eq!(ready(&wait), [0, 0]);
        signal.set();
        wait.timeout_ms = Some(1000);
        let [first, second] = ready(&wait);
        assert_eq!(first, 0);
        assert_ne!(second & POLLIN, 0);
    }

    /// The pipe's ends close on exec.
    #[cfg(unix)]
    #[test]
    fn close_on_exec() {
        assert!(Signal::new().unwrap().os.cloexec());
    }

    fn wake(argument: *mut c_void) {
        // rr: escape(unsafe): argument is the Box the test made for this
        // thread, which takes it back once.
        let waker = unsafe { Box::from_raw(argument.cast::<Waker>()) };
        nap();
        waker.wake();
    }

    /// Another thread wakes a Set that waits with no limit.
    #[test]
    fn wakes_a_set() {
        let mut set = Set::new().unwrap();
        let waker = set.waker(9);
        // rr: escape(leak): the thread takes it back.
        let argument = Box::into_raw(Box::new(waker));
        let _ticket = spawn(wake, argument.cast()).unwrap();
        let start = Instant::now();
        let events = set.wait(None);
        assert!(events.len() == 1 && events[0].key == 9 && events[0].ready == WOKEN);
        assert!(Instant::now().since(start) < 5_000_000_000);
    }
}
