//! The system side of wait: what mod.rs says it is, for each system.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

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

/// Winsock's IPv4 family and stream sockets, which the signal's pair
/// and resolve's lookup both name.
#[cfg(target_os = "windows")]
pub const AF_INET: u16 = 2;
#[cfg(target_os = "windows")]
pub const SOCK_STREAM: i32 = 1;

/// A descriptor to wait on, and for what (POLLIN or POLLOUT).
#[cfg(unix)]
pub struct Fd {
    pub fd: i32,
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
    pub fd: usize,
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
    lock: AtomicBool,
    line: UnsafeCell<Line>,
}

// rr: escape(unsafe): Queue's line is only reached under its lock.
unsafe impl Sync for Queue {}

// rr: escape(shared): one line for the process, which the worker threads
// reach without a caller to lend it to them.
static QUEUE: Queue = Queue {
    // rr: escape(shared): the line's lock.
    lock: AtomicBool::new(false),
    // rr: escape(shared): the line, under the lock.
    line: UnsafeCell::new(Line {
        running: 0,
        first: null_mut(),
        last: null_mut(),
    }),
};

/// Runs f on the line under its lock.
fn locked(f: impl FnOnce(&mut Line)) {
    // Another thread holds the lock while it links or unlinks one work:
    // a few instructions.
    while QUEUE
        .lock
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // rr: escape(unsafe): the lock is held: no one else touches the line.
    f(unsafe { &mut *QUEUE.line.get() });
    QUEUE.lock.store(false, Ordering::Release);
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
        fn pipe(fds: *mut c_int) -> c_int;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        fn write(fd: c_int, buffer: *const c_void, size: usize) -> isize;
        fn close(fd: c_int) -> c_int;
        fn poll(fds: *mut PollFd, count: Count, timeout: c_int) -> c_int;
    }

    // fcntl.h's, the same on macOS and Linux.
    const F_SETFD: c_int = 2;
    #[cfg(test)]
    const F_GETFD: c_int = 1;
    const FD_CLOEXEC: c_int = 1;

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
}

#[cfg(target_os = "windows")]
mod os {
    use super::{AF_INET, SOCK_STREAM, Wait};
    use core::ffi::c_void;
    use core::ptr::{null, null_mut, without_provenance_mut};
    use core::sync::atomic::{AtomicBool, Ordering};

    #[repr(C)]
    struct PollFd {
        fd: usize,
        events: i16,
        revents: i16,
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
    }

    const IPPROTO_TCP: i32 = 6;
    const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
    const HANDLE_FLAG_INHERIT: u32 = 1;
    const INVALID_SOCKET: usize = usize::MAX;
    const INFINITE: u32 = u32::MAX;

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
        Some((reader, writer))
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
}

#[cfg(test)]
mod tests {
    use super::{POLLIN, Signal, THREADS_MAX, Wait, ready, spawn};
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
}
