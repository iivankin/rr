//! The system side of thread: what mod.rs says it is, for each system.

use crate::base::poll::{Signal, Waker};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

/// Work for another thread: what it needs, moved in with it, and what it
/// finds, kept in it. run runs once, on a thread of the pool (spawn) or
/// on a thread of its own (start). Being `dyn Work + Send` and owned,
/// it holds no reference into the caller's stack and nothing another
/// thread may not have: the compiler refuses both.
pub trait Work {
    fn run(&mut self);
}

/// How the loop that spawned a Job learns it is done: told only after
/// the work returned, so that take then gives it back.
pub enum Done {
    /// Wakes the loop's Poll: it sees WOKEN, and takes its jobs that
    /// are done.
    Wake(Waker),
    /// Sets the signal: for a component whose Want names it, which a
    /// loop follows in its Poll or block waits on.
    Signal(Arc<Signal>),
}

impl Done {
    fn tell(&self) {
        match self {
            Done::Wake(waker) => waker.wake(),
            Done::Signal(signal) => signal.set(),
        }
    }
}

/// Why no thread runs the work.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// The system started no thread: out of memory or of threads. The
    /// work was not kept, and never runs.
    Start,
    /// The system would not wait for the thread: its handle is not one,
    /// which is a bug in this program.
    Join,
}

/// The most threads the pool runs at once, as libuv's default pool
/// holds 4 and at most 1024 (UV_THREADPOOL_SIZE): enough for lookups and
/// chain checks that wait on the network, few enough to start. More work
/// waits its turn, first in first out.
pub const THREADS_MAX: usize = 32;

/// The stack of every thread started here, as Rust's std gives its own
/// threads: macOS gives a thread 512 KiB, musl 128 KiB.
const STACK_BYTES: usize = 2 << 20;

/// A job's states: in line, taken by a thread, run to its end, or
/// cancelled while in line.
const QUEUED: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;
const CANCELLED: u8 = 3;

/// What a Job and the pool share: the state, the work, and how to tell.
struct Shared {
    state: AtomicU8,
    work: UnsafeCell<Option<Box<dyn Work + Send>>>,
    done: Done,
}

// rr: escape(unsafe): work is reached by one thread at a time, as state
// says: the thread that moved it from QUEUED to RUNNING, until it stores
// DONE (Release); then, or once it moved it from QUEUED to CANCELLED, the
// Job alone, which reads state with Acquire first. done is Waker or
// Arc<Signal>, which any thread may use.
unsafe impl Sync for Shared {}

/// Work spawn took for the pool: done says when it ran, take gives it
/// back then. Dropped, it cancels the work if no thread took it yet, as
/// cancel does; detach lets it run whenever its turn comes.
#[must_use]
pub struct Job {
    shared: Arc<Shared>,
    /// The work runs in its turn whatever becomes of the job.
    detached: bool,
}

impl Job {
    /// Whether the work ran to its end: take gives it back then.
    pub fn done(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) == DONE
    }

    /// The work, back, once it ran, with what it found: Err, the job
    /// itself, while it waits or runs.
    pub fn take(self) -> Result<Box<dyn Work + Send>, Job> {
        if !self.done() {
            return Err(self);
        }
        self.work().ok_or(self)
    }

    /// Keeps the work from starting, when no thread took it: then it is
    /// the caller's again, never run. Err, the job itself, when a thread
    /// runs it or ran it.
    pub fn cancel(self) -> Result<Box<dyn Work + Send>, Job> {
        if !self.stop() {
            return Err(self);
        }
        self.work().ok_or(self)
    }

    /// Lets the work run in its turn, with no job to cancel it: the
    /// thread drops it once it ran.
    pub fn detach(mut self) {
        self.detached = true;
    }

    /// Moves the work from the line to cancelled; whether it was there.
    fn stop(&self) -> bool {
        self.shared
            .state
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// The work, out of what the pool shares, once DONE or CANCELLED.
    #[must_use]
    fn work(&self) -> Option<Box<dyn Work + Send>> {
        // rr: escape(unsafe): the state is DONE or CANCELLED, which this
        // job saw: no thread reaches work any more (Shared's Sync).
        unsafe { (*self.shared.work.get()).take() }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Work still in line never runs, and goes here, on this thread.
        if !self.detached && self.stop() {
            // rr: escape(recursion): a work that holds jobs drops them
            // here, each one the program spawned: as deep as it nested
            // them, which it does not without end.
            drop(self.work());
        }
    }
}

/// Runs work on a thread of the pool: a new one while fewer than
/// THREADS_MAX run and none is idle, else the first that is free, in the
/// order of the calls (libuv's threadpool.c: one line under a mutex, its
/// threads asleep on a condition variable until work comes). done tells
/// the caller's loop once the work returned; the Job gives it back.
/// Err when no thread could be started and none runs: work never runs.
pub fn spawn(work: Box<dyn Work + Send>, done: Done) -> Result<Job, Error> {
    // rr: escape(shared): the job and the pool's line hold it.
    let shared = Arc::new(Shared {
        state: AtomicU8::new(QUEUED),
        work: UnsafeCell::new(Some(work)),
        done,
    });
    let job = Job {
        // rr: escape(copy): the line's holder of what the job shares.
        shared: Arc::clone(&shared),
        detached: false,
    };
    if !POOL.queue(shared) {
        return Ok(job);
    }
    if let Some(thread) = os::start(pooled, core::ptr::null_mut()) {
        os::detach(thread);
        return Ok(job);
    }
    if POOL.unstart(&job.shared) {
        return Err(Error::Start);
    }
    Ok(job)
}

/// The pool's line of work and its threads, under its lock: the threads
/// reach it from outside any caller's call tree, as a signal handler
/// would.
struct Pool {
    lock: Lock,
    more: Cond,
    line: UnsafeCell<Line>,
}

struct Line {
    // rr: escape(bound): one for each Job a caller keeps in line.
    queue: VecDeque<Arc<Shared>>,
    threads: usize,
    idle: usize,
}

// rr: escape(unsafe): line is reached only under lock.
unsafe impl Sync for Pool {}

// rr: escape(shared): one pool for the process, as libuv's, which its
// threads reach without a caller to lend it to them.
static POOL: Pool = Pool {
    lock: Lock::new(),
    more: Cond::new(),
    // rr: escape(shared): the line, under the lock.
    line: UnsafeCell::new(Line {
        queue: VecDeque::new(),
        threads: 0,
        idle: 0,
    }),
};

impl Pool {
    /// Runs f on the line, under the lock; f never takes it again.
    fn locked(&self, f: impl FnOnce(&mut Line, &Cond)) {
        let _held = self.lock.lock();
        // rr: escape(unsafe): the lock is held: no one else touches the
        // line.
        f(unsafe { &mut *self.line.get() }, &self.more);
    }

    /// Puts shared in line and wakes an idle thread; whether a thread is
    /// to be started for it, which the caller does, unlocked.
    #[must_use]
    fn queue(&self, shared: Arc<Shared>) -> bool {
        let mut start = false;
        self.locked(|line, more| {
            line.queue.push_back(shared);
            if line.idle > 0 {
                more.signal();
                return;
            }
            if line.threads < THREADS_MAX {
                line.threads += 1;
                start = true;
            }
        });
        start
    }

    /// The thread for shared did not start; when none runs, shared is
    /// taken out of line, never to run: whether it was.
    #[must_use]
    fn unstart(&self, shared: &Arc<Shared>) -> bool {
        let mut taken = false;
        self.locked(|line, _| {
            line.threads -= 1;
            if line.threads == 0 {
                line.queue.retain(|queued| !Arc::ptr_eq(queued, shared));
                taken = true;
            }
        });
        taken
    }

    /// The first in line; asleep until there is one.
    fn next(&self) -> Arc<Shared> {
        let held = self.lock.lock();
        loop {
            // rr: escape(unsafe): the lock is held: no one else touches
            // the line.
            let line = unsafe { &mut *self.line.get() };
            if let Some(first) = line.queue.pop_front() {
                return first;
            }
            line.idle += 1;
            self.more.wait(&held);
            // rr: escape(unsafe): the lock is held again.
            let again = unsafe { &mut *self.line.get() };
            again.idle -= 1;
        }
    }
}

/// A thread of the pool: the work in line, one after another, for the
/// life of the process, as libuv's threads; work cancelled in line is
/// passed over.
fn pooled(_argument: *mut c_void) {
    // rr: escape(loop): the pool's threads serve until the process ends.
    loop {
        let shared = POOL.next();
        let taken = shared
            .state
            .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if !taken {
            continue;
        }
        // rr: escape(unsafe): RUNNING: this thread alone reaches work,
        // until it stores DONE.
        if let Some(work) = unsafe { &mut *shared.work.get() } {
            work.run();
        }
        shared.state.store(DONE, Ordering::Release);
        shared.done.tell();
    }
}

/// A thread of its own, running one Work, such as a loop with its own
/// Poll: join waits for its end. Dropped, it is detached and runs on.
#[must_use]
pub struct Thread {
    handle: Option<os::Handle>,
    /// Kept by the thread that started it, on every system alike (a
    /// pthread_t is a pointer on macOS).
    _here: PhantomData<*const ()>,
}

impl Thread {
    /// Waits until the thread's work returned, for a thread that may
    /// block: a loop is told it is over another way (a Waker, a queue)
    /// and joins after.
    #[cfg_attr(rr, rr::blocking)]
    pub fn join(mut self) -> Result<(), Error> {
        let Some(handle) = self.handle.take() else {
            return Err(Error::Join);
        };
        if os::join(handle) {
            Ok(())
        } else {
            Err(Error::Join)
        }
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            os::detach(handle);
        }
    }
}

/// Runs work on a new thread of its own, with a stack of 2 MiB, for as
/// long as it runs: a loop of its own, on another core. The work is
/// dropped there when run returns.
pub fn start(work: Box<dyn Work + Send>) -> Result<Thread, Error> {
    // A thin pointer to the work, which is a wide one.
    // rr: escape(leak): the thread takes it back, or this call does.
    let raw = Box::into_raw(Box::new(work));
    match os::start(own, raw.cast()) {
        Some(handle) => Ok(Thread {
            handle: Some(handle),
            _here: PhantomData,
        }),
        None => {
            // rr: escape(unsafe): no thread took it; it is this call's.
            drop(unsafe { Box::from_raw(raw) });
            Err(Error::Start)
        }
    }
}

/// A thread of start's: its work, then its end.
fn own(argument: *mut c_void) {
    // rr: escape(unsafe): start made argument of a Box of the work for
    // this thread alone, which takes it back once.
    let mut work = unsafe { Box::from_raw(argument.cast::<Box<dyn Work + Send>>()) };
    work.run();
}

/// A mutex of the system's, for the few words a lock guards: the pool's
/// line and queue's. It is used in place: a static, or a field of what an
/// Arc holds; one moved while a thread holds it or waits on it is
/// undefined, which a Guard's borrow forbids while it lives.
pub struct Lock {
    os: os::Mutex,
}

// rr: escape(unsafe): the system's mutex is made for threads to share.
unsafe impl Sync for Lock {}
// rr: escape(unsafe): a mutex no thread holds may go to another thread.
unsafe impl Send for Lock {}

/// The lock, held until dropped.
#[must_use]
pub struct Guard<'a> {
    lock: &'a Lock,
}

impl Lock {
    pub const fn new() -> Lock {
        Lock {
            os: os::Mutex::new(),
        }
    }

    /// Takes the lock, waiting while another thread holds it. A thread
    /// that holds it does not take it again: POSIX leaves that undefined
    /// for the mutex PTHREAD_MUTEX_INITIALIZER makes.
    pub fn lock(&self) -> Guard<'_> {
        self.os.lock();
        Guard { lock: self }
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.lock.os.unlock();
    }
}

/// A condition variable of the system's, waited on under a Lock.
pub struct Cond {
    os: os::Cond,
}

// rr: escape(unsafe): the system's condition variable is made for
// threads to share.
unsafe impl Sync for Cond {}
// rr: escape(unsafe): one no thread waits on may go to another thread.
unsafe impl Send for Cond {}

impl Cond {
    pub const fn new() -> Cond {
        Cond {
            os: os::Cond::new(),
        }
    }

    /// Wakes one thread that waits, if any.
    pub fn signal(&self) {
        self.os.signal();
    }

    /// Wakes every thread that waits.
    pub fn broadcast(&self) {
        self.os.broadcast();
    }

    /// Lets go of held's lock and sleeps until signalled, then takes the
    /// lock again; it may wake for nothing, so the caller tests what it
    /// waits for again. Always with the same lock.
    #[cfg_attr(rr, rr::blocking)]
    pub fn wait(&self, held: &Guard<'_>) {
        self.os.wait(&held.lock.os);
    }
}

#[cfg(unix)]
mod os {
    use core::cell::UnsafeCell;
    use core::ffi::{c_int, c_void};

    /// pthread_t: a pointer on macOS, an unsigned long in glibc and musl.
    #[cfg(target_os = "macos")]
    pub type Handle = *mut c_void;
    #[cfg(not(target_os = "macos"))]
    pub type Handle = core::ffi::c_ulong;

    // glibc before 2.34 keeps the threads in libpthread; later ones and
    // musl keep them in libc, and glibc's libpthread is then empty.
    #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "pthread"))]
    // rr: escape(unsafe): each signature is the C library's, from its headers.
    unsafe extern "C" {
        #[must_use]
        fn pthread_create(
            thread: *mut Handle,
            attributes: *const Attributes,
            start: extern "C" fn(*mut c_void) -> *mut c_void,
            argument: *mut c_void,
        ) -> c_int;
        #[must_use]
        fn pthread_detach(thread: Handle) -> c_int;
        #[must_use]
        fn pthread_join(thread: Handle, result: *mut *mut c_void) -> c_int;
        #[must_use]
        fn pthread_attr_init(attributes: *mut Attributes) -> c_int;
        #[must_use]
        fn pthread_attr_setstacksize(attributes: *mut Attributes, size: usize) -> c_int;
        #[must_use]
        fn pthread_attr_destroy(attributes: *mut Attributes) -> c_int;
        #[must_use]
        fn pthread_mutex_lock(mutex: *mut Words) -> c_int;
        #[must_use]
        fn pthread_mutex_unlock(mutex: *mut Words) -> c_int;
        #[must_use]
        fn pthread_cond_wait(cond: *mut Words, mutex: *mut Words) -> c_int;
        #[must_use]
        fn pthread_cond_signal(cond: *mut Words) -> c_int;
        #[must_use]
        fn pthread_cond_broadcast(cond: *mut Words) -> c_int;
        fn abort() -> !;
    }

    /// Room for a pthread_mutex_t, a pthread_cond_t or a
    /// pthread_attr_t, aligned as each: macOS's are a long and 56, 40
    /// and 56 bytes (sys/_pthread/_pthread_types.h); glibc's mutex 40
    /// bytes on x86_64 and 48 on aarch64, its cond 48, its attr 56 and 64
    /// (sysdeps/*/nptl/bits/pthreadtypes-arch.h); musl's 40, 48 and 56
    /// (include/alltypes.h.in). Eight words hold each.
    type Words = [u64; 8];
    type Attributes = Words;

    #[cfg(target_os = "macos")]
    const SIZES: [usize; 3] = [64, 48, 64];
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const SIZES: [usize; 3] = [40, 48, 56];
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    const SIZES: [usize; 3] = [48, 48, 64];
    const _: () = assert!(
        size_of::<Words>() >= SIZES[0]
            && size_of::<Words>() >= SIZES[1]
            && size_of::<Words>() >= SIZES[2]
            && align_of::<Words>() == 8
    );

    /// PTHREAD_MUTEX_INITIALIZER's and PTHREAD_COND_INITIALIZER's first
    /// word: macOS's _PTHREAD_MUTEX_SIG_init and _PTHREAD_COND_SIG_init
    /// (its SDK's pthread/pthread_impl.h); glibc's (whose mutex kind
    /// PTHREAD_MUTEX_TIMED_NP is 0) and musl's are all zeros.
    #[cfg(target_os = "macos")]
    const MUTEX_INIT: u64 = 0x32AA_ABA7;
    #[cfg(target_os = "macos")]
    const COND_INIT: u64 = 0x3CB0_B1BB;
    #[cfg(not(target_os = "macos"))]
    const MUTEX_INIT: u64 = 0;
    #[cfg(not(target_os = "macos"))]
    const COND_INIT: u64 = 0;

    /// What a call on a mutex or condition variable of ours cannot
    /// answer but on one never made or misused: what it guards is then
    /// in no known state, and the process stops there.
    fn check(code: c_int) {
        if code != 0 {
            // rr: escape(unsafe): abort takes nothing and never returns.
            unsafe { abort() }
        }
    }

    /// A pthread_mutex_t, made as PTHREAD_MUTEX_INITIALIZER makes it.
    pub struct Mutex(UnsafeCell<Words>);

    impl Mutex {
        pub const fn new() -> Mutex {
            // rr: escape(shared): the C library's mutex, which threads
            // share to take turns.
            Mutex(UnsafeCell::new([MUTEX_INIT, 0, 0, 0, 0, 0, 0, 0]))
        }

        pub fn lock(&self) {
            // rr: escape(unsafe): the mutex is in place while it is used.
            check(unsafe { pthread_mutex_lock(self.0.get()) });
        }

        pub fn unlock(&self) {
            // rr: escape(unsafe): this thread holds the mutex.
            check(unsafe { pthread_mutex_unlock(self.0.get()) });
        }
    }

    /// A pthread_cond_t, made as PTHREAD_COND_INITIALIZER makes it.
    pub struct Cond(UnsafeCell<Words>);

    impl Cond {
        pub const fn new() -> Cond {
            // rr: escape(shared): the C library's condition variable,
            // which threads share to wait.
            Cond(UnsafeCell::new([COND_INIT, 0, 0, 0, 0, 0, 0, 0]))
        }

        pub fn signal(&self) {
            // rr: escape(unsafe): the condition variable is in place.
            check(unsafe { pthread_cond_signal(self.0.get()) });
        }

        pub fn broadcast(&self) {
            // rr: escape(unsafe): the condition variable is in place.
            check(unsafe { pthread_cond_broadcast(self.0.get()) });
        }

        pub fn wait(&self, mutex: &Mutex) {
            // rr: escape(unsafe): this thread holds mutex, the one the
            // waits on this condition variable take.
            check(unsafe { pthread_cond_wait(self.0.get(), mutex.0.get()) });
        }
    }

    extern "C" fn begin(argument: *mut c_void) -> *mut c_void {
        // rr: escape(unsafe): start put the thread's entry and argument
        // in a Box for it alone, which it takes back once.
        let start = unsafe { alloc::boxed::Box::from_raw(argument.cast::<super::Start>()) };
        (start.entry)(start.argument);
        core::ptr::null_mut()
    }

    /// Starts a thread on entry(argument), with a stack of STACK_BYTES;
    /// its handle, to join or detach once, or None when it did not start.
    #[must_use]
    pub fn start(entry: fn(*mut c_void), argument: *mut c_void) -> Option<Handle> {
        let mut attributes: Attributes = [0; 8];
        // rr: escape(unsafe): attributes has room for a pthread_attr_t.
        if unsafe { pthread_attr_init(&raw mut attributes) } != 0 {
            return None;
        }
        // rr: escape(unsafe): attributes was made just now.
        let sized = unsafe { pthread_attr_setstacksize(&raw mut attributes, super::STACK_BYTES) };
        let start = alloc::boxed::Box::new(super::Start { entry, argument });
        // rr: escape(leak): the thread takes it back, or this call does.
        let raw = alloc::boxed::Box::into_raw(start);
        // rr: escape(unsafe): an integer or a null pointer, which
        // pthread_create fills before it is read.
        let mut thread: Handle = unsafe { core::mem::zeroed() };
        // rr: escape(unsafe): begin takes the Box passed to it.
        let code = unsafe {
            pthread_create(
                &raw mut thread,
                if sized == 0 {
                    &raw const attributes
                } else {
                    core::ptr::null()
                },
                begin,
                raw.cast(),
            )
        };
        // rr: escape(unsafe): attributes was made, and is let go once.
        check(unsafe { pthread_attr_destroy(&raw mut attributes) });
        if code != 0 {
            // rr: escape(unsafe): no thread took it; it is this call's.
            drop(unsafe { alloc::boxed::Box::from_raw(raw) });
            return None;
        }
        Some(thread)
    }

    /// Lets the thread run on, its handle let go of.
    pub fn detach(thread: Handle) {
        // rr: escape(unsafe): thread is joinable, and is detached once.
        unsafe {
            // rr: escape(discard): a joinable thread pthread_detach cannot
            // refuse.
            let _: c_int = pthread_detach(thread);
        }
    }

    /// Waits for the thread's end; whether the system could.
    #[must_use]
    pub fn join(thread: Handle) -> bool {
        // rr: escape(unsafe): thread is joinable, and is joined once; its
        // result is not asked for.
        unsafe { pthread_join(thread, core::ptr::null_mut()) == 0 }
    }
}

#[cfg(target_os = "windows")]
mod os {
    use crate::base::poll::INFINITE;
    use core::cell::UnsafeCell;
    use core::ffi::c_void;
    use core::ptr::{null, null_mut};

    pub type Handle = *mut c_void;

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
        #[must_use]
        fn CloseHandle(handle: *mut c_void) -> i32;
        #[must_use]
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn AcquireSRWLockExclusive(lock: *mut *mut c_void);
        fn ReleaseSRWLockExclusive(lock: *mut *mut c_void);
        #[must_use]
        fn SleepConditionVariableSRW(
            cond: *mut *mut c_void,
            lock: *mut *mut c_void,
            milliseconds: u32,
            flags: u32,
        ) -> i32;
        fn WakeConditionVariable(cond: *mut *mut c_void);
        fn WakeAllConditionVariable(cond: *mut *mut c_void);
    }

    /// winbase.h's: the stack size is the reservation, not the commit.
    const STACK_SIZE_PARAM_IS_A_RESERVATION: u32 = 0x1_0000;
    const WAIT_OBJECT_0: u32 = 0;

    /// SRWLOCK and CONDITION_VARIABLE (synchapi.h): a pointer each, made
    /// null by SRWLOCK_INIT and CONDITION_VARIABLE_INIT; Acquire, Release
    /// and Wake return nothing and cannot fail. The lock is taken only
    /// exclusive: the shared mode's bug that Rust's std left SRWLOCK for
    /// (rust-lang/rust#121949) is not met.
    type Word = *mut c_void;
    const _: () = assert!(size_of::<Word>() == size_of::<usize>());

    pub struct Mutex(UnsafeCell<Word>);

    impl Mutex {
        pub const fn new() -> Mutex {
            // rr: escape(shared): the system's lock, which threads share
            // to take turns.
            Mutex(UnsafeCell::new(null_mut()))
        }

        pub fn lock(&self) {
            // rr: escape(unsafe): the lock is in place while it is used.
            unsafe { AcquireSRWLockExclusive(self.0.get()) };
        }

        pub fn unlock(&self) {
            // rr: escape(unsafe): this thread holds the lock.
            unsafe { ReleaseSRWLockExclusive(self.0.get()) };
        }
    }

    pub struct Cond(UnsafeCell<Word>);

    impl Cond {
        pub const fn new() -> Cond {
            // rr: escape(shared): the system's condition variable, which
            // threads share to wait.
            Cond(UnsafeCell::new(null_mut()))
        }

        pub fn signal(&self) {
            // rr: escape(unsafe): the condition variable is in place.
            unsafe { WakeConditionVariable(self.0.get()) };
        }

        pub fn broadcast(&self) {
            // rr: escape(unsafe): the condition variable is in place.
            unsafe { WakeAllConditionVariable(self.0.get()) };
        }

        pub fn wait(&self, mutex: &Mutex) {
            // rr: escape(unsafe): this thread holds mutex exclusive, the
            // one the waits on this condition variable take.
            unsafe {
                // rr: escape(discard): with no limit it fails only for a
                // bad argument; a wake for nothing is the caller's to
                // test, as on POSIX.
                let _: i32 = SleepConditionVariableSRW(self.0.get(), mutex.0.get(), INFINITE, 0);
            }
        }
    }

    extern "system" fn begin(argument: *mut c_void) -> u32 {
        // rr: escape(unsafe): start put the thread's entry and argument
        // in a Box for it alone, which it takes back once.
        let start = unsafe { alloc::boxed::Box::from_raw(argument.cast::<super::Start>()) };
        (start.entry)(start.argument);
        0
    }

    /// Starts a thread on entry(argument), with a stack of STACK_BYTES;
    /// its handle, to join or detach once, or None when it did not start.
    #[must_use]
    pub fn start(entry: fn(*mut c_void), argument: *mut c_void) -> Option<Handle> {
        let start = alloc::boxed::Box::new(super::Start { entry, argument });
        // rr: escape(leak): the thread takes it back, or this call does.
        let raw = alloc::boxed::Box::into_raw(start);
        let flags = STACK_SIZE_PARAM_IS_A_RESERVATION;
        // rr: escape(unsafe): begin takes the Box passed to it.
        let thread = unsafe {
            CreateThread(
                null(),
                super::STACK_BYTES,
                begin,
                raw.cast(),
                flags,
                null_mut(),
            )
        };
        if thread.is_null() {
            // rr: escape(unsafe): no thread took it; it is this call's.
            drop(unsafe { alloc::boxed::Box::from_raw(raw) });
            return None;
        }
        Some(thread)
    }

    pub fn detach(thread: Handle) {
        // rr: escape(unsafe): the thread runs on without its handle.
        unsafe {
            // rr: escape(discard): the thread runs on whatever CloseHandle
            // answers.
            let _: i32 = CloseHandle(thread);
        }
    }

    #[must_use]
    pub fn join(thread: Handle) -> bool {
        // rr: escape(unsafe): thread is a handle of ours, waited on once.
        let ended = unsafe { WaitForSingleObject(thread, INFINITE) } == WAIT_OBJECT_0;
        detach(thread);
        ended
    }
}

/// What a new thread runs: entry, on argument.
struct Start {
    entry: fn(*mut c_void),
    argument: *mut c_void,
}
