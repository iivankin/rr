//! Threads for a program whose loops wait on an io::Io, as libuv gives
//! them: a pool for work that blocks, as tokio's spawn_blocking has it, of
//! at most 512 threads by default (pool sets it), each of which ends after
//! 10 s without work (started as work comes, asleep on a condition
//! variable, one first-in-first-out line under a mutex, as libuv's), its work a Box<dyn Work + Send>
//! moved in and given back once it ran, a Job that cancels work still in line
//! when dropped and tells a Notify when done (io's run does, which wakes the
//! loop's Io); threads of their own for loops on other cores, with a 2 MiB
//! stack, joined by a blocking join; and the system's mutex and condition
//! variable (pthread on Linux and macOS, SRWLOCK and CONDITION_VARIABLE on
//! Windows), held by a guard.
//!
//! Threads for a program whose loops wait on an io::Io, as libuv gives a
//! loop its threads: a pool for work that blocks, and threads of their own
//! for loops on other cores. No callback runs on a loop: a job that is
//! done tells its Notify from the pool's thread, as io's run wakes the
//! loop's Io, and the loop takes it.
//!
//! The pool (spawn) is libuv's threadpool.c with tokio's limits: at most
//! 512 threads by default (pool sets it, up to THREADS_MAX), started as
//! work comes and none is idle, which then sleep on a condition variable
//! for the next and end after 10 s without it; one line of work, first in
//! first out, under a mutex. A Job cancels work still in line when it is
//! dropped (cancel gives it back), never work a thread took, which runs
//! to its end, as uv_cancel. Once the work returned, the job tells its
//! Notify, and take gives the work back.
//!
//! Work is moved in and given back: a `Box<dyn Work + Send>`, owned, so
//! it holds no reference into the caller's stack and nothing that may
//! not cross threads, which the compiler checks; no pointer goes in that
//! could dangle, and nothing is unsafe to call. It comes back as the
//! trait object: rr has no generics, and Rust's Any, which would give
//! back the type, is dyn of a trait of another crate, which rr refuses.
//! A caller that needs its own type back (resolve's lookups, trust's
//! checks) keeps its jobs in a field that it alone fills, each with
//! its one type of work, and turns the Box back into that type in its
//! the sys module, whose Safety says so; a program can keep what its work finds
//! in atomics shared with it instead.
//!
//! start runs one Work on a thread of its own, with a stack of 2 MiB:
//! such as a loop with its own Io, which it makes there (an io_uring
//! stays with the thread that made it), told to end by a Waker; join
//! waits for it, for a thread that may block. Lock and Cond are the system's mutex and
//! condition variable, pthread's on Linux and macOS, SRWLOCK and
//! CONDITION_VARIABLE on Windows, for the pool and queue: a guard holds
//! the lock while it lives, and a wait on a Cond is `#[rr::blocking]`, as
//! join is, which rr refuses on the path of a loop marked rr::poll.

// rr: checked(0.5.2)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
// rr: option(os, many): Which systems does it build for?
// rr: choice(os = linux, default): Linux
// rr: choice(os = macos, default): macOS
// rr: choice(os = windows, default): Windows
// rr: option(arch, many): Which CPUs does it build for?
// rr: choice(arch = x86_64, default): x86-64
// rr: choice(arch = aarch64, default): AArch64 (ARM64)
// rr: choice(arch = other, default): any other, on portable code

// rr: unless(os = linux)
#[cfg(target_os = "linux")]
compile_error!("rr add cut thread without linux: add it again with linux in --option os");
// rr: end(os = linux)
// rr: unless(os = macos)
#[cfg(target_os = "macos")]
compile_error!("rr add cut thread without macos: add it again with macos in --option os");
// rr: end(os = macos)
// rr: unless(os = windows)
#[cfg(windows)]
compile_error!("rr add cut thread without windows: add it again with windows in --option os");
// rr: end(os = windows)
// rr: unless(arch = x86_64)
#[cfg(target_arch = "x86_64")]
compile_error!("rr add cut thread without x86_64: add it again with x86_64 in --option arch");
// rr: end(arch = x86_64)
// rr: unless(arch = aarch64)
#[cfg(target_arch = "aarch64")]
compile_error!("rr add cut thread without aarch64: add it again with aarch64 in --option arch");
// rr: end(arch = aarch64)
// rr: unless(arch = other)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("rr add cut thread without other: add it again with other in --option arch");
// rr: end(arch = other)

mod sys {
    //! The system side of thread: what the top of the file says it is, for each system.

    use alloc::boxed::Box;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use core::cell::UnsafeCell;
    use core::ffi::c_void;
    use core::marker::PhantomData;
    use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

    /// Work for another thread: what it needs, moved in with it, and what it
    /// finds, kept in it. run runs once, on a thread of the pool (spawn) or
    /// on a thread of its own (start). Being `dyn Work + Send` and owned,
    /// it holds no reference into the caller's stack and nothing another
    /// thread may not have: the compiler refuses both.
    pub trait Work {
        fn run(&mut self);
    }

    /// How the loop that spawned a Job learns it is done: told on the
    /// pool's thread only after the work returned, so that take then gives
    /// it back. io's run tells the loop's Io, which hands the work back as
    /// an Event.
    pub trait Notify {
        fn notify(&self);
    }

    /// A job's Notify, which the job and the pool's thread hold.
    pub type Done = Arc<dyn Notify + Send + Sync>;

    /// Why no thread runs the work.
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug, PartialEq))]
    // rr: end(tests = yes)
    pub enum Error {
        /// The system started no thread: out of memory or of threads. The
        /// work was not kept, and never runs.
        Start,
        /// The system would not wait for the thread: its handle is not one,
        /// which is a bug in this program.
        Join,
    }

    /// The most threads pool lets the pool run at once, as libuv's pool
    /// holds at most 1024 (UV_THREADPOOL_SIZE).
    pub const THREADS_MAX: usize = 1024;

    // rr: escape(shared): the pool's limits, which pool sets for the process
    // and its threads read: at most so many threads at once, as tokio's
    // blocking pool holds 512 by default (max_blocking_threads), each of
    // which ends once it waited so long for work, 10 s as tokio's do
    // (thread_keep_alive). More work waits its turn, first in first out.
    static MOST: AtomicUsize = AtomicUsize::new(512);
    // rr: escape(shared): likewise.
    static IDLE_MS: AtomicU32 = AtomicU32::new(10_000);

    /// How many threads the pool runs now, idle or not.
    #[must_use]
    pub fn threads() -> usize {
        POOL.threads()
    }

    /// Sets how many threads the pool runs at most (1 to THREADS_MAX) and
    /// how long one waits for work before it ends: tokio's
    /// max_blocking_threads and thread_keep_alive. Threads running stay
    /// until they are idle so long.
    pub fn pool(most: usize, idle: core::time::Duration) {
        MOST.store(most.clamp(1, THREADS_MAX), Ordering::Release);
        let ms = u32::try_from(idle.as_millis()).unwrap_or(u32::MAX).max(1);
        IDLE_MS.store(ms, Ordering::Release);
    }

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
    // Job alone, which reads state with Acquire first. done is Send and Sync.
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
    /// the pool's most run and none is idle, else the first that is free, in the
    /// order of the calls (libuv's threadpool.c: one line under a mutex, its
    /// threads asleep on a condition variable until work comes). done tells
    /// the caller's loop once the work returned; the Job gives it back.
    /// Err gives the work back, never run, when no thread could be started
    /// and none runs: the system is out of memory or of threads.
    pub fn spawn(work: Box<dyn Work + Send>, done: Done) -> Result<Job, Box<dyn Work + Send>> {
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
            // Out of line and still QUEUED, so cancel takes it back.
            return match job.cancel() {
                Ok(unrun) => Err(unrun),
                // rr: escape(panic): no thread took it, as unstart says.
                Err(_) => unreachable!("work out of the pool's line was taken"),
            };
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
                if line.threads < MOST.load(Ordering::Acquire) {
                    line.threads += 1;
                    start = true;
                }
            });
            start
        }

        /// How many threads the pool runs now, idle or not.
        fn threads(&self) -> usize {
            let mut count = 0;
            self.locked(|line, _| count = line.threads);
            count
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

        /// The first in line, asleep until there is one; None once the
        /// thread waited IDLE_MS for it, and is to end.
        #[must_use]
        fn next(&self) -> Option<Arc<Shared>> {
            let held = self.lock.lock();
            loop {
                // rr: escape(unsafe): the lock is held: no one else touches
                // the line.
                let line = unsafe { &mut *self.line.get() };
                if let Some(first) = line.queue.pop_front() {
                    return Some(first);
                }
                line.idle += 1;
                let timed_out = self.more.wait_for(&held, IDLE_MS.load(Ordering::Acquire));
                // rr: escape(unsafe): the lock is held again.
                let again = unsafe { &mut *self.line.get() };
                again.idle -= 1;
                if timed_out && again.queue.is_empty() {
                    again.threads -= 1;
                    return None;
                }
            }
        }
    }

    /// A thread of the pool: the work in line, one after another, until it
    /// waited IDLE_MS for more, as tokio's blocking threads; work cancelled
    /// in line is passed over.
    fn pooled(_argument: *mut c_void) {
        loop {
            let Some(shared) = POOL.next() else {
                return;
            };
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
            shared.done.notify();
        }
    }

    /// A thread of its own, running one Work, such as a loop with its own
    /// Io: join waits for its end. Dropped, it is detached and runs on.
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

        /// As wait, for at most ms milliseconds: whether that time passed.
        #[cfg_attr(rr, rr::blocking)]
        #[must_use]
        pub fn wait_for(&self, held: &Guard<'_>, ms: u32) -> bool {
            self.os.wait_for(&held.lock.os, ms)
        }
    }

    // rr: section(os = linux macos)
    #[cfg(unix)]
    mod os {
        use core::cell::UnsafeCell;
        use core::ffi::{c_int, c_void};

        // rr: section(tests = yes)
        /// A millisecond: struct timespec, a time_t and a long.
        #[cfg(test)]
        pub fn nap() {
            let wanted = [0i64, 1_000_000];
            // rr: escape(unsafe): wanted is a timespec; a signal that ends it
            // early ends a nap.
            unsafe {
                // rr: escape(discard): wanted is a timespec; a signal that ends
                // it early ends a nap.
                let _: c_int = nanosleep(&raw const wanted, core::ptr::null_mut());
            }
        }
        // rr: end(tests = yes)

        // rr: section(os = macos)
        /// pthread_t: a pointer on macOS, an unsigned long in glibc and musl.
        #[cfg(target_os = "macos")]
        pub type Handle = *mut c_void;
        // rr: end(os = macos)
        // rr: section(os = linux windows)
        #[cfg(not(target_os = "macos"))]
        pub type Handle = core::ffi::c_ulong;
        // rr: end(os = linux windows)

        // glibc before 2.34 keeps the threads in libpthread; later ones and
        // musl keep them in libc, and glibc's libpthread is then empty.
        #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "pthread"))]
        // rr: escape(unsafe): each signature is the C library's, from its
        // headers.
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
            // rr: section(tests = yes)
            #[cfg(test)]
            #[must_use]
            fn nanosleep(wanted: *const [i64; 2], left: *mut [i64; 2]) -> c_int;
            // rr: end(tests = yes)
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
            fn pthread_cond_timedwait(
                cond: *mut Words,
                mutex: *mut Words,
                until: *const [i64; 2],
            ) -> c_int;
            #[must_use]
            fn clock_gettime(clock: c_int, time: *mut [i64; 2]) -> c_int;
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

        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        const SIZES: [usize; 3] = [64, 48, 64];
        // rr: end(os = macos)
        // rr: section(os = linux)
        // rr: section(arch = x86_64)
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        const SIZES: [usize; 3] = [40, 48, 56];
        // rr: end(arch = x86_64)
        // rr: end(os = linux)
        // rr: section(os = linux)
        // rr: section(arch = aarch64)
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        const SIZES: [usize; 3] = [48, 48, 64];
        // rr: end(arch = aarch64)
        // rr: end(os = linux)
        const _: () = assert!(
            size_of::<Words>() >= SIZES[0]
                && size_of::<Words>() >= SIZES[1]
                && size_of::<Words>() >= SIZES[2]
                && align_of::<Words>() == 8
        );

        // rr: section(os = macos)
        /// PTHREAD_MUTEX_INITIALIZER's and PTHREAD_COND_INITIALIZER's first
        /// word: macOS's _PTHREAD_MUTEX_SIG_init and _PTHREAD_COND_SIG_init
        /// (its SDK's pthread/pthread_impl.h); glibc's (whose mutex kind
        /// PTHREAD_MUTEX_TIMED_NP is 0) and musl's are all zeros.
        #[cfg(target_os = "macos")]
        const MUTEX_INIT: u64 = 0x32AA_ABA7;
        // rr: end(os = macos)
        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        const COND_INIT: u64 = 0x3CB0_B1BB;
        // rr: end(os = macos)
        // rr: section(os = linux windows)
        #[cfg(not(target_os = "macos"))]
        const MUTEX_INIT: u64 = 0;
        // rr: end(os = linux windows)
        // rr: section(os = linux windows)
        #[cfg(not(target_os = "macos"))]
        const COND_INIT: u64 = 0;
        // rr: end(os = linux windows)

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

            /// At most ms: the deadline is on CLOCK_REALTIME (0 on Linux and
            /// macOS), as a condition variable made statically keeps it, and a
            /// change of the clock moves it; whether it passed.
            #[must_use]
            pub fn wait_for(&self, mutex: &Mutex, ms: u32) -> bool {
                let mut now = [0i64; 2];
                // rr: escape(unsafe): now is a struct timespec.
                if unsafe { clock_gettime(0, &raw mut now) } != 0 {
                    self.wait(mutex);
                    return false;
                }
                let [seconds, nanoseconds] = now;
                let nanoseconds = nanoseconds + i64::from(ms % 1000) * 1_000_000;
                let until = [
                    seconds + i64::from(ms / 1000) + nanoseconds / 1_000_000_000,
                    nanoseconds % 1_000_000_000,
                ];
                // rr: escape(unsafe): this thread holds mutex, the one the
                // waits on this condition variable take; until is a timespec.
                let done = unsafe {
                    pthread_cond_timedwait(self.0.get(), mutex.0.get(), &raw const until)
                };
                done != 0
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
            let sized =
                unsafe { pthread_attr_setstacksize(&raw mut attributes, super::STACK_BYTES) };
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
    // rr: end(os = linux macos)

    // rr: section(os = windows)
    #[cfg(target_os = "windows")]
    mod os {
        use core::cell::UnsafeCell;
        use core::ffi::c_void;
        use core::ptr::{null, null_mut};

        pub type Handle = *mut c_void;

        /// winbase.h: a wait with no limit.
        pub const INFINITE: u32 = 0xFFFF_FFFF;

        // rr: section(tests = yes)
        #[cfg(test)]
        pub fn nap() {
            // rr: escape(unsafe): Sleep takes a plain number.
            unsafe { Sleep(1) }
        }
        // rr: end(tests = yes)

        #[link(name = "kernel32", kind = "raw-dylib")]
        // rr: escape(unsafe): each signature is kernel32's, from its
        // documentation.
        unsafe extern "system" {
            // rr: section(tests = yes)
            #[cfg(test)]
            fn Sleep(milliseconds: u32);
            // rr: end(tests = yes)
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
                    let _: i32 =
                        SleepConditionVariableSRW(self.0.get(), mutex.0.get(), INFINITE, 0);
                }
            }

            /// At most ms: whether that time passed, as the call fails then
            /// (ERROR_TIMEOUT).
            #[must_use]
            pub fn wait_for(&self, mutex: &Mutex, ms: u32) -> bool {
                // rr: escape(unsafe): this thread holds mutex exclusive, the
                // one the waits on this condition variable take.
                let woken =
                    unsafe { SleepConditionVariableSRW(self.0.get(), mutex.0.get(), ms, 0) };
                woken == 0
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
    // rr: end(os = windows)

    // rr: section(os = windows)
    /// Windows's wait with no limit, for io's.
    #[cfg(target_os = "windows")]
    pub use os::INFINITE;
    // rr: end(os = windows)

    /// What a new thread runs: entry, on argument.
    struct Start {
        entry: fn(*mut c_void),
        argument: *mut c_void,
    }

    // rr: section(tests = yes)
    /// Sleeps a millisecond, for the tests.
    #[cfg(test)]
    pub fn nap() {
        os::nap();
    }
    // rr: end(tests = yes)
}

pub use sys::*;

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    //! thread's tests: the pool's line, its jobs as a loop takes them, a
    //! loop on a thread of its own, and the lock under them.

    use super::{Cond, Job, Lock, Notify, Work, nap, pool, spawn, start, threads};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::time::Duration;

    /// The threads the line's test lets the pool run.
    const THREADS: usize = 32;
    const JOBS: usize = THREADS + 8;

    // The line's jobs' record, which their threads write.
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

    /// Waits up to five seconds for done.
    fn until(done: impl Fn() -> bool) -> bool {
        (0..5000).any(|_| {
            nap();
            done()
        })
    }

    /// Counts what it is told, as a loop's Io would be woken.
    struct Count {
        told: AtomicUsize,
    }

    impl Notify for Count {
        fn notify(&self) {
            self.told.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn count() -> Arc<Count> {
        // rr: escape(shared): the pool's threads tell it, the test reads it.
        Arc::new(Count {
            // rr: escape(shared): what it was told.
            told: AtomicUsize::new(0),
        })
    }

    /// A job of the line: it runs until the test opens.
    struct Held {
        index: usize,
    }

    impl Work for Held {
        fn run(&mut self) {
            RAN[self.index].store(true, Ordering::SeqCst);
            let now = NOW.fetch_add(1, Ordering::SeqCst) + 1;
            MOST.fetch_max(now, Ordering::SeqCst);
            while !OPEN.load(Ordering::SeqCst) {
                nap();
            }
            NOW.fetch_sub(1, Ordering::SeqCst);
            DONE.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn held(index: usize, told: &Arc<Count>) -> Job {
        // rr: escape(copy): each job tells the test's count.
        let Ok(job) = spawn(Box::new(Held { index }), Arc::<Count>::clone(told)) else {
            panic!("no thread for the pool");
        };
        job
    }

    /// More jobs than threads: THREADS run, the rest wait in line and
    /// run as threads free; one cancelled in line never runs, and is given
    /// back; nor one whose job is dropped there; one detached runs; one a
    /// thread took is not cancelled. Each that ran tells once.
    #[test]
    fn line() {
        pool(THREADS, Duration::from_secs(10));
        let told = count();
        let mut jobs = Vec::new();
        for index in 0..JOBS - 3 {
            jobs.push(held(index, &told));
        }
        let dropped = held(JOBS - 3, &told);
        let cancelled = held(JOBS - 2, &told);
        held(JOBS - 1, &told).detach();
        assert!(until(|| NOW.load(Ordering::SeqCst) == THREADS));
        nap();
        assert_eq!(NOW.load(Ordering::SeqCst), THREADS);
        assert!(cancelled.cancel().is_ok());
        drop(dropped);
        let running = jobs.swap_remove(0);
        let running = running.cancel().err().unwrap();
        assert!(!running.done());
        jobs.push(running);
        OPEN.store(true, Ordering::SeqCst);
        assert!(until(|| DONE.load(Ordering::SeqCst) == JOBS - 2));
        assert!(until(|| told.told.load(Ordering::Acquire) == JOBS - 2));
        for _ in 0..50 {
            nap();
        }
        assert_eq!(DONE.load(Ordering::SeqCst), JOBS - 2);
        assert_eq!(told.told.load(Ordering::Acquire), JOBS - 2);
        assert_eq!(MOST.load(Ordering::SeqCst), THREADS);
        assert!(!RAN[JOBS - 3].load(Ordering::SeqCst));
        assert!(!RAN[JOBS - 2].load(Ordering::SeqCst));
        assert!(RAN[JOBS - 1].load(Ordering::SeqCst));
        for job in jobs {
            assert!(job.take().is_ok());
        }
    }

    /// A thread that waited the pool's idle time for work ends; one starts
    /// again for the next work.
    #[test]
    fn idle_threads_end() {
        pool(4, Duration::from_millis(50));
        let told = count();
        for _ in 0..2 {
            // rr: escape(copy): each job tells the test's count.
            let Ok(job) = spawn(Box::new(Held { index: 0 }), Arc::<Count>::clone(&told)) else {
                panic!("no thread for the pool");
            };
            OPEN.store(true, Ordering::SeqCst);
            assert!(until(|| job.done()));
            assert!(job.take().is_ok());
            assert!(until(|| threads() == 0));
        }
    }

    /// What a sum found, and how many sums were dropped.
    // rr: escape(shared): the sums dropped, on whatever thread.
    static SUMS_DROPPED: AtomicUsize = AtomicUsize::new(0);

    struct Sum {
        up_to: u64,
        found: Arc<AtomicUsize>,
    }

    impl Work for Sum {
        fn run(&mut self) {
            let sum = (1..=self.up_to).sum::<u64>();
            self.found
                .store(usize::try_from(sum).unwrap(), Ordering::Release);
        }
    }

    impl Drop for Sum {
        fn drop(&mut self) {
            SUMS_DROPPED.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A job tells its Notify once its work returned, and not before; take
    /// refuses before, and gives the work back after, which lives until the
    /// loop drops it.
    #[test]
    fn tells_when_done() {
        let told = count();
        // rr: escape(shared): the work's answer, which the test reads.
        let found = Arc::new(AtomicUsize::new(0));
        let sum = Sum {
            up_to: 1000,
            // rr: escape(copy): the work's holder of the answer.
            found: Arc::clone(&found),
        };
        // rr: escape(copy): the job's holder of the count.
        let Ok(job) = spawn(Box::new(sum), Arc::<Count>::clone(&told)) else {
            panic!("no thread for the pool");
        };
        assert!(until(|| told.told.load(Ordering::Acquire) == 1));
        assert!(job.done());
        assert_eq!(found.load(Ordering::Acquire), 500_500);
        let before = SUMS_DROPPED.load(Ordering::SeqCst);
        let Ok(work) = job.take() else {
            panic!("a job done gives its work back")
        };
        assert_eq!(SUMS_DROPPED.load(Ordering::SeqCst), before);
        drop(work);
        assert_eq!(SUMS_DROPPED.load(Ordering::SeqCst), before + 1);
    }

    /// A loop on a thread of its own, told to end by a flag under a lock,
    /// as a queue tells its workers.
    struct Loop {
        gate: Arc<Gate>,
        turns: Arc<AtomicUsize>,
    }

    struct Gate {
        lock: Lock,
        changed: Cond,
        stop: AtomicBool,
    }

    impl Work for Loop {
        fn run(&mut self) {
            let held = self.gate.lock.lock();
            while !self.gate.stop.load(Ordering::Acquire) {
                self.turns.fetch_add(1, Ordering::AcqRel);
                self.gate.changed.wait(&held);
            }
        }
    }

    /// A started thread runs until told to end, and is joined.
    #[test]
    fn runs_a_loop() {
        // rr: escape(shared): the test and the loop hold it.
        let gate = Arc::new(Gate {
            lock: Lock::new(),
            changed: Cond::new(),
            stop: AtomicBool::new(false),
        });
        // rr: escape(shared): the loop counts its turns.
        let turns = Arc::new(AtomicUsize::new(0));
        let thread = start(Box::new(Loop {
            // rr: escape(copy): the loop's holder of the gate.
            gate: Arc::clone(&gate),
            // rr: escape(copy): the loop's holder of the count.
            turns: Arc::clone(&turns),
        }))
        .unwrap();
        assert!(until(|| turns.load(Ordering::Acquire) >= 1));
        {
            let _held = gate.lock.lock();
            gate.stop.store(true, Ordering::Release);
            gate.changed.broadcast();
        }
        assert_eq!(thread.join(), Ok(()));
    }
}
// rr: end(tests = yes)
