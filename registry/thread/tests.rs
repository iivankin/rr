//! thread's tests: the pool's line, its jobs as a loop takes them, a
//! loop on a thread of its own, and the lock under them.

use super::{Done, Job, THREADS_MAX, Work, spawn, start};
use crate::base::poll::{Instant, Poll, Ready, Signal, Waker, Want, block, ready};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const JOBS: usize = THREADS_MAX + 8;

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

/// Waits a millisecond.
fn nap() {
    let mut want = Want::READY;
    want.timeout_ms = Some(1);
    ready(&want);
}

/// Waits up to five seconds for done.
fn until(done: impl Fn() -> bool) -> bool {
    (0..5000).any(|_| {
        nap();
        done()
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

fn held(index: usize, waker: &Waker) -> Job {
    // rr: escape(copy): each job wakes the test's Poll.
    spawn(Box::new(Held { index }), Done::Wake(waker.clone())).unwrap()
}

/// More jobs than threads: THREADS_MAX run, the rest wait in line and
/// run as threads free; one cancelled in line never runs, and is given
/// back; nor one whose job is dropped there; one detached runs; one a
/// thread took is not cancelled.
#[test]
fn line() {
    let mut poll = Poll::new().unwrap();
    let waker = poll.waker(1);
    let mut jobs = Vec::new();
    for index in 0..JOBS - 3 {
        jobs.push(held(index, &waker));
    }
    let dropped = held(JOBS - 3, &waker);
    let cancelled = held(JOBS - 2, &waker);
    held(JOBS - 1, &waker).detach();
    assert!(until(|| NOW.load(Ordering::SeqCst) == THREADS_MAX));
    nap();
    assert_eq!(NOW.load(Ordering::SeqCst), THREADS_MAX);
    assert!(cancelled.cancel().is_ok());
    drop(dropped);
    let running = jobs.swap_remove(0);
    let running = running.cancel().err().unwrap();
    assert!(!running.done());
    jobs.push(running);
    OPEN.store(true, Ordering::SeqCst);
    assert!(until(|| DONE.load(Ordering::SeqCst) == JOBS - 2));
    for _ in 0..50 {
        nap();
    }
    assert_eq!(DONE.load(Ordering::SeqCst), JOBS - 2);
    assert_eq!(MOST.load(Ordering::SeqCst), THREADS_MAX);
    assert!(!RAN[JOBS - 3].load(Ordering::SeqCst));
    assert!(!RAN[JOBS - 2].load(Ordering::SeqCst));
    assert!(RAN[JOBS - 1].load(Ordering::SeqCst));
    poll.poll(Some(Instant::now().after_ms(1000)));
    for job in jobs {
        assert!(job.take().is_ok());
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

/// A job wakes its loop's Poll once its work returned, and not before;
/// take refuses before, and gives the work back after, which lives
/// until the loop drops it.
#[test]
fn wakes_its_loop() {
    let mut poll = Poll::new().unwrap();
    let waker = poll.waker(7);
    // rr: escape(shared): the work's answer, which the test reads.
    let found = Arc::new(AtomicUsize::new(0));
    let sum = Sum {
        up_to: 1000,
        // rr: escape(copy): the work's holder of the answer.
        found: Arc::clone(&found),
    };
    let mut job = spawn(Box::new(sum), Done::Wake(waker)).unwrap();
    let end = Instant::now().after_ms(10_000);
    while !job.done() {
        assert!(!end.reached_by(Instant::now()));
        for event in poll.poll(Some(end)) {
            assert!(event.key == 7 && event.ready.woken());
        }
    }
    assert_eq!(found.load(Ordering::Acquire), 500_500);
    let before = SUMS_DROPPED.load(Ordering::SeqCst);
    let Ok(work) = job.take() else {
        panic!("a job done gives its work back")
    };
    assert_eq!(SUMS_DROPPED.load(Ordering::SeqCst), before);
    drop(work);
    assert_eq!(SUMS_DROPPED.load(Ordering::SeqCst), before + 1);
    job = spawn(
        Box::new(Sum {
            up_to: 1,
            // rr: escape(copy): the work's holder of the answer.
            found: Arc::clone(&found),
        }),
        // rr: escape(shared): the job's signal, which nothing waits on.
        Done::Signal(Arc::new(Signal::new().unwrap())),
    )
    .unwrap();
    drop(job);
}

/// A job sets the Signal a component's Want names once it is done.
#[test]
fn sets_a_signal() {
    // rr: escape(shared): the job sets it, the test waits on it.
    let signal = Arc::new(Signal::new().unwrap());
    // rr: escape(shared): the work's answer.
    let found = Arc::new(AtomicUsize::new(0));
    let work = Sum {
        up_to: 10,
        // rr: escape(copy): the work's holder of the answer.
        found: Arc::clone(&found),
    };
    // rr: escape(copy): the job's holder of the signal.
    let job = spawn(Box::new(work), Done::Signal(Arc::clone(&signal))).unwrap();
    let mut want = signal.want();
    want.timeout_ms = Some(10_000);
    block(&want);
    assert!(job.done());
    assert_eq!(found.load(Ordering::Acquire), 55);
    assert!(job.take().is_ok());
}

/// A loop on a thread of its own: its Poll, made here, moved in; a
/// Waker tells it to end, and it counts its wakes.
struct Loop {
    poll: Poll,
    stop: Arc<AtomicBool>,
    wakes: Arc<AtomicUsize>,
}

impl Work for Loop {
    fn run(&mut self) {
        serve(self);
    }
}

/// The loop, marked as a program marks its own.
#[cfg_attr(rr, rr::poll)]
fn serve(state: &mut Loop) {
    let end = Instant::now().after_ms(10_000);
    while !state.stop.load(Ordering::Acquire) && !end.reached_by(Instant::now()) {
        for event in state.poll.poll(Some(end)) {
            if event.ready.any(Ready::WOKEN) {
                state.wakes.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

/// A started thread runs its own loop until told to end, and is joined.
#[test]
fn runs_a_loop() {
    let mut poll = Poll::new().unwrap();
    let waker = poll.waker(3);
    // rr: escape(shared): the test tells the loop to end.
    let stop = Arc::new(AtomicBool::new(false));
    // rr: escape(shared): the loop counts its wakes.
    let wakes = Arc::new(AtomicUsize::new(0));
    let thread = start(Box::new(Loop {
        poll,
        // rr: escape(copy): the loop's holder of the flag.
        stop: Arc::clone(&stop),
        // rr: escape(copy): the loop's holder of the count.
        wakes: Arc::clone(&wakes),
    }))
    .unwrap();
    waker.wake();
    assert!(until(|| wakes.load(Ordering::Acquire) >= 1));
    stop.store(true, Ordering::Release);
    waker.wake();
    assert_eq!(thread.join(), Ok(()));
}
