//! The system side of queue: its line, under thread's Lock.

use crate::base::net::Handoff;
use crate::base::poll::Waker;
use crate::base::thread::{Cond, Lock};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;

/// The most a queue holds: a connection waits in it for its loop, and a
/// listener's own backlog is of this order (SOMAXCONN, 4096 on Linux).
pub const CAPACITY_MAX: usize = 1 << 16;

/// Why channel made no queue.
#[cfg_attr(test, derive(Debug))]
pub enum Error {
    /// A capacity of 0, which takes nothing, or past CAPACITY_MAX.
    Capacity,
}

/// Why a push was refused; the connection and its tag come back with it,
/// the caller's again: to another worker's queue, or to drop, which
/// closes it.
pub enum Push {
    /// The queue holds its capacity: its loop is behind.
    Full(Handoff, u64),
    /// The Receiver is gone: its loop ended.
    Closed(Handoff, u64),
}

/// Every Sender is gone and the queue is empty: nothing more comes.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Closed;

/// What the senders and the receiver share.
struct Shared {
    lock: Lock,
    /// Signalled when an item comes or the last sender goes.
    more: Cond,
    /// Signalled when room is made or the receiver goes.
    room: Cond,
    line: UnsafeCell<Line>,
    /// The receiver's loop, woken at each push and when the last sender
    /// goes.
    waker: Waker,
}

struct Line {
    items: VecDeque<(Handoff, u64)>,
    capacity: usize,
    senders: usize,
    receiver: bool,
}

// rr: escape(unsafe): line is reached only under lock; the rest is the
// system's, made for threads to share, and a Waker, any thread's.
unsafe impl Sync for Shared {}

/// A queue of capacity connections for the loop whose Poll waker wakes:
/// its Sender, which may be cloned for more threads, and its Receiver.
pub fn channel(capacity: usize, waker: Waker) -> Result<(Sender, Receiver), Error> {
    if capacity == 0 || capacity > CAPACITY_MAX {
        return Err(Error::Capacity);
    }
    // rr: escape(shared): the senders and the receiver, on their threads.
    let shared = Arc::new(Shared {
        lock: Lock::new(),
        more: Cond::new(),
        room: Cond::new(),
        line: UnsafeCell::new(Line {
            items: VecDeque::with_capacity(capacity),
            capacity,
            senders: 1,
            receiver: true,
        }),
        waker,
    });
    let sender = Sender {
        // rr: escape(copy): the sender's holder of the queue.
        shared: Arc::clone(&shared),
    };
    Ok((sender, Receiver { shared }))
}

/// What puts connections in a queue, from any thread.
pub struct Sender {
    shared: Arc<Shared>,
}

impl Clone for Sender {
    fn clone(&self) -> Sender {
        let held = self.shared.lock.lock();
        // rr: escape(unsafe): the lock is held: no one else touches the
        // line.
        unsafe { (*self.shared.line.get()).senders += 1 };
        drop(held);
        Sender {
            // rr: escape(copy): another sender of the same queue.
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Sender {
    /// Puts the connection in the queue, tagged, and wakes its loop:
    /// at once, for a loop that may not block. Refused when it is full
    /// or its receiver is gone, with the connection given back.
    pub fn push(&self, handoff: Handoff, tag: u64) -> Result<(), Push> {
        let held = self.shared.lock.lock();
        // rr: escape(unsafe): the lock is held: no one else touches the
        // line.
        let line = unsafe { &mut *self.shared.line.get() };
        if !line.receiver {
            return Err(Push::Closed(handoff, tag));
        }
        if line.items.len() >= line.capacity {
            return Err(Push::Full(handoff, tag));
        }
        line.items.push_back((handoff, tag));
        drop(held);
        self.shared.more.signal();
        self.shared.waker.wake();
        Ok(())
    }

    /// Puts the connection in the queue, waiting while it is full, for a
    /// thread that may block; refused only when the receiver is gone.
    #[cfg_attr(rr, rr::blocking)]
    pub fn push_blocking(&self, handoff: Handoff, tag: u64) -> Result<(), Push> {
        let shared = &*self.shared;
        let held = shared.lock.lock();
        loop {
            // rr: escape(unsafe): the lock is held: no one else touches
            // the line.
            let line = unsafe { &mut *shared.line.get() };
            if !line.receiver {
                return Err(Push::Closed(handoff, tag));
            }
            if line.items.len() < line.capacity {
                line.items.push_back((handoff, tag));
                drop(held);
                shared.more.signal();
                shared.waker.wake();
                return Ok(());
            }
            shared.room.wait(&held);
        }
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        let held = self.shared.lock.lock();
        // rr: escape(unsafe): the lock is held: no one else touches the
        // line.
        let line = unsafe { &mut *self.shared.line.get() };
        line.senders -= 1;
        let last = line.senders == 0;
        drop(held);
        if last {
            self.shared.more.broadcast();
            self.shared.waker.wake();
        }
    }
}

/// What takes connections out of a queue, on its loop's thread: after a
/// WOKEN, pop until it gives None, then wait again.
pub struct Receiver {
    shared: Arc<Shared>,
}

impl Receiver {
    /// The first connection in line and its tag, at once; None when the
    /// queue is empty; Closed once it is empty and every Sender is gone.
    pub fn pop(&self) -> Result<Option<(Handoff, u64)>, Closed> {
        let held = self.shared.lock.lock();
        // rr: escape(unsafe): the lock is held: no one else touches the
        // line.
        let line = unsafe { &mut *self.shared.line.get() };
        let first = line.items.pop_front();
        let closed = first.is_none() && line.senders == 0;
        drop(held);
        if closed {
            return Err(Closed);
        }
        if first.is_some() {
            self.shared.room.signal();
        }
        Ok(first)
    }

    /// The first connection in line and its tag, waiting for one, for a
    /// thread that may block; Closed once it is empty and every Sender is
    /// gone.
    #[cfg_attr(rr, rr::blocking)]
    pub fn pop_blocking(&self) -> Result<(Handoff, u64), Closed> {
        let shared = &*self.shared;
        let held = shared.lock.lock();
        loop {
            // rr: escape(unsafe): the lock is held: no one else touches
            // the line.
            let line = unsafe { &mut *shared.line.get() };
            if let Some(first) = line.items.pop_front() {
                drop(held);
                shared.room.signal();
                return Ok(first);
            }
            if line.senders == 0 {
                return Err(Closed);
            }
            shared.more.wait(&held);
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let held = self.shared.lock.lock();
        // rr: escape(unsafe): the lock is held: no one else touches the
        // line.
        let line = unsafe { &mut *self.shared.line.get() };
        line.receiver = false;
        let left = core::mem::take(&mut line.items);
        drop(held);
        self.shared.room.broadcast();
        // The connections no loop took are closed here, unlocked.
        drop(left);
    }
}
