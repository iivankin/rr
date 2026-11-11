//! A bounded queue between threads for a loop on each core: io Streams with
//! a tag, from the thread that accepts to a worker's loop, whose Io each
//! push wakes; a line under the system's mutex with condition variables for
//! threads that may block, no lock-free code; a push to a full queue refused
//! at once with the connection given back; Closed once every Sender is gone.
//! Its tests run a server on N threads, an Io each, fed by an accept thread,
//! and bench its connections a second.
//!
//! A queue between threads, for a loop on each core: it carries an
//! accepted connection (an io::Stream, released from the accepting Io
//! before any operation ran on it) and a tag from the thread that accepts
//! to a worker's loop, whose Io each push wakes; the worker pops it after
//! its wait, adopts it as a Conn and starts receiving on it in its own Io,
//! the only one it ever runs in (on Windows a socket stays in the
//! completion port it first ran in). That is how a server spreads its
//! connections over its cores, as no system but Linux does it itself.
//!
//! As libuv's queues, it is a line under a mutex, with condition
//! variables for the threads that may block (push_blocking,
//! pop_blocking, `#[rr::blocking]`): no lock-free code. It is bounded:
//! a push to a full queue is refused at once and gives the connection
//! back (Push::Full), for another worker or to close, so that a loop
//! that accepts never waits on one that is behind. Its element is one
//! type, as rr has no generics: a program that hands off something
//! else copies the component and changes the type.
//!
//! A Sender may be cloned for more threads; when the last is dropped the
//! receiver's loop is woken, and pop says Closed once the queue is
//! empty: the worker ends. A Receiver dropped closes what is still in
//! line, and a push after is refused (Push::Closed). Each push wakes the
//! loop, which pops until None after each wait: a loop that pops fewer
//! is woken again only by the next push.
//!
//! The tests run such a server on N threads, an Io each, made here and
//! moved to its thread before its first wait, and count the connections
//! each worker served, handed off by an accept thread round robin; and a
//! bench of connections a second.

// rr: checked(0.5.2)
// rr: needs(io, thread)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests
// rr: choice(tests = no): none

mod sys {
    //! The system side of queue: its line, under thread's Lock.

    use crate::base::io::{Stream, Waker};
    use crate::base::thread::{Cond, Lock};
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use core::cell::UnsafeCell;

    /// The most a queue holds: a connection waits in it for its loop, and a
    /// listener's own backlog is of this order (SOMAXCONN, 4096 on Linux).
    pub const CAPACITY_MAX: usize = 1 << 16;

    /// Why channel made no queue.
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug))]
    // rr: end(tests = yes)
    pub enum Error {
        /// A capacity of 0, which takes nothing, or past CAPACITY_MAX.
        Capacity,
    }

    /// Why a push was refused; the connection and its tag come back with it,
    /// the caller's again: to another worker's queue, or to drop, which
    /// closes it.
    pub enum Push {
        /// The queue holds its capacity: its loop is behind.
        Full(Stream, u64),
        /// The Receiver is gone: its loop ended.
        Closed(Stream, u64),
    }

    /// Every Sender is gone and the queue is empty: nothing more comes.
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug, PartialEq))]
    // rr: end(tests = yes)
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
        items: VecDeque<(Stream, u64)>,
        capacity: usize,
        senders: usize,
        receiver: bool,
    }

    // rr: escape(unsafe): line is reached only under lock; the rest is the
    // system's, made for threads to share, and a Waker, any thread's.
    unsafe impl Sync for Shared {}

    /// A queue of capacity connections for the loop whose Io waker wakes:
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
        pub fn push(&self, stream: Stream, tag: u64) -> Result<(), Push> {
            let held = self.shared.lock.lock();
            // rr: escape(unsafe): the lock is held: no one else touches the
            // line.
            let line = unsafe { &mut *self.shared.line.get() };
            if !line.receiver {
                return Err(Push::Closed(stream, tag));
            }
            if line.items.len() >= line.capacity {
                return Err(Push::Full(stream, tag));
            }
            line.items.push_back((stream, tag));
            drop(held);
            self.shared.more.signal();
            self.shared.waker.wake();
            Ok(())
        }

        /// Puts the connection in the queue, waiting while it is full, for a
        /// thread that may block; refused only when the receiver is gone.
        #[cfg_attr(rr, rr::blocking)]
        pub fn push_blocking(&self, stream: Stream, tag: u64) -> Result<(), Push> {
            let shared = &*self.shared;
            let held = shared.lock.lock();
            loop {
                // rr: escape(unsafe): the lock is held: no one else touches
                // the line.
                let line = unsafe { &mut *shared.line.get() };
                if !line.receiver {
                    return Err(Push::Closed(stream, tag));
                }
                if line.items.len() < line.capacity {
                    line.items.push_back((stream, tag));
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
    /// wait, pop until it gives None, then wait again.
    pub struct Receiver {
        shared: Arc<Shared>,
    }

    impl Receiver {
        /// The first connection in line and its tag, at once; None when the
        /// queue is empty; Closed once it is empty and every Sender is gone.
        pub fn pop(&self) -> Result<Option<(Stream, u64)>, Closed> {
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
        pub fn pop_blocking(&self) -> Result<(Stream, u64), Closed> {
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
}

pub use sys::*;

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    //! queue's tests: the queue alone, then a server with a loop on each of
    //! WORKERS threads, as a program on several cores runs one: an accept
    //! thread hands each connection to a worker's queue, round robin.

    use super::{CAPACITY_MAX, Closed, Error, Push, Receiver, Sender, channel};
    use crate::base::io::{Conn, Data, Done, Event, Io, Listener, Room, Stream};
    use crate::base::thread::{Thread, Work, start};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::net::{Ipv4Addr, SocketAddr};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::time::Duration;
    use test::Bencher;

    /// The worker threads of the server.
    const WORKERS: usize = 4;
    /// The keys of a worker's Io: its connections by their index below
    /// ACCEPT, the accept thread's listener.
    const ACCEPT: u64 = 1 << 40;
    /// What each client sends, and gets back.
    const MESSAGE: &[u8] = b"ping, and its pong";
    /// The clients at once: macOS cuts a listen queue to 128.
    const AT_ONCE: usize = 64;
    const TURN: Duration = Duration::from_millis(10);

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    /// The next event, within ten seconds.
    fn next(io: &mut Io) -> Event {
        for _ in 0..1000 {
            if let Some(event) = io.next() {
                return event;
            }
            io.wait(Some(TURN)).unwrap();
        }
        panic!("no event in ten seconds");
    }

    /// count connections accepted on a listener of their own, released
    /// before any operation ran on them; and the Io of their clients,
    /// which keep them open.
    fn accepted(count: usize) -> (Vec<Stream>, Io, Vec<Conn>) {
        let mut io = Io::new(4 * count + 4, 0, 0).unwrap();
        let bound = Listener::bind(loopback(), 16).unwrap();
        let at = bound.local().unwrap();
        assert!(io.accept(bound, ACCEPT).is_ok());
        for _ in 0..count {
            assert!(io.connect(at, 0).is_ok());
        }
        let (mut servers, mut clients) = (Vec::new(), Vec::new());
        while servers.len() < count || clients.len() < count {
            let event = next(&mut io);
            if let Done::Accepted { listener, result } = event.done {
                let Ok(stream) = io.release(result.unwrap().0) else {
                    panic!("not released");
                };
                servers.push(stream);
                if servers.len() < count {
                    assert!(io.accept(listener, ACCEPT).is_ok());
                }
            } else if let Done::Connected(result) = event.done {
                clients.push(result.unwrap());
            } else {
                panic!("not a connection");
            }
        }
        (servers, io, clients)
    }

    /// A queue takes what its capacity holds and refuses the rest at once,
    /// giving it back; pops come first in first out, with their tags;
    /// Closed once every sender is gone and the line is empty; a receiver
    /// gone refuses pushes. A capacity of 0 is refused.
    #[test]
    fn line() {
        let mut io = Io::new(4, 0, 0).unwrap();
        assert!(matches!(channel(0, io.waker()), Err(Error::Capacity)));
        assert!(matches!(
            channel(CAPACITY_MAX + 1, io.waker()),
            Err(Error::Capacity)
        ));
        let (sender, receiver) = channel(2, io.waker()).unwrap();
        let (mut streams, _peers, _clients) = accepted(3);
        let third = streams.pop().unwrap();
        for (tag, stream) in streams.into_iter().enumerate() {
            assert!(sender.push(stream, u64::try_from(tag).unwrap()).is_ok());
        }
        let refused = sender.push(third, 9);
        assert!(matches!(refused, Err(Push::Full(_, 9))));
        // Each push woke the Io: a wait with nothing running returns.
        assert_eq!(io.wait(None), Ok(0));
        assert!(matches!(receiver.pop(), Ok(Some((_, 0)))));
        // rr: escape(copy): a second sender, which the queue counts.
        let other = sender.clone();
        drop(sender);
        assert!(matches!(receiver.pop(), Ok(Some((_, 1)))));
        assert!(matches!(receiver.pop(), Ok(None)));
        drop(other);
        assert_eq!(receiver.pop().err(), Some(Closed));
        let (lone, gone) = channel(1, io.waker()).unwrap();
        drop(gone);
        let Err(Push::Full(back, _)) = refused else {
            panic!("the full queue gave the connection back")
        };
        assert!(matches!(lone.push(back, 3), Err(Push::Closed(_, 3))));
    }

    /// A receiver that may block waits for what another thread pushes, and
    /// for the end when its last sender goes.
    #[test]
    fn blocks_until_pushed() {
        let mut io = Io::new(4, 0, 0).unwrap();
        let (sender, receiver) = channel(4, io.waker()).unwrap();
        let (mut streams, _peers, _clients) = accepted(1);
        // rr: escape(shared): the waiting thread counts what it took.
        let taken = Arc::new(AtomicUsize::new(0));
        let thread = start(Box::new(Taker {
            receiver,
            // rr: escape(copy): the thread's holder of the count.
            taken: Arc::clone(&taken),
        }))
        .unwrap();
        assert!(sender.push_blocking(streams.pop().unwrap(), 5).is_ok());
        drop(sender);
        thread.join().unwrap();
        assert_eq!(taken.load(Ordering::Acquire), 1);
    }

    struct Taker {
        receiver: Receiver,
        taken: Arc<AtomicUsize>,
    }

    impl Work for Taker {
        fn run(&mut self) {
            while let Ok((_stream, tag)) = self.receiver.pop_blocking() {
                assert_eq!(tag, 5);
                self.taken.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    /// A worker: its Io, made on the test's thread and moved to its own
    /// before its first wait, and its queue; it echoes what each connection
    /// sends until its queue closes, and counts the connections it served.
    /// Its connections are by their key.
    struct Worker {
        io: Io,
        receiver: Receiver,
        served: Arc<AtomicUsize>,
        conns: Vec<Option<Conn>>,
    }

    impl Work for Worker {
        fn run(&mut self) {
            serve(self);
        }
    }

    /// The worker's loop, marked as a program marks its own.
    #[cfg_attr(rr, rr::poll)]
    fn serve(worker: &mut Worker) {
        let mut closed = false;
        let mut open = 0usize;
        while !closed || open > 0 {
            worker.io.wait(Some(Duration::from_secs(10))).unwrap();
            loop {
                match worker.receiver.pop() {
                    Ok(Some((stream, _tag))) => {
                        let Ok(conn) = worker.io.adopt(stream) else {
                            panic!("a full table");
                        };
                        // A key a closed connection left, or a new one, as
                        // many as the Io holds.
                        let at = match worker.conns.iter().position(Option::is_none) {
                            Some(at) => at,
                            None if worker.conns.len() < 4 * AT_ONCE => {
                                worker.conns.push(None);
                                worker.conns.len() - 1
                            }
                            None => panic!("more connections than the Io holds"),
                        };
                        let key = u64::try_from(at).unwrap();
                        let room = Room::Buffer(Vec::with_capacity(256));
                        assert!(worker.io.receive(&conn, room, key).is_ok());
                        if let Some(free) = worker.conns.get_mut(at) {
                            *free = Some(conn);
                        }
                        open += 1;
                    }
                    Ok(None) => break,
                    Err(Closed) => {
                        closed = true;
                        break;
                    }
                }
            }
            while let Some(event) = worker.io.next() {
                open -= echo(worker, event);
            }
        }
    }

    /// Sends back what a connection received and closes it, which ends it
    /// once that is sent: the server closes first, so that TIME_WAIT stays
    /// on its side, where its one port is, and not on the clients'
    /// ephemeral ports, which a bench of many connections would use up. 1
    /// when one closed.
    fn echo(worker: &mut Worker, event: Event) -> usize {
        let index = usize::try_from(event.key).unwrap();
        match event.done {
            Done::Received { buffer, result } => {
                let Some(conn) = worker.conns.get_mut(index).and_then(Option::take) else {
                    panic!("no such connection");
                };
                if result.is_ok_and(|count| count > 0) {
                    assert!(
                        worker
                            .io
                            .send(&conn, Data::Bytes(buffer), event.key)
                            .is_ok()
                    );
                }
                worker.io.close(conn);
                worker.served.fetch_add(1, Ordering::AcqRel);
                1
            }
            Done::Sent { result, .. } => {
                assert!(result.is_ok());
                0
            }
            Done::Accepted { .. }
            | Done::Connected(_)
            | Done::Elapsed(_)
            | Done::Ran { .. }
            | Done::SentTo { .. }
            | Done::ReceivedFrom { .. }
            | Done::Chunk(_)
            | Done::Stopped(_)
            | Done::Opened { .. }
            | Done::Read { .. }
            | Done::Written { .. }
            | Done::Synced { .. } => panic!("not a worker's operation"),
        }
    }

    /// The accept thread: its own Io, and the workers' senders, round robin.
    struct Acceptor {
        io: Io,
        listener: Option<Listener>,
        senders: Vec<Sender>,
        stop: Arc<AtomicBool>,
    }

    impl Work for Acceptor {
        fn run(&mut self) {
            hand_off(self);
        }
    }

    #[cfg_attr(rr, rr::poll)]
    fn hand_off(acceptor: &mut Acceptor) {
        let mut next = 0usize;
        if let Some(listener) = acceptor.listener.take() {
            assert!(acceptor.io.accept(listener, ACCEPT).is_ok());
        }
        while !acceptor.stop.load(Ordering::Acquire) {
            acceptor.io.wait(Some(TURN)).unwrap();
            while let Some(event) = acceptor.io.next() {
                let Done::Accepted { listener, result } = event.done else {
                    panic!("not an accept");
                };
                assert!(acceptor.io.accept(listener, ACCEPT).is_ok());
                let Ok((conn, _peer)) = result else {
                    continue;
                };
                let Ok(stream) = acceptor.io.release(conn) else {
                    panic!("not released");
                };
                let count = acceptor.senders.len();
                let tag = u64::try_from(next).unwrap();
                next += 1;
                let Some(sender) = acceptor.senders.get(next % count) else {
                    continue;
                };
                assert!(sender.push(stream, tag).is_ok());
            }
        }
    }

    struct Server {
        address: SocketAddr,
        acceptor: Thread,
        stop: Arc<AtomicBool>,
        workers: Vec<(Thread, Arc<AtomicUsize>)>,
    }

    /// WORKERS loops, each on its thread with its Io and queue, and the
    /// accept thread that feeds them.
    fn server() -> Server {
        let listener = Listener::bind(loopback(), 128).unwrap();
        let address = listener.local().unwrap();
        let (mut senders, mut workers) = (Vec::new(), Vec::new());
        for _ in 0..WORKERS {
            let mut io = Io::new(4 * AT_ONCE, 0, 0).unwrap();
            let (sender, receiver) = channel(AT_ONCE, io.waker()).unwrap();
            senders.push(sender);
            // rr: escape(shared): the worker counts, the test reads.
            let served = Arc::new(AtomicUsize::new(0));
            let worker = Worker {
                io,
                receiver,
                // rr: escape(copy): the worker's holder of the count.
                served: Arc::clone(&served),
                conns: Vec::new(),
            };
            workers.push((start(Box::new(worker)).unwrap(), served));
        }
        // rr: escape(shared): the test tells the acceptor to end.
        let stop = Arc::new(AtomicBool::new(false));
        let acceptor = Acceptor {
            io: Io::new(4, 0, 0).unwrap(),
            listener: Some(listener),
            senders,
            // rr: escape(copy): the acceptor's holder of the flag.
            stop: Arc::clone(&stop),
        };
        let acceptor = start(Box::new(acceptor)).unwrap();
        Server {
            address,
            acceptor,
            stop,
            workers,
        }
    }

    /// Ends the server: the acceptor, whose senders close the queues, and
    /// then each worker; how many connections each served.
    fn stop(server: Server) -> Vec<usize> {
        server.stop.store(true, Ordering::Release);
        server.acceptor.join().unwrap();
        let mut served = Vec::new();
        for (thread, count) in server.workers {
            thread.join().unwrap();
            served.push(count.load(Ordering::Acquire));
        }
        served
    }

    /// count clients of address, AT_ONCE at a time, each sending MESSAGE
    /// as it receives, reading it back, and then the server's end; each by
    /// its key in conns.
    fn clients(io: &mut Io, address: SocketAddr, count: usize) {
        let mut done = 0;
        let mut conns: Vec<Option<Conn>> = Vec::with_capacity(AT_ONCE);
        while done < count {
            let batch = AT_ONCE.min(count - done);
            conns.clear();
            for key in 0..batch {
                assert!(io.connect(address, u64::try_from(key).unwrap()).is_ok());
                conns.push(None);
            }
            let mut left = batch;
            while left > 0 {
                let event = next(io);
                let index = usize::try_from(event.key).unwrap();
                match event.done {
                    Done::Connected(result) => {
                        let conn = result.unwrap();
                        let bytes = Data::Bytes(Vec::from(MESSAGE));
                        assert!(io.send(&conn, bytes, event.key).is_ok());
                        let room = Room::Buffer(Vec::with_capacity(64));
                        assert!(io.receive(&conn, room, event.key).is_ok());
                        if let Some(at) = conns.get_mut(index) {
                            *at = Some(conn);
                        }
                    }
                    Done::Sent { result, .. } => result.unwrap(),
                    Done::Received { mut buffer, result } => {
                        let Some(conn) = conns.get_mut(index).and_then(Option::take) else {
                            panic!("no such connection");
                        };
                        if result.unwrap() == 0 {
                            io.close(conn);
                            left -= 1;
                            continue;
                        }
                        assert_eq!(buffer, MESSAGE);
                        buffer.clear();
                        assert!(io.receive(&conn, Room::Buffer(buffer), event.key).is_ok());
                        if let Some(at) = conns.get_mut(index) {
                            *at = Some(conn);
                        }
                    }
                    Done::Accepted { .. }
                    | Done::Elapsed(_)
                    | Done::Ran { .. }
                    | Done::SentTo { .. }
                    | Done::ReceivedFrom { .. }
                    | Done::Chunk(_)
                    | Done::Stopped(_)
                    | Done::Opened { .. }
                    | Done::Read { .. }
                    | Done::Written { .. }
                    | Done::Synced { .. } => panic!("not a client's operation"),
                }
            }
            done += batch;
        }
    }

    /// Every worker serves: connections spread over the loops, each echoed.
    #[test]
    fn every_worker_serves() {
        let server = server();
        let mut io = Io::new(4 * AT_ONCE, 0, 0).unwrap();
        clients(&mut io, server.address, 8 * WORKERS);
        drop(io);
        let served = stop(server);
        assert_eq!(served.iter().sum::<usize>(), 8 * WORKERS);
        assert!(served.iter().all(|&count| count > 0), "{served:?}");
    }

    /// A connection's round trip through the server, AT_ONCE at a time.
    #[bench]
    fn connections(b: &mut Bencher) {
        let server = server();
        let mut io = Io::new(4 * AT_ONCE, 0, 0).unwrap();
        b.iter(|| clients(&mut io, server.address, AT_ONCE));
        drop(io);
        drop(stop(server));
    }
}
// rr: end(tests = yes)
