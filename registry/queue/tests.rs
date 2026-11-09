//! queue's tests: the queue alone, then a server with a loop on each of
//! WORKERS threads, as a program on several cores runs one: on Linux
//! each worker listens on the shared address (SO_REUSEPORT); on macOS
//! and Windows, where bind_shared is Unbalanced, an accept thread hands
//! each connection to a worker's queue, round robin.

use super::{CAPACITY_MAX, Closed, Error, Push, Receiver, Sender, channel};
use crate::base::net::{self, Handoff, Io, Listener, Stream};
use crate::base::poll::{Instant, Interest, Poll, Ready, Waker};
use crate::base::thread::{Thread, Work, start};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use test::Bencher;

/// The worker threads of the server.
const WORKERS: usize = 4;
/// The keys of a loop's Poll: its queue's wakes, its listener, and its
/// connections by their index below these.
const WOKEN: u64 = 1 << 40;
const LISTENER: u64 = 1 << 41;
/// The reads one event gets at most, as libuv reads a stream 32 times:
/// a peer that sends as fast as it is read does not hold the loop.
const READS_MAX: usize = 32;
/// What a connection holds to write back at most: it reads no more
/// until its peer took some.
const PENDING_MAX: usize = 64 * 1024;
/// What each client sends, and gets back.
const MESSAGE: &[u8] = b"ping, and its pong";
/// The clients at once: macOS cuts a listen queue to 128.
const AT_ONCE: usize = 64;

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// The events of one poll, as (key, ready), into events.
fn gather(poll: &mut Poll, until: Instant, events: &mut Vec<(u64, Ready)>) {
    events.clear();
    for event in poll.poll(Some(until)) {
        events.push((event.key, event.ready));
    }
}

/// count connections accepted on a listener of their own, handed off;
/// and their clients, which keep them open.
fn handoffs(count: usize) -> (Vec<Handoff>, Vec<Stream>) {
    let mut poll = Poll::new().unwrap();
    let mut listener = Listener::bind(loopback(), 16).unwrap();
    listener.watch(&mut poll, Interest::Read, LISTENER).unwrap();
    let mut clients = Vec::new();
    let mut accepted = Vec::new();
    let end = Instant::now().after_ms(10_000);
    while accepted.len() < count {
        if clients.len() < count {
            clients.push(Stream::connect(listener.local().unwrap()).unwrap());
        }
        assert!(!end.reached_by(Instant::now()));
        poll.poll(Some(Instant::now().after_ms(10)));
        while let Some(handoff) = listener.accept_handoff().unwrap() {
            accepted.push(handoff);
        }
    }
    listener.close(&mut poll).unwrap();
    (accepted, clients)
}

/// A queue takes what its capacity holds and refuses the rest at once,
/// giving it back; pops come first in first out, with their tags; each
/// push wakes the receiver's Poll; Closed once every sender is gone and
/// the line is empty; a receiver gone refuses pushes. A capacity of 0
/// is refused.
#[test]
fn line() {
    assert!(matches!(
        channel(0, Poll::new().unwrap().waker(1)),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        channel(CAPACITY_MAX + 1, Poll::new().unwrap().waker(1)),
        Err(Error::Capacity)
    ));
    let mut poll = Poll::new().unwrap();
    let (sender, receiver) = channel(2, poll.waker(WOKEN)).unwrap();
    let (mut handoffs, _clients) = handoffs(3);
    let third = handoffs.pop().unwrap();
    for (tag, handoff) in handoffs.into_iter().enumerate() {
        assert!(sender.push(handoff, u64::try_from(tag).unwrap()).is_ok());
    }
    let refused = sender.push(third, 9);
    assert!(matches!(refused, Err(Push::Full(_, 9))));
    let woken = poll.poll(Some(Instant::now().after_ms(1000)));
    assert!(woken.len() == 1 && woken[0].key == WOKEN && woken[0].ready.woken());
    assert!(matches!(receiver.pop(), Ok(Some((_, 0)))));
    // rr: escape(copy): a second sender, which the queue counts.
    let other = sender.clone();
    drop(sender);
    assert!(matches!(receiver.pop(), Ok(Some((_, 1)))));
    assert!(matches!(receiver.pop(), Ok(None)));
    drop(other);
    assert_eq!(receiver.pop().err(), Some(Closed));
    let (lone, gone) = channel(1, poll.waker(WOKEN)).unwrap();
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
    let mut poll = Poll::new().unwrap();
    let (sender, receiver) = channel(4, poll.waker(WOKEN)).unwrap();
    let (mut handoffs, _clients) = handoffs(1);
    // rr: escape(shared): the waiting thread counts what it took.
    let taken = Arc::new(AtomicUsize::new(0));
    let thread = start(Box::new(Taker {
        receiver,
        // rr: escape(copy): the thread's holder of the count.
        taken: Arc::clone(&taken),
    }))
    .unwrap();
    assert!(sender.push_blocking(handoffs.pop().unwrap(), 5).is_ok());
    drop(sender);
    thread.join().unwrap();
    assert_eq!(taken.load(Ordering::Acquire), 1);
}

/// What a thread that may block takes from its queue.
struct Taker {
    receiver: Receiver,
    taken: Arc<AtomicUsize>,
}

impl Work for Taker {
    fn run(&mut self) {
        while let Ok((handoff, tag)) = self.receiver.pop_blocking() {
            assert_eq!(tag, 5);
            drop(handoff);
            self.taken.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// A connection a worker serves: its stream, while open, and what it
/// read and has not yet written back.
struct Connection {
    stream: Option<Stream>,
    pending: Vec<u8>,
}

/// A worker: its own Poll, its queue, on Linux its own listener on the
/// shared address, and the count of what it served.
struct Worker {
    /// Boxed, as it is some 200 bytes, so that the worker is small to
    /// move to its thread.
    poll: Box<Poll>,
    receiver: Receiver,
    listener: Option<Listener>,
    served: Arc<AtomicUsize>,
}

impl Work for Worker {
    fn run(&mut self) {
        serve(self);
    }
}

/// A worker's loop: connections from its queue or its listener, each
/// echoed back, until its queue is Closed and its last connection ends.
#[cfg_attr(rr, rr::poll)]
fn serve(worker: &mut Worker) {
    let poll = &mut worker.poll;
    if let Some(listener) = worker.listener.as_mut() {
        listener.watch(poll, Interest::Read, LISTENER).unwrap();
    }
    let mut connections: Vec<Connection> = Vec::new();
    let mut events = Vec::new();
    let mut buffer = [0u8; 4096];
    let (mut closed, mut live) = (false, 0usize);
    let end = Instant::now().after_ms(60_000);
    while !closed || live > 0 {
        assert!(!end.reached_by(Instant::now()), "{live} connections left");
        gather(poll, end, &mut events);
        for &(key, ready) in &events {
            let fresh = match key {
                WOKEN => adopt(&worker.receiver, &mut closed),
                LISTENER => accept(worker.listener.as_ref()),
                _ => {
                    let at = usize::try_from(key).unwrap();
                    live -= echo(poll, &mut connections[at], key, ready, &mut buffer);
                    Vec::new()
                }
            };
            for stream in fresh {
                live += 1;
                worker.served.fetch_add(1, Ordering::AcqRel);
                let at = connections.iter().position(|c| c.stream.is_none());
                let at = at.unwrap_or(connections.len());
                if at == connections.len() {
                    connections.push(Connection {
                        stream: None,
                        pending: Vec::new(),
                    });
                }
                let connection = &mut connections[at];
                connection.stream = Some(stream);
                connection.pending.clear();
                let watched = connection.stream.as_mut().unwrap();
                watched
                    .watch(poll, Interest::Read, u64::try_from(at).unwrap())
                    .unwrap();
            }
        }
    }
    if let Some(listener) = worker.listener.take() {
        listener.close(poll).unwrap();
    }
}

/// What the queue has, each made this thread's stream; closed once it
/// says Closed.
fn adopt(receiver: &Receiver, closed: &mut bool) -> Vec<Stream> {
    let mut fresh = Vec::new();
    // Each pop takes one off a line no longer than its capacity.
    loop {
        match receiver.pop() {
            Ok(Some((handoff, _))) => fresh.push(Stream::adopt(handoff)),
            Ok(None) => return fresh,
            Err(Closed) => {
                *closed = true;
                return fresh;
            }
        }
    }
}

/// What the listener has waiting, on Linux.
fn accept(listener: Option<&Listener>) -> Vec<Stream> {
    let mut fresh = Vec::new();
    if let Some(listener) = listener {
        while let Some((stream, _)) = listener.accept().unwrap() {
            fresh.push(stream);
        }
    }
    fresh
}

/// One event of a connection: up to READS_MAX reads, what was read
/// written back as the system takes it; 1 when the peer ended and the
/// connection closed.
fn echo(
    poll: &mut Poll,
    connection: &mut Connection,
    key: u64,
    ready: Ready,
    buffer: &mut [u8],
) -> usize {
    let Some(stream) = connection.stream.as_mut() else {
        return 0;
    };
    let mut ended = ready.error();
    for _ in 0..READS_MAX {
        if ended || !ready.to_read() || connection.pending.len() >= PENDING_MAX {
            break;
        }
        match stream.read(buffer) {
            Ok(Io::Done(0)) | Err(_) => ended = true,
            Ok(Io::Done(got)) => connection.pending.extend_from_slice(&buffer[..got]),
            Ok(Io::Blocked) => break,
        }
    }
    while !ended && !connection.pending.is_empty() {
        match stream.write(&connection.pending) {
            Ok(Io::Done(sent)) => drop(connection.pending.drain(..sent)),
            Ok(Io::Blocked) => break,
            Err(_) => ended = true,
        }
    }
    if ended {
        connection.stream.take().unwrap().close(poll).unwrap();
        return 1;
    }
    let interest = Interest::new(true, !connection.pending.is_empty());
    stream.watch(poll, interest, key).unwrap();
    0
}

/// The accept thread of macOS and Windows: its Poll, the listener, a
/// sender to each worker's queue, and what tells it to end.
struct Acceptor {
    /// Boxed, as the worker's.
    poll: Box<Poll>,
    listener: Listener,
    senders: Vec<Sender>,
    stop: Arc<AtomicBool>,
}

impl Work for Acceptor {
    fn run(&mut self) {
        hand_off(self);
    }
}

/// The accept thread's loop: each connection to the next worker, round
/// robin, or the one after when its queue is full; until told to end,
/// when the senders go with it and the workers' queues close.
#[cfg_attr(rr, rr::poll)]
fn hand_off(acceptor: &mut Acceptor) {
    let poll = &mut acceptor.poll;
    acceptor
        .listener
        .watch(poll, Interest::Read, LISTENER)
        .unwrap();
    let mut events = Vec::new();
    let mut next = 0usize;
    while !acceptor.stop.load(Ordering::Acquire) {
        gather(poll, Instant::now().after_ms(60_000), &mut events);
        while let Some(handoff) = acceptor.listener.accept_handoff().unwrap() {
            send(&acceptor.senders, &mut next, handoff);
        }
    }
}

/// Hands the connection to the next worker that has room; one none has
/// room for is dropped, which closes it.
fn send(senders: &[Sender], next: &mut usize, handoff: Handoff) {
    let mut item = handoff;
    for _ in 0..senders.len() {
        let at = *next % senders.len();
        *next = next.wrapping_add(1);
        match senders[at].push(item, 0) {
            Ok(()) => return,
            Err(Push::Full(back, _) | Push::Closed(back, _)) => item = back,
        }
    }
}

/// A server on WORKERS loops, and how it ends.
struct Server {
    address: SocketAddr,
    threads: Vec<Thread>,
    served: Vec<Arc<AtomicUsize>>,
    /// Linux: the senders, which end the workers when dropped.
    senders: Vec<Sender>,
    /// macOS and Windows: the accept thread's flag and Waker.
    acceptor: Option<(Arc<AtomicBool>, Waker)>,
}

/// Starts the server: each worker's Poll and queue made here and moved to
/// its thread; listeners that share the address where the system spreads
/// connections among them, else one listener on an accept thread.
fn server() -> Server {
    let shared = Listener::bind_shared(loopback(), 1024);
    let balanced = !matches!(shared, Err(net::Error::Unbalanced));
    let first = match shared {
        Ok(listener) => listener,
        Err(_) => Listener::bind(loopback(), 1024).unwrap(),
    };
    let address = first.local().unwrap();
    let mut listeners = Vec::from([first]);
    while balanced && listeners.len() < WORKERS {
        listeners.push(Listener::bind_shared(address, 1024).unwrap());
    }
    let mut server = Server {
        address,
        threads: Vec::new(),
        served: Vec::new(),
        senders: Vec::new(),
        acceptor: None,
    };
    for _ in 0..WORKERS {
        let mut poll = Poll::new().unwrap();
        let (sender, receiver) = channel(1024, poll.waker(WOKEN)).unwrap();
        // rr: escape(shared): the worker counts, the test reads.
        let served = Arc::new(AtomicUsize::new(0));
        let listener = if balanced { listeners.pop() } else { None };
        let worker = Box::new(Worker {
            poll: Box::new(poll),
            receiver,
            listener,
            // rr: escape(copy): the worker's holder of its count.
            served: Arc::clone(&served),
        });
        server.threads.push(start(worker).unwrap());
        server.served.push(served);
        server.senders.push(sender);
    }
    if !balanced {
        let mut poll = Poll::new().unwrap();
        let waker = poll.waker(WOKEN);
        // rr: escape(shared): the test tells the accept thread to end.
        let stop = Arc::new(AtomicBool::new(false));
        let acceptor = Box::new(Acceptor {
            poll: Box::new(poll),
            listener: listeners.pop().unwrap(),
            senders: core::mem::take(&mut server.senders),
            // rr: escape(copy): the accept thread's holder of the flag.
            stop: Arc::clone(&stop),
        });
        server.threads.push(start(acceptor).unwrap());
        server.acceptor = Some((stop, waker));
    }
    server
}

/// Ends the server and waits for its threads; what each worker served.
fn stop(server: Server) -> Vec<usize> {
    let Server {
        threads,
        served,
        senders,
        acceptor,
        ..
    } = server;
    drop(senders);
    if let Some((stop, waker)) = acceptor {
        stop.store(true, Ordering::Release);
        waker.wake();
    }
    for thread in threads {
        thread.join().unwrap();
    }
    // rr: escape(copy): the counts, for the test to read once the
    // workers are gone.
    served
        .iter()
        .map(|count| count.load(Ordering::Acquire))
        .collect()
}

/// A client: its stream while open, what it sent and got back.
struct Client {
    stream: Option<Stream>,
    sent: usize,
    got: usize,
}

/// count clients, AT_ONCE at a time, each of which sends MESSAGE, reads
/// it back whole and closes: the program's side of the server.
#[cfg_attr(rr, rr::poll)]
fn clients(poll: &mut Poll, address: SocketAddr, count: usize, events: &mut Vec<(u64, Ready)>) {
    let mut clients: Vec<Client> = Vec::new();
    let mut buffer = [0u8; 64];
    let mut finished = 0;
    let end = Instant::now().after_ms(60_000);
    while finished < count {
        while clients.len() < count && clients.len() - finished < AT_ONCE {
            let mut stream = Stream::connect(address).unwrap();
            let key = u64::try_from(clients.len()).unwrap();
            stream.watch(poll, Interest::Both, key).unwrap();
            clients.push(Client {
                stream: Some(stream),
                sent: 0,
                got: 0,
            });
        }
        assert!(!end.reached_by(Instant::now()), "{finished} of {count}");
        gather(poll, end, events);
        for &(key, ready) in events.iter() {
            let at = usize::try_from(key).unwrap();
            finished += talk(poll, &mut clients[at], key, ready, &mut buffer);
        }
    }
}

/// A client's turn; 1 when it got its message back, and closed.
fn talk(poll: &mut Poll, client: &mut Client, key: u64, ready: Ready, buffer: &mut [u8]) -> usize {
    let Some(stream) = client.stream.as_mut() else {
        return 0;
    };
    assert!(!ready.error(), "client {key}: {:?}", stream.connected());
    if ready.writable() && client.sent < MESSAGE.len() {
        if let Io::Done(sent) = stream.write(&MESSAGE[client.sent..]).unwrap() {
            client.sent += sent;
        }
        if client.sent == MESSAGE.len() {
            stream.watch(poll, Interest::Read, key).unwrap();
        }
    }
    while ready.to_read() {
        match stream.read(buffer).unwrap() {
            Io::Done(0) => panic!("client {key}: the server ended at {}", client.got),
            Io::Done(got) => {
                assert_eq!(&buffer[..got], &MESSAGE[client.got..client.got + got]);
                client.got += got;
            }
            Io::Blocked => break,
        }
        if client.got == MESSAGE.len() {
            // A reset, so that no port waits out TIME_WAIT: the bench
            // makes more connections than the system has ports.
            client.stream.take().unwrap().abort(poll).unwrap();
            return 1;
        }
    }
    0
}

/// Many connections to a server on WORKERS loops: every one is served,
/// and every worker served some, on each system's way to spread them.
#[test]
fn every_worker_serves() {
    assert!(net::descriptors(4096) >= 512);
    let server = server();
    let mut poll = Poll::new().unwrap();
    let mut events = Vec::new();
    clients(&mut poll, server.address, 400, &mut events);
    let served = stop(server);
    assert_eq!(served.iter().sum::<usize>(), 400, "served {served:?}");
    assert!(served.iter().all(|&count| count > 0), "served {served:?}");
}

/// Connections a second through the server: each turn, AT_ONCE clients
/// connect, send, read back and close; a second over the time a turn
/// takes, times AT_ONCE.
#[bench]
fn connections(b: &mut Bencher) {
    assert!(net::descriptors(4096) >= 512);
    let server = server();
    let mut poll = Poll::new().unwrap();
    let mut events = Vec::new();
    b.iter(|| clients(&mut poll, server.address, AT_ONCE, &mut events));
    let served = stop(server);
    assert!(served.iter().sum::<usize>() > 0);
}
