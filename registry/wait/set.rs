//! A Set: what one thread's loop waits on when it serves many
//! connections at once. Each descriptor (a socket on Windows) is added
//! with what the loop wants of it, reading or writing, and a key the
//! loop picks, such as the index of its connection; a token names the
//! entry until it is removed. Any entry, and a timer without a
//! descriptor, may hold a deadline on the system's monotonic clock.
//! wait sleeps until something is ready or the nearest deadline comes,
//! then says, by key, what is ready and which deadlines passed.
//!
//! Readiness is level-triggered on every system: an entry is reported
//! on each wait while its condition holds, so the loop may read or write
//! a part and come back. Interest in writing is for when there is
//! something to write: a socket is nearly always writable. Errors and
//! the peer's hangup come whatever the interest, and a report may be
//! spurious: a read or write that would block is not an error.
//!
//! A descriptor is removed before it is closed. One closed first is
//! dropped by the system; a new descriptor that gets its number is
//! then added as new, and the old token only lets go of its entry.
//!
//! A Set is one thread's; a Waker wakes it from another.

use super::sys::{self, Poller, Raw, Wake};
use super::{Fd, POLLIN, POLLOUT, Wait};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Interest and readiness: the entry can be read without blocking (or
/// a listener has a connection to accept), or written.
pub const READ: u8 = 1;
pub const WRITE: u8 = 2;
/// Readiness only: the peer hung up, and reads end once what it sent is
/// read; or an error is pending, which the next read or write returns.
pub const HUP: u8 = 4;
pub const ERROR: u8 = 8;
/// The entry's deadline passed; it is cleared until set again.
pub const EXPIRED: u8 = 16;
/// A Waker woke the Set.
pub const WOKEN: u8 = 32;

/// A point on the system's monotonic clock, in nanoseconds since a start
/// of the system's choosing: CLOCK_MONOTONIC on Linux, CLOCK_UPTIME_RAW
/// on macOS, QueryPerformanceCounter on Windows, as Rust's std reads it.
#[derive(Clone, Copy)]
pub struct Instant {
    ns: u64,
}

impl Instant {
    pub fn now() -> Instant {
        Instant {
            ns: sys::monotonic_ns(),
        }
    }

    /// ms milliseconds later.
    pub fn after_ms(self, ms: u64) -> Instant {
        Instant {
            ns: self.ns.saturating_add(ms.saturating_mul(1_000_000)),
        }
    }

    /// The nanoseconds from earlier to self; none when earlier is later.
    pub fn since(self, earlier: Instant) -> u64 {
        self.ns.saturating_sub(earlier.ns)
    }

    /// Whether self is not after other.
    pub fn reached_by(self, other: Instant) -> bool {
        self.ns <= other.ns
    }
}

/// An entry of a Set, until it is removed: a token of a removed entry
/// names nothing, even once its place is taken again.
#[derive(Clone, Copy)]
pub struct Token {
    index: u32,
    generation: u32,
}

/// What wait found of one entry: its key, and what is ready.
pub struct Event {
    pub key: u64,
    pub ready: u8,
}

/// An entry's place, kept while its entry lives and reused after.
struct Slot {
    /// Counts the entries that held the place: a token of another names
    /// nothing. Never 0, which names the waker to the system.
    generation: u32,
    live: bool,
    fd: Option<Raw>,
    /// The system watches fd for this entry: not once it was closed and
    /// another descriptor took its number.
    attached: bool,
    interest: u8,
    key: u64,
    deadline: Option<Instant>,
    /// The wait that reported the entry last, and where in its events.
    batch: u64,
    event: usize,
}

/// What a Waker wakes, from any thread.
pub struct Waker {
    wake: Arc<Wake>,
}

impl Clone for Waker {
    fn clone(&self) -> Waker {
        Waker {
            // rr: escape(copy): another thread's holder of the same waker.
            wake: Arc::clone(&self.wake),
        }
    }
}

impl Waker {
    /// Wakes the Set: its next wait, or the one it is in, returns with
    /// WOKEN. Wakes before that wait are one.
    pub fn wake(&self) {
        self.wake.wake();
    }
}

/// A component's entries in a Set, as its Wait says: its descriptors
/// and a timer for its timeout. follow keeps them in step.
pub struct Watch {
    fds: [Option<Token>; 2],
    timer: Option<Token>,
}

impl Watch {
    pub const NONE: Watch = Watch {
        fds: [None; 2],
        timer: None,
    };
}

pub struct Set {
    poller: Poller,
    // rr: escape(bound): one place for each entry the loop keeps, which
    // the descriptors it may open bound.
    slots: Vec<Slot>,
    // rr: escape(bound): no more places than slots.
    free: Vec<u32>,
    /// Which entry the system watches each descriptor for.
    // rr: escape(bound): one for each live entry with a descriptor.
    owners: BTreeMap<Raw, u32>,
    /// The deadlines, nearest first: when, and whose.
    // rr: escape(bound): one for each live entry with a deadline.
    deadlines: BTreeSet<(u64, u32)>,
    /// What the system reported at the last wait: a key, and readiness.
    found: Vec<(u64, u8)>,
    // rr: escape(bound): one for each entry, at most.
    events: Vec<Event>,
    batch: u64,
    /// The key wakes are reported with.
    woken: u64,
}

impl Set {
    pub fn new() -> Option<Set> {
        Poller::new().map(Set::with)
    }

    /// A Set on the system's portable way, where it has another: WSAPoll
    /// on Windows, where Set::new takes socket notifications.
    #[cfg(all(test, target_os = "windows"))]
    pub fn polled() -> Option<Set> {
        Poller::polled().map(Set::with)
    }

    fn with(poller: Poller) -> Set {
        Set {
            poller,
            slots: Vec::new(),
            free: Vec::new(),
            owners: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            found: Vec::new(),
            events: Vec::new(),
            batch: 0,
            woken: 0,
        }
    }

    /// Watches fd for interest (READ, WRITE, both or none), reported
    /// with key. None when the system refuses it.
    pub fn add(&mut self, fd: Raw, interest: u8, key: u64) -> Option<Token> {
        let token = self.place(Some(fd), interest, key)?;
        if let Some(other) = self.owners.get(&fd).copied() {
            // Closed without being removed, its number taken by fd: the
            // system dropped the old entry, or drops it now.
            self.detach(other);
        }
        if !self.poller.add(fd, token_key(token), interest) {
            self.release(token.index);
            return None;
        }
        self.owners.insert(fd, token.index);
        Some(token)
    }

    /// A timer: an entry without a descriptor, for a deadline alone.
    pub fn timer(&mut self, key: u64) -> Option<Token> {
        self.place(None, 0, key)
    }

    /// Changes what the entry waits for; false when the system refuses.
    pub fn modify(&mut self, token: Token, interest: u8) -> bool {
        let Some(slot) = self.slot_mut(token) else {
            return false;
        };
        let (fd, old, attached) = (slot.fd, slot.interest, slot.attached);
        slot.interest = interest;
        let Some(fd) = fd else {
            return true;
        };
        if !attached || old == interest {
            return true;
        }
        self.poller.modify(fd, token_key(token), old, interest)
    }

    /// Sets or clears the entry's deadline. Once it passes, wait reports
    /// EXPIRED for the entry and clears it.
    pub fn deadline(&mut self, token: Token, at: Option<Instant>) {
        let Some(slot) = self.slot_mut(token) else {
            return;
        };
        let old = slot.deadline;
        slot.deadline = at;
        if let Some(old) = old {
            self.deadlines.remove(&(old.ns, token.index));
        }
        if let Some(at) = at {
            self.deadlines.insert((at.ns, token.index));
        }
    }

    /// Removes the entry, before its descriptor is closed; its token
    /// then names nothing.
    pub fn remove(&mut self, token: Token) {
        if self.slot_mut(token).is_none() {
            return;
        }
        self.deadline(token, None);
        self.detach(token.index);
        self.release(token.index);
    }

    /// What wakes this Set from another thread; its wakes are reported
    /// with key.
    pub fn waker(&mut self, key: u64) -> Waker {
        self.woken = key;
        Waker {
            wake: self.poller.waker(),
        }
    }

    /// Waits until an entry is ready, a deadline passes, a Waker wakes
    /// the Set or until comes, and says what happened: one event for
    /// each entry, its readiness and EXPIRED together. Empty when until
    /// came first, or on a spurious wake.
    pub fn wait(&mut self, until: Option<Instant>) -> &[Event] {
        self.events.clear();
        self.batch = self.batch.wrapping_add(1);
        let now = Instant::now();
        let nearest = self.deadlines.first().map(|&(ns, _)| Instant { ns });
        let next = match (nearest, until) {
            (Some(a), Some(b)) => Some(if a.reached_by(b) { a } else { b }),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };
        let timeout = next.map(|at| at.since(now));
        self.found.clear();
        self.poller.wait(timeout, &mut self.found);
        let mut woken = false;
        for at in 0..self.found.len() {
            let Some(&(key, ready)) = self.found.get(at) else {
                break;
            };
            match key {
                // A completion port keeps a packet for each wake.
                0 if woken => {}
                0 => {
                    woken = true;
                    self.events.push(Event {
                        key: self.woken,
                        ready: WOKEN,
                    });
                }
                _ => self.found_ready(key, ready),
            }
        }
        self.expire(Instant::now());
        &self.events
    }

    /// Keeps watch's entries as wait says: its descriptors, reported
    /// with key, and its timeout as a deadline (READY's, none, is due
    /// now). false when the system refused a descriptor. Its entries are
    /// unfollowed before the component goes, which closes them.
    pub fn follow(&mut self, watch: &mut Watch, wait: &Wait, key: u64) -> bool {
        let mut added = true;
        for (at, fd) in wait.fds.iter().enumerate() {
            let wanted = (at < wait.count && fd.fd != Fd::NONE.fd).then(|| (fd.fd, interest(fd)));
            let Some(place) = watch.fds.get_mut(at) else {
                break;
            };
            added &= self.keep(place, wanted, key);
        }
        if watch.timer.is_none() {
            watch.timer = self.timer(key);
        }
        if let Some(timer) = watch.timer {
            let at = wait.timeout_ms.map(|ms| Instant::now().after_ms(ms));
            self.deadline(timer, at);
        }
        added
    }

    /// Removes watch's entries, before the component closes them.
    pub fn unfollow(&mut self, watch: &mut Watch) {
        for place in &mut watch.fds {
            if let Some(token) = place.take() {
                self.remove(token);
            }
        }
        if let Some(timer) = watch.timer.take() {
            self.remove(timer);
        }
    }

    /// One of a watch's descriptors as wanted: added, changed, moved to
    /// another descriptor or removed.
    fn keep(&mut self, place: &mut Option<Token>, wanted: Option<(Raw, u8)>, key: u64) -> bool {
        let current = place.and_then(|token| Some((token, self.slot_mut(token)?.fd?)));
        match (current, wanted) {
            (Some((token, fd)), Some((want, interest))) if fd == want => {
                self.modify(token, interest)
            }
            (current, wanted) => {
                if let Some((token, _)) = current {
                    self.remove(token);
                }
                *place = None;
                let Some((fd, interest)) = wanted else {
                    return true;
                };
                *place = self.add(fd, interest, key);
                place.is_some()
            }
        }
    }

    /// A place for a new entry.
    fn place(&mut self, fd: Option<Raw>, interest: u8, key: u64) -> Option<Token> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                let index = u32::try_from(self.slots.len()).ok()?;
                self.slots.push(Slot {
                    generation: 1,
                    live: false,
                    fd: None,
                    attached: false,
                    interest: 0,
                    key: 0,
                    deadline: None,
                    batch: 0,
                    event: 0,
                });
                index
            }
        };
        let slot = self.slots.get_mut(usize::try_from(index).ok()?)?;
        slot.live = true;
        slot.fd = fd;
        slot.attached = fd.is_some();
        slot.interest = interest;
        slot.key = key;
        slot.deadline = None;
        Some(Token {
            index,
            generation: slot.generation,
        })
    }

    /// Frees the place: the next entry there has another generation.
    fn release(&mut self, index: u32) {
        let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
        else {
            return;
        };
        slot.live = false;
        slot.fd = None;
        slot.attached = false;
        slot.generation = match slot.generation.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        self.free.push(index);
    }

    /// The system stops watching the entry's descriptor.
    fn detach(&mut self, index: u32) {
        let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
        else {
            return;
        };
        let (Some(fd), true) = (slot.fd, slot.attached) else {
            return;
        };
        slot.attached = false;
        let key = token_key(Token {
            index,
            generation: slot.generation,
        });
        let interest = slot.interest;
        if self.owners.get(&fd) == Some(&index) {
            self.owners.remove(&fd);
        }
        self.poller.remove(fd, key, interest);
    }

    fn slot_mut(&mut self, token: Token) -> Option<&mut Slot> {
        let slot = self.slots.get_mut(usize::try_from(token.index).ok()?)?;
        (slot.live && slot.generation == token.generation).then_some(slot)
    }

    /// What the system reported for key: dropped when its entry is gone
    /// or no longer watched.
    fn found_ready(&mut self, key: u64, ready: u8) {
        let token = Token {
            index: u32::try_from(key & u64::from(u32::MAX)).unwrap_or(u32::MAX),
            generation: u32::try_from(key >> 32).unwrap_or(0),
        };
        let attached = self.slot_mut(token).is_some_and(|slot| slot.attached);
        if attached {
            self.report(token.index, ready);
        }
    }

    /// The deadlines due by now: reported, and cleared.
    fn expire(&mut self, now: Instant) {
        while let Some(&(ns, index)) = self.deadlines.first() {
            if now.ns < ns {
                break;
            }
            self.deadlines.remove(&(ns, index));
            if let Some(slot) = usize::try_from(index)
                .ok()
                .and_then(|at| self.slots.get_mut(at))
            {
                slot.deadline = None;
            }
            self.report(index, EXPIRED);
        }
    }

    /// Adds ready to the entry's event of this wait, or makes it one.
    fn report(&mut self, index: u32, ready: u8) {
        let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
        else {
            return;
        };
        if slot.batch == self.batch {
            if let Some(event) = self.events.get_mut(slot.event) {
                event.ready |= ready;
            }
            return;
        }
        slot.batch = self.batch;
        slot.event = self.events.len();
        self.events.push(Event {
            key: slot.key,
            ready,
        });
    }
}

/// How the system names an entry: its generation, never 0, then its
/// index; 0 names the waker.
fn token_key(token: Token) -> u64 {
    (u64::from(token.generation) << 32) | u64::from(token.index)
}

/// The interest a component's descriptor states in poll's events.
fn interest(fd: &Fd) -> u8 {
    let read = if fd.events & POLLIN != 0 { READ } else { 0 };
    let write = if fd.events & POLLOUT != 0 { WRITE } else { 0 };
    read | write
}

#[cfg(test)]
mod tests {
    use super::super::sys::net::{self, Io};
    use super::super::{Raw, Signal, Wait};
    use super::{ERROR, EXPIRED, HUP, Instant, READ, Set, Token, WOKEN, WRITE, Watch};
    use alloc::vec::Vec;
    use test::Bencher;

    /// Every way the system has to wait: on Windows, socket notifications
    /// and WSAPoll both.
    fn sets() -> Vec<Set> {
        #[cfg(target_os = "windows")]
        return Vec::from([Set::new().unwrap(), Set::polled().unwrap()]);
        #[cfg(not(target_os = "windows"))]
        return Vec::from([Set::new().unwrap()]);
    }

    /// The events of one wait, as (key, ready).
    fn wait(set: &mut Set, until: Instant) -> Vec<(u64, u8)> {
        // rr: escape(copy): the test reads the events while it changes
        // the Set.
        set.wait(Some(until))
            .iter()
            .map(|event| (event.key, event.ready))
            .collect()
    }

    /// Waits up to ten seconds for key with any of want; its readiness.
    fn until(set: &mut Set, key: u64, want: u8) -> u8 {
        let end = Instant::now().after_ms(10_000);
        loop {
            for (found, ready) in wait(set, end) {
                if found == key && ready & want != 0 {
                    return ready;
                }
            }
            assert!(!end.reached_by(Instant::now()), "nothing for key {key}");
        }
    }

    /// Waits ms milliseconds, and checks that key was not reported with
    /// any of these.
    fn quiet(set: &mut Set, key: u64, these: u8, ms: u64) {
        let end = Instant::now().after_ms(ms);
        while !end.reached_by(Instant::now()) {
            for (found, ready) in wait(set, end) {
                assert!(
                    found != key || ready & these == 0,
                    "key {key} reported {ready}"
                );
            }
        }
    }

    /// A connection: the client's socket and the server's.
    fn pair(set: &mut Set) -> (Raw, Raw) {
        let (listener, port) = net::listener();
        let client = net::dial(port).unwrap();
        let token = set.add(listener, READ, u64::MAX).unwrap();
        until(set, u64::MAX, READ);
        let server = net::take(listener).unwrap();
        set.remove(token);
        net::close(listener);
        (client, server)
    }

    /// What each client sends and gets back: its seed's bytes.
    const SIZE: usize = 32 * 1024;
    const LISTENER: u64 = 1;
    const SERVER: u64 = 2 << 32;
    const CLIENT: u64 = 3 << 32;
    const INDEX: u64 = 0xFFFF_FFFF;

    fn byte(seed: usize, at: usize) -> u8 {
        u8::try_from((seed * 31 + at * 7) % 251).unwrap()
    }

    struct Client {
        fd: Raw,
        token: Token,
        sent: usize,
        got: usize,
        done: bool,
    }

    struct Peer {
        fd: Raw,
        token: Token,
        pending: Vec<u8>,
        ended: bool,
        closed: bool,
    }

    /// Hundreds of clients and their server in one loop: each client
    /// sends 32 KiB in whatever pieces the system takes, the server sends
    /// back what it reads as it can, and the client checks every byte;
    /// the server sees each client's end and closes.
    #[test]
    fn echo_many() {
        let files = net::files(4096);
        let count = usize::try_from(files.saturating_sub(64) / 2)
            .unwrap()
            .min(500);
        assert!(count >= 100, "only {files} descriptors");
        for mut set in sets() {
            echo(&mut set, count);
        }
    }

    fn echo(set: &mut Set, count: usize) {
        let (listener, port) = net::listener();
        let listening = set.add(listener, READ, LISTENER).unwrap();
        let mut clients: Vec<Client> = Vec::new();
        let mut peers: Vec<Peer> = Vec::new();
        let (mut finished, mut closed) = (0, 0);
        let mut buffer = [0u8; 16 * 1024];
        let end = Instant::now().after_ms(60_000);
        while finished < count || closed < count {
            // 64 clients at most at a time: macOS caps a listen queue at
            // 128.
            while clients.len() < count && clients.len() - finished < 64 {
                let fd = net::dial(port).unwrap();
                let key = CLIENT | u64::try_from(clients.len()).unwrap();
                let token = set.add(fd, READ | WRITE, key).unwrap();
                clients.push(Client {
                    fd,
                    token,
                    sent: 0,
                    got: 0,
                    done: false,
                });
            }
            let now = Instant::now();
            assert!(
                !end.reached_by(now),
                "{finished} of {count} done, {closed} closed"
            );
            for (key, ready) in wait(set, end) {
                let index = usize::try_from(key & INDEX).unwrap();
                match key & !INDEX {
                    0 => {
                        while let Some(fd) = net::take(listener) {
                            let peer_key = SERVER | u64::try_from(peers.len()).unwrap();
                            let token = set.add(fd, READ, peer_key).unwrap();
                            peers.push(Peer {
                                fd,
                                token,
                                pending: Vec::new(),
                                ended: false,
                                closed: false,
                            });
                        }
                    }
                    SERVER => closed += serve(set, &mut peers[index], ready, &mut buffer),
                    CLIENT => finished += talk(set, &mut clients[index], index, ready, &mut buffer),
                    _ => panic!("key {key}"),
                }
            }
        }
        set.remove(listening);
        net::close(listener);
    }

    /// A client's turn: send what the system takes, check what came
    /// back; 1 when it got all of it back, and closed.
    fn talk(
        set: &mut Set,
        client: &mut Client,
        seed: usize,
        ready: u8,
        buffer: &mut [u8],
    ) -> usize {
        if client.done {
            return 0;
        }
        assert_eq!(ready & ERROR, 0, "client {seed}: {}", net::error(client.fd));
        while ready & WRITE != 0 && client.sent < SIZE {
            let piece = buffer.len().min(SIZE - client.sent);
            for (at, slot) in buffer[..piece].iter_mut().enumerate() {
                *slot = byte(seed, client.sent + at);
            }
            match net::write(client.fd, &buffer[..piece]) {
                Io::Done(sent) => client.sent += sent,
                Io::Blocked => break,
                Io::Failed(error) => panic!("client {seed} sending: {error}"),
            }
            if client.sent == SIZE {
                assert!(set.modify(client.token, READ));
            }
        }
        if ready & (READ | HUP) == 0 {
            return 0;
        }
        loop {
            match net::read(client.fd, buffer) {
                Io::Done(0) => panic!("client {seed}: the server ended at {}", client.got),
                Io::Done(got) => {
                    for (at, &byte_got) in buffer[..got].iter().enumerate() {
                        assert_eq!(byte_got, byte(seed, client.got + at), "client {seed}");
                    }
                    client.got += got;
                }
                Io::Blocked => return 0,
                Io::Failed(error) => panic!("client {seed} receiving: {error}"),
            }
            if client.got == SIZE {
                set.remove(client.token);
                net::close(client.fd);
                client.done = true;
                return 1;
            }
        }
    }

    /// The server's turn for one client: read while there is room, send
    /// back what it can, watch for what is left; 1 when the client ended
    /// and all went back, and closed.
    fn serve(set: &mut Set, peer: &mut Peer, ready: u8, buffer: &mut [u8]) -> usize {
        if peer.closed {
            return 0;
        }
        assert_eq!(ready & ERROR, 0, "server: {}", net::error(peer.fd));
        while ready & (READ | HUP) != 0 && !peer.ended && peer.pending.len() < 256 * 1024 {
            match net::read(peer.fd, buffer) {
                Io::Done(0) => peer.ended = true,
                Io::Done(got) => peer.pending.extend_from_slice(&buffer[..got]),
                Io::Blocked => break,
                Io::Failed(error) => panic!("server receiving: {error}"),
            }
        }
        while !peer.pending.is_empty() {
            match net::write(peer.fd, &peer.pending) {
                Io::Done(sent) => drop(peer.pending.drain(..sent)),
                Io::Blocked => break,
                Io::Failed(error) => panic!("server sending: {error}"),
            }
        }
        if peer.ended && peer.pending.is_empty() {
            set.remove(peer.token);
            net::close(peer.fd);
            peer.closed = true;
            return 1;
        }
        let read = if peer.ended { 0 } else { READ };
        let write = if peer.pending.is_empty() { 0 } else { WRITE };
        assert!(set.modify(peer.token, read | write));
        0
    }

    /// A writer fills what the system takes until it blocks; the reader
    /// then drains it, and the writer is told when it may go on, to the
    /// last of 8 MiB, which arrive whole and in order.
    #[test]
    fn backpressure() {
        let mut chunk = Vec::new();
        chunk.resize(64 * 1024, 0u8);
        for mut set in sets() {
            let (client, server) = pair(&mut set);
            let total = 8 << 20;
            let (mut sent, mut got) = (0, 0);
            let mut blocked = false;
            while !blocked && sent < 1 << 30 {
                for (at, slot) in chunk.iter_mut().enumerate() {
                    *slot = byte(1, sent + at);
                }
                match net::write(client, &chunk) {
                    Io::Done(count) => sent += count,
                    Io::Blocked => blocked = true,
                    Io::Failed(error) => panic!("sending: {error}"),
                }
            }
            assert!(blocked, "sent {sent} without blocking");
            let total = total.max(sent + 1);
            let writer = set.add(client, WRITE, 1).unwrap();
            let reader = set.add(server, READ, 2).unwrap();
            let end = Instant::now().after_ms(30_000);
            while got < total {
                assert!(!end.reached_by(Instant::now()), "got {got} of {total}");
                for (key, ready) in wait(&mut set, end) {
                    if key == 2 && ready & READ != 0 {
                        while let Io::Done(count) = net::read(server, &mut chunk) {
                            assert!(count > 0, "ended at {got}");
                            for (at, &found) in chunk[..count].iter().enumerate() {
                                assert_eq!(found, byte(1, got + at));
                            }
                            got += count;
                        }
                    }
                    if key == 1 && ready & WRITE != 0 && sent < total {
                        let piece = chunk.len().min(total - sent);
                        for (at, slot) in chunk[..piece].iter_mut().enumerate() {
                            *slot = byte(1, sent + at);
                        }
                        if let Io::Done(count) = net::write(client, &chunk[..piece]) {
                            sent += count;
                        }
                        if sent == total {
                            assert!(set.modify(writer, 0));
                        }
                    }
                }
            }
            set.remove(writer);
            set.remove(reader);
            net::close(client);
            net::close(server);
        }
    }

    /// A connection to a port nobody listens on fails, and the Set says
    /// so: the case WSAPoll missed before Windows 10 2004.
    #[test]
    fn refused() {
        for mut set in sets() {
            let (listener, port) = net::listener();
            net::close(listener);
            match net::dial(port) {
                Err(error) => assert_eq!(error, net::REFUSED),
                Ok(fd) => {
                    let token = set.add(fd, READ | WRITE, 1).unwrap();
                    until(&mut set, 1, ERROR | HUP);
                    assert_eq!(net::error(fd), net::REFUSED);
                    set.remove(token);
                    net::close(fd);
                }
            }
        }
    }

    /// The peer's close reads as the end; its reset as an error.
    #[test]
    fn hangup() {
        for mut set in sets() {
            let (client, server) = pair(&mut set);
            let token = set.add(client, READ, 1).unwrap();
            net::close(server);
            until(&mut set, 1, READ | HUP);
            assert_eq!(net::read(client, &mut [0; 8]), Io::Done(0));
            set.remove(token);
            net::close(client);

            let (reset_client, reset_server) = pair(&mut set);
            let reset_token = set.add(reset_client, READ, 2).unwrap();
            net::reset(reset_server);
            until(&mut set, 2, READ | HUP | ERROR);
            assert_eq!(net::read(reset_client, &mut [0; 8]), Io::Failed(net::RESET));
            set.remove(reset_token);
            net::close(reset_client);
        }
    }

    /// Interest is what is reported: none, then writing alone, changed
    /// while the system still watches for the old; then reading, until
    /// there is nothing left to read.
    #[test]
    fn interest() {
        for mut set in sets() {
            let (client, server) = pair(&mut set);
            let token = set.add(client, 0, 1).unwrap();
            assert_eq!(net::write(server, b"x"), Io::Done(1));
            quiet(&mut set, 1, READ | WRITE, 50);
            assert!(set.modify(token, WRITE));
            assert_eq!(until(&mut set, 1, WRITE) & READ, 0);
            assert!(set.modify(token, READ));
            until(&mut set, 1, READ);
            assert_eq!(net::read(client, &mut [0; 8]), Io::Done(1));
            quiet(&mut set, 1, READ | WRITE, 50);
            set.remove(token);
            net::close(client);
            net::close(server);
        }
    }

    /// A removed entry's token names nothing, even once a new socket
    /// takes its number and its place in the Set.
    #[test]
    fn stale_token() {
        for mut set in sets() {
            let (client, server) = pair(&mut set);
            let old = set.add(client, READ, 1).unwrap();
            assert_eq!(net::write(server, b"x"), Io::Done(1));
            until(&mut set, 1, READ);
            set.remove(old);
            net::close(client);
            net::close(server);
            let (new_client, new_server) = pair(&mut set);
            let new = set.add(new_client, READ, 2).unwrap();
            assert!(!set.modify(old, READ | WRITE));
            set.deadline(old, Some(Instant::now()));
            set.remove(old);
            assert_eq!(net::write(new_server, b"y"), Io::Done(1));
            until(&mut set, 2, READ);
            quiet(&mut set, 1, u8::MAX, 30);
            set.remove(new);
            net::close(new_client);
            net::close(new_server);
        }
    }

    /// A socket closed before its entry is removed: a new one with its
    /// number is watched for itself, and removing the old entry does not
    /// take the new one's watch away.
    #[test]
    fn closed_before_removed() {
        closed_first(&mut Set::new().unwrap());
    }

    /// As closed_before_removed, on WSAPoll.
    #[cfg(target_os = "windows")]
    #[test]
    fn closed_before_removed_polled() {
        closed_first(&mut Set::polled().unwrap());
    }

    fn closed_first(set: &mut Set) {
        let (old_client, old_server) = pair(set);
        let old = set.add(old_client, READ, 1).unwrap();
        net::close(old_client);
        let (client, server) = pair(set);
        let new = set.add(client, READ, 2).unwrap();
        set.remove(old);
        assert_eq!(net::write(server, b"z"), Io::Done(1));
        until(set, 2, READ);
        quiet(set, 1, u8::MAX, 30);
        set.remove(new);
        net::close(client);
        net::close(server);
        net::close(old_server);
    }

    /// Timers: each deadline that stands is reported once, never before
    /// it, nearest first; cleared, moved and removed ones as they were
    /// left. A wait with nothing to report returns empty.
    #[test]
    fn deadlines() {
        let mut set = Set::new().unwrap();
        let start = Instant::now();
        assert!(set.wait(Some(start.after_ms(20))).is_empty());
        let mut tokens = Vec::new();
        let mut due = Vec::new();
        for key in 0..200u64 {
            let token = set.timer(key).unwrap();
            let at = start.after_ms(30 + key * 37 % 97);
            set.deadline(token, Some(at));
            tokens.push(token);
            due.push(Some(at));
        }
        for key in (0..200).step_by(10) {
            set.deadline(tokens[key], None);
            due[key] = None;
        }
        for key in (3..200).step_by(7) {
            let later = start.after_ms(150 + u64::try_from(key % 50).unwrap());
            set.deadline(tokens[key], Some(later));
            due[key] = Some(later);
        }
        for key in (5..200).step_by(13) {
            set.remove(tokens[key]);
            due[key] = None;
        }
        let mut fired: Vec<(usize, Instant)> = Vec::new();
        let end = start.after_ms(400);
        while !end.reached_by(Instant::now()) {
            for (key, ready) in wait(&mut set, end) {
                assert_eq!(ready, EXPIRED);
                fired.push((usize::try_from(key).unwrap(), Instant::now()));
            }
        }
        let standing = due.iter().filter(|at| at.is_some()).count();
        assert_eq!(fired.len(), standing);
        for &(key, at) in &fired {
            assert!(due[key].unwrap().reached_by(at), "timer {key} early");
        }
        for pair in fired.windows(2) {
            let (first, second) = (due[pair[0].0].unwrap(), due[pair[1].0].unwrap());
            assert!(
                first.reached_by(second),
                "timers {} and {} out of order",
                pair[0].0,
                pair[1].0
            );
        }
    }

    /// A component's Wait in a Set: READY is due at once, a descriptor
    /// is reported when ready, a timeout alone takes the descriptor's
    /// place.
    #[test]
    fn follows_a_wait() {
        for mut set in sets() {
            let mut watch = Watch::NONE;
            assert!(set.follow(&mut watch, &Wait::READY, 5));
            until(&mut set, 5, EXPIRED);
            let signal = Signal::new().unwrap();
            assert!(set.follow(&mut watch, &signal.wait(), 5));
            quiet(&mut set, 5, u8::MAX, 30);
            signal.set();
            until(&mut set, 5, READ);
            let mut timed = Wait::READY;
            timed.timeout_ms = Some(20);
            assert!(set.follow(&mut watch, &timed, 5));
            assert_eq!(until(&mut set, 5, EXPIRED) & READ, 0);
            set.unfollow(&mut watch);
            quiet(&mut set, 5, u8::MAX, 30);
        }
    }

    /// Wakes from this thread before a wait are one event, and a woken
    /// Set is quiet again; another thread's wake is in sys's tests.
    #[test]
    fn wakes_once() {
        for mut set in sets() {
            let waker = set.waker(9);
            waker.wake();
            waker.wake();
            let woken = wait(&mut set, Instant::now().after_ms(1000));
            assert_eq!(woken, Vec::from([(9, WOKEN)]));
            quiet(&mut set, 9, u8::MAX, 30);
        }
    }

    /// A thousand connections, all idle but one, which gets a byte: a
    /// wait and a read for each, as a server with many idle clients
    /// pays for each request.
    #[bench]
    fn one_of_a_thousand(b: &mut Bencher) {
        assert!(net::files(4096) >= 2100);
        let mut set = Set::new().unwrap();
        let mut pairs = Vec::new();
        for key in 0..1000u64 {
            let (client, server) = pair(&mut set);
            let token = set.add(server, READ, key).unwrap();
            pairs.push((client, server, token));
        }
        let (writer, reader, _) = pairs[500];
        let mut byte = [0u8; 1];
        b.iter(|| {
            assert_eq!(net::write(writer, b"x"), Io::Done(1));
            loop {
                let ready = set.wait(None);
                if ready.iter().any(|event| event.key == 500) {
                    break;
                }
            }
            assert_eq!(net::read(reader, &mut byte), Io::Done(1));
        });
        for (client, server, token) in pairs {
            set.remove(token);
            net::close(client);
            net::close(server);
        }
    }
}
