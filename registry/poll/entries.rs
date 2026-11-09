//! A Poll: what one thread's loop waits on when it serves many
//! connections at once. Each descriptor (a socket on Windows) is added
//! with what the loop wants of it, reading or writing, and a key the
//! loop picks, such as the index of its connection; a token names the
//! entry until it is removed. Any entry, and a timer without a
//! descriptor, may hold a deadline on the system's monotonic clock.
//! poll sleeps until something is ready or the nearest deadline comes,
//! then says, by key, what is ready and which deadlines passed: the loop
//! dispatches each event by its key, as with mio, and no callback runs.
//!
//! Readiness is level-triggered on every system: an entry is reported
//! on each poll while its condition holds, so the loop may read or write
//! a part and come back. That is how a loop stays fair: it bounds what it
//! does for one event, as libuv reads and writes a stream at most 32
//! times for each (uv__read, uv__write), and what is left is reported
//! again at the next poll, after every other connection had its turn.
//! One that reads until the socket is empty lets a peer that sends as
//! fast as it reads hold the loop. What is reported is what the entry's Interest
//! asks, the same on every system (Ready says what each condition
//! means): errors with any interest, the peer's hangup with reading; an
//! entry with Interest::None is not watched at all, as when the loop
//! stops reading to let a slow peer catch up, and what happened to it
//! shows when it has one again, or at its next read or write. Only its
//! deadline still counts. A report may be spurious: a read or write that
//! would block is not an error.
//!
//! Every call that names an entry says when it is refused (PollError): a
//! token is its own Poll's, and names its entry until that is removed; a
//! token of another Poll, or of an entry gone, is refused, never read as
//! another entry.
//!
//! One poll reports at most 256 descriptors (all on WSAPoll); the rest,
//! still ready, the next. Deadlines are never reported early, and may be
//! late by what the system's wait counts in: on Linux and Windows a
//! timeout is whole milliseconds, rounded up, and Windows wakes on its
//! timer's tick, 15.6 ms unless the program asked for a finer one. A
//! deadline moved a little later costs nothing (deadline says how).
//!
//! A descriptor is in a Poll once, and is removed before it is closed,
//! so that nothing the system still holds of it is reported for the
//! descriptor that takes its number next. A component that owns its
//! descriptors (net) adds them with add_owned: its Owned entry is taken
//! out by close alone, which closes the descriptor once, and remove
//! refuses its token, which the component lends for deadlines. add refuses
//! one the system still watches for its entry, as Linux's epoll refuses
//! it, on every system: one added twice. One closed first is dropped by
//! the system, and its entry stays, with its deadline, until it is
//! removed or a new descriptor gets its number: that one is added as
//! new, the old entry goes, and its token names nothing; what the system
//! had queued for the old one may then be reported for it once, as a
//! spurious report. The system watches an entry only while it has an
//! interest, and WSAPoll watches a socket only by the handle the Poll
//! hands it: an entry with none, or any on WSAPoll, the system cannot
//! tell from a closed one, and a descriptor added again takes its place
//! as a new one does. On Linux that holds only when the closed
//! descriptor was the last open on its socket: epoll watches the socket,
//! not the number, so after dup or fork another descriptor keeps it
//! watched, and its events come back on every wait for an entry the Poll
//! no longer reports.
//!
//! A Poll is one thread's at a time: it may be made on one and moved to
//! another before it runs there, as thread::start's worker loops are; a
//! Waker wakes it from any other.

use super::sys::{self, Poller, Raw, Wake};
use super::{Fd, POLLIN, POLLOUT, Want};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

/// What the system reports, as bits: the pollers' own, which Ready
/// carries out of the Poll.
pub(super) const READ: u8 = 1;
pub(super) const WRITE: u8 = 2;
pub(super) const HUP: u8 = 4;
pub(super) const ERROR: u8 = 8;
const EXPIRED: u8 = 16;
const WOKEN: u8 = 32;

/// What the loop wants of an entry: to read (or, for a listener, to
/// accept), to write, both, or nothing for now. Interest in writing is
/// for when there is something to write: a socket is nearly always
/// writable.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Interest {
    /// Not watched: only the entry's deadline counts.
    None,
    Read,
    Write,
    Both,
}

impl Interest {
    /// Read, Write, Both or None, as read and write say.
    pub fn new(read: bool, write: bool) -> Interest {
        match (read, write) {
            (false, false) => Interest::None,
            (true, false) => Interest::Read,
            (false, true) => Interest::Write,
            (true, true) => Interest::Both,
        }
    }

    pub fn reads(self) -> bool {
        matches!(self, Interest::Read | Interest::Both)
    }

    pub fn writes(self) -> bool {
        matches!(self, Interest::Write | Interest::Both)
    }

    /// As the pollers take it.
    fn bits(self) -> u8 {
        match self {
            Interest::None => 0,
            Interest::Read => READ,
            Interest::Write => WRITE,
            Interest::Both => READ | WRITE,
        }
    }
}

/// What poll found of an entry, the same on every system:
///
/// - readable: it can be read without blocking, or a listener has a
///   connection to accept; reported with an interest in reading;
/// - writable: reported with an interest in writing;
/// - hangup: the peer finished or is gone, and reads end once what it
///   sent is read; reported with an interest in reading only. With an
///   interest in writing alone, a hangup the system reports shows as
///   writable: the write says what became of the peer;
/// - error: an error is pending, which the next read or write returns;
///   reported with any interest;
/// - expired: the entry's deadline passed; it is cleared until set again;
/// - woken: a Waker woke the Poll.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Ready(u8);

impl Ready {
    pub const READABLE: Ready = Ready(READ);
    pub const WRITABLE: Ready = Ready(WRITE);
    pub const HANGUP: Ready = Ready(HUP);
    pub const ERROR: Ready = Ready(ERROR);
    pub const EXPIRED: Ready = Ready(EXPIRED);
    pub const WOKEN: Ready = Ready(WOKEN);
    /// Every condition: for a test of anything at all.
    pub const ANY: Ready = Ready(READ | WRITE | HUP | ERROR | EXPIRED | WOKEN);

    pub fn readable(self) -> bool {
        self.0 & READ != 0
    }

    pub fn writable(self) -> bool {
        self.0 & WRITE != 0
    }

    pub fn hangup(self) -> bool {
        self.0 & HUP != 0
    }

    pub fn error(self) -> bool {
        self.0 & ERROR != 0
    }

    pub fn expired(self) -> bool {
        self.0 & EXPIRED != 0
    }

    pub fn woken(self) -> bool {
        self.0 & WOKEN != 0
    }

    /// Something to read: readable, a hangup, or an error the read says.
    pub fn to_read(self) -> bool {
        self.0 & (READ | HUP | ERROR) != 0
    }

    /// self and other together.
    #[must_use]
    pub const fn with(self, other: Ready) -> Ready {
        Ready(self.0 | other.0)
    }

    /// Whether self holds any of other.
    pub fn any(self, other: Ready) -> bool {
        self.0 & other.0 != 0
    }
}

/// Why a Poll refused a call. Nothing changed then.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum PollError {
    /// The token is another Poll's.
    Foreign,
    /// The token's entry is gone: removed, or its descriptor closed and
    /// its number added again as a new entry.
    Gone,
    /// The descriptor is in the Poll already: added before, open, and not
    /// removed.
    Twice,
    /// The entry's descriptor is a component's (net's sockets): only its
    /// owner, which closes it, takes it out, by close.
    Owned,
    /// The token names a timer or entry without a descriptor, which close
    /// does not take.
    NoDescriptor,
    /// The system refused it.
    System,
    /// The Poll holds as many entries as it can name.
    Full,
}

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
    #[must_use]
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

/// An entry of a Poll, until it is removed: a token of a removed entry
/// names nothing, even once its place is taken again, and a token is
/// refused by every Poll but the one that gave it (PollError::Foreign).
#[derive(Clone, Copy)]
#[must_use]
pub struct Token {
    poll: u32,
    index: u32,
    generation: u32,
}

/// An entry whose descriptor its holder closes through the Poll alone, as
/// net's sockets are: Poll::close takes it, and remove refuses its token,
/// so the descriptor is closed once, by the one that owns it. Neither
/// Copy nor Clone; token() names the entry for its deadline and interest.
#[must_use]
pub struct Owned {
    token: Token,
}

impl Owned {
    pub fn token(&self) -> Token {
        self.token
    }
}

/// What poll found of one entry: its key, and what is ready.
pub struct Event {
    pub key: u64,
    pub ready: Ready,
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
    /// Added by add_owned: closed by close, never removed by remove.
    owned: bool,
    interest: Interest,
    key: u64,
    deadline: Option<Instant>,
    /// Where the deadline is filed in the Poll's deadlines, while it has
    /// one: at it, or up to LAZY_NS before it (deadline says why).
    filed: u64,
    /// The poll that reported the entry last, and where in its events.
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
    /// Wakes the Poll: its next poll, or the one it is in, returns with
    /// woken. Wakes before that poll are one.
    pub fn wake(&self) {
        self.wake.wake();
    }
}

/// A component's entries in a Poll, as its Want says: its descriptors
/// and a timer for its timeout. follow keeps them in step.
pub struct Follow {
    fds: [Option<Token>; 2],
    timer: Option<Token>,
}

impl Follow {
    pub const NONE: Follow = Follow {
        fds: [None; 2],
        timer: None,
    };
}

/// The number the next Poll takes, for its tokens: 2^32 Polls in one
/// process before one shares the first's.
// rr: escape(shared): one count for the process, whose threads each make
// their Polls.
static POLLS: AtomicU32 = AtomicU32::new(1);

pub struct Poll {
    poller: Poller,
    /// This Poll's number, in each of its tokens.
    id: u32,
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
    /// What the system reported at the last poll: a key, and readiness.
    found: Vec<(u64, u8)>,
    // rr: escape(bound): one for each entry, at most.
    events: Vec<Event>,
    batch: u64,
    /// The key wakes are reported with.
    woken: u64,
}

/// How an entry's descriptor leaves the system's watch.
#[derive(Clone, Copy)]
enum Detach {
    /// Told to, while it is open.
    Remove,
    /// Told to, and then closed.
    Close,
    /// Closed already: the poller forgets its record.
    Forget,
}

impl Poll {
    pub fn new() -> Option<Poll> {
        Poller::new().map(Poll::with)
    }

    /// A Poll on the system's portable way, where it has another: WSAPoll
    /// on Windows, where Poll::new takes socket notifications.
    #[cfg(all(test, target_os = "windows"))]
    pub fn polled() -> Option<Poll> {
        Poller::polled().map(Poll::with)
    }

    fn with(poller: Poller) -> Poll {
        Poll {
            poller,
            id: POLLS.fetch_add(1, Ordering::Relaxed),
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

    /// Watches fd for interest, reported with key. The caller keeps fd:
    /// it removes the entry before it closes fd.
    pub fn add(&mut self, fd: Raw, interest: Interest, key: u64) -> Result<Token, PollError> {
        self.attach(fd, interest, key, false)
    }

    /// Watches fd for interest, reported with key, as an entry only close
    /// takes out, closing fd with it: for a component that owns fd, as
    /// net's sockets do, and hands the token out for deadlines.
    pub fn add_owned(&mut self, fd: Raw, interest: Interest, key: u64) -> Result<Owned, PollError> {
        let token = self.attach(fd, interest, key, true)?;
        Ok(Owned { token })
    }

    /// A timer: an entry without a descriptor, for a deadline alone.
    pub fn timer(&mut self, key: u64) -> Result<Token, PollError> {
        self.place(None, Interest::None, key, false)
    }

    /// Changes what the entry waits for. What the system refused stays
    /// as it was, so that the next modify asks it again.
    pub fn modify(&mut self, token: Token, interest: Interest) -> Result<(), PollError> {
        let slot = self.slot_mut(token)?;
        let (fd, old) = (slot.fd, slot.interest.bits());
        if let Some(fd) = fd
            && old != interest.bits()
            && !self
                .poller
                .modify(fd, token_key(token), old, interest.bits())
        {
            return Err(PollError::System);
        }
        self.slot_mut(token)?.interest = interest;
        Ok(())
    }

    /// Reports the entry with key from now on: the system is not asked,
    /// as it names the entry by its token, which stays.
    pub fn rekey(&mut self, token: Token, key: u64) -> Result<(), PollError> {
        self.slot_mut(token)?.key = key;
        Ok(())
    }

    /// Sets or clears the entry's deadline. Once it passes, poll reports
    /// the entry expired and clears it.
    ///
    /// A deadline moved later by less than LAZY_NS stays filed where it
    /// was, as nginx leaves a timer that moves by less than its
    /// NGX_TIMER_LAZY_DELAY: a connection that pushes its deadline on at
    /// each read touches the deadlines' tree at most once in that time,
    /// not at each read. The entry, filed early, is filed again at its
    /// deadline once it comes first, so it is never reported early.
    pub fn deadline(&mut self, token: Token, at: Option<Instant>) -> Result<(), PollError> {
        let slot = self.slot_mut(token)?;
        let filed = slot.deadline.map(|_| slot.filed);
        slot.deadline = at;
        if let (Some(filed), Some(at)) = (filed, at)
            && at.ns >= filed
            && at.ns - filed < LAZY_NS
        {
            return Ok(());
        }
        if let Some(at) = at {
            slot.filed = at.ns;
        }
        if let Some(filed) = filed {
            self.deadlines.remove(&(filed, token.index));
        }
        if let Some(at) = at {
            self.deadlines.insert((at.ns, token.index));
        }
        Ok(())
    }

    /// Removes the entry, before the caller closes its descriptor; its
    /// token then names nothing. An owned entry is refused: close takes
    /// it.
    pub fn remove(&mut self, token: Token) -> Result<(), PollError> {
        if self.slot_mut(token)?.owned {
            return Err(PollError::Owned);
        }
        self.take(token, Detach::Remove);
        Ok(())
    }

    /// Removes the owned entry and closes its descriptor. Refused, and
    /// nothing closed, when the entry is another Poll's, gone or has no
    /// descriptor the system still watches for it: the owner closes its
    /// descriptor itself then.
    pub fn close(&mut self, Owned { token }: Owned) -> Result<(), PollError> {
        let slot = self.slot_mut(token)?;
        if slot.fd.is_none() || !slot.attached {
            return Err(PollError::NoDescriptor);
        }
        self.take(token, Detach::Close);
        Ok(())
    }

    /// What wakes this Poll from another thread; its wakes are reported
    /// with key.
    pub fn waker(&mut self, key: u64) -> Waker {
        self.woken = key;
        Waker {
            wake: self.poller.waker(),
        }
    }

    /// Waits until an entry is ready, a deadline passes, a Waker wakes
    /// the Poll or until comes, and says what happened: one event for
    /// each entry, its readiness and expiry together. Empty when until
    /// came first, or on a spurious wake.
    pub fn poll(&mut self, until: Option<Instant>) -> &[Event] {
        self.events.clear();
        self.batch = self.batch.wrapping_add(1);
        self.refile();
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
                        ready: Ready::WOKEN,
                    });
                }
                _ => self.found_ready(key, ready),
            }
        }
        self.expire(Instant::now());
        &self.events
    }

    /// Keeps follow's entries as want says: its descriptors and its
    /// timeout as a deadline (READY's, none, is due now), all reported
    /// with key, the one given last. Err when the system refused a
    /// descriptor; the others are kept as want says all the same. Its
    /// entries are unfollowed before the component goes, which closes
    /// them.
    pub fn follow(&mut self, follow: &mut Follow, want: &Want, key: u64) -> Result<(), PollError> {
        let mut wanted = [None; 2];
        for ((at, fd), wish) in want.fds.iter().enumerate().zip(&mut wanted) {
            if at < want.count && fd.fd != Fd::NONE.fd {
                *wish = Some((fd.fd, interest(fd)));
            }
        }
        // A descriptor named twice is one entry, for both interests: a
        // Poll holds each once.
        if let [Some((first, one)), Some((second, other))] = wanted
            && first == second
        {
            let both = Interest::new(one.reads() || other.reads(), one.writes() || other.writes());
            wanted = [Some((first, both)), None];
        }
        // Entries go with their descriptor, wherever the Want now names
        // it; the ones it no longer names are removed before any is
        // added, so that a descriptor never stands in the Poll twice.
        let mut kept: [Option<Token>; 2] = [None; 2];
        for held in &mut follow.fds {
            if let Some(token) = held.take() {
                let fd = self.slot_mut(token).ok().and_then(|slot| slot.fd);
                let at = wanted
                    .iter()
                    .position(|wish| wish.is_some_and(|(named, _)| Some(named) == fd));
                match at.and_then(|at| kept.get_mut(at)) {
                    Some(place) => *place = Some(token),
                    // Gone already, when it is not this Poll's own.
                    None => self.remove(token).unwrap_or(()),
                }
            }
        }
        let mut result = Ok(());
        for ((place, wish), held) in follow.fds.iter_mut().zip(wanted).zip(kept) {
            let outcome = match (wish, held) {
                (Some((_, interest)), Some(token)) => self
                    .modify(token, interest)
                    .and_then(|()| self.rekey(token, key))
                    .map(|()| Some(token)),
                (Some((fd, interest)), None) => self.add(fd, interest, key).map(Some),
                (None, _) => Ok(None),
            };
            *place = match outcome {
                Ok(token) => token,
                Err(error) => {
                    result = result.and(Err(error));
                    held
                }
            };
        }
        let timer = match follow.timer {
            Some(timer) => self.rekey(timer, key).map(|()| timer),
            None => self.timer(key),
        };
        let at = want.timeout_ms.map(|ms| Instant::now().after_ms(ms));
        match timer.and_then(|timer| self.deadline(timer, at).map(|()| timer)) {
            Ok(timer) => follow.timer = Some(timer),
            Err(error) => {
                follow.timer = None;
                result = result.and(Err(error));
            }
        }
        result
    }

    /// Removes follow's entries, before the component closes them.
    pub fn unfollow(&mut self, follow: &mut Follow) {
        for place in &mut follow.fds {
            if let Some(token) = place.take() {
                // Gone already, when it is not this Poll's own.
                self.remove(token).unwrap_or(());
            }
        }
        if let Some(timer) = follow.timer.take() {
            self.remove(timer).unwrap_or(());
        }
    }

    /// Adds fd as a new entry, owned or not.
    fn attach(
        &mut self,
        fd: Raw,
        interest: Interest,
        key: u64,
        owned: bool,
    ) -> Result<Token, PollError> {
        // Whether the system still watches fd for the entry it has: then
        // it is open, the one that entry was added with.
        if let Some(&other) = self.owners.get(&fd)
            && let Some(slot) = usize::try_from(other)
                .ok()
                .and_then(|at| self.slots.get(at))
            && slot.attached
        {
            let held = token_key(Token {
                poll: self.id,
                index: other,
                generation: slot.generation,
            });
            if self.poller.holds(fd, held, slot.interest.bits()) {
                return Err(PollError::Twice);
            }
        }
        let token = self.place(Some(fd), interest, key, owned)?;
        if !self.poller.add(fd, token_key(token), interest.bits()) {
            self.release(token.index);
            return Err(PollError::System);
        }
        if let Some(other) = self.owners.insert(fd, token.index) {
            // Closed without being removed, its number taken by fd: the
            // system dropped the old entry when it was closed, and only
            // the poller's own record of it is left to forget. The entry
            // goes, deadline and all; its token names nothing.
            self.forget(other);
        }
        Ok(token)
    }

    /// Takes the entry out, as how says, deadline and all.
    fn take(&mut self, token: Token, how: Detach) {
        self.clear(token.index);
        self.detach(token.index, how);
        self.release(token.index);
    }

    /// A place for a new entry.
    fn place(
        &mut self,
        fd: Option<Raw>,
        interest: Interest,
        key: u64,
        owned: bool,
    ) -> Result<Token, PollError> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                // rr: escape(discard): past u32::MAX places is all the
                // cause there is.
                let index = u32::try_from(self.slots.len())
                    .ok()
                    .ok_or(PollError::Full)?;
                self.slots.push(Slot {
                    generation: 1,
                    live: false,
                    fd: None,
                    attached: false,
                    owned: false,
                    interest: Interest::None,
                    key: 0,
                    deadline: None,
                    filed: 0,
                    batch: 0,
                    event: 0,
                });
                index
            }
        };
        let slot = usize::try_from(index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
            .ok_or(PollError::Full)?;
        slot.live = true;
        slot.fd = fd;
        slot.attached = fd.is_some();
        slot.owned = owned;
        slot.interest = interest;
        slot.key = key;
        slot.deadline = None;
        Ok(Token {
            poll: self.id,
            index,
            generation: slot.generation,
        })
    }

    /// The entry of a descriptor closed before it was removed goes.
    fn forget(&mut self, index: u32) {
        self.detach(index, Detach::Forget);
        self.clear(index);
        self.release(index);
    }

    /// Clears the entry's deadline.
    fn clear(&mut self, index: u32) {
        let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
        else {
            return;
        };
        if slot.deadline.take().is_some() {
            self.deadlines.remove(&(slot.filed, index));
        }
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
        slot.owned = false;
        slot.generation = match slot.generation.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        self.free.push(index);
    }

    /// The system stops watching the entry's descriptor, as how says.
    fn detach(&mut self, index: u32, how: Detach) {
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
            poll: self.id,
            index,
            generation: slot.generation,
        });
        let interest = slot.interest.bits();
        if self.owners.get(&fd) == Some(&index) {
            self.owners.remove(&fd);
        }
        match how {
            Detach::Remove => self.poller.remove(fd, key, interest),
            Detach::Close => self.poller.close(fd, key, interest),
            // epoll and kqueue dropped it with the descriptor and keep
            // nothing; Windows's pollers keep their own record of it.
            #[cfg(target_os = "windows")]
            Detach::Forget => self.poller.forget(key),
            #[cfg(not(target_os = "windows"))]
            Detach::Forget => {}
        }
    }

    /// The token's entry: refused when the token is another Poll's or
    /// its entry is gone.
    fn slot_mut(&mut self, token: Token) -> Result<&mut Slot, PollError> {
        if token.poll != self.id {
            return Err(PollError::Foreign);
        }
        usize::try_from(token.index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
            .filter(|slot| slot.live && slot.generation == token.generation)
            .ok_or(PollError::Gone)
    }

    /// What the system reported for key, as the entry's interest asks:
    /// dropped when the entry is gone, no longer watched or has none, as
    /// a notification sent before the interest changed may be. A hangup
    /// shows with reading alone, as each system reports it there; with
    /// writing alone, where Linux reports a full one, WSAPoll any, and
    /// macOS and socket notifications none, it shows as writable, which
    /// the others report then too.
    fn found_ready(&mut self, key: u64, ready: u8) {
        let token = Token {
            poll: self.id,
            index: u32::try_from(key & u64::from(u32::MAX)).unwrap_or(u32::MAX),
            generation: u32::try_from(key >> 32).unwrap_or(0),
        };
        let Ok(slot) = self.slot_mut(token) else {
            return;
        };
        let shown = match (slot.attached, slot.interest) {
            (false, _) | (_, Interest::None) => 0,
            (true, Interest::Read) => ready & (READ | HUP | ERROR),
            (true, Interest::Both) => ready & (READ | WRITE | HUP | ERROR),
            (true, Interest::Write) if ready & HUP != 0 => WRITE | (ready & ERROR),
            (true, Interest::Write) => ready & (WRITE | ERROR),
        };
        if shown != 0 {
            self.report(token.index, shown);
        }
    }

    /// The deadlines due by now: reported, and cleared; one filed early
    /// is filed again at its deadline, after which it comes in its order.
    fn expire(&mut self, now: Instant) {
        while let Some(&(ns, index)) = self.deadlines.first() {
            if now.ns < ns {
                break;
            }
            if self.later(ns, index) {
                continue;
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

    /// Files again at their deadlines those filed early that come first,
    /// so that the wait is for a deadline that stands.
    fn refile(&mut self) {
        while let Some(&(ns, index)) = self.deadlines.first() {
            if !self.later(ns, index) {
                break;
            }
        }
    }

    /// Whether the entry filed at ns has its deadline later: then it is
    /// filed again there, later than ns, once for each time it was moved
    /// lazily.
    #[must_use]
    fn later(&mut self, ns: u64, index: u32) -> bool {
        let Some(slot) = usize::try_from(index)
            .ok()
            .and_then(|at| self.slots.get_mut(at))
        else {
            return false;
        };
        let Some(at) = slot.deadline.filter(|at| at.ns > ns) else {
            return false;
        };
        slot.filed = at.ns;
        self.deadlines.remove(&(ns, index));
        self.deadlines.insert((at.ns, index));
        true
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
                let before = event.ready;
                event.ready = before.with(Ready(ready));
            }
            return;
        }
        slot.batch = self.batch;
        slot.event = self.events.len();
        self.events.push(Event {
            key: slot.key,
            ready: Ready(ready),
        });
    }
}

/// How much later a deadline may move and stay filed where it was: 300
/// ms, nginx's NGX_TIMER_LAZY_DELAY. It costs no accuracy, as the entry
/// is filed again at its deadline before that is waited for; at most it
/// moves the entry once in that time instead of at every change.
const LAZY_NS: u64 = 300_000_000;

/// How the system names an entry: its generation, never 0, then its
/// index; 0 names the waker.
fn token_key(token: Token) -> u64 {
    (u64::from(token.generation) << 32) | u64::from(token.index)
}

/// The interest a component's descriptor states in poll's events.
fn interest(fd: &Fd) -> Interest {
    Interest::new(fd.events & POLLIN != 0, fd.events & POLLOUT != 0)
}

#[cfg(test)]
mod tests {
    use super::super::{Fd, Signal, Want};
    use super::{Follow, Instant, Interest, Poll, PollError, Ready};
    use alloc::vec::Vec;
    use test::Bencher;

    /// Every way the system has to wait: on Windows, socket notifications
    /// and WSAPoll both.
    fn polls() -> Vec<Poll> {
        #[cfg(target_os = "windows")]
        return Vec::from([Poll::new().unwrap(), Poll::polled().unwrap()]);
        #[cfg(not(target_os = "windows"))]
        return Vec::from([Poll::new().unwrap()]);
    }

    /// The events of one wait, as (key, ready).
    fn events(poll: &mut Poll, until: Instant) -> Vec<(u64, Ready)> {
        // rr: escape(copy): the test reads the events while it changes
        // the Poll.
        poll.poll(Some(until))
            .iter()
            .map(|event| (event.key, event.ready))
            .collect()
    }

    /// Waits up to ten seconds for key with any of want; its readiness.
    fn until(poll: &mut Poll, key: u64, want: Ready) -> Ready {
        let end = Instant::now().after_ms(10_000);
        loop {
            for (found, ready) in events(poll, end) {
                if found == key && ready.any(want) {
                    return ready;
                }
            }
            assert!(!end.reached_by(Instant::now()), "nothing for key {key}");
        }
    }

    /// Waits ms milliseconds, and checks that key was not reported with
    /// any of these.
    fn quiet(poll: &mut Poll, key: u64, these: Ready, ms: u64) {
        let end = Instant::now().after_ms(ms);
        while !end.reached_by(Instant::now()) {
            for (found, ready) in events(poll, end) {
                assert!(
                    found != key || !ready.any(these),
                    "key {key} reported {ready:?}"
                );
            }
        }
    }

    /// Timers: each deadline that stands is reported once, never before
    /// it, nearest first; cleared, moved and removed ones as they were
    /// left. A wait with nothing to report returns empty.
    #[test]
    fn deadlines() {
        let mut poll = Poll::new().unwrap();
        let start = Instant::now();
        assert!(poll.poll(Some(start.after_ms(20))).is_empty());
        let mut tokens = Vec::new();
        let mut due = Vec::new();
        for key in 0..200u64 {
            let token = poll.timer(key).unwrap();
            let at = start.after_ms(30 + key * 37 % 97);
            poll.deadline(token, Some(at)).unwrap();
            tokens.push(token);
            due.push(Some(at));
        }
        for key in (0..200).step_by(10) {
            poll.deadline(tokens[key], None).unwrap();
            due[key] = None;
        }
        for key in (3..200).step_by(7) {
            let later = start.after_ms(150 + u64::try_from(key % 50).unwrap());
            poll.deadline(tokens[key], Some(later)).unwrap();
            due[key] = Some(later);
        }
        for key in (5..200).step_by(13) {
            poll.remove(tokens[key]).unwrap();
            due[key] = None;
        }
        let mut fired: Vec<(usize, Instant)> = Vec::new();
        let end = start.after_ms(400);
        while !end.reached_by(Instant::now()) {
            for (key, ready) in events(&mut poll, end) {
                assert_eq!(ready, Ready::EXPIRED);
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

    /// A deadline pushed on a little at a time, as a connection pushes
    /// its own at each read, stays filed early: it is reported once, at
    /// its last place and not before, beside one moved earlier and one
    /// moved far.
    #[test]
    fn deadlines_pushed_on() {
        let mut poll = Poll::new().unwrap();
        let start = Instant::now();
        let pushed = poll.timer(1).unwrap();
        let earlier = poll.timer(2).unwrap();
        let far = poll.timer(3).unwrap();
        poll.deadline(earlier, Some(start.after_ms(200))).unwrap();
        poll.deadline(far, Some(start.after_ms(20))).unwrap();
        for ms in 20..120 {
            poll.deadline(pushed, Some(start.after_ms(ms))).unwrap();
        }
        poll.deadline(earlier, Some(start.after_ms(60))).unwrap();
        poll.deadline(far, Some(start.after_ms(900))).unwrap();
        poll.deadline(far, Some(start.after_ms(150))).unwrap();
        let mut fired = Vec::new();
        let end = start.after_ms(400);
        while !end.reached_by(Instant::now()) {
            for (key, ready) in events(&mut poll, end) {
                assert_eq!(ready, Ready::EXPIRED);
                fired.push((key, Instant::now()));
            }
        }
        assert_eq!(fired.len(), 3);
        for (&(key, at), (want, due)) in fired.iter().zip([(2, 60), (1, 119), (3, 150)]) {
            assert_eq!(key, want);
            assert!(start.after_ms(due).reached_by(at), "{key} early");
        }
    }

    /// The cost of pushing a deadline on, as a connection does at each
    /// read: 10,000 entries, each moved 1 ms later at its turn, as nginx
    /// leaves a timer that moves by less than 300 ms where it is.
    #[bench]
    fn deadline_pushed_on(b: &mut Bencher) {
        let mut poll = Poll::new().unwrap();
        let start = Instant::now().after_ms(60_000);
        let mut tokens = Vec::new();
        for key in 0..10_000u64 {
            let token = poll.timer(key).unwrap();
            poll.deadline(token, Some(start.after_ms(key % 1000)))
                .unwrap();
            tokens.push(token);
        }
        let mut turn = 0u64;
        b.iter(|| {
            turn += 1;
            let key = turn % 10_000;
            let at = start.after_ms(key % 1000 + turn / 10_000);
            let token = tokens[usize::try_from(key).unwrap()];
            poll.deadline(token, Some(at)).unwrap();
        });
    }

    /// A component's Want in a Poll: READY is due at once, a descriptor
    /// is reported when ready, a timeout alone takes the descriptor's
    /// place.
    #[test]
    fn follows_a_wait() {
        for mut poll in polls() {
            let mut follow = Follow::NONE;
            poll.follow(&mut follow, &Want::READY, 5).unwrap();
            until(&mut poll, 5, Ready::EXPIRED);
            let signal = Signal::new().unwrap();
            poll.follow(&mut follow, &signal.want(), 5).unwrap();
            quiet(&mut poll, 5, Ready::ANY, 30);
            signal.set();
            until(&mut poll, 5, Ready::READABLE);
            let mut timed = Want::READY;
            timed.timeout_ms = Some(20);
            poll.follow(&mut follow, &timed, 5).unwrap();
            assert!(!until(&mut poll, 5, Ready::EXPIRED).readable());
            poll.unfollow(&mut follow);
            quiet(&mut poll, 5, Ready::ANY, 30);
        }
    }

    /// A Want followed under a new key is reported under it: its kept
    /// descriptor and its timer both, and nothing under the old.
    #[test]
    fn follows_under_a_new_key() {
        for mut poll in polls() {
            let mut follow = Follow::NONE;
            let signal = Signal::new().unwrap();
            let mut timed = signal.want();
            timed.timeout_ms = Some(10_000);
            poll.follow(&mut follow, &timed, 5).unwrap();
            timed.timeout_ms = Some(20);
            poll.follow(&mut follow, &timed, 6).unwrap();
            assert!(until(&mut poll, 6, Ready::EXPIRED).expired());
            signal.set();
            until(&mut poll, 6, Ready::READABLE);
            quiet(&mut poll, 5, Ready::ANY, 30);
            poll.unfollow(&mut follow);
        }
    }

    /// Wakes from this thread before a wait are one event, and a woken
    /// Poll is quiet again; another thread's wake is in sys's tests.
    #[test]
    fn wakes_once() {
        for mut poll in polls() {
            let waker = poll.waker(9);
            waker.wake();
            waker.wake();
            let woken = events(&mut poll, Instant::now().after_ms(1000));
            assert_eq!(woken, Vec::from([(9, Ready::WOKEN)]));
            quiet(&mut poll, 9, Ready::ANY, 30);
        }
    }

    /// A descriptor that moves to the other place of the Want keeps its
    /// entry; the one the Want no longer names goes, and wakes nothing.
    #[test]
    fn follows_a_descriptor_that_moves() {
        for mut poll in polls() {
            let (first, second) = (Signal::new().unwrap(), Signal::new().unwrap());
            let mut follow = Follow::NONE;
            let [one, _] = first.want().fds;
            let [two, _] = second.want().fds;
            let both = Want {
                fds: [one, two],
                count: 2,
                timeout_ms: None,
            };
            poll.follow(&mut follow, &both, 5).unwrap();
            let [moved, _] = second.want().fds;
            let alone = Want {
                fds: [moved, Fd::NONE],
                count: 1,
                timeout_ms: None,
            };
            poll.follow(&mut follow, &alone, 5).unwrap();
            first.set();
            quiet(&mut poll, 5, Ready::ANY, 30);
            second.set();
            until(&mut poll, 5, Ready::READABLE);
            poll.unfollow(&mut follow);
        }
    }

    /// A token is its own Poll's: another Poll, whose entries take the same
    /// places and generations, refuses it, and its own entry is untouched.
    /// A removed entry's token is gone, and an owned entry is only closed.
    #[test]
    fn tokens_name_their_own_set() {
        let mut first = Poll::new().unwrap();
        let mut second = Poll::new().unwrap();
        let mine = first.timer(1).unwrap();
        let theirs = second.timer(2).unwrap();
        second
            .deadline(theirs, Some(Instant::now().after_ms(10)))
            .unwrap();
        assert_eq!(second.remove(mine), Err(PollError::Foreign));
        assert_eq!(second.rekey(mine, 3), Err(PollError::Foreign));
        assert_eq!(second.deadline(mine, None), Err(PollError::Foreign));
        assert_eq!(second.modify(mine, Interest::Read), Err(PollError::Foreign));
        until(&mut second, 2, Ready::EXPIRED);
        first.remove(mine).unwrap();
        assert_eq!(first.remove(mine), Err(PollError::Gone));
        assert_eq!(first.rekey(mine, 4), Err(PollError::Gone));
        let signal = Signal::new().unwrap();
        let [fd, _] = signal.want().fds;
        let token = first.add(fd.fd, Interest::Read, 7).unwrap();
        assert_eq!(
            first.add(fd.fd, Interest::Read, 8).err(),
            Some(PollError::Twice)
        );
        first.remove(token).unwrap();
        let owned = first.add_owned(fd.fd, Interest::None, 9).unwrap();
        assert_eq!(first.remove(owned.token()), Err(PollError::Owned));
        // close would close the signal's descriptor, which the signal
        // closes itself: the entry stays until the Poll goes.
        assert!(owned.token().poll == first.id);
    }

    /// Interest from the two wishes, and what each holds.
    #[test]
    fn interests() {
        for (read, write, interest) in [
            (false, false, Interest::None),
            (true, false, Interest::Read),
            (false, true, Interest::Write),
            (true, true, Interest::Both),
        ] {
            assert_eq!(Interest::new(read, write), interest);
            assert_eq!((interest.reads(), interest.writes()), (read, write));
        }
        let ready = Ready::READABLE.with(Ready::HANGUP);
        assert!(ready.readable() && ready.hangup() && ready.to_read());
        assert!(!ready.writable() && !ready.error() && !ready.expired() && !ready.woken());
        assert!(Ready::ERROR.to_read() && !Ready::WRITABLE.to_read());
    }
}
