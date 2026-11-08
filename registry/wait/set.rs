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
//! something to write: a socket is nearly always writable. With an
//! interest, errors and the peer's hangup come with it; an entry with
//! none is not watched at all, as when the loop stops reading to let a
//! slow peer catch up, and what happened to it shows when it has one
//! again, or at its next read or write. Only its deadline still counts.
//! A report may be spurious: a read or write that would block is not an
//! error.
//!
//! One wait reports at most 256 descriptors (all on WSAPoll); the rest,
//! still ready, the next. Deadlines are never reported early, and may be late by what the
//! system's wait counts in: on Linux and Windows a timeout is whole
//! milliseconds, rounded up, and Windows wakes on its timer's tick, 15.6
//! ms unless the program asked for a finer one.
//!
//! A descriptor is in a Set once, and is removed before it is closed:
//! close does both, so that nothing the system still holds of it is
//! reported for the descriptor that takes its number next. add refuses
//! one the system still watches for its entry, as Linux's epoll refuses
//! it, on every system: one added twice. One closed first is dropped by
//! the system, and its entry stays, with its deadline, until it is
//! removed or a new descriptor gets its number: that one is added as
//! new, the old entry goes, and its token names nothing; what the system
//! had queued for the old one may then be reported for it once, as a
//! spurious report. The system watches an entry only while it has an
//! interest, and WSAPoll watches a socket only by the handle the Set
//! hands it: an entry with none, or any on WSAPoll, the system cannot
//! tell from a closed one, and a descriptor added again takes its place
//! as a new one does. On Linux that holds only when the closed
//! descriptor was the last open on its socket: epoll watches the socket,
//! not the number, so after dup or fork another descriptor keeps it
//! watched, and its events come back on every wait for an entry the Set
//! no longer reports.
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
/// names nothing, even once its place is taken again. A token is for the
/// Set that gave it: another Set reads it as its own entry of that place,
/// as an index into the wrong array would be.
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
    /// with key. None when the system refuses it, or when fd is in the
    /// Set already: added before, open, and not removed.
    pub fn add(&mut self, fd: Raw, interest: u8, key: u64) -> Option<Token> {
        // Whether the system still watches fd for the entry it has: then
        // it is open, the one that entry was added with.
        if let Some(&other) = self.owners.get(&fd)
            && let Some(slot) = usize::try_from(other)
                .ok()
                .and_then(|at| self.slots.get(at))
            && slot.attached
        {
            let held = token_key(Token {
                index: other,
                generation: slot.generation,
            });
            if self.poller.holds(fd, held, slot.interest) {
                return None;
            }
        }
        let token = self.place(Some(fd), interest, key)?;
        if !self.poller.add(fd, token_key(token), interest) {
            self.release(token.index);
            return None;
        }
        if let Some(other) = self.owners.insert(fd, token.index) {
            // Closed without being removed, its number taken by fd: the
            // system dropped the old entry when it was closed, and only
            // the poller's own record of it is left to forget. The entry
            // goes, deadline and all; its token names nothing.
            self.forget(other);
        }
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
        let (fd, old) = (slot.fd, slot.interest);
        let changed = match fd {
            Some(fd) if old != interest => self.poller.modify(fd, token_key(token), old, interest),
            _ => true,
        };
        // What the system refused stays as it was, so that the next
        // modify asks it again.
        if let (true, Some(taken)) = (changed, self.slot_mut(token)) {
            taken.interest = interest;
        }
        changed
    }

    /// Reports the entry with key from now on: the system is not asked,
    /// as it names the entry by its token, which stays.
    pub fn rekey(&mut self, token: Token, key: u64) -> bool {
        let Some(slot) = self.slot_mut(token) else {
            return false;
        };
        slot.key = key;
        true
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
        self.detach(token.index, Detach::Remove);
        self.release(token.index);
    }

    /// Removes the entry and closes its descriptor, which the caller
    /// gives up. False, and nothing closed, when the token names no
    /// entry with a descriptor.
    pub fn close(&mut self, token: Token) -> bool {
        let Some(slot) = self.slot_mut(token) else {
            return false;
        };
        if slot.fd.is_none() || !slot.attached {
            return false;
        }
        self.deadline(token, None);
        self.detach(token.index, Detach::Close);
        self.release(token.index);
        true
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
        let mut wanted = [None; 2];
        for ((at, fd), want) in wait.fds.iter().enumerate().zip(&mut wanted) {
            if at < wait.count && fd.fd != Fd::NONE.fd {
                *want = Some((fd.fd, interest(fd)));
            }
        }
        // A descriptor named twice is one entry, for both interests: a
        // Set holds each once.
        if let [Some((first, one)), Some((second, other))] = wanted
            && first == second
        {
            wanted = [Some((first, one | other)), None];
        }
        // Entries go with their descriptor, wherever the Wait now names
        // it; the ones it no longer names are removed before any is
        // added, so that a descriptor never stands in the Set twice.
        let mut kept: [Option<Token>; 2] = [None; 2];
        for held in &mut watch.fds {
            if let Some(token) = held.take() {
                let fd = self.slot_mut(token).and_then(|slot| slot.fd);
                let at = wanted
                    .iter()
                    .position(|want| want.is_some_and(|(named, _)| Some(named) == fd));
                match at.and_then(|at| kept.get_mut(at)) {
                    Some(place) => *place = Some(token),
                    None => self.remove(token),
                }
            }
        }
        let mut added = true;
        for ((place, want), held) in watch.fds.iter_mut().zip(wanted).zip(kept) {
            *place = match (want, held) {
                (Some((_, interest)), Some(token)) => {
                    added &= self.modify(token, interest);
                    Some(token)
                }
                (Some((fd, interest)), None) => {
                    let token = self.add(fd, interest, key);
                    added &= token.is_some();
                    token
                }
                (None, _) => None,
            };
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
        if let Some(at) = slot.deadline.take() {
            self.deadlines.remove(&(at.ns, index));
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
            index,
            generation: slot.generation,
        });
        let interest = slot.interest;
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

    fn slot_mut(&mut self, token: Token) -> Option<&mut Slot> {
        let slot = self.slots.get_mut(usize::try_from(token.index).ok()?)?;
        (slot.live && slot.generation == token.generation).then_some(slot)
    }

    /// What the system reported for key, as the entry's interest asks:
    /// dropped when the entry is gone, no longer watched or has none, as
    /// a notification sent before the interest changed may be.
    fn found_ready(&mut self, key: u64, ready: u8) {
        let token = Token {
            index: u32::try_from(key & u64::from(u32::MAX)).unwrap_or(u32::MAX),
            generation: u32::try_from(key >> 32).unwrap_or(0),
        };
        let Some(slot) = self.slot_mut(token) else {
            return;
        };
        let shown = match (slot.attached, slot.interest) {
            (false, _) | (_, 0) => 0,
            (true, interest) => ready & (interest | HUP | ERROR),
        };
        if shown != 0 {
            self.report(token.index, shown);
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
    use super::super::{Fd, Signal, Wait};
    use super::{EXPIRED, Instant, READ, Set, WOKEN, Watch};
    use alloc::vec::Vec;

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

    /// A descriptor that moves to the other place of the Wait keeps its
    /// entry; the one the Wait no longer names goes, and wakes nothing.
    #[test]
    fn follows_a_descriptor_that_moves() {
        for mut set in sets() {
            let (first, second) = (Signal::new().unwrap(), Signal::new().unwrap());
            let mut watch = Watch::NONE;
            let [one, _] = first.wait().fds;
            let [two, _] = second.wait().fds;
            let both = Wait {
                fds: [one, two],
                count: 2,
                timeout_ms: None,
            };
            assert!(set.follow(&mut watch, &both, 5));
            let [moved, _] = second.wait().fds;
            let alone = Wait {
                fds: [moved, Fd::NONE],
                count: 1,
                timeout_ms: None,
            };
            assert!(set.follow(&mut watch, &alone, 5));
            first.set();
            quiet(&mut set, 5, u8::MAX, 30);
            second.set();
            until(&mut set, 5, READ);
            set.unfollow(&mut watch);
        }
    }
}
