//! The lookup of one name, as Go's goLookupIPCNAMEOrder does it, as a
//! state machine. A literal address is itself; /etc/hosts comes first
//! or last as the order says; localhost names are loopback (RFC 6761).
//! Then each name of the search list is asked in turn, A and AAAA at
//! once (one after the other with single-request), each of the servers
//! in order or rotated, attempts times, each exchange over UDP with its
//! own timeout and again over TCP when the answer was cut (or over TCP
//! alone with use-vc). NXDOMAIN, or no address, ends a family's search
//! on that name; SERVFAIL, a bad answer or a timeout tries the next
//! server. The first name that gives any address ends the lookup.
//!
//! Each family keeps at most one socket: an action opens one to a
//! server, replacing the one it had, and sends a query, or closes it.
//! What comes back is handed in with the family it came on.

use super::conf::{Config, Queries, Rotation, SEARCH_MAX, SERVERS_MAX, Transport};
use super::nss::{Order, localhost};
use super::{ADDRESSES_MAX, Address, Error, NAME_MAX, Search, address, ends_with, hosts, sort};
use crate::dns;
#[cfg(fuzzing)]
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The most names one lookup asks: the search list's and the name.
const CANDIDATES_MAX: usize = SEARCH_MAX + 1;

/// The query of one family, with the socket it keeps.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Lane {
    A,
    Aaaa,
}

impl Lane {
    pub const ALL: [Lane; 2] = [Lane::A, Lane::Aaaa];

    /// 0 or 1, for a caller's table of sockets.
    pub fn index(self) -> usize {
        match self {
            Lane::A => 0,
            Lane::Aaaa => 1,
        }
    }

    fn kind(self) -> dns::Kind {
        match self {
            Lane::A => dns::Kind::A,
            Lane::Aaaa => dns::Kind::Aaaa,
        }
    }
}

/// What the caller does for the lookup.
pub enum Action<'a> {
    /// Open a UDP socket to the server's port 53, in place of any the
    /// lane had, and send the message on it.
    Udp {
        lane: Lane,
        server: Address,
        message: &'a [u8],
    },
    /// Open a TCP connection to the server's port 53, in place of any
    /// socket the lane had, and send the message, framed, on it.
    Tcp {
        lane: Lane,
        server: Address,
        message: &'a [u8],
    },
    /// Close the lane's socket.
    Close { lane: Lane },
}

/// What a lookup starts from.
pub struct Start<'a> {
    /// The name, as a program asks for it: `www`, `example.com.`.
    pub name: &'a [u8],
    pub config: &'a Config,
    pub order: Order,
    /// /etc/hosts's text, or None when there is no such file.
    pub hosts: Option<&'a [u8]>,
    /// Random bytes for the query ids and the first server.
    pub random: [u8; 16],
    pub now_ms: u64,
}

/// What resolv.conf says about each exchange.
struct Settings {
    servers: [Address; SERVERS_MAX],
    servers_count: usize,
    timeout_ms: u64,
    attempts: usize,
    transport: Transport,
    trust_ad: bool,
}

#[derive(Clone, Copy)]
enum State {
    /// Not started on this name.
    Idle,
    /// Waiting for the answer on UDP, or on TCP, until the deadline.
    Udp {
        deadline_ms: u64,
    },
    Tcp {
        deadline_ms: u64,
    },
    /// The number of addresses, or why there are none.
    Done(Result<usize, Error>),
}

#[derive(Clone, Copy)]
enum Want {
    Udp,
    Tcp,
    Close,
}

/// A family's query of the name being asked.
struct Query {
    lane: Lane,
    state: State,
    /// The exchanges tried: attempts times each server.
    step: usize,
    /// The server the first exchange goes to.
    offset: usize,
    id: u16,
    /// The query as TCP frames it, to length; UDP sends it without the
    /// length's two bytes.
    message: [u8; dns::QUERY_MAX],
    length: usize,
    /// A TCP answer as it comes: the one buffer a lookup allocates, the
    /// first time this lane goes over TCP, and kept for the next.
    framing: dns::Tcp,
    want: Option<Want>,
    /// Why the last exchange failed.
    error: Option<Error>,
    records: [dns::Record; ADDRESSES_MAX],
}

pub struct Lookup {
    settings: Settings,
    queries: [Query; 2],
    sequential: bool,
    /// The name as given and the search list, from which each name to
    /// ask is made into current in its turn.
    name: [u8; NAME_MAX],
    name_length: usize,
    search: Search,
    candidates: [Candidate; CANDIDATES_MAX],
    candidates_count: usize,
    /// Which candidate is the name as given: its error is the one Go
    /// reports.
    bare: Option<usize>,
    candidate: usize,
    current: [u8; NAME_MAX],
    current_length: usize,
    /// The first error of the names asked, or the bare name's.
    error: Option<Error>,
    order: Order,
    key: [u8; 16],
    /// The ids taken from key so far.
    counter: u64,
    /// The first server of each query, when rotating.
    rotation: Option<usize>,
    /// The addresses found, to count. While DNS has found none, the
    /// first files of them are what /etc/hosts gave, for dns,files.
    addresses: [Address; ADDRESSES_MAX],
    count: usize,
    files: usize,
    outcome: Option<Result<(), Error>>,
}

/// A name a lookup asks, made from the name as given.
#[derive(Clone, Copy)]
enum Candidate {
    /// The name, which ends in a dot.
    AsIs,
    /// The name and a final dot.
    Dotted,
    /// The name, a dot and this search domain.
    Suffix(usize),
}

impl Query {
    fn new(lane: Lane) -> Query {
        Query {
            lane,
            state: State::Idle,
            step: 0,
            offset: 0,
            id: 0,
            message: [0; dns::QUERY_MAX],
            length: 0,
            framing: dns::Tcp::new(),
            want: None,
            error: None,
            records: [dns::Record::EMPTY; ADDRESSES_MAX],
        }
    }

    /// Readies it for another lookup, keeping the TCP buffer.
    fn reset(&mut self) {
        self.state = State::Idle;
        self.step = 0;
        self.offset = 0;
        self.length = 0;
        self.framing.clear();
        self.want = None;
        self.error = None;
    }

    fn deadline_ms(&self) -> Option<u64> {
        match self.state {
            State::Udp { deadline_ms } | State::Tcp { deadline_ms } => Some(deadline_ms),
            State::Idle | State::Done(_) => None,
        }
    }

    fn finish(&mut self, result: Result<usize, Error>) {
        if self.deadline_ms().is_some() {
            self.want = Some(Want::Close);
        }
        self.state = State::Done(result);
    }

    /// The exchange failed: the next server, or the error once all were
    /// tried attempts times.
    fn retry(&mut self, error: Error, ask: &Ask<'_>) {
        self.error = Some(error);
        self.step += 1;
        if self.step >= ask.settings.attempts * ask.settings.servers_count {
            self.finish(Err(error));
        } else {
            self.send(ask);
        }
    }

    /// Writes the next exchange's query and asks for it to be sent.
    fn send(&mut self, ask: &Ask<'_>) {
        self.id = ask.id;
        self.framing.clear();
        let query = self.query(ask);
        let Ok(length) = dns::framed_query(&mut self.message, &query) else {
            // Go cannot write such a name either.
            self.finish(Err(Error::Misbehaving));
            return;
        };
        self.length = length;
        let deadline_ms = ask.now_ms.saturating_add(ask.settings.timeout_ms);
        match ask.settings.transport {
            Transport::Udp => {
                self.want = Some(Want::Udp);
                self.state = State::Udp { deadline_ms };
            }
            Transport::Tcp => self.tcp(deadline_ms),
        }
    }

    fn tcp(&mut self, deadline_ms: u64) {
        self.framing.clear();
        self.want = Some(Want::Tcp);
        self.state = State::Tcp { deadline_ms };
    }

    fn query<'a>(&self, ask: &Ask<'a>) -> dns::Query<'a> {
        dns::Query {
            id: self.id,
            name: ask.name,
            kind: self.lane.kind(),
            edns: true,
            ad: ask.settings.trust_ad,
        }
    }

    /// Reads an answer, as Go's exchange, checkHeader and skipToAnswer
    /// read it.
    fn answer(&mut self, message: &[u8], transport: dns::Transport, ask: &Ask<'_>) {
        let query = self.query(ask);
        let udp = matches!(transport, dns::Transport::Udp);
        match dns::reply(message, &query, transport, &mut self.records) {
            // Another query's, forged, or not DNS: keep waiting.
            Err(dns::Error::Mismatch | dns::Error::Unreadable) if udp => {}
            Err(dns::Error::Truncated) => {
                let deadline_ms = ask.now_ms.saturating_add(ask.settings.timeout_ms);
                self.tcp(deadline_ms);
            }
            Err(dns::Error::NoName) => self.finish(Err(Error::NotFound)),
            Err(dns::Error::Server(2)) => self.retry(Error::Temporary, ask),
            Err(
                dns::Error::Server(_)
                | dns::Error::Mismatch
                | dns::Error::Unreadable
                | dns::Error::Format
                | dns::Error::Chain
                | dns::Error::TooLarge
                | dns::Error::Name,
            ) => self.retry(Error::Misbehaving, ask),
            Ok(answer) if lame(&answer.header) => self.retry(Error::Misbehaving, ask),
            // No answer of the type for anyone: no such host, and no
            // other server is asked. Answers of the type for another
            // name than the one asked give no address, and no error.
            Ok(answer) if answer.answers_of_type == 0 => self.finish(Err(Error::NotFound)),
            Ok(answer) => self.finish(Ok(answer.count)),
        }
    }
}

/// What an exchange needs of the lookup: the name, the settings, the
/// id for a new query, and the time.
struct Ask<'a> {
    name: &'a [u8],
    settings: &'a Settings,
    id: u16,
    now_ms: u64,
}

/// A referral from a server that does not recurse, which glibc and Go
/// pass over: no answer, no additional records, neither AA nor RA.
fn lame(header: &dns::Header) -> bool {
    let referral = header.answers == 0 && header.additionals == 0;
    referral && !header.authoritative() && !header.recursion_available()
}

impl Lookup {
    /// Starts the lookup. It may be over at once: a literal address,
    /// /etc/hosts, localhost, or a name that is not one.
    pub fn new(start: &Start<'_>) -> Lookup {
        const NONE: Address = Address::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let mut lookup = Lookup {
            settings: Settings {
                servers: [NONE; SERVERS_MAX],
                servers_count: 1,
                timeout_ms: 0,
                attempts: 1,
                transport: Transport::Udp,
                trust_ad: false,
            },
            queries: [Query::new(Lane::A), Query::new(Lane::Aaaa)],
            sequential: false,
            name: [0; NAME_MAX],
            name_length: 0,
            search: Search::EMPTY,
            candidates: [Candidate::AsIs; CANDIDATES_MAX],
            candidates_count: 0,
            bare: None,
            candidate: 0,
            current: [0; NAME_MAX],
            current_length: 0,
            error: None,
            order: start.order,
            key: start.random,
            counter: 0,
            rotation: None,
            addresses: [NONE; ADDRESSES_MAX],
            count: 0,
            files: 0,
            outcome: None,
        };
        lookup.restart(start);
        lookup
    }

    /// Starts another lookup in this one's place, as new does: nothing
    /// moves, and a TCP buffer it had is kept for the next. The sockets
    /// of the one before are the caller's to close first; what still
    /// comes on them carries old ids and is dropped.
    pub fn restart(&mut self, start: &Start<'_>) {
        let config = start.config;
        for (slot, server) in self.settings.servers.iter_mut().zip(config.servers()) {
            *slot = *server;
        }
        self.settings.servers_count = config.servers().len().clamp(1, SERVERS_MAX);
        self.settings.timeout_ms = config.timeout_ms;
        self.settings.attempts = usize::from(config.attempts.max(1));
        self.settings.transport = config.transport;
        self.settings.trust_ad = config.trust_ad;
        for query in &mut self.queries {
            query.reset();
        }
        self.sequential = matches!(config.queries, Queries::Sequential);
        self.name_length = 0;
        self.candidates_count = 0;
        self.bare = None;
        self.candidate = 0;
        self.current_length = 0;
        self.error = None;
        self.order = start.order;
        self.key = start.random;
        self.counter = 0;
        self.rotation = None;
        if matches!(config.rotation, Rotation::Rotate) {
            let first = siphash(&self.key, u64::MAX) % 256;
            self.rotation = usize::try_from(first).ok();
        }
        self.count = 0;
        self.files = 0;
        self.outcome = None;
        self.begin(start);
    }

    fn begin(&mut self, start: &Start<'_>) {
        let name = start.name;
        if let Some(literal) = address(name) {
            self.found(&[literal]);
            return;
        }
        if let Some(text) = start.hosts {
            self.files = hosts::hosts(text, name, &mut self.addresses);
        }
        let files_first = matches!(self.order, Order::FilesDns | Order::Files);
        if files_first && self.files > 0 {
            self.count = self.files;
            self.outcome = Some(Ok(()));
            return;
        }
        if localhost(name) {
            self.found(&[
                Address::new(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                Address::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ]);
            return;
        }
        if matches!(self.order, Order::Files) || !domain_name(name) {
            self.outcome = Some(Err(Error::NotFound));
            return;
        }
        // A domain name is at most NAME_MAX bytes.
        let Some(slot) = self.name.get_mut(..name.len()) else {
            self.outcome = Some(Err(Error::NotFound));
            return;
        };
        slot.copy_from_slice(name);
        self.name_length = name.len();
        let search = start.config.search();
        // rr: escape(copy): the lookup outlives the configuration.
        self.search.clone_from(search);
        let (count, bare) = name_list(name, start.config.ndots, search, &mut self.candidates);
        self.candidates_count = count;
        self.bare = bare;
        if count == 0 {
            self.end();
            return;
        }
        self.ask_name(start.now_ms);
        self.advance(start.now_ms);
    }

    /// Ends the lookup with these addresses.
    fn found(&mut self, addresses: &[Address]) {
        for (slot, address) in self.addresses.iter_mut().zip(addresses) {
            *slot = *address;
        }
        self.count = addresses.len().min(ADDRESSES_MAX);
        self.outcome = Some(Ok(()));
    }

    /// Asks both families of the current name.
    fn ask_name(&mut self, now_ms: u64) {
        self.current_length = 0;
        let name = self.name.get(..self.name_length).unwrap_or_default();
        let parts: [&[u8]; 3] = match self.candidates.get(self.candidate) {
            Some(Candidate::AsIs) => [name, b"", b""],
            Some(Candidate::Dotted) => [name, b".", b""],
            Some(Candidate::Suffix(index)) => {
                [name, b".", self.search.get(*index).unwrap_or_default()]
            }
            None => [b""; 3],
        };
        for part in parts {
            let end = self.current_length + part.len();
            // name_list kept each name to NAME_MAX.
            if let Some(slot) = self.current.get_mut(self.current_length..end) {
                slot.copy_from_slice(part);
                self.current_length = end;
            }
        }
        for query in &mut self.queries {
            query.state = State::Idle;
        }
        self.start_lane(Lane::A, now_ms);
        if !self.sequential {
            self.start_lane(Lane::Aaaa, now_ms);
        }
    }

    fn start_lane(&mut self, lane: Lane, now_ms: u64) {
        let count = self.settings.servers_count;
        let offset = match self.rotation.as_mut() {
            Some(next) => {
                // Go turns the first server one on for each query.
                let offset = *next % count;
                *next = offset + 1;
                offset
            }
            None => 0,
        };
        let id = self.next_id();
        let name = self.current.get(..self.current_length).unwrap_or_default();
        let ask = Ask {
            name,
            settings: &self.settings,
            id,
            now_ms,
        };
        let Some(query) = self.queries.get_mut(lane.index()) else {
            return;
        };
        query.step = 0;
        query.error = None;
        query.offset = offset;
        query.send(&ask);
    }

    fn next_id(&mut self) -> u16 {
        self.counter = self.counter.wrapping_add(1);
        u16::try_from(siphash(&self.key, self.counter) & 0xffff).unwrap_or(0)
    }

    /// After an event: starts AAAA after A when sequential, and once both
    /// are done takes the addresses, or asks the next name.
    fn advance(&mut self, now_ms: u64) {
        // Each turn either waits or moves to the next name.
        for _ in 0..=self.candidates_count {
            if self.outcome.is_some() {
                return;
            }
            let [first, second] = &self.queries;
            if !matches!(first.state, State::Done(_)) {
                return;
            }
            if matches!(second.state, State::Idle) {
                self.start_lane(Lane::Aaaa, now_ms);
                continue;
            }
            if !matches!(second.state, State::Done(_)) {
                return;
            }
            self.collect();
            if self.count > 0 {
                self.close();
                self.outcome = Some(Ok(()));
                return;
            }
            self.candidate += 1;
            if self.candidate >= self.candidates_count {
                self.end();
                return;
            }
            self.ask_name(now_ms);
        }
    }

    /// Takes both families' addresses of the name asked, or their errors.
    fn collect(&mut self) {
        let bare = self.bare == Some(self.candidate);
        for query in &self.queries {
            match query.state {
                State::Done(Ok(count)) => {
                    // What /etc/hosts gave is of no use once DNS answers.
                    let free = self.addresses.get_mut(self.count..).unwrap_or_default();
                    for (slot, record) in free.iter_mut().zip(query.records.iter().take(count)) {
                        *slot = Address::new(record.address);
                        self.count += 1;
                    }
                }
                State::Done(Err(error)) => {
                    if self.error.is_none() || bare {
                        self.error = Some(error);
                    }
                }
                State::Idle | State::Udp { .. } | State::Tcp { .. } => {}
            }
        }
    }

    /// No name gave an address: /etc/hosts last, or the error.
    fn end(&mut self) {
        self.close();
        if matches!(self.order, Order::DnsFiles) && self.files > 0 {
            self.count = self.files;
            self.outcome = Some(Ok(()));
            return;
        }
        self.outcome = Some(Err(self.error.unwrap_or(Error::NotFound)));
    }

    fn close(&mut self) {
        for query in &mut self.queries {
            if query.deadline_ms().is_some() {
                query.state = State::Done(Err(Error::Timeout));
                query.want = Some(Want::Close);
            }
        }
    }

    /// Runs f on the lane's query in its current exchange, then moves on.
    fn on(&mut self, lane: Lane, now_ms: u64, f: impl FnOnce(&mut Query, &Ask<'_>)) {
        if self.outcome.is_some() {
            return;
        }
        let name = self.current.get(..self.current_length).unwrap_or_default();
        let id = siphash(&self.key, self.counter.wrapping_add(1)) & 0xffff;
        let ask = Ask {
            name,
            settings: &self.settings,
            id: u16::try_from(id).unwrap_or(0),
            now_ms,
        };
        let Some(query) = self.queries.get_mut(lane.index()) else {
            return;
        };
        let step = query.step;
        f(query, &ask);
        // A retry took the id offered.
        if query.step != step {
            self.counter = self.counter.wrapping_add(1);
        }
        self.advance(now_ms);
    }

    /// A datagram that came on the lane's UDP socket.
    pub fn udp(&mut self, lane: Lane, message: &[u8], now_ms: u64) {
        self.on(lane, now_ms, |query, ask| {
            if matches!(query.state, State::Udp { .. }) {
                query.answer(message, dns::Transport::Udp, ask);
            }
        });
    }

    /// Bytes that came on the lane's TCP connection.
    pub fn tcp(&mut self, lane: Lane, bytes: &[u8], now_ms: u64) {
        self.on(lane, now_ms, |query, ask| {
            if !matches!(query.state, State::Tcp { .. }) {
                return;
            }
            if query.framing.feed(bytes).is_err() {
                query.retry(Error::Misbehaving, ask);
                return;
            }
            if query.framing.message().is_none() {
                return;
            }
            // The whole answer: whatever it says, this exchange is over.
            // The framing is lent out of the query while it reads, and
            // comes back cleared, its buffer kept.
            let mut framing = core::mem::replace(&mut query.framing, dns::Tcp::new());
            if let Some(message) = framing.message() {
                query.answer(message, dns::Transport::Tcp, ask);
            }
            framing.clear();
            query.framing = framing;
        });
    }

    /// The lane's socket failed: refused, unreachable, or closed before
    /// the whole answer came.
    pub fn failed(&mut self, lane: Lane, now_ms: u64) {
        self.on(lane, now_ms, |query, ask| {
            if query.deadline_ms().is_some() {
                query.retry(Error::Temporary, ask);
            }
        });
    }

    /// The time: exchanges past their deadline fail.
    pub fn tick(&mut self, now_ms: u64) {
        for lane in Lane::ALL {
            self.on(lane, now_ms, |query, ask| {
                if query
                    .deadline_ms()
                    .is_some_and(|deadline_ms| deadline_ms <= now_ms)
                {
                    query.retry(Error::Timeout, ask);
                }
            });
        }
    }

    /// The next thing to do, until None.
    pub fn action(&mut self) -> Option<Action<'_>> {
        let servers = &self.settings.servers;
        let count = self.settings.servers_count;
        for query in &mut self.queries {
            let Some(want) = query.want.take() else {
                continue;
            };
            let lane = query.lane;
            let index = (query.offset + query.step) % count;
            let server = *servers.get(index).unwrap_or(&servers[0]);
            let framed = query.message.get(..query.length).unwrap_or_default();
            return Some(match want {
                Want::Udp => Action::Udp {
                    lane,
                    server,
                    message: framed.get(2..).unwrap_or_default(),
                },
                Want::Tcp => Action::Tcp {
                    lane,
                    server,
                    message: framed,
                },
                Want::Close => Action::Close { lane },
            });
        }
        None
    }

    /// When to call tick next, or None when nothing waits.
    pub fn deadline_ms(&self) -> Option<u64> {
        self.queries.iter().filter_map(Query::deadline_ms).min()
    }

    /// None while the lookup runs; then the addresses, or why none.
    pub fn result(&self) -> Option<Result<&[Address], Error>> {
        let addresses = self.addresses.get(..self.count).unwrap_or_default();
        self.outcome.map(|outcome| outcome.map(|()| addresses))
    }

    /// Sorts the addresses found by RFC 6724, from the source address
    /// the system would use for each (see sort::sort).
    pub fn sort(&mut self, sources: &[Option<IpAddr>]) {
        sort::sort(
            self.addresses.get_mut(..self.count).unwrap_or_default(),
            sources,
        );
    }
}

/// Go's isDomainName: labels of letters, digits, `_` and `-`, not all
/// digits, none empty or past 63 bytes, 253 bytes in all and a final dot.
fn domain_name(name: &[u8]) -> bool {
    if name == b"." {
        return true;
    }
    let length = name.len();
    if length == 0 || length > NAME_MAX || (length == NAME_MAX && !name.ends_with(b".")) {
        return false;
    }
    let (mut last, mut letters, mut label) = (b'.', false, 0);
    for &byte in name {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                letters = true;
                label += 1;
            }
            b'0'..=b'9' => label += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                letters = true;
                label += 1;
            }
            b'.' => {
                if last == b'.' || last == b'-' || label == 0 || label > 63 {
                    return false;
                }
                label = 0;
            }
            _ => return false,
        }
        last = byte;
    }
    last != b'-' && label <= 63 && letters
}

/// Go's nameList: the names to ask, in order, into out; how many, and
/// which is the name as given. A name with ndots dots or more is asked
/// first as it is, else last; a final dot asks it alone; .onion never;
/// a name past NAME_MAX is passed over.
fn name_list(
    name: &[u8],
    ndots: u8,
    search: &Search,
    out: &mut [Candidate; CANDIDATES_MAX],
) -> (usize, Option<usize>) {
    let onion = |text: &[u8]| ends_with(text.strip_suffix(b".").unwrap_or(text), b".onion");
    if name.ends_with(b".") {
        if onion(name) {
            return (0, None);
        }
        out[0] = Candidate::AsIs;
        return (1, None);
    }
    let mut count = 0;
    let mut push = |candidate: Candidate| {
        if let Some(slot) = out.get_mut(count) {
            *slot = candidate;
            count += 1;
        }
        count - 1
    };
    let dots = name
        .iter()
        .fold(0, |total, byte| total + usize::from(*byte == b'.'));
    let first = dots >= usize::from(ndots);
    let dotted = name.len() < NAME_MAX && !onion(name);
    let mut bare = None;
    if first && dotted {
        bare = Some(push(Candidate::Dotted));
    }
    for index in 0..search.len() {
        let suffix = search.get(index).unwrap_or_default();
        if !onion(suffix) && name.len() + 1 + suffix.len() <= NAME_MAX {
            push(Candidate::Suffix(index));
        }
    }
    if !first && dotted {
        bare = Some(push(Candidate::Dotted));
    }
    (count, bare)
}

/// SipHash-2-4 of one word: query ids that whoever sees some cannot
/// tell the rest from, out of the caller's random key.
fn siphash(key: &[u8; 16], word: u64) -> u64 {
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = *key;
    let k0 = u64::from_le_bytes([a, b, c, d, e, f, g, h]);
    let k1 = u64::from_le_bytes([i, j, k, l, m, n, o, p]);
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let round = |state: &mut [u64; 4]| {
        let [mut v0, mut v1, mut v2, mut v3] = *state;
        v0 = v0.wrapping_add(v1);
        v1 = v1.rotate_left(13) ^ v0;
        v0 = v0.rotate_left(32);
        v2 = v2.wrapping_add(v3);
        v3 = v3.rotate_left(16) ^ v2;
        v0 = v0.wrapping_add(v3);
        v3 = v3.rotate_left(21) ^ v0;
        v2 = v2.wrapping_add(v1);
        v1 = v1.rotate_left(17) ^ v2;
        v2 = v2.rotate_left(32);
        *state = [v0, v1, v2, v3];
    };
    // One block of eight bytes, then the last, which holds the length.
    for block in [word, 8 << 56] {
        v[3] ^= block;
        round(&mut v);
        round(&mut v);
        v[0] ^= block;
    }
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// Records the last query of each lane, as a server would see it.
#[cfg(fuzzing)]
fn take_actions(lookup: &mut Lookup, sent: &mut [Vec<u8>; 2]) {
    while let Some(action) = lookup.action() {
        match action {
            Action::Udp { lane, message, .. } | Action::Tcp { lane, message, .. } => {
                let length = usize::from(matches!(action, Action::Tcp { .. })) * 2;
                sent[lane.index()].clear();
                sent[lane.index()].extend_from_slice(&message[length..]);
            }
            Action::Close { .. } => {}
        }
    }
}

/// Any bytes as the network's side of a lookup: answers built on the
/// queries sent, cut TCP, failures and time. Whatever comes, the lookup
/// ends within its bounds and gives no more addresses than the limit.
#[cfg(fuzzing)]
pub fn fuzz_lookup(input: &[u8]) {
    use super::fake::answer;
    let config = Config::parse(
        Some(b"nameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch a b\noptions attempts:2 timeout:1"),
        b"",
    );
    let start = Start {
        name: b"www",
        config: &config,
        order: Order::FilesDns,
        hosts: None,
        random: [7; 16],
        now_ms: 0,
    };
    let mut lookup = Lookup::new(&start);
    let mut sent: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    let mut now_ms = 0;
    for chunk in input.split(|byte| *byte == 0xa5) {
        take_actions(&mut lookup, &mut sent);
        let (&op, rest) = chunk.split_first().unwrap_or((&0, &[]));
        let lane = if op & 1 == 0 { Lane::A } else { Lane::Aaaa };
        let query = &sent[lane.index()];
        let flags = (u16::from(rest.first().copied().unwrap_or(0)) << 8) | 0x0080;
        let mut message = if query.is_empty() {
            Vec::new()
        } else {
            answer(query, flags & 0x87ff, &[])
        };
        if let (Some(counts), Some(given)) = (message.get_mut(6..12), rest.get(1..7)) {
            counts.copy_from_slice(given);
        }
        message.extend_from_slice(rest.get(7..).unwrap_or_default());
        match (op >> 1) % 5 {
            0 => lookup.udp(lane, &message, now_ms),
            1 => {
                let size = u16::try_from(message.len()).unwrap_or(0).to_be_bytes();
                lookup.tcp(lane, &size, now_ms);
                for piece in message.chunks(usize::from(op >> 4) + 1) {
                    lookup.tcp(lane, piece, now_ms);
                }
            }
            2 => lookup.failed(lane, now_ms),
            3 => lookup.udp(lane, rest, now_ms),
            _ => {
                now_ms += u64::from(op);
                lookup.tick(now_ms);
            }
        }
    }
    // A second at a time ends every exchange in time: three names, two
    // servers, two attempts, UDP and TCP.
    for _ in 0..3 * 2 * 2 * 2 {
        take_actions(&mut lookup, &mut sent);
        if lookup.result().is_some() {
            break;
        }
        now_ms += 1000;
        lookup.tick(now_ms);
    }
    let result = lookup.result().unwrap();
    if let Ok(addresses) = result {
        assert!(!addresses.is_empty() && addresses.len() <= ADDRESSES_MAX);
    }
    assert!(lookup.deadline_ms().is_none());
}

#[cfg(test)]
mod tests {
    use super::super::conf::Config;
    use super::super::fake::{answer, answer_into, asks, ip, ips, question};
    use super::super::nss::Order;
    use super::super::{Address, Error};
    use super::{Action, Lane, Lookup, Start, domain_name};
    use alloc::vec::Vec;
    use core::net::IpAddr;
    use test::Bencher;

    /// What a fake server does with a query.
    #[derive(Clone, Copy)]
    enum Reply {
        Addresses(&'static [&'static str]),
        NxDomain,
        ServFail,
        Refused,
        /// TC over UDP, the addresses over TCP.
        Truncate(&'static [&'static str]),
        /// Nothing: the query times out.
        Drop,
        /// The socket fails: ICMP unreachable, or a TCP reset.
        Unreachable,
        Lame,
        /// A reply with another id first, then the addresses.
        Forged(&'static [&'static str]),
    }

    /// A query the lookup sent.
    struct Sent {
        lane: Lane,
        server: IpAddr,
        name: Vec<u8>,
        tcp: bool,
        at_ms: u64,
    }

    /// Which servers answer how: by the name asked, then the server,
    /// then the family, else all alike.
    struct Rule {
        all: Reply,
        name: Option<(&'static [u8], Reply)>,
        server: Option<(&'static str, Reply)>,
        lane: Option<(Lane, Reply)>,
    }

    impl Rule {
        fn all(reply: Reply) -> Rule {
            Rule {
                all: reply,
                name: None,
                server: None,
                lane: None,
            }
        }

        fn name(self, name: &'static [u8], reply: Reply) -> Rule {
            Rule {
                name: Some((name, reply)),
                ..self
            }
        }

        fn server(self, server: &'static str, reply: Reply) -> Rule {
            Rule {
                server: Some((server, reply)),
                ..self
            }
        }

        fn lane(self, lane: Lane, reply: Reply) -> Rule {
            Rule {
                lane: Some((lane, reply)),
                ..self
            }
        }

        fn reply(&self, sent: &Sent) -> Reply {
            if let Some((name, reply)) = self.name
                && sent.name == name
            {
                return reply;
            }
            if let Some((server, reply)) = self.server
                && sent.server == ip(server).ip
            {
                return reply;
            }
            match self.lane {
                Some((lane, reply)) if lane == sent.lane => reply,
                Some(_) | None => self.all,
            }
        }
    }

    enum Delivery {
        Udp(Lane, Vec<u8>),
        Tcp(Lane, Vec<u8>),
        Fail(Lane),
    }

    /// A network of fake servers, each query answered as rule says, at
    /// once; when nothing comes, the clock jumps to the deadline.
    struct Net {
        rule: Rule,
        log: Vec<Sent>,
        now_ms: u64,
    }

    impl Net {
        fn new(rule: Rule) -> Net {
            Net {
                rule,
                log: Vec::new(),
                now_ms: 1000,
            }
        }

        fn run(&mut self, lookup: &mut Lookup) {
            for _ in 0..1000 {
                let mut deliveries = Vec::new();
                while let Some(action) = lookup.action() {
                    let (lane, server, message, tcp) = match action {
                        Action::Udp {
                            lane,
                            server,
                            message,
                        } => (lane, server, message, false),
                        Action::Tcp {
                            lane,
                            server,
                            message,
                        } => (lane, server, &message[2..], true),
                        Action::Close { .. } => continue,
                    };
                    assert_eq!(
                        usize::from(u16::from_be_bytes([message[10], message[11]])),
                        1
                    );
                    let sent = Sent {
                        lane,
                        server: server.ip,
                        name: question(message),
                        tcp,
                        at_ms: self.now_ms,
                    };
                    deliver(&mut deliveries, self.rule.reply(&sent), &sent, message);
                    self.log.push(sent);
                }
                let idle = deliveries.is_empty();
                for delivery in deliveries {
                    match delivery {
                        Delivery::Udp(lane, bytes) => lookup.udp(lane, &bytes, self.now_ms),
                        Delivery::Tcp(lane, bytes) => {
                            // In pieces, as TCP may bring it.
                            for piece in bytes.chunks(5) {
                                lookup.tcp(lane, piece, self.now_ms);
                            }
                        }
                        Delivery::Fail(lane) => lookup.failed(lane, self.now_ms),
                    }
                }
                if lookup.result().is_some() {
                    assert!(lookup.action().is_none() || lookup.deadline_ms().is_none());
                    return;
                }
                if idle {
                    self.now_ms = lookup.deadline_ms().unwrap();
                    lookup.tick(self.now_ms);
                }
            }
            panic!("the lookup did not end");
        }
    }

    fn deliver(out: &mut Vec<Delivery>, reply: Reply, sent: &Sent, query: &[u8]) {
        let lane = sent.lane;
        let respond = |flags: u16, ips: &[&str]| {
            let mut found = Vec::new();
            for text in ips {
                found.push(ip(text).ip);
            }
            let message = answer(query, flags, &found);
            if sent.tcp {
                let mut framed = Vec::new();
                framed.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
                framed.extend_from_slice(&message);
                Delivery::Tcp(lane, framed)
            } else {
                Delivery::Udp(lane, message)
            }
        };
        match reply {
            Reply::Addresses(ips) => out.push(respond(0, ips)),
            Reply::NxDomain => out.push(respond(3, &[])),
            Reply::ServFail => out.push(respond(2, &[])),
            Reply::Refused => out.push(respond(5, &[])),
            Reply::Truncate(ips) if sent.tcp => out.push(respond(0x0200, ips)),
            Reply::Truncate(_) => out.push(respond(0x0200, &[])),
            Reply::Drop => {}
            Reply::Unreachable => out.push(Delivery::Fail(lane)),
            Reply::Lame => {
                let mut message = answer(query, 0, &[]);
                message[3] &= !0x80;
                out.push(Delivery::Udp(lane, message));
            }
            Reply::Forged(ips) => {
                let mut forged = answer(query, 0, &[]);
                forged[0] ^= 0xff;
                out.push(Delivery::Udp(lane, forged));
                out.push(respond(0, ips));
            }
        }
    }

    fn lookup(name: &str, config: &Config, order: Order, hosts: Option<&[u8]>) -> Lookup {
        Lookup::new(&Start {
            name: name.as_bytes(),
            config,
            order,
            hosts,
            random: [1; 16],
            now_ms: 1000,
        })
    }

    fn conf(text: &str) -> Config {
        Config::parse(Some(text.as_bytes()), b"")
    }

    fn found(lookup: &Lookup) -> Result<Vec<Address>, Error> {
        let addresses = lookup.result().unwrap()?;
        let mut out = Vec::new();
        // rr: escape(copy): the test compares what the lookup found.
        out.extend_from_slice(addresses);
        Ok(out)
    }

    /// The queries as (server, name, lane, tcp).
    fn asked(net: &Net) -> Vec<(IpAddr, &[u8], Lane, bool)> {
        let mut out = Vec::new();
        for sent in &net.log {
            out.push((sent.server, sent.name.as_slice(), sent.lane, sent.tcp));
        }
        out
    }

    const ONE: &str = "nameserver 10.0.0.1\n";
    const TWO: &str = "nameserver 10.0.0.1\nnameserver 10.0.0.2\n";
    const BOTH: &[&str] = &["192.0.2.1", "2001:db8::1"];

    fn server(text: &str) -> IpAddr {
        ip(text).ip
    }

    /// A and AAAA go at once to the first server, over UDP, and both
    /// answers make the result, A first.
    #[test]
    fn answers() {
        let config = conf(ONE);
        let mut found_lookup = lookup("example.com", &config, Order::FilesDns, None);
        let mut net = Net::new(Rule::all(Reply::Addresses(BOTH)));
        net.run(&mut found_lookup);
        assert_eq!(found(&found_lookup), Ok(ips(BOTH)));
        let first = server("10.0.0.1");
        assert_eq!(
            asked(&net),
            [
                (first, &b"example.com."[..], Lane::A, false),
                (first, b"example.com.", Lane::Aaaa, false)
            ]
        );
        // A reply with another id is not the answer, and is waited past.
        let mut forged = lookup("example.com", &config, Order::FilesDns, None);
        Net::new(Rule::all(Reply::Forged(BOTH))).run(&mut forged);
        assert_eq!(found(&forged), Ok(ips(BOTH)));
    }

    /// The first server says nothing: after the timeout, the second.
    #[test]
    fn times_out_to_the_next_server() {
        let config = conf("nameserver 10.0.0.1\nnameserver 10.0.0.2\noptions timeout:2\n");
        let mut slow = lookup("example.com", &config, Order::Dns, None);
        let mut net = Net::new(Rule::all(Reply::Addresses(BOTH)).server("10.0.0.1", Reply::Drop));
        net.run(&mut slow);
        assert_eq!(found(&slow), Ok(ips(BOTH)));
        assert_eq!(net.log.len(), 4);
        assert_eq!(
            (net.log[2].server, net.log[2].at_ms),
            (server("10.0.0.2"), 3000)
        );
    }

    /// No server answers: each is asked attempts times, then Timeout.
    #[test]
    fn times_out() {
        let config =
            conf("nameserver 10.0.0.1\nnameserver 10.0.0.2\noptions attempts:3 timeout:1\n");
        let mut silent = lookup("example.com", &config, Order::Dns, None);
        let mut net = Net::new(Rule::all(Reply::Drop));
        net.run(&mut silent);
        assert_eq!(found(&silent), Err(Error::Timeout));
        // Two servers, three attempts, two families; a second apiece.
        assert_eq!(net.log.len(), 12);
        assert_eq!(net.now_ms, 1000 + 6 * 1000);
        // rr: escape(copy): the test compares the servers asked.
        let servers: Vec<IpAddr> = net
            .log
            .iter()
            .filter(|sent| sent.lane == Lane::A)
            .map(|sent| sent.server)
            .collect();
        let (a, b) = (server("10.0.0.1"), server("10.0.0.2"));
        assert_eq!(servers, [a, b, a, b, a, b]);
    }

    /// TC over UDP asks the same server again over TCP; use-vc asks
    /// over TCP alone.
    #[test]
    fn truncated_goes_to_tcp() {
        let config = conf(ONE);
        let mut cut = lookup("example.com", &config, Order::Dns, None);
        let mut net = Net::new(Rule::all(Reply::Truncate(BOTH)));
        net.run(&mut cut);
        assert_eq!(found(&cut), Ok(ips(BOTH)));
        // rr: escape(copy): the test compares the transports.
        let tcp: Vec<bool> = net.log.iter().map(|sent| sent.tcp).collect();
        assert_eq!(tcp, [false, false, true, true]);
        let config_vc = conf("nameserver 10.0.0.1\noptions use-vc\n");
        let mut vc = lookup("example.com", &config_vc, Order::Dns, None);
        let mut net_vc = Net::new(Rule::all(Reply::Truncate(BOTH)));
        net_vc.run(&mut vc);
        assert_eq!(found(&vc), Ok(ips(BOTH)));
        assert!(net_vc.log.iter().all(|sent| sent.tcp) && net_vc.log.len() == 2);
    }

    /// SERVFAIL, REFUSED, a lame referral or an unreachable server: the
    /// next server; when all fail so, the error says which way.
    #[test]
    fn failures_go_to_the_next_server() {
        let config = conf(TWO);
        for (reply, error) in [
            (Reply::ServFail, Error::Temporary),
            (Reply::Refused, Error::Misbehaving),
            (Reply::Lame, Error::Misbehaving),
            (Reply::Unreachable, Error::Temporary),
        ] {
            let mut rescued = lookup("example.com", &config, Order::Dns, None);
            let mut net = Net::new(Rule::all(Reply::Addresses(BOTH)).server("10.0.0.1", reply));
            net.run(&mut rescued);
            assert_eq!(found(&rescued), Ok(ips(BOTH)));
            assert_eq!(net.log.len(), 4);
            assert_eq!(net.now_ms, 1000, "no wait for a server that answered");
            let mut failing = lookup("example.com", &config, Order::Dns, None);
            let mut all = Net::new(Rule::all(reply));
            all.run(&mut failing);
            assert_eq!(found(&failing), Err(error));
            // Each name of the list: the search list is empty here.
            assert_eq!(all.log.len(), 2 * 2 * 2);
        }
    }

    /// NXDOMAIN ends a name at the first server, and the next name of
    /// the search list is asked; a name with fewer dots than ndots is
    /// asked as it is last.
    #[test]
    fn search_list() {
        let config = conf(
            "nameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch a.example b.example\noptions ndots:2\n",
        );
        let mut www = lookup("www.x", &config, Order::Dns, None);
        let mut net = Net::new(Rule::all(Reply::NxDomain).name(b"www.x.", Reply::Addresses(BOTH)));
        net.run(&mut www);
        assert_eq!(found(&www), Ok(ips(BOTH)));
        let first = server("10.0.0.1");
        // rr: escape(copy): the test compares the names asked.
        let names: Vec<&[u8]> = asked(&net).iter().map(|sent| sent.1).collect();
        assert_eq!(
            names,
            [
                &b"www.x.a.example."[..],
                b"www.x.a.example.",
                b"www.x.b.example.",
                b"www.x.b.example.",
                b"www.x.",
                b"www.x."
            ]
        );
        assert!(net.log.iter().all(|sent| sent.server == first));
        // With enough dots, as it is first; a final dot, alone.
        for (name, want) in [("a.b.c", &b"a.b.c."[..]), ("x.", b"x.")] {
            let mut dotted = lookup(name, &config, Order::Dns, None);
            let mut net_dotted = Net::new(Rule::all(Reply::Addresses(BOTH)));
            net_dotted.run(&mut dotted);
            assert_eq!(net_dotted.log[0].name, want);
        }
        let mut nowhere = lookup("x.", &config, Order::Dns, None);
        let mut net_nowhere = Net::new(Rule::all(Reply::NxDomain));
        net_nowhere.run(&mut nowhere);
        assert_eq!(found(&nowhere), Err(Error::NotFound));
        assert_eq!(net_nowhere.log.len(), 2);
    }

    /// The error of the name as given wins over the search list's.
    #[test]
    fn bare_name_error() {
        let config = conf("nameserver 10.0.0.1\nsearch a.example\n");
        let mut failing = lookup("www", &config, Order::Dns, None);
        let mut net = Net::new(Rule::all(Reply::NxDomain).name(b"www.", Reply::ServFail));
        net.run(&mut failing);
        assert_eq!(found(&failing), Err(Error::Temporary));
        let mut nx = lookup("www", &config, Order::Dns, None);
        Net::new(Rule::all(Reply::ServFail).name(b"www.", Reply::NxDomain)).run(&mut nx);
        assert_eq!(found(&nx), Err(Error::NotFound));
    }

    /// No address of a family is not a failure when the other has some.
    #[test]
    fn one_family() {
        let config = conf(ONE);
        let mut v4 = lookup("example.com", &config, Order::Dns, None);
        Net::new(Rule::all(Reply::Addresses(&["192.0.2.7"]))).run(&mut v4);
        assert_eq!(found(&v4), Ok(ips(&["192.0.2.7"])));
    }

    /// rotate starts each query one server on, from a random first.
    #[test]
    fn rotation() {
        let config =
            conf("nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\noptions rotate\n");
        let mut firsts = Vec::new();
        for random in 0..8 {
            let mut rotated = Lookup::new(&Start {
                name: b"example.com",
                config: &config,
                order: Order::Dns,
                hosts: None,
                random: [random; 16],
                now_ms: 0,
            });
            let mut net = Net::new(Rule::all(Reply::Addresses(BOTH)));
            net.run(&mut rotated);
            let a = config
                .servers()
                .iter()
                .position(|s| s.ip == net.log[0].server)
                .unwrap();
            let aaaa = config
                .servers()
                .iter()
                .position(|s| s.ip == net.log[1].server)
                .unwrap();
            assert_eq!(aaaa, (a + 1) % 3);
            firsts.push(a);
        }
        assert!(firsts.contains(&0) && firsts.contains(&1) && firsts.contains(&2));
    }

    /// single-request asks AAAA only once A has its answer.
    #[test]
    fn single_request() {
        let config = conf("nameserver 10.0.0.1\noptions single-request timeout:1\n");
        let mut sequential = lookup("example.com", &config, Order::Dns, None);
        let mut net = Net::new(Rule::all(Reply::Addresses(BOTH)).lane(Lane::A, Reply::Drop));
        net.run(&mut sequential);
        assert_eq!(found(&sequential), Ok(ips(&["2001:db8::1"])));
        // rr: escape(copy): the test compares the order of the queries.
        let lanes: Vec<(Lane, u64)> = net.log.iter().map(|sent| (sent.lane, sent.at_ms)).collect();
        assert_eq!(
            lanes,
            [(Lane::A, 1000), (Lane::A, 2000), (Lane::Aaaa, 3000)]
        );
    }

    /// Literals, /etc/hosts in either order, localhost, and names that
    /// are not, without a query.
    #[test]
    fn without_dns() {
        let config = conf(ONE);
        let hosts: &[u8] = b"192.0.2.9 db\n";
        let none = |name: &str, order: Order, text: Option<&[u8]>| {
            let mut quiet = lookup(name, &config, order, text);
            let mut net = Net::new(Rule::all(Reply::Drop));
            if quiet.result().is_none() {
                net.run(&mut quiet);
            }
            (found(&quiet), net.log.len())
        };
        assert_eq!(
            none("db", Order::FilesDns, Some(hosts)),
            (Ok(ips(&["192.0.2.9"])), 0)
        );
        assert_eq!(
            none("db", Order::Files, Some(hosts)),
            (Ok(ips(&["192.0.2.9"])), 0)
        );
        assert_eq!(
            none("other", Order::Files, Some(hosts)),
            (Err(Error::NotFound), 0)
        );
        assert_eq!(
            none("fe80::1%eth0", Order::Dns, None),
            (Ok(ips(&["fe80::1%eth0"])), 0)
        );
        assert_eq!(
            none("192.0.2.1", Order::Dns, None),
            (Ok(ips(&["192.0.2.1"])), 0)
        );
        assert_eq!(
            none("localhost", Order::Dns, None),
            (Ok(ips(&["::1", "127.0.0.1"])), 0)
        );
        assert_eq!(
            none("a.localhost.", Order::FilesDns, Some(b"\n")),
            (Ok(ips(&["::1", "127.0.0.1"])), 0)
        );
        assert_eq!(
            none("localhost", Order::FilesDns, Some(b"127.0.0.2 localhost\n")),
            (Ok(ips(&["127.0.0.2"])), 0)
        );
        for bad in [
            "", "a..b", "-a.b", "a-.b", "123", "a b", "x.onion", "x.onion.",
        ] {
            assert_eq!(
                none(bad, Order::Dns, None),
                (Err(Error::NotFound), 0),
                "{bad}"
            );
        }
        // dns,files asks DNS first, and hosts when it found nothing.
        let mut last = lookup("db", &config, Order::DnsFiles, Some(hosts));
        let mut net = Net::new(Rule::all(Reply::NxDomain));
        net.run(&mut last);
        assert_eq!(found(&last), Ok(ips(&["192.0.2.9"])));
        assert_eq!(net.log.len(), 2);
    }

    /// trust-ad sets AD in each query, and only then.
    #[test]
    fn trust_ad() {
        for (text, ad) in [("nameserver 10.0.0.1\noptions trust-ad\n", 0x20), (ONE, 0)] {
            let config = conf(text);
            let mut asking = lookup("example.com", &config, Order::Dns, None);
            let Some(Action::Udp { message, .. }) = asking.action() else {
                panic!("no query");
            };
            assert_eq!(message[3] & 0x20, ad);
        }
    }

    #[test]
    fn domain_names() {
        let long = [b'a'; 63];
        let mut name = Vec::new();
        for _ in 0..4 {
            name.extend_from_slice(&long);
            name.push(b'.');
        }
        assert!(domain_name(&name[..253]));
        assert!(!domain_name(&name[..254]));
        name.truncate(252);
        name.push(b'.');
        assert!(domain_name(&name));
        assert!(!domain_name(&[b'a'; 64]));
        for good in [".", "a", "_srv.x", "1a", "a-b.c.", "x1.2"] {
            assert!(domain_name(good.as_bytes()), "{good}");
        }
    }

    /// A server for the bench that keeps its buffers from one lookup to
    /// the next, so that what allocates is the lookup alone: NXDOMAIN
    /// for every name but www.b.example, which is cut over UDP and
    /// answered over TCP.
    struct Server {
        queries: [Vec<u8>; 2],
        tcp: [bool; 2],
        reply: Vec<u8>,
        addresses: [IpAddr; 2],
    }

    impl Server {
        fn serve(&mut self, lookup: &mut Lookup) {
            for _ in 0..100 {
                let mut asked = [false; 2];
                while let Some(action) = lookup.action() {
                    let (lane, message, tcp) = match action {
                        Action::Udp { lane, message, .. } => (lane, message, false),
                        Action::Tcp { lane, message, .. } => (lane, &message[2..], true),
                        Action::Close { .. } => continue,
                    };
                    let query = &mut self.queries[lane.index()];
                    query.clear();
                    query.extend_from_slice(message);
                    self.tcp[lane.index()] = tcp;
                    asked[lane.index()] = true;
                }
                for lane in Lane::ALL {
                    if !asked[lane.index()] {
                        continue;
                    }
                    let query = &self.queries[lane.index()];
                    let found = asks(query, b"\x03www\x01b\x07example\x00");
                    let flags = if found { 0x0200 } else { 3 };
                    let ips: &[IpAddr] = if found { &self.addresses } else { &[] };
                    answer_into(&mut self.reply, query, flags, ips);
                    if self.tcp[lane.index()] {
                        let size = u16::try_from(self.reply.len()).unwrap().to_be_bytes();
                        lookup.tcp(lane, &size, 1000);
                        lookup.tcp(lane, &self.reply, 1000);
                    } else {
                        lookup.udp(lane, &self.reply, 1000);
                    }
                }
                if lookup.result().is_some() {
                    return;
                }
            }
            panic!("the lookup did not end");
        }
    }

    /// A lookup through the search list: NXDOMAIN for the first name,
    /// then A and AAAA, TC and TCP for the second.
    #[bench]
    fn full_lookup(b: &mut Bencher) {
        let config = conf("nameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch a.example b.example\n");
        let mut server = Server {
            queries: [Vec::new(), Vec::new()],
            tcp: [false; 2],
            reply: Vec::new(),
            addresses: [ip("192.0.2.1").ip, ip("2001:db8::1").ip],
        };
        let start = Start {
            name: b"www",
            config: &config,
            order: Order::FilesDns,
            hosts: Some(b"127.0.0.1 localhost\n"),
            random: [1; 16],
            now_ms: 1000,
        };
        b.iter(|| {
            let mut fresh = Lookup::new(&start);
            server.serve(&mut fresh);
            assert_eq!(
                fresh.result().map(|result| result.map(<[Address]>::len)),
                Some(Ok(2))
            );
        });
    }

    /// The same lookup again in the same place: its TCP buffers are
    /// kept, and nothing allocates or moves.
    #[bench]
    fn lookup_again(b: &mut Bencher) {
        let config = conf("nameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch a.example b.example\n");
        let mut server = Server {
            queries: [Vec::new(), Vec::new()],
            tcp: [false; 2],
            reply: Vec::new(),
            addresses: [ip("192.0.2.1").ip, ip("2001:db8::1").ip],
        };
        let start = Start {
            name: b"www",
            config: &config,
            order: Order::FilesDns,
            hosts: Some(b"127.0.0.1 localhost\n"),
            random: [1; 16],
            now_ms: 1000,
        };
        let mut again = Lookup::new(&start);
        b.iter(|| {
            again.restart(&start);
            server.serve(&mut again);
            assert_eq!(
                again.result().map(|result| result.map(<[Address]>::len)),
                Some(Ok(2))
            );
        });
    }

    /// The lookup's size, which its owner holds whole.
    #[test]
    fn size() {
        assert!(size_of::<Lookup>() <= 8192, "{}", size_of::<Lookup>());
    }
}
