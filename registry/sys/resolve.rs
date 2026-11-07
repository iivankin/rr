//! Looking up a host's addresses as the system would, without blocking
//! the caller's loop, the same on all three: start a lookup, poll it
//! until it is done, take the addresses; drop it to cancel.
//!
//! Linux has no C library here: the lookup is resolver.rs, Go's own
//! resolver, on this file's sockets, which the caller's poll loop waits
//! on (wait() says which, and until when). macOS keeps VPN and split DNS
//! in its system configuration, not resolv.conf, so its getaddrinfo
//! answers, as Go's does there, on a thread of its own; a pipe says it
//! is done. Windows answers through GetAddrInfoW on a thread too, as Go
//! does there, and a pair of loopback sockets says it is done, which a
//! WSAPoll waits on beside the program's own sockets.

use super::wait;
use alloc::vec::Vec;
use core::net::IpAddr;

/// What a lookup waits on: the type every component's poll loop takes.
pub use super::wait::Wait;

/// An address, and for a link-local IPv6 one the interface it is on.
#[derive(Clone, Copy)]
pub struct Address {
    pub ip: IpAddr,
    pub scope: u32,
}

impl Address {
    #[cfg(target_os = "linux")]
    const NONE: Address = Address {
        ip: IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
        scope: 0,
    };
}

/// Why a lookup gave no address.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// No such host.
    NotFound,
    /// No answer in time.
    Timeout,
    /// The servers or the network failed for now.
    Temporary,
    /// Anything else: a server that answers nonsense, a system error.
    Failed,
}

/// One name's lookup. Dropping it cancels it.
pub struct Lookup {
    os: os::State,
}

impl Lookup {
    /// Starts looking up name, a host name or a literal address.
    pub fn start(name: &[u8]) -> Lookup {
        Lookup {
            os: os::State::start(name),
        }
    }

    /// Does what is ready, without waiting: None while the lookup runs,
    /// then the addresses, best first, or why there are none.
    pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
        self.os.poll()
    }

    /// What to wait on before polling again.
    pub fn wait(&self) -> Wait {
        self.os.wait()
    }

    /// Stops the lookup; what it had is released.
    pub fn cancel(self) {
        drop(self);
    }
}

/// Looks up name and waits for the answer.
pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
    os::resolve(name)
}

/// The addresses of a lookup that is over, for the caller to keep.
fn owned(result: Result<&[Address], Error>) -> Result<Vec<Address>, Error> {
    let mut addresses = Vec::new();
    // rr: escape(copy): the lookup that holds them ends here.
    addresses.extend_from_slice(result?);
    Ok(addresses)
}

/// Polls the lookup and waits as it says, until it is over.
fn finish(mut lookup: Lookup) -> Result<Vec<Address>, Error> {
    // Each wait ends at the lookup's own deadline, and the lookup ends
    // once its deadlines have passed.
    loop {
        if let Some(result) = lookup.poll() {
            return owned(result);
        }
        wait::block(&lookup.wait());
    }
}

/// The name with a NUL after it, or None when it holds one.
fn c_string(name: &[u8]) -> Option<Vec<u8>> {
    if name.contains(&0) {
        return None;
    }
    let mut text = Vec::with_capacity(name.len() + 1);
    text.extend_from_slice(name);
    text.push(0);
    Some(text)
}

#[cfg(target_os = "linux")]
mod os {
    use super::super::file::{self, Descriptor};
    use super::super::wait::{self, Fd, POLLERR, POLLHUP, POLLIN, POLLOUT};
    use super::{Address, Error, Wait};
    use crate::dns;
    use crate::resolver;
    use crate::resolver::ADDRESSES_MAX;
    use crate::resolver::conf::Config;
    use crate::resolver::lookup::{Action, Lane, Start};
    use crate::resolver::nss::{self, Nss, Order, Plan};
    use alloc::vec::Vec;
    use core::net::IpAddr;

    #[cfg(target_arch = "x86_64")]
    mod nr {
        pub const IOCTL: usize = 16;
        pub const SOCKET: usize = 41;
        pub const CONNECT: usize = 42;
        pub const SENDTO: usize = 44;
        pub const RECVFROM: usize = 45;
        pub const GETSOCKNAME: usize = 51;
        pub const GETSOCKOPT: usize = 55;
        pub const UNAME: usize = 63;
        pub const CLOCK_GETTIME: usize = 228;
        pub const GETRANDOM: usize = 318;
    }

    #[cfg(target_arch = "aarch64")]
    mod nr {
        pub const IOCTL: usize = 29;
        pub const SOCKET: usize = 198;
        pub const CONNECT: usize = 203;
        pub const SENDTO: usize = 206;
        pub const RECVFROM: usize = 207;
        pub const GETSOCKNAME: usize = 204;
        pub const GETSOCKOPT: usize = 209;
        pub const UNAME: usize = 160;
        pub const CLOCK_GETTIME: usize = 113;
        pub const GETRANDOM: usize = 278;
    }

    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    const SOCK_STREAM: usize = 1;
    const SOCK_DGRAM: usize = 2;
    const SOCK_NONBLOCK: usize = 0o4000;
    const SOCK_CLOEXEC: usize = 0o2_000_000;
    const SOL_SOCKET: usize = 1;
    const SO_ERROR: usize = 4;
    const SIOCGIFINDEX: usize = 0x8933;
    const CLOCK_MONOTONIC: usize = 1;
    const EINTR: isize = 4;
    const EAGAIN: isize = 11;
    const EINPROGRESS: isize = 115;
    const PORT: u16 = 53;

    /// The most bytes read of resolv.conf and nsswitch.conf, and of
    /// /etc/hosts, which blocking lists make long.
    const CONF_BYTES_MAX: usize = 64 << 10;
    const HOSTS_BYTES_MAX: usize = 16 << 20;
    /// The largest datagram read: what servers send to an EDNS0 query
    /// even when they pass over its size.
    const DATAGRAM_MAX: usize = 4096;
    /// The most datagrams read from a socket in one poll.
    const DATAGRAMS_MAX: usize = 8;

    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        address: [u8; 4],
        zero: [u8; 8],
    }

    #[repr(C)]
    struct SockaddrIn6 {
        family: u16,
        port: u16,
        flowinfo: u32,
        address: [u8; 16],
        scope: u32,
    }

    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    /// struct ifreq: an interface's name, then its index.
    #[repr(C)]
    struct InterfaceRequest {
        name: [u8; 16],
        index: i32,
        rest: [u8; 20],
    }

    /// A socket's address, as connect takes it.
    enum Peer {
        V4(SockaddrIn),
        V6(SockaddrIn6),
    }

    impl Peer {
        fn new(ip: IpAddr, scope: u32) -> Peer {
            match ip {
                IpAddr::V4(v4) => Peer::V4(SockaddrIn {
                    family: AF_INET,
                    port: PORT.to_be(),
                    address: v4.octets(),
                    zero: [0; 8],
                }),
                IpAddr::V6(v6) => Peer::V6(SockaddrIn6 {
                    family: AF_INET6,
                    port: PORT.to_be(),
                    flowinfo: 0,
                    address: v6.octets(),
                    scope,
                }),
            }
        }

        fn family(&self) -> u16 {
            match self {
                Peer::V4(_) => AF_INET,
                Peer::V6(_) => AF_INET6,
            }
        }

        /// The address and its size, for a system call.
        fn raw(&mut self) -> (usize, usize) {
            match self {
                Peer::V4(v4) => ((&raw mut *v4).expose_provenance(), size_of::<SockaddrIn>()),
                Peer::V6(v6) => ((&raw mut *v6).expose_provenance(), size_of::<SockaddrIn6>()),
            }
        }
    }

    /// System call n on plain numbers and memory the caller vouches for:
    /// its result, or the error number.
    fn call(n: usize, args: [usize; 6]) -> Result<usize, isize> {
        file::call(n, args).map_err(|error| isize::try_from(error).unwrap_or(isize::MAX))
    }

    /// The file at path, up to limit bytes; None when it cannot be
    /// read, which Go takes as no file.
    fn read_file(path: &[u8], limit: usize) -> Option<Vec<u8>> {
        let mut text = Vec::new();
        match file::read(path, limit, &mut text) {
            Ok(_whole) => Some(text),
            Err(_) => None,
        }
    }

    /// The host's name, from uname's nodename, in names.
    fn hostname(names: &mut [u8; 6 * 65]) -> &[u8] {
        if call(
            nr::UNAME,
            [names.as_mut_ptr().expose_provenance(), 0, 0, 0, 0, 0],
        )
        .is_err()
        {
            return b"";
        }
        let node = names.get(65..130).unwrap_or_default();
        let end = node
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(node.len());
        node.get(..end).unwrap_or_default()
    }

    fn random() -> [u8; 16] {
        let mut bytes = [0u8; 16];
        // getrandom of 16 bytes waits only before the kernel's pool is
        // first ready, early in boot.
        // rr: escape(discard): on failure the bytes stay zero, which only
        // makes ids easier to guess.
        let _filled = call(
            nr::GETRANDOM,
            [bytes.as_mut_ptr().expose_provenance(), 16, 0, 0, 0, 0],
        );
        bytes
    }

    pub fn now_ms() -> u64 {
        let mut time = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        // rr: escape(discard): the monotonic clock is always there.
        let _read = call(
            nr::CLOCK_GETTIME,
            [
                CLOCK_MONOTONIC,
                (&raw mut time).expose_provenance(),
                0,
                0,
                0,
                0,
            ],
        );
        let seconds = u64::try_from(time.seconds).unwrap_or(0);
        let milliseconds = u64::try_from(time.nanoseconds / 1_000_000).unwrap_or(0);
        seconds.saturating_mul(1000).saturating_add(milliseconds)
    }

    /// The interface index of a zone: its number, or its name's index.
    fn scope(zone: &[u8]) -> u32 {
        if zone.is_empty() {
            return 0;
        }
        if zone.iter().all(u8::is_ascii_digit) {
            let mut number: u32 = 0;
            for digit in zone {
                number = number
                    .saturating_mul(10)
                    .saturating_add(u32::from(digit - b'0'));
            }
            return number;
        }
        let mut request = InterfaceRequest {
            name: [0; 16],
            index: 0,
            rest: [0; 20],
        };
        // A zone is at most 16 bytes; the name needs its NUL.
        let Some(slot) = request
            .name
            .get_mut(..zone.len())
            .filter(|_| zone.len() < 16)
        else {
            return 0;
        };
        slot.copy_from_slice(zone);
        let Ok(fd) = call(
            nr::SOCKET,
            [usize::from(AF_INET), SOCK_DGRAM | SOCK_CLOEXEC, 0, 0, 0, 0],
        ) else {
            return 0;
        };
        let socket = Descriptor::new(fd);
        let ask = [
            socket.raw(),
            SIOCGIFINDEX,
            (&raw mut request).expose_provenance(),
            0,
            0,
            0,
        ];
        match call(nr::IOCTL, ask) {
            Ok(_) => u32::try_from(request.index).unwrap_or(0),
            Err(_) => 0,
        }
    }

    fn to_address(address: &resolver::Address) -> Address {
        Address {
            ip: address.ip,
            scope: scope(address.zone.as_bytes()),
        }
    }

    /// A socket of kind to server's port 53, connecting; for UDP the
    /// connect is done, for TCP it goes on in the background.
    fn open(server: &resolver::Address, kind: usize) -> Option<Descriptor> {
        let mut peer = Peer::new(server.ip, scope(server.zone.as_bytes()));
        let flags = kind | SOCK_NONBLOCK | SOCK_CLOEXEC;
        let fd = call(nr::SOCKET, [usize::from(peer.family()), flags, 0, 0, 0, 0]).ok()?;
        let socket = Descriptor::new(fd);
        let (address, size) = peer.raw();
        match call(nr::CONNECT, [socket.raw(), address, size, 0, 0, 0]) {
            Ok(_) | Err(EINPROGRESS) => Some(socket),
            Err(_) => None,
        }
    }

    fn send(socket: &Descriptor, bytes: &[u8]) -> Result<usize, isize> {
        call(
            nr::SENDTO,
            [
                socket.raw(),
                bytes.as_ptr().expose_provenance(),
                bytes.len(),
                0,
                0,
                0,
            ],
        )
    }

    fn receive(socket: &Descriptor, into: &mut [u8]) -> Result<usize, isize> {
        let ask = [
            socket.raw(),
            into.as_mut_ptr().expose_provenance(),
            into.len(),
            0,
            0,
            0,
        ];
        call(nr::RECVFROM, ask)
    }

    /// The error a background connect ended with, 0 when it worked.
    fn connect_error(socket: &Descriptor) -> i32 {
        let mut error: i32 = 0;
        let mut size: u32 = 4;
        let ask = [
            socket.raw(),
            SOL_SOCKET,
            SO_ERROR,
            (&raw mut error).expose_provenance(),
            (&raw mut size).expose_provenance(),
            0,
        ];
        match call(nr::GETSOCKOPT, ask) {
            Ok(_) => error,
            Err(_) => -1,
        }
    }

    /// The source address the system would use to reach address, as Go
    /// learns it: connect a UDP socket, which sends nothing, and ask.
    fn source(address: &Address) -> Option<IpAddr> {
        let mut peer = Peer::new(address.ip, address.scope);
        let fd = call(
            nr::SOCKET,
            [
                usize::from(peer.family()),
                SOCK_DGRAM | SOCK_CLOEXEC,
                0,
                0,
                0,
                0,
            ],
        )
        .ok()?;
        let socket = Descriptor::new(fd);
        let (target, size) = peer.raw();
        call(nr::CONNECT, [socket.raw(), target, size, 0, 0, 0]).ok()?;
        let mut local = Peer::new(address.ip, 0);
        let (into, capacity) = local.raw();
        let mut length = u32::try_from(capacity).ok()?;
        let ask = [
            socket.raw(),
            into,
            (&raw mut length).expose_provenance(),
            0,
            0,
            0,
        ];
        call(nr::GETSOCKNAME, ask).ok()?;
        match local {
            Peer::V4(v4) => Some(IpAddr::from(v4.address)),
            Peer::V6(v6) => Some(IpAddr::from(v6.address)),
        }
    }

    /// A lane's socket: UDP, or TCP with the query still to write.
    struct Socket {
        descriptor: Descriptor,
        tcp: Option<Tcp>,
    }

    struct Tcp {
        pending: [u8; dns::QUERY_MAX],
        length: usize,
        written: usize,
    }

    impl Socket {
        fn events(&self) -> i16 {
            match &self.tcp {
                Some(tcp) if tcp.written < tcp.length => POLLOUT,
                Some(_) | None => POLLIN,
            }
        }
    }

    pub struct State {
        lookup: resolver::lookup::Lookup,
        sockets: [Option<Socket>; 2],
        /// The addresses, to the count the outcome gives.
        found: [Address; ADDRESSES_MAX],
        outcome: Option<Result<usize, Error>>,
    }

    fn error(error: resolver::Error) -> Error {
        match error {
            resolver::Error::NotFound => Error::NotFound,
            resolver::Error::Timeout => Error::Timeout,
            resolver::Error::Temporary => Error::Temporary,
            resolver::Error::Misbehaving => Error::Failed,
        }
    }

    impl State {
        pub fn start(name: &[u8]) -> State {
            let mut names = [0; 6 * 65];
            let hostname = hostname(&mut names);
            let resolv = read_file(b"/etc/resolv.conf", CONF_BYTES_MAX);
            let config = Config::parse(resolv.as_deref(), hostname);
            let nss =
                read_file(b"/etc/nsswitch.conf", CONF_BYTES_MAX).map(|text| Nss::parse(&text));
            // No C library here: Go's netgo answer, which is always its own.
            let order = match nss::plan(nss.as_ref(), &config, name, None) {
                Plan::Own(order) => order,
                Plan::System => Order::FilesDns,
            };
            let hosts = read_file(b"/etc/hosts", HOSTS_BYTES_MAX);
            let start = Start {
                name,
                config: &config,
                order,
                hosts: hosts.as_deref(),
                random: random(),
                now_ms: now_ms(),
            };
            let mut state = State {
                lookup: resolver::lookup::Lookup::new(&start),
                sockets: [None, None],
                found: [Address::NONE; ADDRESSES_MAX],
                outcome: None,
            };
            state.act(start.now_ms);
            state
        }

        pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
            if self.outcome.is_none() {
                self.step();
            }
            let found = &self.found;
            self.outcome
                .map(|outcome| outcome.map(|count| found.get(..count).unwrap_or_default()))
        }

        /// Reads what is ready, then moves the lookup on.
        fn step(&mut self) {
            // Each lane's socket in its own slot, none where it has none.
            let mut wait = Wait::READY;
            wait.count = 2;
            for (slot, socket) in wait.fds.iter_mut().zip(&self.sockets) {
                if let Some(socket) = socket {
                    *slot = Fd {
                        fd: socket.descriptor.fd(),
                        events: socket.events(),
                    };
                }
            }
            let happened = wait::ready(&wait);
            let now = now_ms();
            for (lane, revents) in Lane::ALL.into_iter().zip(happened) {
                if revents != 0 {
                    self.ready(lane, revents, now);
                }
            }
            self.lookup.tick(now);
            self.act(now);
            self.finish();
        }

        /// The lane's socket is ready for what it waits on.
        fn ready(&mut self, lane: Lane, revents: i16, now: u64) {
            let mut buffer = [0; DATAGRAM_MAX];
            let Some(socket) = self.sockets.get_mut(lane.index()).and_then(Option::as_mut) else {
                return;
            };
            let failed = revents & (POLLERR | POLLHUP) != 0;
            match socket.tcp.as_mut() {
                None => {
                    for _ in 0..DATAGRAMS_MAX {
                        match receive(&socket.descriptor, &mut buffer) {
                            Ok(n) => {
                                self.lookup
                                    .udp(lane, buffer.get(..n).unwrap_or_default(), now)
                            }
                            Err(EAGAIN | EINTR) => break,
                            Err(_) => {
                                // Refused or unreachable, as ICMP said.
                                self.lookup.failed(lane, now);
                                break;
                            }
                        }
                    }
                }
                Some(tcp) if tcp.written < tcp.length => {
                    if failed || connect_error(&socket.descriptor) != 0 {
                        self.lookup.failed(lane, now);
                        return;
                    }
                    match send(
                        &socket.descriptor,
                        tcp.pending.get(tcp.written..tcp.length).unwrap_or_default(),
                    ) {
                        Ok(n) => tcp.written += n,
                        Err(EAGAIN | EINTR) => {}
                        Err(_) => self.lookup.failed(lane, now),
                    }
                }
                Some(_) => match receive(&socket.descriptor, &mut buffer) {
                    // Closed before the whole answer came.
                    Ok(0) => self.lookup.failed(lane, now),
                    Ok(n) => self
                        .lookup
                        .tcp(lane, buffer.get(..n).unwrap_or_default(), now),
                    Err(EAGAIN | EINTR) => {}
                    Err(_) => self.lookup.failed(lane, now),
                },
            }
        }

        /// Does what the lookup asks: sockets opened, queries sent.
        fn act(&mut self, now: u64) {
            // Each turn fails a lane whose socket would not open, which
            // the lookup answers with another server or its end.
            for _ in 0..=resolver::conf::SERVERS_MAX * usize::from(resolver::conf::ATTEMPTS_MAX) * 2
            {
                let mut failed = [false; 2];
                while let Some(action) = self.lookup.action() {
                    let (lane, opened) = match action {
                        Action::Udp {
                            lane,
                            server,
                            message,
                        } => {
                            let socket = open(&server, SOCK_DGRAM)
                                .filter(|socket| send(socket, message).is_ok());
                            let opened = socket.map(|descriptor| Socket {
                                descriptor,
                                tcp: None,
                            });
                            (lane, Some(opened))
                        }
                        Action::Tcp {
                            lane,
                            server,
                            message,
                        } => {
                            let mut pending = [0; dns::QUERY_MAX];
                            let length = message.len().min(dns::QUERY_MAX);
                            // The query waits here until the connection is up.
                            if let (Some(slot), Some(query)) =
                                (pending.get_mut(..length), message.get(..length))
                            {
                                slot.copy_from_slice(query);
                            }
                            let tcp = Some(Tcp {
                                pending,
                                length,
                                written: 0,
                            });
                            let opened = open(&server, SOCK_STREAM)
                                .map(|descriptor| Socket { descriptor, tcp });
                            (lane, Some(opened))
                        }
                        Action::Close { lane } => (lane, None),
                    };
                    let Some(slot) = self.sockets.get_mut(lane.index()) else {
                        continue;
                    };
                    *slot = None;
                    if let Some(opened) = opened {
                        if opened.is_none()
                            && let Some(flag) = failed.get_mut(lane.index())
                        {
                            *flag = true;
                        }
                        *slot = opened;
                    }
                }
                if failed == [false; 2] {
                    return;
                }
                for (lane, flag) in Lane::ALL.into_iter().zip(failed) {
                    if flag {
                        self.lookup.failed(lane, now);
                    }
                }
            }
        }

        /// Once the lookup is over: the sockets closed, the addresses
        /// sorted by the routes the system has to each.
        fn finish(&mut self) {
            let Some(result) = self.lookup.result() else {
                return;
            };
            let mut sources = [None; ADDRESSES_MAX];
            let count = match result {
                Ok(addresses) => {
                    for (slot, address) in sources.iter_mut().zip(addresses) {
                        *slot = source(&to_address(address));
                    }
                    addresses.len().min(ADDRESSES_MAX)
                }
                Err(_) => 0,
            };
            self.lookup.sort(sources.get(..count).unwrap_or_default());
            self.sockets = [None, None];
            self.outcome = Some(match self.lookup.result() {
                Some(Ok(addresses)) => {
                    for (slot, address) in self.found.iter_mut().zip(addresses) {
                        *slot = to_address(address);
                    }
                    Ok(addresses.len().min(ADDRESSES_MAX))
                }
                Some(Err(failure)) => Err(error(failure)),
                None => Err(Error::Failed),
            });
        }

        pub fn wait(&self) -> Wait {
            let mut wait = Wait::READY;
            if self.outcome.is_some() {
                return wait;
            }
            for socket in self.sockets.iter().flatten() {
                if let Some(slot) = wait.fds.get_mut(wait.count) {
                    *slot = Fd {
                        fd: socket.descriptor.fd(),
                        events: socket.events(),
                    };
                    wait.count += 1;
                }
            }
            wait.timeout_ms = self
                .lookup
                .deadline_ms()
                .map(|deadline| deadline.saturating_sub(now_ms()));
            wait
        }
    }

    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        super::finish(super::Lookup::start(name))
    }
}

#[cfg(target_os = "macos")]
mod os {
    use super::{Address, Error, c_string};
    use alloc::vec::Vec;
    use core::ffi::{c_char, c_int};
    use core::net::IpAddr;
    use core::ptr::null_mut;

    /// struct addrinfo, as macOS's netdb.h lays it out.
    #[repr(C)]
    struct AddrInfo {
        flags: c_int,
        family: c_int,
        socktype: c_int,
        protocol: c_int,
        addrlen: u32,
        canonname: *mut c_char,
        addr: *mut u8,
        next: *mut AddrInfo,
    }

    #[link(name = "c")]
    // rr: escape(unsafe): each signature is the C library's, from its headers.
    unsafe extern "C" {
        fn getaddrinfo(
            node: *const c_char,
            service: *const c_char,
            hints: *const AddrInfo,
            result: *mut *mut AddrInfo,
        ) -> c_int;
        fn freeaddrinfo(info: *mut AddrInfo);
    }

    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 30;
    const SOCK_STREAM: c_int = 1;
    const EAI_AGAIN: c_int = 2;
    const EAI_NODATA: c_int = 7;
    const EAI_NONAME: c_int = 8;

    pub use super::thread::State;

    /// A name as getaddrinfo takes it: NUL-terminated.
    pub type Name = Vec<u8>;

    pub fn name(name: &[u8]) -> Option<Name> {
        c_string(name)
    }

    fn error(code: c_int) -> Error {
        match code {
            EAI_NONAME | EAI_NODATA => Error::NotFound,
            EAI_AGAIN => Error::Temporary,
            _ => Error::Failed,
        }
    }

    /// getaddrinfo's addresses of name, as it orders them (RFC 6724).
    pub fn lookup(name: &[u8]) -> Result<Vec<Address>, Error> {
        let hints = AddrInfo {
            flags: 0,
            family: 0,
            socktype: SOCK_STREAM,
            protocol: 0,
            addrlen: 0,
            canonname: null_mut(),
            addr: null_mut(),
            next: null_mut(),
        };
        let mut list = null_mut();
        // rr: escape(unsafe): name is NUL-terminated; list is ours to fill.
        let code = unsafe {
            getaddrinfo(
                name.as_ptr().cast(),
                core::ptr::null(),
                &raw const hints,
                &raw mut list,
            )
        };
        if code != 0 {
            return Err(error(code));
        }
        let mut addresses = Vec::new();
        let mut next = list;
        while !next.is_null() {
            // rr: escape(unsafe): next is an entry of getaddrinfo's list.
            let info = unsafe { &*next };
            if let Some(address) = address(info) {
                addresses.push(address);
            }
            next = info.next;
        }
        // rr: escape(unsafe): list came from getaddrinfo, freed once.
        unsafe { freeaddrinfo(list) };
        if addresses.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(addresses)
    }

    /// The address of an entry: sockaddr_in or sockaddr_in6, after the
    /// length and family bytes BSD starts them with.
    fn address(info: &AddrInfo) -> Option<Address> {
        let size = usize::try_from(info.addrlen).ok()?;
        if info.addr.is_null() || size < 16 {
            return None;
        }
        // rr: escape(unsafe): addr holds addrlen bytes.
        let bytes = unsafe { core::slice::from_raw_parts(info.addr, size) };
        match (
            bytes.get(1).copied()?,
            bytes.get(4..8),
            bytes.get(8..24),
            bytes.get(24..28),
        ) {
            (AF_INET, Some(v4), _, _) => Some(Address {
                ip: IpAddr::from(<[u8; 4]>::try_from(v4).ok()?),
                scope: 0,
            }),
            (AF_INET6, _, Some(v6), Some(scope)) => Some(Address {
                ip: IpAddr::from(<[u8; 16]>::try_from(v6).ok()?),
                // sin6_scope_id is in the host's order, which is little
                // on every Mac.
                scope: u32::from_le_bytes(<[u8; 4]>::try_from(scope).ok()?),
            }),
            _ => None,
        }
    }

    /// getaddrinfo blocks the caller's thread, which is what was asked.
    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        lookup(&c_string(name).ok_or(Error::NotFound)?)
    }
}

#[cfg(target_os = "windows")]
mod os {
    use super::super::wait::{self, AF_INET, SOCK_STREAM};
    use super::{Address, Error};
    use alloc::vec::Vec;
    use core::net::IpAddr;
    use core::ptr::{null, null_mut};

    pub use super::thread::State;

    /// ADDRINFOW, from ws2def.h.
    #[repr(C)]
    struct AddrInfo {
        flags: i32,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: usize,
        canonname: *mut u16,
        addr: *mut u8,
        next: *mut AddrInfo,
    }

    #[link(name = "ws2_32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is ws2_32's, from its documentation.
    unsafe extern "system" {
        fn GetAddrInfoW(
            name: *const u16,
            service: *const u16,
            hints: *const AddrInfo,
            result: *mut *mut AddrInfo,
        ) -> i32;
        fn FreeAddrInfoW(info: *mut AddrInfo);
    }

    const AF_INET6: u16 = 23;
    const WSAETIMEDOUT: i32 = 10060;
    const WSAHOST_NOT_FOUND: i32 = 11001;
    const WSATRY_AGAIN: i32 = 11002;
    const WSANO_DATA: i32 = 11004;

    /// A name as GetAddrInfoW takes it: UTF-16, NUL-terminated.
    pub type Name = Vec<u16>;

    pub fn name(name: &[u8]) -> Option<Name> {
        let text = core::str::from_utf8(name).ok()?;
        if name.contains(&0) {
            return None;
        }
        let mut wide = Vec::new();
        for unit in text.encode_utf16() {
            wide.push(unit);
        }
        wide.push(0);
        Some(wide)
    }

    fn error(code: i32) -> Error {
        match code {
            WSAHOST_NOT_FOUND | WSANO_DATA => Error::NotFound,
            WSATRY_AGAIN => Error::Temporary,
            WSAETIMEDOUT => Error::Timeout,
            _ => Error::Failed,
        }
    }

    /// GetAddrInfoW's addresses of name, as it orders them (RFC 6724).
    pub fn lookup(name: &[u16]) -> Result<Vec<Address>, Error> {
        wait::startup();
        let hints = AddrInfo {
            flags: 0,
            family: 0,
            socktype: SOCK_STREAM,
            protocol: 0,
            addrlen: 0,
            canonname: null_mut(),
            addr: null_mut(),
            next: null_mut(),
        };
        let mut list = null_mut();
        // rr: escape(unsafe): name is NUL-terminated; list is ours to fill.
        let code = unsafe { GetAddrInfoW(name.as_ptr(), null(), &raw const hints, &raw mut list) };
        if code != 0 {
            return Err(error(code));
        }
        let mut found = Vec::new();
        let mut next = list;
        while !next.is_null() {
            // rr: escape(unsafe): next is an entry of the system's list.
            let info = unsafe { &*next };
            if let Some(address) = address(info) {
                found.push(address);
            }
            next = info.next;
        }
        if !list.is_null() {
            // rr: escape(unsafe): list came from GetAddrInfoW, freed once.
            unsafe { FreeAddrInfoW(list) };
        }
        if found.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(found)
    }

    /// The address of an entry: SOCKADDR_IN or SOCKADDR_IN6.
    fn address(info: &AddrInfo) -> Option<Address> {
        if info.addr.is_null() || info.addrlen < 16 {
            return None;
        }
        // rr: escape(unsafe): addr holds addrlen bytes.
        let bytes = unsafe { core::slice::from_raw_parts(info.addr, info.addrlen) };
        let family = u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]);
        match (family, bytes.get(4..8), bytes.get(8..24), bytes.get(24..28)) {
            (AF_INET, Some(v4), _, _) => Some(Address {
                ip: IpAddr::from(<[u8; 4]>::try_from(v4).ok()?),
                scope: 0,
            }),
            (AF_INET6, _, Some(v6), Some(scope)) => Some(Address {
                ip: IpAddr::from(<[u8; 16]>::try_from(v6).ok()?),
                scope: u32::from_le_bytes(<[u8; 4]>::try_from(scope).ok()?),
            }),
            _ => None,
        }
    }

    /// GetAddrInfoW blocks the caller's thread, which is what was asked.
    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        lookup(&self::name(name).ok_or(Error::NotFound)?)
    }
}

/// A lookup on a thread of its own, on macOS and Windows, where the
/// system's lookup blocks: getaddrinfo, which knows macOS's VPN and
/// split DNS, and GetAddrInfoW, which Go uses on Windows too. The
/// thread and the lookup share a block, which the last of the two to
/// let go frees, so a lookup dropped while the thread runs never waits;
/// one dropped while still in spawn's line never starts.
#[cfg(any(target_os = "macos", target_os = "windows"))]
mod thread {
    use super::super::wait::{self, Signal};
    use super::os::{self, Name};
    use super::{Address, Error, Wait};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The thread writes result, then sets done and the signal; the
    /// lookup reads result only after it saw done.
    struct Shared {
        holders: AtomicUsize,
        done: AtomicBool,
        name: Name,
        result: UnsafeCell<Result<Vec<Address>, Error>>,
        signal: Signal,
    }

    /// Lets go of shared; the last holder frees it.
    fn release(shared: *mut Shared) {
        // rr: escape(unsafe): shared lives until its holders let go.
        let holders = unsafe { &(*shared).holders };
        if holders.fetch_sub(1, Ordering::AcqRel) == 1 {
            // rr: escape(unsafe): no one else holds it now.
            drop(unsafe { Box::from_raw(shared) });
        }
    }

    fn run(argument: *mut c_void) {
        let shared = argument.cast::<Shared>();
        // rr: escape(unsafe): the thread is a holder of shared.
        let state = unsafe { &*shared };
        let result = os::lookup(&state.name);
        // rr: escape(unsafe): only this thread touches result before done.
        unsafe { *state.result.get() = result };
        state.done.store(true, Ordering::Release);
        state.signal.set();
        release(shared);
    }

    pub struct State {
        shared: *mut Shared,
        /// The result, once taken from the thread.
        taken: Option<Result<Vec<Address>, Error>>,
        /// The work, to take out of spawn's line when dropped before it
        /// started.
        ticket: Option<wait::Ticket>,
    }

    impl State {
        pub fn start(name: &[u8]) -> State {
            let mut state = State {
                shared: null_mut(),
                taken: None,
                ticket: None,
            };
            let Some(name) = os::name(name) else {
                state.taken = Some(Err(Error::NotFound));
                return state;
            };
            let Some(signal) = Signal::new() else {
                state.taken = Some(Err(Error::Failed));
                return state;
            };
            let shared = Box::new(Shared {
                // rr: escape(shared): the lookup and the thread both hold it.
                holders: AtomicUsize::new(2),
                // rr: escape(shared): the thread says it is done.
                done: AtomicBool::new(false),
                name,
                // rr: escape(shared): the thread's answer, handed over once.
                result: UnsafeCell::new(Err(Error::Failed)),
                signal,
            });
            // rr: escape(leak): the lookup and the thread hold it, and
            // release frees it.
            let raw = Box::into_raw(shared);
            state.shared = raw;
            state.ticket = wait::spawn(run, raw.cast());
            if state.ticket.is_none() {
                // The thread never held it.
                release(raw);
                state.taken = Some(Err(Error::Failed));
            }
            state
        }

        pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
            if self.taken.is_none() && !self.shared.is_null() {
                // rr: escape(unsafe): this lookup holds shared.
                let shared = unsafe { &*self.shared };
                if !shared.done.load(Ordering::Acquire) {
                    return None;
                }
                // rr: escape(unsafe): the thread is done with result.
                let result = unsafe { &mut *shared.result.get() };
                self.taken = Some(core::mem::replace(result, Err(Error::Failed)));
                release(self.shared);
                self.shared = null_mut();
            }
            match &self.taken {
                Some(Ok(addresses)) => Some(Ok(addresses)),
                Some(Err(error)) => Some(Err(*error)),
                None => None,
            }
        }

        pub fn wait(&self) -> Wait {
            if self.taken.is_some() || self.shared.is_null() {
                return Wait::READY;
            }
            // rr: escape(unsafe): this lookup holds shared.
            let shared = unsafe { &*self.shared };
            shared.signal.wait()
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            if self.shared.is_null() {
                return;
            }
            // Work still in line never runs: its holder is let go here.
            if self.ticket.as_ref().is_some_and(wait::Ticket::cancel) {
                release(self.shared);
            }
            // The thread, when it runs on, frees what is left.
            release(self.shared);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Lookup, resolve};

    fn loopback(addresses: &[super::Address]) -> bool {
        !addresses.is_empty() && addresses.iter().all(|address| address.ip.is_loopback())
    }

    /// localhost, blocking and through the poll loop, gives loopback
    /// addresses, from /etc/hosts or as RFC 6761 says.
    #[test]
    fn localhost() {
        assert!(loopback(&resolve(b"localhost").unwrap()));
        let mut lookup = Lookup::start(b"localhost");
        for _ in 0..1000 {
            if let Some(result) = lookup.poll() {
                assert!(loopback(result.unwrap()));
                return;
            }
            super::wait::block(&lookup.wait());
        }
        panic!("localhost did not resolve");
    }

    /// Literal addresses are themselves.
    #[test]
    fn literals() {
        let found = resolve(b"192.0.2.1").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].ip, core::net::IpAddr::from([192, 0, 2, 1]));
        assert!(resolve(b"::1").unwrap()[0].ip.is_loopback());
    }

    /// A name that is not one is not found, without asking anyone; a
    /// lookup dropped while it runs is let go.
    #[test]
    fn bad_names_and_cancel() {
        for bad in [&b"a\0b"[..], b"bad..name", b"-x.invalid"] {
            assert!(
                matches!(resolve(bad), Err(Error::NotFound | Error::Failed)),
                "{bad:?}"
            );
        }
        Lookup::start(b"example.com").cancel();
    }

    /// example.com has an address, when the network is up.
    #[test]
    fn example_com() {
        match resolve(b"example.com") {
            Ok(found) => assert!(found.iter().all(|address| !address.ip.is_loopback())),
            Err(error) => assert!(error != Error::Failed, "{error:?}"),
        }
        assert!(matches!(
            resolve(b"nx.rr-test.invalid"),
            Err(Error::NotFound | Error::Temporary | Error::Timeout)
        ));
    }
}
