//! The system side of net: what mod.rs says it is, for each system.

use crate::base::poll::{Interest, Owned, Poll, PollError, Raw, Token};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Why a socket call failed, as a loop acts on it.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// Nobody listens there.
    Refused,
    /// The peer reset or aborted the connection, or is gone and a write,
    /// or the system's keep-alive (ENETRESET, WSAENETRESET), found out.
    Reset,
    /// The connection timed out.
    TimedOut,
    /// No route to the host or its network, or either is down.
    Unreachable,
    /// The address is taken.
    InUse,
    /// A read or write before the connection is made, on every system
    /// alike: wait for the stream to be writable, then try again.
    NotConnected,
    /// A read into no room, whose Done(0) could not be told from the
    /// peer's end.
    NoRoom,
    /// bind_shared where the system does not balance connections among
    /// listeners that share an address: macOS gives them all to the one
    /// bound last, Windows shares none. Accept on one thread and hand
    /// the connections to the others (accept_handoff).
    Unbalanced,
    /// Anything else: the system's code (errno, or WSAGetLastError's).
    Other(i32),
}

/// What a read or write did now.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Io {
    /// So many bytes; a read of 0 is the peer's end.
    Done(usize),
    /// Nothing now: wait for readiness.
    Blocked,
}

/// The bytes of a sockaddr_in6, the larger of the two.
const ADDRESS_BYTES: usize = 28;

/// A socket, and its entry in a Poll with the key it was watched with;
/// open until its Poll or its drop closes it, once: the entry is Owned,
/// which only close takes out of the Poll.
struct Socket {
    fd: Raw,
    entry: Option<(Owned, u64)>,
}

impl Socket {
    fn new(fd: Raw) -> Socket {
        Socket { fd, entry: None }
    }

    /// The socket's entry: added once, then changed in place, its key as
    /// well, as the system holds a registration for each socket once
    /// (socket notifications take another only after the first is gone).
    /// Another Poll than the first is refused.
    fn watch(&mut self, poll: &mut Poll, interest: Interest, key: u64) -> Result<(), PollError> {
        let Some((owned, old)) = &mut self.entry else {
            let owned = poll.add_owned(self.fd, interest, key)?;
            self.entry = Some((owned, key));
            return Ok(());
        };
        if *old != key {
            poll.rekey(owned.token(), key)?;
            *old = key;
        }
        poll.modify(owned.token(), interest)
    }

    fn token(&self) -> Option<Token> {
        self.entry.as_ref().map(|(owned, _)| owned.token())
    }

    /// Hands the socket to its Poll, which takes it out and closes it; one
    /// in no Poll, or one poll does not hold, drop closes, and the Poll's
    /// refusal says why.
    fn close(mut self, poll: &mut Poll) -> Result<(), PollError> {
        let Some((owned, _)) = self.entry.take() else {
            return Ok(());
        };
        poll.close(owned)?;
        // rr: escape(leak): the Poll closed the socket, which drop would
        // close again; the value holds nothing else.
        core::mem::forget(self);
        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        os::close(self.fd);
    }
}

/// Where a connection is: still being made, made, or failed with the
/// error the system said once.
#[derive(Clone, Copy)]
enum Link {
    Connecting,
    Connected,
    Failed(Error),
}

/// A TCP connection.
pub struct Stream {
    socket: Socket,
    link: Link,
}

impl Stream {
    /// Begins a connection to address. It is made once the socket is
    /// writable, or has an error or a hangup, and connected says so.
    pub fn connect(address: SocketAddr) -> Result<Stream, Error> {
        let socket = Socket::new(os::open(&address)?);
        os::no_delay(socket.fd, true)?;
        let (bytes, length) = encode(&address);
        os::connect(socket.fd, bytes.get(..length).unwrap_or_default())?;
        Ok(Stream {
            socket,
            link: Link::Connecting,
        })
    }

    /// Whether the connection is made: false while it is still being
    /// made, its error once it failed, the same error every time.
    pub fn connected(&mut self) -> Result<bool, Error> {
        match self.link {
            Link::Connected => return Ok(true),
            Link::Failed(error) => return Err(error),
            Link::Connecting => {}
        }
        if let Err(error) = os::pending(self.socket.fd) {
            self.link = Link::Failed(error);
            return Err(error);
        }
        if !os::established(self.socket.fd) {
            return Ok(false);
        }
        self.link = Link::Connected;
        Ok(true)
    }

    /// Ready for a read or write: made, or NotConnected while it is still
    /// being made, or its error.
    fn ready(&mut self) -> Result<(), Error> {
        if self.connected()? {
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }

    /// Reads what has come, into into, which has room: an empty one is
    /// NoRoom.
    #[cfg_attr(rr, rr::hot)]
    pub fn read(&mut self, into: &mut [u8]) -> Result<Io, Error> {
        if into.is_empty() {
            return Err(Error::NoRoom);
        }
        if !matches!(self.link, Link::Connected) {
            self.ready()?;
        }
        os::read(self.socket.fd, into)
    }

    /// Writes what the system takes of from now.
    #[cfg_attr(rr, rr::hot)]
    pub fn write(&mut self, from: &[u8]) -> Result<Io, Error> {
        if !matches!(self.link, Link::Connected) {
            self.ready()?;
        }
        os::write(self.socket.fd, from)
    }

    /// Ends the writing side: the peer reads its end, and may still send.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.ready()?;
        os::finish(self.socket.fd)
    }

    /// Whether small writes go at once (TCP_NODELAY, on for every stream,
    /// as Go has it: a loop writes whole messages), or wait to be joined
    /// with the next (Nagle's algorithm), for one that writes in pieces.
    pub fn no_delay(&self, on: bool) -> Result<(), Error> {
        os::no_delay(self.socket.fd, on)
    }

    pub fn local(&self) -> Option<SocketAddr> {
        os::local(self.socket.fd)
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        os::peer(self.socket.fd)
    }

    /// Puts the stream in poll with interest, reported with key, or
    /// changes them. Refused for another Poll than the first.
    pub fn watch(
        &mut self,
        poll: &mut Poll,
        interest: Interest,
        key: u64,
    ) -> Result<(), PollError> {
        self.socket.watch(poll, interest, key)
    }

    /// The stream's entry in its Poll, for a deadline: Poll::remove refuses
    /// it, and only the stream's close takes it out.
    pub fn token(&self) -> Option<Token> {
        self.socket.token()
    }

    /// The socket as the system names it, which the stream still owns.
    pub fn raw(&self) -> Raw {
        self.socket.fd
    }

    /// Takes the stream out of poll, and closes it. The socket is closed
    /// whatever poll says; Err when poll is not the Poll it was watched in,
    /// whose entry then stays until that Poll gets a socket of its number.
    pub fn close(self, poll: &mut Poll) -> Result<(), PollError> {
        self.socket.close(poll)
    }

    /// Closes with a reset (SO_LINGER 0), as for a peer that misbehaved:
    /// what was not sent is dropped. Err as close says.
    pub fn abort(self, poll: &mut Poll) -> Result<(), PollError> {
        os::reset(self.socket.fd);
        self.socket.close(poll)
    }
}

/// An accepted connection in no Poll yet, for another thread's loop:
/// accept_handoff makes it, a queue carries it, and Stream::adopt makes
/// it a stream of the thread that watches it, in its Poll alone. Its
/// socket is its own, closed when it is dropped: one that never arrives
/// is closed all the same.
pub struct Handoff {
    socket: Socket,
    peer: SocketAddr,
}

impl Handoff {
    /// The address of the peer, as accept gave it.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

impl Stream {
    /// The handed-off connection as a stream of this thread's: made, and
    /// in no Poll until watch puts it in one.
    pub fn adopt(handoff: Handoff) -> Stream {
        Stream {
            socket: handoff.socket,
            link: Link::Connected,
        }
    }
}

/// A TCP listener.
pub struct Listener {
    socket: Socket,
}

impl Listener {
    /// Listens on address, with a queue of backlog connections, which
    /// the system may cut (SOMAXCONN, 128 on macOS by default).
    pub fn bind(address: SocketAddr, backlog: u32) -> Result<Listener, Error> {
        let socket = Socket::new(os::open(&address)?);
        os::prepare(socket.fd, address.is_ipv6())?;
        let (bytes, length) = encode(&address);
        os::bind(socket.fd, bytes.get(..length).unwrap_or_default())?;
        os::listen(socket.fd, backlog)?;
        Ok(Listener { socket })
    }

    /// Listens on address beside other listeners on it, each on its own
    /// thread's loop, among which the system spreads the connections:
    /// SO_REUSEPORT on Linux, whose kernel picks a listener by a hash of
    /// each connection's addresses. Every one of them is bound so, by the
    /// same user, who alone may join them; one closed drops the
    /// connections waiting in its queue (net.ipv4.tcp_migrate_req is off
    /// by default). macOS and Windows refuse it (Unbalanced): macOS gives
    /// every connection to the listener bound last, and Windows has no
    /// such option; one listener there accepts, and hands off.
    pub fn bind_shared(address: SocketAddr, backlog: u32) -> Result<Listener, Error> {
        if !os::BALANCED {
            return Err(Error::Unbalanced);
        }
        let socket = Socket::new(os::open(&address)?);
        os::prepare(socket.fd, address.is_ipv6())?;
        os::share(socket.fd)?;
        let (bytes, length) = encode(&address);
        os::bind(socket.fd, bytes.get(..length).unwrap_or_default())?;
        os::listen(socket.fd, backlog)?;
        Ok(Listener { socket })
    }

    /// The next connection, in no Poll yet, for another thread's loop
    /// (Handoff); None when none waits.
    pub fn accept_handoff(&self) -> Result<Option<Handoff>, Error> {
        let Some((stream, peer)) = self.accept()? else {
            return Ok(None);
        };
        Ok(Some(Handoff {
            socket: stream.socket,
            peer,
        }))
    }

    /// The next connection and its peer's address; None when none waits.
    pub fn accept(&self) -> Result<Option<(Stream, SocketAddr)>, Error> {
        let Some((fd, peer)) = os::accept(self.socket.fd)? else {
            return Ok(None);
        };
        let stream = Stream {
            socket: Socket::new(fd),
            link: Link::Connected,
        };
        if stream.no_delay(true).is_err() {
            // Only Nagle's algorithm stays, as Go leaves it then; a socket
            // that cannot take the option shows its error at its read.
        }
        Ok(Some((stream, peer)))
    }

    /// The socket as the system names it, which the listener still owns.
    pub fn raw(&self) -> Raw {
        self.socket.fd
    }

    /// The address it listens on: with the port the system chose for 0.
    pub fn local(&self) -> Option<SocketAddr> {
        os::local(self.socket.fd)
    }

    /// Puts the listener in poll with interest, reported with key, or
    /// changes them. Refused for another Poll than the first.
    pub fn watch(
        &mut self,
        poll: &mut Poll,
        interest: Interest,
        key: u64,
    ) -> Result<(), PollError> {
        self.socket.watch(poll, interest, key)
    }

    /// The listener's entry in its Poll, for a deadline.
    pub fn token(&self) -> Option<Token> {
        self.socket.token()
    }

    /// Takes the listener out of poll, and closes it; Err as Stream's
    /// close says.
    pub fn close(self, poll: &mut Poll) -> Result<(), PollError> {
        self.socket.close(poll)
    }
}

/// Raises the descriptors this process may hold to want, or as many as
/// the system lets it, and says how many it has: a server of many
/// connections needs more than the 256 (macOS) or 1024 (Linux) a process
/// starts with, as Go raises them itself. Windows sets no such limit.
///
/// The limit raised is the soft one (RLIMIT_NOFILE), which a child the
/// process starts inherits, and a program that uses select may need low
/// (FD_SETSIZE, 1024): Go gives the children it starts the limit back.
/// descriptors_before says what it was, for a caller that starts one to
/// set in the child before exec.
pub fn descriptors(want: u64) -> u64 {
    os::descriptors(want)
}

/// The soft limit of descriptors before descriptors first raised it;
/// None while it has not, and on Windows.
pub fn descriptors_before() -> Option<u64> {
    os::descriptors_before()
}

/// address as the system's sockaddr_in or sockaddr_in6, and its length.
/// The family is a byte after the length on macOS, two bytes in the
/// host's order, little on every target, elsewhere; the port and the
/// flow label are in the network's order; the scope in the host's.
fn encode(address: &SocketAddr) -> ([u8; ADDRESS_BYTES], usize) {
    let mut bytes = [0u8; ADDRESS_BYTES];
    let (family, length) = match address {
        SocketAddr::V4(_) => (os::AF_INET, 16),
        SocketAddr::V6(_) => (os::AF_INET6, ADDRESS_BYTES),
    };
    put(&mut bytes, 0, &os::family(family, length));
    put(&mut bytes, 2, &address.port().to_be_bytes());
    match address {
        SocketAddr::V4(v4) => put(&mut bytes, 4, &v4.ip().octets()),
        SocketAddr::V6(v6) => {
            put(&mut bytes, 4, &v6.flowinfo().to_be_bytes());
            put(&mut bytes, 8, &v6.ip().octets());
            put(&mut bytes, 24, &v6.scope_id().to_le_bytes());
        }
    }
    (bytes, length)
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    if let Some(place) = bytes.get_mut(at..at + value.len()) {
        place.copy_from_slice(value);
    }
}

/// The address in a sockaddr the system filled.
fn decode(bytes: &[u8]) -> Option<SocketAddr> {
    let family = os::family_of(bytes)?;
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    if family == os::AF_INET {
        let ip: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
        return Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)));
    }
    if family != os::AF_INET6 {
        return None;
    }
    let flow = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
    let ip: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
    let scope = u32::from_le_bytes(bytes.get(24..28)?.try_into().ok()?);
    Some(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(ip),
        port,
        flow,
        scope,
    )))
}

/// Linux and macOS: the C library's sockets.
#[cfg(unix)]
mod os {
    use super::{ADDRESS_BYTES, Error, Io, decode};
    use crate::base::poll::SOCK_STREAM;
    use core::ffi::c_int;
    use core::net::SocketAddr;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// The system's calls, apart from the functions named after them.
    mod c {
        use core::ffi::{c_int, c_void};

        #[link(name = "c")]
        // rr: escape(unsafe): each signature is the C library's, from its headers.
        unsafe extern "C" {
            #[must_use]
            pub(super) fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
            #[must_use]
            pub(super) fn bind(fd: c_int, address: *const u8, length: u32) -> c_int;
            #[must_use]
            pub(super) fn listen(fd: c_int, backlog: c_int) -> c_int;
            #[cfg(target_os = "linux")]
            #[must_use]
            pub(super) fn accept4(
                fd: c_int,
                address: *mut u8,
                length: *mut u32,
                flags: c_int,
            ) -> c_int;
            #[cfg(target_os = "macos")]
            #[must_use]
            pub(super) fn accept(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            #[must_use]
            pub(super) fn connect(fd: c_int, address: *const u8, length: u32) -> c_int;
            #[must_use]
            pub(super) fn getsockname(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            #[cfg(target_os = "macos")]
            #[must_use]
            pub(super) fn sysctlbyname(
                name: *const core::ffi::c_char,
                old: *mut c_void,
                old_length: *mut usize,
                new: *const c_void,
                new_length: usize,
            ) -> c_int;
            #[must_use]
            pub(super) fn getpeername(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            #[must_use]
            pub(super) fn getsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *mut c_void,
                length: *mut u32,
            ) -> c_int;
            #[must_use]
            pub(super) fn setsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *const c_void,
                length: u32,
            ) -> c_int;
            #[must_use]
            pub(super) fn send(
                fd: c_int,
                buffer: *const c_void,
                length: usize,
                flags: c_int,
            ) -> isize;
            #[must_use]
            pub(super) fn recv(
                fd: c_int,
                buffer: *mut c_void,
                length: usize,
                flags: c_int,
            ) -> isize;
            #[must_use]
            pub(super) fn shutdown(fd: c_int, how: c_int) -> c_int;
            #[must_use]
            pub(super) fn close(fd: c_int) -> c_int;
            #[cfg(target_os = "macos")]
            #[must_use]
            pub(super) fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
            #[must_use]
            pub(super) fn getrlimit(resource: c_int, limit: *mut u64) -> c_int;
            #[must_use]
            pub(super) fn setrlimit(resource: c_int, limit: *const u64) -> c_int;
        }
    }

    // sys/socket.h's, netinet/in.h's, netinet/tcp.h's and errno.h's: Linux's
    // from asm-generic, as x86_64 and aarch64 have them, macOS's from its
    // SDK.
    pub use crate::base::poll::{AF_INET, AF_INET6};
    use crate::base::poll::{EINTR, ETIMEDOUT, errno};
    const IPPROTO_TCP: c_int = 6;
    const IPPROTO_IPV6: c_int = 41;
    const TCP_NODELAY: c_int = 1;
    const SHUT_WR: c_int = 1;
    const EPIPE: c_int = 32;
    #[cfg(target_os = "linux")]
    mod numbers {
        use core::ffi::c_int;
        pub const SOL_SOCKET: c_int = 1;
        pub const SO_ERROR: c_int = 4;
        pub const SO_LINGER: c_int = 13;
        pub const SO_REUSEADDR: c_int = 2;
        pub const SO_REUSEPORT: c_int = 15;
        pub const IPV6_V6ONLY: c_int = 26;
        pub const SEND_FLAGS: c_int = 0x4000;
        pub const SOCK_NONBLOCK: c_int = 0x800;
        pub const SOCK_CLOEXEC: c_int = 0x8_0000;
        pub const EAGAIN: c_int = 11;
        pub const EINPROGRESS: c_int = 115;
        pub const ECONNREFUSED: c_int = 111;
        pub const ECONNRESET: c_int = 104;
        pub const ECONNABORTED: c_int = 103;
        pub const EHOSTUNREACH: c_int = 113;
        pub const ENETUNREACH: c_int = 101;
        pub const EADDRINUSE: c_int = 98;
        pub const ENETDOWN: c_int = 100;
        pub const ENETRESET: c_int = 102;
        pub const EPROTO: c_int = 71;
        pub const ENOPROTOOPT: c_int = 92;
        pub const EHOSTDOWN: c_int = 112;
        pub const ENONET: c_int = 64;
        pub const EOPNOTSUPP: c_int = 95;
    }
    #[cfg(target_os = "macos")]
    mod numbers {
        use core::ffi::c_int;
        pub const SOL_SOCKET: c_int = 0xffff;
        pub const SO_ERROR: c_int = 0x1007;
        pub const SO_LINGER: c_int = 0x80;
        pub const SO_REUSEADDR: c_int = 0x4;
        pub const SO_NOSIGPIPE: c_int = 0x1022;
        pub const IPV6_V6ONLY: c_int = 27;
        /// SO_NOSIGPIPE on the socket stands for MSG_NOSIGNAL.
        pub const SEND_FLAGS: c_int = 0;
        pub const F_GETFL: c_int = 3;
        pub const F_SETFL: c_int = 4;
        pub const O_NONBLOCK: c_int = 0x4;
        pub const EAGAIN: c_int = 35;
        pub const EINPROGRESS: c_int = 36;
        pub const ECONNREFUSED: c_int = 61;
        pub const ECONNRESET: c_int = 54;
        pub const ECONNABORTED: c_int = 53;
        pub const EHOSTUNREACH: c_int = 65;
        pub const ENETUNREACH: c_int = 51;
        pub const EADDRINUSE: c_int = 48;
        pub const ENETDOWN: c_int = 50;
        pub const ENETRESET: c_int = 52;
        pub const EHOSTDOWN: c_int = 64;
    }
    use numbers::{
        EADDRINUSE, EAGAIN, ECONNABORTED, ECONNREFUSED, ECONNRESET, EHOSTDOWN, EHOSTUNREACH,
        EINPROGRESS, ENETDOWN, ENETRESET, ENETUNREACH, IPV6_V6ONLY, SEND_FLAGS, SO_ERROR,
        SO_LINGER, SO_REUSEADDR, SOL_SOCKET,
    };

    pub fn error(code: c_int) -> Error {
        match code {
            ECONNREFUSED => Error::Refused,
            ECONNRESET | EPIPE | ECONNABORTED | ENETRESET => Error::Reset,
            ETIMEDOUT => Error::TimedOut,
            EHOSTUNREACH | ENETUNREACH | EHOSTDOWN | ENETDOWN => Error::Unreachable,
            EADDRINUSE => Error::InUse,
            other => Error::Other(other),
        }
    }

    /// The call's error, when it returned -1.
    fn check(done: c_int) -> Result<(), Error> {
        if done < 0 {
            Err(error(errno()))
        } else {
            Ok(())
        }
    }

    /// The family's bytes at the start of a sockaddr of length bytes.
    #[cfg(target_os = "macos")]
    pub fn family(family: u16, length: usize) -> [u8; 2] {
        [
            u8::try_from(length).unwrap_or(0),
            u8::try_from(family).unwrap_or(0),
        ]
    }

    #[cfg(target_os = "linux")]
    pub fn family(family: u16, _length: usize) -> [u8; 2] {
        family.to_le_bytes()
    }

    #[cfg(target_os = "macos")]
    pub fn family_of(bytes: &[u8]) -> Option<u16> {
        bytes.get(1).copied().map(u16::from)
    }

    #[cfg(target_os = "linux")]
    pub fn family_of(bytes: &[u8]) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
    }

    fn domain(address: &SocketAddr) -> c_int {
        c_int::from(if address.is_ipv4() { AF_INET } else { AF_INET6 })
    }

    fn length(bytes: &[u8]) -> u32 {
        u32::try_from(bytes.len()).unwrap_or(0)
    }

    /// A new socket for address's family: non-blocking, closed on exec,
    /// in one call.
    #[cfg(target_os = "linux")]
    pub fn open(address: &SocketAddr) -> Result<c_int, Error> {
        use numbers::{SOCK_CLOEXEC, SOCK_NONBLOCK};
        let kind = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
        // rr: escape(unsafe): socket takes plain numbers.
        let fd = unsafe { c::socket(domain(address), kind, 0) };
        check(fd)?;
        Ok(fd)
    }

    /// A new socket for address's family, made non-blocking, closed on
    /// exec and without SIGPIPE, as macOS has no flags for it at once.
    #[cfg(target_os = "macos")]
    pub fn open(address: &SocketAddr) -> Result<c_int, Error> {
        // rr: escape(unsafe): socket takes plain numbers.
        let fd = unsafe { c::socket(domain(address), SOCK_STREAM, 0) };
        check(fd)?;
        prepare_new(fd).inspect_err(|_| close(fd))?;
        Ok(fd)
    }

    #[cfg(target_os = "macos")]
    fn prepare_new(fd: c_int) -> Result<(), Error> {
        use crate::base::poll::{F_SETFD, FD_CLOEXEC};
        use numbers::{F_GETFL, F_SETFL, O_NONBLOCK, SO_NOSIGPIPE};
        // rr: escape(unsafe): fd is open.
        let flags = unsafe { c::fcntl(fd, F_GETFL) };
        check(flags)?;
        // rr: escape(unsafe): fd is open.
        check(unsafe { c::fcntl(fd, F_SETFL, flags | O_NONBLOCK) })?;
        // rr: escape(unsafe): fd is open.
        check(unsafe { c::fcntl(fd, F_SETFD, FD_CLOEXEC) })?;
        option(fd, SOL_SOCKET, SO_NOSIGPIPE, 1)
    }

    fn option(fd: c_int, level: c_int, name: c_int, value: c_int) -> Result<(), Error> {
        // An int in the host's order, little on every target.
        let bytes = value.to_le_bytes();
        // rr: escape(unsafe): bytes holds an int, as each option here takes.
        let done = unsafe { c::setsockopt(fd, level, name, bytes.as_ptr().cast(), length(&bytes)) };
        check(done)
    }

    /// A listener's options: its address taken again while connections
    /// to it linger in TIME_WAIT; IPv6 alone on an IPv6 socket.
    pub fn prepare(fd: c_int, v6: bool) -> Result<(), Error> {
        option(fd, SOL_SOCKET, SO_REUSEADDR, 1)?;
        if v6 {
            option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1)?;
        }
        Ok(())
    }

    pub fn no_delay(fd: c_int, on: bool) -> Result<(), Error> {
        option(fd, IPPROTO_TCP, TCP_NODELAY, i32::from(on))
    }

    /// Whether the kernel spreads connections among listeners that share
    /// an address: Linux's SO_REUSEPORT does (since 3.9); macOS's gives
    /// them to the one bound last.
    #[cfg(target_os = "linux")]
    pub const BALANCED: bool = true;
    #[cfg(target_os = "macos")]
    pub const BALANCED: bool = false;

    /// Lets other listeners of this user bind the address beside it.
    #[cfg(target_os = "linux")]
    pub fn share(fd: c_int) -> Result<(), Error> {
        option(fd, SOL_SOCKET, numbers::SO_REUSEPORT, 1)
    }

    /// Never reached: BALANCED refuses first.
    #[cfg(target_os = "macos")]
    pub fn share(_fd: c_int) -> Result<(), Error> {
        Err(Error::Unbalanced)
    }

    pub fn bind(fd: c_int, address: &[u8]) -> Result<(), Error> {
        // rr: escape(unsafe): address is a sockaddr of its length.
        check(unsafe { c::bind(fd, address.as_ptr(), length(address)) })
    }

    pub fn listen(fd: c_int, backlog: u32) -> Result<(), Error> {
        let backlog = c_int::try_from(backlog).unwrap_or(c_int::MAX);
        // rr: escape(unsafe): fd is bound.
        check(unsafe { c::listen(fd, backlog) })
    }

    /// Begins a connection; one still being made is no error.
    pub fn connect(fd: c_int, address: &[u8]) -> Result<(), Error> {
        // rr: escape(unsafe): address is a sockaddr of its length.
        if unsafe { c::connect(fd, address.as_ptr(), length(address)) } == 0 {
            return Ok(());
        }
        match errno() {
            EINPROGRESS | EINTR => Ok(()),
            code => Err(error(code)),
        }
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    fn accept_one(fd: c_int, address: &mut [u8], size: &mut u32) -> c_int {
        use numbers::{SOCK_CLOEXEC, SOCK_NONBLOCK};
        // rr: escape(unsafe): address holds size bytes.
        unsafe { c::accept4(fd, address.as_mut_ptr(), size, SOCK_NONBLOCK | SOCK_CLOEXEC) }
    }

    #[cfg(target_os = "macos")]
    #[must_use]
    fn accept_one(fd: c_int, address: &mut [u8], size: &mut u32) -> c_int {
        // rr: escape(unsafe): address holds size bytes.
        unsafe { c::accept(fd, address.as_mut_ptr(), size) }
    }

    /// What a failed accept says of the connection it took, not of the
    /// listener: none waits, or the one that did is gone. Linux passes on
    /// the new connection's network errors too, which accept(2) says to
    /// take as EAGAIN.
    #[cfg(target_os = "linux")]
    fn passing(code: c_int) -> bool {
        use numbers::{ENONET, ENOPROTOOPT, EOPNOTSUPP, EPROTO};
        matches!(
            code,
            EAGAIN
                | EINTR
                | ECONNABORTED
                | ENETDOWN
                | EPROTO
                | ENOPROTOOPT
                | EHOSTDOWN
                | ENONET
                | EHOSTUNREACH
                | EOPNOTSUPP
                | ENETUNREACH
        )
    }

    #[cfg(target_os = "macos")]
    fn passing(code: c_int) -> bool {
        matches!(code, EAGAIN | EINTR | ECONNABORTED)
    }

    /// A connection macOS took, made as every socket here is; one it
    /// cannot be made (reset before, as setsockopt then says) is gone.
    #[cfg(target_os = "macos")]
    fn adopt(fd: c_int) -> bool {
        if prepare_new(fd).is_ok() {
            return true;
        }
        close(fd);
        false
    }

    /// accept4 made it whole.
    #[cfg(target_os = "linux")]
    fn adopt(_fd: c_int) -> bool {
        true
    }

    /// The next connection waiting, and its peer; None when none waits,
    /// or when the one that did was reset before it was taken.
    pub fn accept(fd: c_int) -> Result<Option<(c_int, SocketAddr)>, Error> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        let accepted = accept_one(fd, &mut address, &mut size);
        if accepted < 0 {
            let code = errno();
            return if passing(code) {
                Ok(None)
            } else {
                Err(error(code))
            };
        }
        if !adopt(accepted) {
            return Ok(None);
        }
        let filled = usize::try_from(size).unwrap_or(0);
        match address.get(..filled).and_then(decode) {
            Some(peer) => Ok(Some((accepted, peer))),
            None => {
                close(accepted);
                Ok(None)
            }
        }
    }

    fn io(done: isize) -> Result<Io, Error> {
        if let Ok(count) = usize::try_from(done) {
            return Ok(Io::Done(count));
        }
        match errno() {
            EAGAIN | EINTR => Ok(Io::Blocked),
            code => Err(error(code)),
        }
    }

    pub fn read(fd: c_int, into: &mut [u8]) -> Result<Io, Error> {
        // rr: escape(unsafe): into holds its length.
        io(unsafe { c::recv(fd, into.as_mut_ptr().cast(), into.len(), 0) })
    }

    pub fn write(fd: c_int, from: &[u8]) -> Result<Io, Error> {
        // rr: escape(unsafe): from holds its length.
        io(unsafe { c::send(fd, from.as_ptr().cast(), from.len(), SEND_FLAGS) })
    }

    pub fn finish(fd: c_int) -> Result<(), Error> {
        // rr: escape(unsafe): shutdown takes plain numbers.
        check(unsafe { c::shutdown(fd, SHUT_WR) })
    }

    /// The socket's pending error, which reading clears.
    pub fn pending(fd: c_int) -> Result<(), Error> {
        let mut code = [0u8; 4];
        let mut size = length(&code);
        // rr: escape(unsafe): code holds size bytes.
        let done = unsafe {
            c::getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                code.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        check(done)?;
        // An int in the host's order, little on every target.
        match c_int::from_le_bytes(code) {
            0 => Ok(()),
            code => Err(error(code)),
        }
    }

    #[must_use]
    pub fn local(fd: c_int) -> Option<SocketAddr> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let done = unsafe { c::getsockname(fd, address.as_mut_ptr(), &raw mut size) };
        (done == 0).then_some(())?;
        decode(address.get(..usize::try_from(size).ok()?)?)
    }

    /// Whether the connection is made: its peer has a name once it is.
    pub fn established(fd: c_int) -> bool {
        peer(fd).is_some()
    }

    #[must_use]
    pub fn peer(fd: c_int) -> Option<SocketAddr> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let done = unsafe { c::getpeername(fd, address.as_mut_ptr(), &raw mut size) };
        (done == 0).then_some(())?;
        decode(address.get(..usize::try_from(size).ok()?)?)
    }

    /// Closes with a reset: struct linger, on and 0 seconds.
    pub fn reset(fd: c_int) {
        let mut linger = [0u8; 8];
        if let Some(on) = linger.get_mut(..4) {
            // An int in the host's order, little on every target.
            on.copy_from_slice(&1i32.to_le_bytes());
        }
        // rr: escape(unsafe): linger is a struct linger of its length.
        unsafe {
            // rr: escape(discard): refused, the close that follows is an
            // orderly one: a reset is only asked for.
            let _: c_int = c::setsockopt(fd, SOL_SOCKET, SO_LINGER, linger.as_ptr().cast(), 8);
        }
    }

    pub fn close(fd: c_int) {
        // rr: escape(unsafe): fd is its owner's, closed once, by its drop.
        unsafe {
            // rr: escape(discard): close releases the descriptor whatever it
            // answers; no one is left to tell.
            let _: c_int = c::close(fd);
        }
    }

    /// RLIMIT_NOFILE (sys/resource.h); struct rlimit is two rlim_t, the
    /// current limit and the most it may be raised to.
    #[cfg(target_os = "linux")]
    const RLIMIT_NOFILE: c_int = 7;
    #[cfg(target_os = "macos")]
    const RLIMIT_NOFILE: c_int = 8;

    /// macOS's kern.maxfilesperproc, the most descriptors a process may
    /// hold whatever its hard limit says; no limit when it cannot be read.
    #[cfg(target_os = "macos")]
    #[must_use]
    fn per_process() -> u64 {
        let mut most = 0i32;
        let mut length = size_of::<i32>();
        // rr: escape(unsafe): the name is NUL-terminated; most is an int
        // of length bytes.
        let read = unsafe {
            c::sysctlbyname(
                c"kern.maxfilesperproc".as_ptr(),
                (&raw mut most).cast(),
                &raw mut length,
                core::ptr::null(),
                0,
            )
        };
        match (read, u64::try_from(most)) {
            (0, Ok(most)) if most > 0 => most,
            _ => u64::MAX,
        }
    }

    /// Linux keeps the hard limit within fs.nr_open itself.
    #[cfg(target_os = "linux")]
    fn per_process() -> u64 {
        u64::MAX
    }

    /// The soft limit before the first raise; 0 until then. A soft limit
    /// of 0 is never raised from: no descriptor could have opened the
    /// sockets that ask.
    // rr: escape(shared): one limit for the process, which any thread may
    // raise.
    static BEFORE: AtomicU64 = AtomicU64::new(0);

    pub fn descriptors_before() -> Option<u64> {
        Some(BEFORE.load(Ordering::Acquire)).filter(|&before| before != 0)
    }

    #[must_use]
    pub fn descriptors(want: u64) -> u64 {
        let mut limit = [0u64; 2];
        // rr: escape(unsafe): limit is a local struct rlimit.
        if unsafe { c::getrlimit(RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return 0;
        }
        let [current, most] = limit;
        // Up to the hard limit, which Linux keeps within fs.nr_open, and
        // on macOS within kern.maxfilesperproc as well, which the hard
        // limit (often unlimited there) does not show: as Go raises it.
        let asked = want.min(most).min(per_process());
        if asked > current {
            let raised = [asked, most];
            // rr: escape(discard): the first raise keeps what it raised
            // from; a later one finds it kept.
            let _first = BEFORE.compare_exchange(0, current, Ordering::AcqRel, Ordering::Acquire);
            // rr: escape(unsafe): raised is a local struct rlimit.
            unsafe {
                // rr: escape(discard): refused, the limit stays as it was,
                // which getrlimit reads below.
                let _: c_int = c::setrlimit(RLIMIT_NOFILE, raised.as_ptr());
            }
        }
        // What the system holds now, which it may have cut.
        // rr: escape(unsafe): limit is a local struct rlimit.
        if unsafe { c::getrlimit(RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return current;
        }
        let [now, _] = limit;
        now
    }
}

/// Windows: Winsock.
#[cfg(target_os = "windows")]
mod os {
    use super::{ADDRESS_BYTES, Error, Io, decode};
    use crate::base::poll::{
        FIONBIO, HANDLE_FLAG_INHERIT, INVALID_SOCKET, IPPROTO_TCP, SOCK_STREAM,
        WSA_FLAG_NO_HANDLE_INHERIT, startup,
    };
    use core::ffi::c_void;
    use core::net::SocketAddr;
    use core::ptr::{null, without_provenance_mut};

    /// The system's calls, apart from the functions named after them.
    mod c {
        use core::ffi::c_void;

        #[link(name = "ws2_32", kind = "raw-dylib")]
        // rr: escape(unsafe): each signature is ws2_32's, from its documentation.
        unsafe extern "system" {
            #[must_use]
            pub(super) fn WSASocketW(
                family: i32,
                kind: i32,
                protocol: i32,
                info: *const c_void,
                group: u32,
                flags: u32,
            ) -> usize;
            #[must_use]
            pub(super) fn bind(socket: usize, address: *const u8, length: i32) -> i32;
            #[must_use]
            pub(super) fn listen(socket: usize, backlog: i32) -> i32;
            #[must_use]
            pub(super) fn accept(socket: usize, address: *mut u8, length: *mut i32) -> usize;
            #[must_use]
            pub(super) fn connect(socket: usize, address: *const u8, length: i32) -> i32;
            #[must_use]
            pub(super) fn getsockname(socket: usize, address: *mut u8, length: *mut i32) -> i32;
            #[must_use]
            pub(super) fn getpeername(socket: usize, address: *mut u8, length: *mut i32) -> i32;
            #[must_use]
            pub(super) fn getsockopt(
                socket: usize,
                level: i32,
                name: i32,
                value: *mut u8,
                length: *mut i32,
            ) -> i32;
            #[must_use]
            pub(super) fn setsockopt(
                socket: usize,
                level: i32,
                name: i32,
                value: *const u8,
                length: i32,
            ) -> i32;
            #[must_use]
            pub(super) fn send(socket: usize, buffer: *const u8, length: i32, flags: i32) -> i32;
            #[must_use]
            pub(super) fn recv(socket: usize, buffer: *mut u8, length: i32, flags: i32) -> i32;
            #[must_use]
            pub(super) fn shutdown(socket: usize, how: i32) -> i32;
            #[must_use]
            pub(super) fn closesocket(socket: usize) -> i32;
            #[must_use]
            pub(super) fn ioctlsocket(socket: usize, command: i32, argument: *mut u32) -> i32;
            #[must_use]
            pub(super) fn WSAGetLastError() -> i32;
        }
    }

    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): its signature is kernel32's, from its documentation.
    unsafe extern "system" {
        #[must_use]
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    }

    // ws2def.h's, ws2ipdef.h's, winsock2.h's and their WSAE* codes.
    pub use crate::base::poll::{AF_INET, AF_INET6};
    const SOL_SOCKET: i32 = 0xffff;
    const SO_ERROR: i32 = 0x1007;
    const SO_LINGER: i32 = 0x80;
    const IPPROTO_IPV6: i32 = 41;
    const IPV6_V6ONLY: i32 = 27;
    const TCP_NODELAY: i32 = 1;
    const SD_SEND: i32 = 1;
    /// mswsock.h: the seconds a socket has been connected.
    const SO_CONNECT_TIME: i32 = 0x700C;
    const WSAEINTR: i32 = 10004;
    const WSAEACCES: i32 = 10013;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAEADDRINUSE: i32 = 10048;
    const WSAENETDOWN: i32 = 10050;
    const WSAENETUNREACH: i32 = 10051;
    const WSAENETRESET: i32 = 10052;
    const WSAECONNABORTED: i32 = 10053;
    const WSAECONNRESET: i32 = 10054;
    const WSAESHUTDOWN: i32 = 10058;
    const WSAETIMEDOUT: i32 = 10060;
    const WSAECONNREFUSED: i32 = 10061;
    const WSAEHOSTDOWN: i32 = 10064;
    const WSAEHOSTUNREACH: i32 = 10065;

    #[must_use]
    fn last() -> i32 {
        // rr: escape(unsafe): the thread's last Winsock error.
        unsafe { c::WSAGetLastError() }
    }

    pub fn error(code: i32) -> Error {
        match code {
            WSAECONNREFUSED => Error::Refused,
            WSAECONNRESET | WSAECONNABORTED | WSAESHUTDOWN | WSAENETRESET => Error::Reset,
            WSAETIMEDOUT => Error::TimedOut,
            WSAEHOSTUNREACH | WSAENETUNREACH | WSAEHOSTDOWN | WSAENETDOWN => Error::Unreachable,
            WSAEADDRINUSE => Error::InUse,
            other => Error::Other(other),
        }
    }

    fn check(done: i32) -> Result<(), Error> {
        if done == 0 {
            Ok(())
        } else {
            Err(error(last()))
        }
    }

    /// The family, two bytes in the host's order, little on Windows.
    pub fn family(family: u16, _length: usize) -> [u8; 2] {
        family.to_le_bytes()
    }

    pub fn family_of(bytes: &[u8]) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
    }

    fn length(bytes: &[u8]) -> i32 {
        i32::try_from(bytes.len()).unwrap_or(0)
    }

    /// Makes a socket non-blocking.
    fn non_blocking(socket: usize) -> Result<(), Error> {
        let mut on = 1u32;
        // rr: escape(unsafe): on is a local u_long.
        check(unsafe { c::ioctlsocket(socket, FIONBIO, &raw mut on) })
    }

    /// A new socket for address's family: non-blocking, and no child
    /// process inherits it.
    pub fn open(address: &SocketAddr) -> Result<usize, Error> {
        startup();
        let family = i32::from(if address.is_ipv4() { AF_INET } else { AF_INET6 });
        let flags = WSA_FLAG_NO_HANDLE_INHERIT;
        // rr: escape(unsafe): WSASocketW takes plain numbers.
        let socket = unsafe { c::WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, null(), 0, flags) };
        if socket == INVALID_SOCKET {
            return Err(error(last()));
        }
        non_blocking(socket).inspect_err(|_| close(socket))?;
        Ok(socket)
    }

    fn option(socket: usize, level: i32, name: i32, value: i32) -> Result<(), Error> {
        let bytes = value.to_le_bytes();
        // rr: escape(unsafe): bytes holds an int, as each option here takes.
        check(unsafe { c::setsockopt(socket, level, name, bytes.as_ptr(), length(&bytes)) })
    }

    /// A listener's options: IPv6 alone on an IPv6 socket, and nothing
    /// for its address, as in Go, libuv and Rust's std. Windows takes an
    /// address again while connections to it linger in TIME_WAIT without
    /// SO_REUSEADDR, which would let another socket take it while it
    /// listens; and SO_EXCLUSIVEADDRUSE refuses it until those
    /// connections are gone (Microsoft's "Using SO_REUSEADDR and
    /// SO_EXCLUSIVEADDRUSE", libuv's issue 1360), which a server that
    /// restarts cannot wait for. Without either, a second listener on the
    /// address is refused, as on Linux and macOS; only the same user may
    /// still take a specific address under a listener on the wildcard
    /// one, which SO_EXCLUSIVEADDRUSE alone would refuse.
    pub fn prepare(socket: usize, v6: bool) -> Result<(), Error> {
        if v6 {
            option(socket, IPPROTO_IPV6, IPV6_V6ONLY, 1)?;
        }
        Ok(())
    }

    pub fn no_delay(socket: usize, on: bool) -> Result<(), Error> {
        option(socket, IPPROTO_TCP, TCP_NODELAY, i32::from(on))
    }

    /// Windows has no option that spreads connections among listeners
    /// on one address: SO_REUSEADDR lets one take it, unbalanced.
    pub const BALANCED: bool = false;

    /// Never reached: BALANCED refuses first.
    pub fn share(_socket: usize) -> Result<(), Error> {
        Err(Error::Unbalanced)
    }

    /// Binds; an address another user's socket holds, or one that set
    /// SO_EXCLUSIVEADDRUSE, or one the system keeps for itself (an
    /// excluded port range), is refused as access denied (WSAEACCES),
    /// which is the address in use.
    pub fn bind(socket: usize, address: &[u8]) -> Result<(), Error> {
        // rr: escape(unsafe): address is a sockaddr of its length.
        if unsafe { c::bind(socket, address.as_ptr(), length(address)) } == 0 {
            return Ok(());
        }
        match last() {
            WSAEACCES => Err(Error::InUse),
            code => Err(error(code)),
        }
    }

    pub fn listen(socket: usize, backlog: u32) -> Result<(), Error> {
        let backlog = i32::try_from(backlog).unwrap_or(i32::MAX);
        // rr: escape(unsafe): the socket is bound.
        check(unsafe { c::listen(socket, backlog) })
    }

    /// Begins a connection; one still being made is no error.
    pub fn connect(socket: usize, address: &[u8]) -> Result<(), Error> {
        // rr: escape(unsafe): address is a sockaddr of its length.
        if unsafe { c::connect(socket, address.as_ptr(), length(address)) } == 0 {
            return Ok(());
        }
        match last() {
            WSAEWOULDBLOCK | WSAEINTR => Ok(()),
            code => Err(error(code)),
        }
    }

    /// The next connection waiting, and its peer; None when none waits,
    /// or when the one that did was reset before it was taken. It is
    /// made non-blocking and not inherited here, whatever it took from
    /// the listener.
    pub fn accept(listener: usize) -> Result<Option<(usize, SocketAddr)>, Error> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let socket = unsafe { c::accept(listener, address.as_mut_ptr(), &raw mut size) };
        if socket == INVALID_SOCKET {
            return match last() {
                WSAEWOULDBLOCK | WSAEINTR | WSAECONNRESET => Ok(None),
                code => Err(error(code)),
            };
        }
        // rr: escape(unsafe): the accepted socket is ours; a SOCKET is a
        // handle.
        let kept =
            unsafe { SetHandleInformation(without_provenance_mut(socket), HANDLE_FLAG_INHERIT, 0) };
        let filled = usize::try_from(size).unwrap_or(0);
        let peer = address.get(..filled).and_then(decode);
        match (kept != 0, non_blocking(socket), peer) {
            (true, Ok(()), Some(peer)) => Ok(Some((socket, peer))),
            _ => {
                close(socket);
                Ok(None)
            }
        }
    }

    fn io(done: i32) -> Result<Io, Error> {
        if let Ok(count) = usize::try_from(done) {
            return Ok(Io::Done(count));
        }
        match last() {
            WSAEWOULDBLOCK | WSAEINTR => Ok(Io::Blocked),
            code => Err(error(code)),
        }
    }

    pub fn read(socket: usize, into: &mut [u8]) -> Result<Io, Error> {
        let room = i32::try_from(into.len()).unwrap_or(i32::MAX);
        // rr: escape(unsafe): into holds at least room bytes.
        io(unsafe { c::recv(socket, into.as_mut_ptr(), room, 0) })
    }

    pub fn write(socket: usize, from: &[u8]) -> Result<Io, Error> {
        let count = i32::try_from(from.len()).unwrap_or(i32::MAX);
        // rr: escape(unsafe): from holds at least count bytes.
        io(unsafe { c::send(socket, from.as_ptr(), count, 0) })
    }

    pub fn finish(socket: usize) -> Result<(), Error> {
        // rr: escape(unsafe): shutdown takes plain numbers.
        check(unsafe { c::shutdown(socket, SD_SEND) })
    }

    /// The socket's pending error.
    pub fn pending(socket: usize) -> Result<(), Error> {
        let mut code = [0u8; 4];
        let mut size = length(&code);
        // rr: escape(unsafe): code holds size bytes.
        let done = unsafe {
            c::getsockopt(
                socket,
                SOL_SOCKET,
                SO_ERROR,
                code.as_mut_ptr(),
                &raw mut size,
            )
        };
        check(done)?;
        match i32::from_le_bytes(code) {
            0 => Ok(()),
            code => Err(error(code)),
        }
    }

    /// Whether the connection is made. getpeername names the peer while
    /// the connection is still being made, and a write then fails with
    /// WSAENOTCONN; SO_CONNECT_TIME says it: the seconds since it was
    /// made, and before that 0xFFFFFFFF or an error, as its two pages
    /// in Microsoft's documentation tell it differently.
    #[must_use]
    pub fn established(socket: usize) -> bool {
        let mut seconds = [0u8; 4];
        let mut size = length(&seconds);
        // rr: escape(unsafe): seconds holds size bytes.
        let done = unsafe {
            c::getsockopt(
                socket,
                SOL_SOCKET,
                SO_CONNECT_TIME,
                seconds.as_mut_ptr(),
                &raw mut size,
            )
        };
        // rr: escape(sentinel): 0xFFFFFFFF is Windows's own word for not
        // connected in SO_CONNECT_TIME.
        done == 0 && u32::from_le_bytes(seconds) != u32::MAX
    }

    #[must_use]
    pub fn local(socket: usize) -> Option<SocketAddr> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let done = unsafe { c::getsockname(socket, address.as_mut_ptr(), &raw mut size) };
        (done == 0).then_some(())?;
        decode(address.get(..usize::try_from(size).ok()?)?)
    }

    #[must_use]
    pub fn peer(socket: usize) -> Option<SocketAddr> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let done = unsafe { c::getpeername(socket, address.as_mut_ptr(), &raw mut size) };
        (done == 0).then_some(())?;
        decode(address.get(..usize::try_from(size).ok()?)?)
    }

    /// Closes with a reset: struct linger, two u_shorts, on and 0.
    pub fn reset(socket: usize) {
        let [on, off] = 1u16.to_le_bytes();
        let linger = [on, off, 0, 0];
        // rr: escape(unsafe): linger is a struct linger of its length.
        unsafe {
            // rr: escape(discard): refused, the close that follows is an
            // orderly one: a reset is only asked for.
            let _: i32 = c::setsockopt(socket, SOL_SOCKET, SO_LINGER, linger.as_ptr(), 4);
        }
    }

    pub fn close(socket: usize) {
        // rr: escape(unsafe): the socket is its owner's, closed once, by its
        // drop.
        unsafe {
            // rr: escape(discard): closesocket releases the socket whatever it
            // answers; no one is left to tell.
            let _: i32 = c::closesocket(socket);
        }
    }

    /// Windows has no limit to raise: as many as asked.
    pub fn descriptors(want: u64) -> u64 {
        want
    }

    pub fn descriptors_before() -> Option<u64> {
        None
    }
}
