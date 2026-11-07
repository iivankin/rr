//! The system side of net: what mod.rs says it is, for each system.

use crate::base::wait::{Raw, Set, Token};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Why a socket call failed, as a loop acts on it.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// Nobody listens there.
    Refused,
    /// The peer reset or aborted the connection, or is gone and a write
    /// found out.
    Reset,
    /// The connection timed out.
    TimedOut,
    /// No route to the host or its network.
    Unreachable,
    /// The address is taken.
    InUse,
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

/// A socket, and its entry in a Set with the key it was watched with.
struct Socket {
    fd: Raw,
    entry: Option<(Token, u64)>,
}

impl Socket {
    fn watch(&mut self, set: &mut Set, interest: u8, key: u64) -> bool {
        match self.entry {
            Some((token, same)) if same == key => set.modify(token, interest),
            entry => {
                if let Some((token, _)) = entry {
                    set.remove(token);
                }
                self.entry = set.add(self.fd, interest, key).map(|token| (token, key));
                self.entry.is_some()
            }
        }
    }

    fn token(&self) -> Option<Token> {
        self.entry.map(|(token, _)| token)
    }

    /// Takes the socket out of the Set, before drop closes it.
    fn leave(&mut self, set: &mut Set) {
        if let Some((token, _)) = self.entry.take() {
            set.remove(token);
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        os::close(self.fd);
    }
}

/// A TCP connection.
pub struct Stream {
    socket: Socket,
}

impl Stream {
    /// Begins a connection to address. It is made once the socket is
    /// writable, or has an error or a hangup, and connected says so.
    pub fn connect(address: SocketAddr) -> Result<Stream, Error> {
        let socket = Socket {
            fd: os::open(&address)?,
            entry: None,
        };
        let (bytes, length) = encode(&address);
        os::connect(socket.fd, bytes.get(..length).unwrap_or_default())?;
        Ok(Stream { socket })
    }

    /// Whether the connection is made: false while it is still being
    /// made, its error once it failed.
    pub fn connected(&self) -> Result<bool, Error> {
        os::pending(self.socket.fd)?;
        Ok(self.peer().is_some())
    }

    /// Reads what has come, into into.
    pub fn read(&self, into: &mut [u8]) -> Result<Io, Error> {
        os::read(self.socket.fd, into)
    }

    /// Writes what the system takes of from now.
    pub fn write(&self, from: &[u8]) -> Result<Io, Error> {
        os::write(self.socket.fd, from)
    }

    /// Ends the writing side: the peer reads its end, and may still send.
    pub fn finish(&self) -> Result<(), Error> {
        os::finish(self.socket.fd)
    }

    /// Sends small writes at once (TCP_NODELAY), as a server that answers
    /// requests wants.
    pub fn no_delay(&self) -> Result<(), Error> {
        os::no_delay(self.socket.fd)
    }

    pub fn local(&self) -> Option<SocketAddr> {
        os::local(self.socket.fd)
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        os::peer(self.socket.fd)
    }

    /// Puts the stream in set with interest, reported with key, or
    /// changes them.
    pub fn watch(&mut self, set: &mut Set, interest: u8, key: u64) -> bool {
        self.socket.watch(set, interest, key)
    }

    /// The stream's entry in its Set, for a deadline.
    pub fn token(&self) -> Option<Token> {
        self.socket.token()
    }

    /// The socket as the system names it, which the stream still owns.
    pub fn raw(&self) -> Raw {
        self.socket.fd
    }

    /// Takes the stream out of set, then closes it.
    pub fn close(mut self, set: &mut Set) {
        self.socket.leave(set);
    }

    /// Closes with a reset (SO_LINGER 0), as for a peer that misbehaved:
    /// what was not sent is dropped.
    pub fn abort(mut self, set: &mut Set) {
        self.socket.leave(set);
        os::reset(self.socket.fd);
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
        let socket = Socket {
            fd: os::open(&address)?,
            entry: None,
        };
        os::prepare(socket.fd, address.is_ipv6())?;
        let (bytes, length) = encode(&address);
        os::bind(socket.fd, bytes.get(..length).unwrap_or_default())?;
        os::listen(socket.fd, backlog)?;
        Ok(Listener { socket })
    }

    /// The next connection and its peer's address; None when none waits.
    pub fn accept(&self) -> Result<Option<(Stream, SocketAddr)>, Error> {
        let Some((fd, peer)) = os::accept(self.socket.fd)? else {
            return Ok(None);
        };
        let stream = Stream {
            socket: Socket { fd, entry: None },
        };
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

    /// Puts the listener in set with interest, reported with key, or
    /// changes them.
    pub fn watch(&mut self, set: &mut Set, interest: u8, key: u64) -> bool {
        self.socket.watch(set, interest, key)
    }

    /// Takes the listener out of set, then closes it.
    pub fn close(mut self, set: &mut Set) {
        self.socket.leave(set);
    }
}

/// Raises the descriptors this process may hold to want, or as many as
/// the system lets it, and says how many it has: a server of many
/// connections needs more than the 256 (macOS) or 1024 (Linux) a process
/// starts with, as Go raises them itself. Windows sets no such limit.
pub fn descriptors(want: u64) -> u64 {
    os::descriptors(want)
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
    use crate::base::wait::SOCK_STREAM;
    use core::ffi::c_int;
    use core::net::SocketAddr;

    /// The system's calls, apart from the functions named after them.
    mod c {
        use core::ffi::{c_int, c_void};

        #[link(name = "c")]
        // rr: escape(unsafe): each signature is the C library's, from its headers.
        unsafe extern "C" {
            pub(super) fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
            pub(super) fn bind(fd: c_int, address: *const u8, length: u32) -> c_int;
            pub(super) fn listen(fd: c_int, backlog: c_int) -> c_int;
            #[cfg(target_os = "linux")]
            pub(super) fn accept4(
                fd: c_int,
                address: *mut u8,
                length: *mut u32,
                flags: c_int,
            ) -> c_int;
            #[cfg(target_os = "macos")]
            pub(super) fn accept(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            pub(super) fn connect(fd: c_int, address: *const u8, length: u32) -> c_int;
            pub(super) fn getsockname(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            pub(super) fn getpeername(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
            pub(super) fn getsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *mut c_void,
                length: *mut u32,
            ) -> c_int;
            pub(super) fn setsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *const c_void,
                length: u32,
            ) -> c_int;
            pub(super) fn send(
                fd: c_int,
                buffer: *const c_void,
                length: usize,
                flags: c_int,
            ) -> isize;
            pub(super) fn recv(
                fd: c_int,
                buffer: *mut c_void,
                length: usize,
                flags: c_int,
            ) -> isize;
            pub(super) fn shutdown(fd: c_int, how: c_int) -> c_int;
            pub(super) fn close(fd: c_int) -> c_int;
            #[cfg(target_os = "macos")]
            pub(super) fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
            pub(super) fn getrlimit(resource: c_int, limit: *mut u64) -> c_int;
            pub(super) fn setrlimit(resource: c_int, limit: *const u64) -> c_int;
            #[cfg(target_os = "macos")]
            pub(super) fn __error() -> *mut c_int;
            #[cfg(target_os = "linux")]
            pub(super) fn __errno_location() -> *mut c_int;
        }
    }

    // sys/socket.h's, netinet/in.h's, netinet/tcp.h's and errno.h's: Linux's
    // from asm-generic, as x86_64 and aarch64 have them, macOS's from its
    // SDK.
    use crate::base::wait::EINTR;
    pub use crate::base::wait::{AF_INET, AF_INET6};
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
        pub const IPV6_V6ONLY: c_int = 26;
        pub const SEND_FLAGS: c_int = 0x4000;
        pub const SOCK_NONBLOCK: c_int = 0x800;
        pub const SOCK_CLOEXEC: c_int = 0x8_0000;
        pub const EAGAIN: c_int = 11;
        pub const EINPROGRESS: c_int = 115;
        pub const ECONNREFUSED: c_int = 111;
        pub const ECONNRESET: c_int = 104;
        pub const ECONNABORTED: c_int = 103;
        pub const ETIMEDOUT: c_int = 110;
        pub const EHOSTUNREACH: c_int = 113;
        pub const ENETUNREACH: c_int = 101;
        pub const EADDRINUSE: c_int = 98;
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
        pub const ETIMEDOUT: c_int = 60;
        pub const EHOSTUNREACH: c_int = 65;
        pub const ENETUNREACH: c_int = 51;
        pub const EADDRINUSE: c_int = 48;
    }
    use numbers::{
        EADDRINUSE, EAGAIN, ECONNABORTED, ECONNREFUSED, ECONNRESET, EHOSTUNREACH, EINPROGRESS,
        ENETUNREACH, ETIMEDOUT, IPV6_V6ONLY, SEND_FLAGS, SO_ERROR, SO_LINGER, SO_REUSEADDR,
        SOL_SOCKET,
    };

    #[cfg(target_os = "macos")]
    fn errno_place() -> *mut c_int {
        // rr: escape(unsafe): the C library's thread-local errno.
        unsafe { c::__error() }
    }

    #[cfg(target_os = "linux")]
    fn errno_place() -> *mut c_int {
        // rr: escape(unsafe): the C library's thread-local errno.
        unsafe { c::__errno_location() }
    }

    fn errno() -> c_int {
        let place = errno_place();
        // rr: escape(unsafe): the place is this thread's errno.
        unsafe { place.read() }
    }

    pub fn error(code: c_int) -> Error {
        match code {
            ECONNREFUSED => Error::Refused,
            ECONNRESET | EPIPE | ECONNABORTED => Error::Reset,
            ETIMEDOUT => Error::TimedOut,
            EHOSTUNREACH | ENETUNREACH => Error::Unreachable,
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
        use crate::base::wait::{F_SETFD, FD_CLOEXEC};
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

    pub fn no_delay(fd: c_int) -> Result<(), Error> {
        option(fd, IPPROTO_TCP, TCP_NODELAY, 1)
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
    fn accept_one(fd: c_int, address: &mut [u8], size: &mut u32) -> c_int {
        use numbers::{SOCK_CLOEXEC, SOCK_NONBLOCK};
        // rr: escape(unsafe): address holds size bytes.
        unsafe { c::accept4(fd, address.as_mut_ptr(), size, SOCK_NONBLOCK | SOCK_CLOEXEC) }
    }

    #[cfg(target_os = "macos")]
    fn accept_one(fd: c_int, address: &mut [u8], size: &mut u32) -> c_int {
        // rr: escape(unsafe): address holds size bytes.
        let accepted = unsafe { c::accept(fd, address.as_mut_ptr(), size) };
        if accepted >= 0 && prepare_new(accepted).is_err() {
            close(accepted);
            return -1;
        }
        accepted
    }

    /// The next connection waiting, and its peer; None when none waits,
    /// or when the one that did was reset before it was taken.
    pub fn accept(fd: c_int) -> Result<Option<(c_int, SocketAddr)>, Error> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        let accepted = accept_one(fd, &mut address, &mut size);
        if accepted < 0 {
            return match errno() {
                EAGAIN | EINTR | ECONNABORTED => Ok(None),
                code => Err(error(code)),
            };
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

    pub fn local(fd: c_int) -> Option<SocketAddr> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let done = unsafe { c::getsockname(fd, address.as_mut_ptr(), &raw mut size) };
        (done == 0).then_some(())?;
        decode(address.get(..usize::try_from(size).ok()?)?)
    }

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
        unsafe { c::setsockopt(fd, SOL_SOCKET, SO_LINGER, linger.as_ptr().cast(), 8) };
    }

    pub fn close(fd: c_int) {
        // rr: escape(unsafe): fd is its owner's, closed once, by its drop.
        unsafe { c::close(fd) };
    }

    /// RLIMIT_NOFILE (sys/resource.h); struct rlimit is two rlim_t, the
    /// current limit and the most it may be raised to.
    #[cfg(target_os = "linux")]
    const RLIMIT_NOFILE: c_int = 7;
    #[cfg(target_os = "macos")]
    const RLIMIT_NOFILE: c_int = 8;

    pub fn descriptors(want: u64) -> u64 {
        let mut limit = [0u64; 2];
        // rr: escape(unsafe): limit is a local struct rlimit.
        if unsafe { c::getrlimit(RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
            return 0;
        }
        let [current, most] = limit;
        if current >= want {
            return current;
        }
        // macOS refuses more than kern.maxfilesperproc: then it stays.
        let raised = [want.min(most), most];
        // rr: escape(unsafe): raised is a local struct rlimit.
        if unsafe { c::setrlimit(RLIMIT_NOFILE, raised.as_ptr()) } == 0 {
            want.min(most)
        } else {
            current
        }
    }
}

/// Windows: Winsock.
#[cfg(target_os = "windows")]
mod os {
    use super::{ADDRESS_BYTES, Error, Io, decode};
    use crate::base::wait::{
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
            pub(super) fn WSASocketW(
                family: i32,
                kind: i32,
                protocol: i32,
                info: *const c_void,
                group: u32,
                flags: u32,
            ) -> usize;
            pub(super) fn bind(socket: usize, address: *const u8, length: i32) -> i32;
            pub(super) fn listen(socket: usize, backlog: i32) -> i32;
            pub(super) fn accept(socket: usize, address: *mut u8, length: *mut i32) -> usize;
            pub(super) fn connect(socket: usize, address: *const u8, length: i32) -> i32;
            pub(super) fn getsockname(socket: usize, address: *mut u8, length: *mut i32) -> i32;
            pub(super) fn getpeername(socket: usize, address: *mut u8, length: *mut i32) -> i32;
            pub(super) fn getsockopt(
                socket: usize,
                level: i32,
                name: i32,
                value: *mut u8,
                length: *mut i32,
            ) -> i32;
            pub(super) fn setsockopt(
                socket: usize,
                level: i32,
                name: i32,
                value: *const u8,
                length: i32,
            ) -> i32;
            pub(super) fn send(socket: usize, buffer: *const u8, length: i32, flags: i32) -> i32;
            pub(super) fn recv(socket: usize, buffer: *mut u8, length: i32, flags: i32) -> i32;
            pub(super) fn shutdown(socket: usize, how: i32) -> i32;
            pub(super) fn closesocket(socket: usize) -> i32;
            pub(super) fn ioctlsocket(socket: usize, command: i32, argument: *mut u32) -> i32;
            pub(super) fn WSAGetLastError() -> i32;
        }
    }

    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): its signature is kernel32's, from its documentation.
    unsafe extern "system" {
        fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    }

    // ws2def.h's, ws2ipdef.h's, winsock2.h's and their WSAE* codes.
    pub use crate::base::wait::{AF_INET, AF_INET6};
    const SOL_SOCKET: i32 = 0xffff;
    const SO_ERROR: i32 = 0x1007;
    const SO_LINGER: i32 = 0x80;
    /// ~SO_REUSEADDR: nobody else may bind the address while it is ours.
    const SO_EXCLUSIVEADDRUSE: i32 = !0x4;
    const IPPROTO_IPV6: i32 = 41;
    const IPV6_V6ONLY: i32 = 27;
    const TCP_NODELAY: i32 = 1;
    const SD_SEND: i32 = 1;
    const WSAEINTR: i32 = 10004;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAEADDRINUSE: i32 = 10048;
    const WSAENETUNREACH: i32 = 10051;
    const WSAECONNABORTED: i32 = 10053;
    const WSAECONNRESET: i32 = 10054;
    const WSAESHUTDOWN: i32 = 10058;
    const WSAETIMEDOUT: i32 = 10060;
    const WSAECONNREFUSED: i32 = 10061;
    const WSAEHOSTUNREACH: i32 = 10065;

    fn last() -> i32 {
        // rr: escape(unsafe): the thread's last Winsock error.
        unsafe { c::WSAGetLastError() }
    }

    pub fn error(code: i32) -> Error {
        match code {
            WSAECONNREFUSED => Error::Refused,
            WSAECONNRESET | WSAECONNABORTED | WSAESHUTDOWN => Error::Reset,
            WSAETIMEDOUT => Error::TimedOut,
            WSAEHOSTUNREACH | WSAENETUNREACH => Error::Unreachable,
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

    /// A listener's options: nobody else binds its address while it
    /// listens; IPv6 alone on an IPv6 socket.
    pub fn prepare(socket: usize, v6: bool) -> Result<(), Error> {
        option(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)?;
        if v6 {
            option(socket, IPPROTO_IPV6, IPV6_V6ONLY, 1)?;
        }
        Ok(())
    }

    pub fn no_delay(socket: usize) -> Result<(), Error> {
        option(socket, IPPROTO_TCP, TCP_NODELAY, 1)
    }

    pub fn bind(socket: usize, address: &[u8]) -> Result<(), Error> {
        // rr: escape(unsafe): address is a sockaddr of its length.
        check(unsafe { c::bind(socket, address.as_ptr(), length(address)) })
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

    pub fn local(socket: usize) -> Option<SocketAddr> {
        let mut address = [0u8; ADDRESS_BYTES];
        let mut size = length(&address);
        // rr: escape(unsafe): address holds size bytes.
        let done = unsafe { c::getsockname(socket, address.as_mut_ptr(), &raw mut size) };
        (done == 0).then_some(())?;
        decode(address.get(..usize::try_from(size).ok()?)?)
    }

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
        unsafe { c::setsockopt(socket, SOL_SOCKET, SO_LINGER, linger.as_ptr(), 4) };
    }

    pub fn close(socket: usize) {
        // rr: escape(unsafe): the socket is its owner's, closed once, by its
        // drop.
        unsafe { c::closesocket(socket) };
    }

    /// Windows has no limit to raise: as many as asked.
    pub fn descriptors(want: u64) -> u64 {
        want
    }
}
