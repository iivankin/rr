//! Host lookup that never blocks the caller's loop, one API on Linux, macOS
//! and Windows: start a Lookup on an io::Io, take the addresses once its
//! Event came (socket_addr keeps a link-local one's interface). The
//! system answers as it answers every program there, on io's pool of
//! threads: the C library's getaddrinfo on Linux and macOS, GetAddrInfoW on
//! Windows, each sorted by RFC 6724; a lookup canceled after a thread took
//! it runs on to the system's timeout, its answer dropped.
//!
//! Looking up a host's addresses as the system would, without blocking the
//! caller's loop, the same on all three:
//!
//! ```text
//! let (lookup, op) = Lookup::start(&mut io, b"example.com", KEY)?;
//! ... the loop waits; an Event with KEY comes (Done::Ran) ...
//! let addresses = lookup.take();     // Some(Ok(..)) or Some(Err(..))
//! ```
//!
//! Connect to an address's socket_addr, which keeps a link-local one's
//! interface. resolve waits for the answer, for a thread that may block:
//! it is `#[rr::blocking]`, which rr refuses on the path of a loop marked
//! `rr::poll`.
//!
//! Some names are answered before any system sees them, the same on all
//! three: no name (empty, ".", not ASCII: an internationalized name comes
//! as its A-labels), .onion (RFC 7686) and a name that ends in a number
//! but is no dotted-decimal address (127.1) are not found; localhost and
//! the names under it are the loopback addresses (RFC 6761); an IPv4
//! address is itself.
//!
//! The system answers, as it answers every program there:
//!
//! - Linux: the C library's getaddrinfo, with nsswitch.conf, files, DNS,
//!   systemd-resolved and mDNS as the system has them.
//! - macOS: getaddrinfo, which asks mDNSResponder, with VPN and split DNS
//!   as the system has them, and asks for IPv6 only where the host has a
//!   routable IPv6 address.
//! - Windows: GetAddrInfoW, as Go and libuv ask it.
//!
//! Each blocks its thread, so a lookup runs on io's pool (thread's): at
//! most as many as thread's pool runs at once, the rest in line. One canceled in
//! line never asks; one a thread took runs on to the system's timeout
//! (resolv.conf's timeout and attempts on Linux), and its answer is
//! dropped.
//!
//! A process out of descriptors may be told a name is not found: macOS's
//! getaddrinfo says EAI_NONAME then, as Go notes, and a C library on Linux
//! that cannot open its files or sockets may not say why either. resolve
//! keeps no answer, and takes what it can tell as for now (a system error
//! of EMFILE or ENFILE); a caller that keeps NotFound keeps it no longer
//! than such a moment.

// rr: checked(0.5.2)
// rr: needs(io, thread)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests
// rr: choice(tests = no): none
// rr: option(os, many): Which systems does it build for?
// rr: choice(os = linux, default): Linux
// rr: choice(os = macos, default): macOS
// rr: choice(os = windows, default): Windows

// rr: unless(os = linux)
#[cfg(target_os = "linux")]
compile_error!("rr add cut resolve without linux: add it again with linux in --option os");
// rr: end(os = linux)
// rr: unless(os = macos)
#[cfg(target_os = "macos")]
compile_error!("rr add cut resolve without macos: add it again with macos in --option os");
// rr: end(os = macos)
// rr: unless(os = windows)
#[cfg(windows)]
compile_error!("rr add cut resolve without windows: add it again with windows in --option os");
// rr: end(os = windows)

mod sys {
    //! The system side of resolve: what the top of the file says it is, for each system.

    use crate::base::io::{AF_INET, AF_INET6, Io, Op, Work};
    use crate::base::thread::Lock;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    /// An address, and for a link-local IPv6 one the interface it is on:
    /// connect to socket_addr's, which keeps it, as a SocketAddr made of ip
    /// alone does not.
    #[derive(Clone, Copy)]
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug, PartialEq))]
    // rr: end(tests = yes)
    pub struct Address {
        pub ip: IpAddr,
        pub scope: u32,
    }

    impl Address {
        /// The address at port, an IPv6 one with its scope.
        pub fn socket_addr(&self, port: u16) -> SocketAddr {
            match self.ip {
                IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
                IpAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(v6, port, 0, self.scope)),
            }
        }
    }

    /// Why a lookup gave no address.
    #[derive(Clone, Copy)]
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug, PartialEq))]
    // rr: end(tests = yes)
    pub enum Error {
        /// No such host.
        NotFound,
        /// The servers or the network failed for now.
        Temporary,
        /// Anything else: a server that answers nonsense, a system error.
        Failed,
        /// Lookup::start: the Io's table is full; take its Events and start
        /// again.
        Full,
    }

    /// What a lookup found, which its work writes on the pool's thread and
    /// the loop takes, under a lock.
    struct Answer {
        lock: Lock,
        found: UnsafeCell<Option<Result<Vec<Address>, Error>>>,
    }

    // rr: escape(unsafe): found is reached only under lock (Answer::put,
    // Answer::take).
    unsafe impl Sync for Answer {}

    impl Answer {
        fn put(&self, found: Result<Vec<Address>, Error>) {
            let _held = self.lock.lock();
            // rr: escape(unsafe): the lock is held: no one else touches it.
            unsafe { *self.found.get() = Some(found) };
        }

        #[must_use]
        fn take(&self) -> Option<Result<Vec<Address>, Error>> {
            let _held = self.lock.lock();
            // rr: escape(unsafe): the lock is held: no one else touches it.
            unsafe { (*self.found.get()).take() }
        }
    }

    /// The lookup io's pool runs: the name in, what the system said out.
    struct Query {
        name: Vec<u8>,
        answer: Arc<Answer>,
    }

    impl Work for Query {
        fn run(&mut self) {
            self.answer.put(resolve(&self.name));
        }
    }

    /// One name's lookup, on an Io's pool: take its addresses once the
    /// Event of its key came. io's cancel keeps it from asking while it
    /// waits in line; dropped, it lets go of what it would find.
    #[must_use]
    pub struct Lookup {
        answer: Arc<Answer>,
    }

    impl Lookup {
        /// Starts looking up name, a host name in ASCII (an
        /// internationalized one as its A-labels, xn--) or a literal
        /// address, on io's pool: the Op, whose Event has key, says when it
        /// is done (Done::Ran).
        pub fn start(io: &mut Io, name: &[u8], key: u64) -> Result<(Lookup, Op), Error> {
            // rr: escape(shared): the lookup and its work hold it.
            let answer = Arc::new(Answer {
                lock: Lock::new(),
                found: UnsafeCell::new(None),
            });
            let mut held = Vec::with_capacity(name.len());
            // rr: escape(copy): the work, on another thread, keeps the name.
            held.extend_from_slice(name);
            let query = Query {
                name: held,
                // rr: escape(copy): the work's holder of the answer.
                answer: Arc::clone(&answer),
            };
            match io.run(Box::new(query), key) {
                Ok(op) => Ok((Lookup { answer }, op)),
                Err(_) => Err(Error::Full),
            }
        }

        /// The addresses, best first, or why there are none: once, after
        /// the lookup's Event came; None before, and after it was taken.
        #[must_use]
        pub fn take(&self) -> Option<Result<Vec<Address>, Error>> {
            self.answer.take()
        }
    }

    /// Looks up name and waits for the answer: never on a loop's thread;
    /// start a Lookup there.
    #[cfg_attr(rr, rr::blocking)]
    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        answered(name).unwrap_or_else(|| os::lookup(name))
    }

    /// What a name gets without asking the system, the same on every one:
    /// - no name: the empty one, ".", one with a NUL, or one not in ASCII,
    ///   which each system would read its own way (Windows answers the empty
    ///   one with the machine's own addresses; it and glibc may encode an
    ///   internationalized name, mDNSResponder sends it as it is);
    /// - a .onion name, which DNS must never see (RFC 7686), as Go has it;
    /// - localhost and every name under it: the loopback addresses, never
    ///   an answer from DNS (RFC 6761 6.3, as browsers and systemd-resolved
    ///   answer);
    /// - an IPv4 address in dotted decimal, with a dot after it or not;
    /// - a name that ends in a number and is no such address, as 127.1 or
    ///   0x7f.1, which getaddrinfo would read as an address and the WHATWG
    ///   URL standard refuses: not found.
    fn answered(name: &[u8]) -> Option<Result<Vec<Address>, Error>> {
        let Ok(text) = core::str::from_utf8(name) else {
            return Some(Err(Error::NotFound));
        };
        if !text.is_ascii() || text.contains('\0') {
            return Some(Err(Error::NotFound));
        }
        let bare = text.strip_suffix('.').unwrap_or(text);
        if bare.is_empty() || bare.ends_with('.') {
            return Some(Err(Error::NotFound));
        }
        if under(bare, "onion") {
            return Some(Err(Error::NotFound));
        }
        if under(bare, "localhost") {
            return Some(Ok(Vec::from([
                Address {
                    ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    scope: 0,
                },
                Address {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    scope: 0,
                },
            ])));
        }
        if let Ok(v4) = bare.parse::<Ipv4Addr>() {
            return Some(Ok(Vec::from([Address {
                ip: IpAddr::V4(v4),
                scope: 0,
            }])));
        }
        let last = bare.rsplit('.').next().unwrap_or(bare);
        let hex = last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let decimal = last.bytes().all(|byte| byte.is_ascii_digit());
        if (hex || decimal) && bare.parse::<Ipv6Addr>().is_err() {
            return Some(Err(Error::NotFound));
        }
        None
    }

    /// Whether name is domain or a name under it, in any case.
    fn under(name: &str, domain: &str) -> bool {
        let Some(start) = name.len().checked_sub(domain.len()) else {
            return false;
        };
        let tail = name.get(start..).unwrap_or_default();
        let before = name.get(..start).unwrap_or_default();
        tail.eq_ignore_ascii_case(domain) && (before.is_empty() || before.ends_with('.'))
    }

    /// The address in a sockaddr_in or sockaddr_in6 of bytes, its family
    /// as the system names it; None for any other.
    fn address(family: u16, bytes: &[u8]) -> Option<Address> {
        match (family, bytes.get(4..8), bytes.get(8..24), bytes.get(24..28)) {
            (AF_INET, Some(v4), _, _) => Some(Address {
                ip: IpAddr::from(<[u8; 4]>::try_from(v4).ok()?),
                scope: 0,
            }),
            (AF_INET6, _, Some(v6), Some(scope)) => Some(Address {
                ip: IpAddr::from(<[u8; 16]>::try_from(v6).ok()?),
                // The scope in the host's order, little on every target.
                scope: u32::from_le_bytes(<[u8; 4]>::try_from(scope).ok()?),
            }),
            _ => None,
        }
    }

    // rr: section(os = linux macos)
    /// Linux and macOS: the C library's getaddrinfo, which sorts the
    /// addresses by RFC 6724.
    #[cfg(unix)]
    mod os {
        use super::{Address, Error, address};
        use crate::base::io::{SOCK_STREAM, errno};
        use alloc::vec::Vec;
        use core::ffi::{c_char, c_int};
        use core::ptr::{null, null_mut};

        // rr: section(os = linux)
        /// struct addrinfo, as glibc's and musl's netdb.h lay it out.
        #[cfg(target_os = "linux")]
        #[repr(C)]
        struct AddrInfo {
            flags: c_int,
            family: c_int,
            socktype: c_int,
            protocol: c_int,
            addrlen: u32,
            addr: *mut u8,
            canonname: *mut c_char,
            next: *mut AddrInfo,
        }
        // rr: end(os = linux)

        // rr: section(os = macos)
        /// struct addrinfo, as macOS's netdb.h lays it out: the name before
        /// the address.
        #[cfg(target_os = "macos")]
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
        // rr: end(os = macos)

        #[link(name = "c")]
        // rr: escape(unsafe): each signature is the C library's, from its headers.
        unsafe extern "C" {
            #[must_use]
            fn getaddrinfo(
                node: *const c_char,
                service: *const c_char,
                hints: *const AddrInfo,
                result: *mut *mut AddrInfo,
            ) -> c_int;
            fn freeaddrinfo(info: *mut AddrInfo);
        }

        // netdb.h's errors: glibc's and musl's (EAI_NODATA is glibc's, and
        // musl keeps its number), macOS's.
        // rr: section(os = linux)
        #[cfg(target_os = "linux")]
        mod numbers {
            use core::ffi::c_int;
            pub const EAI_AGAIN: c_int = -3;
            pub const EAI_NODATA: c_int = -5;
            pub const EAI_NONAME: c_int = -2;
            pub const EAI_SYSTEM: c_int = -11;
        }
        // rr: end(os = linux)
        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        mod numbers {
            use core::ffi::c_int;
            pub const EAI_AGAIN: c_int = 2;
            pub const EAI_NODATA: c_int = 7;
            pub const EAI_NONAME: c_int = 8;
            pub const EAI_SYSTEM: c_int = 11;
        }
        // rr: end(os = macos)
        use numbers::{EAI_AGAIN, EAI_NODATA, EAI_NONAME, EAI_SYSTEM};
        /// errno.h's: the process, or the system, has no descriptor to spare.
        const ENFILE: c_int = 23;
        const EMFILE: c_int = 24;

        /// getaddrinfo's error; errno, read on its thread right after, says
        /// why a system error was one: out of descriptors is for now, as
        /// Go reads it (go.dev/issue/6232).
        fn error(code: c_int, system: c_int) -> Error {
            match (code, system) {
                (EAI_NONAME | EAI_NODATA, _) => Error::NotFound,
                (EAI_AGAIN, _) | (EAI_SYSTEM, EMFILE | ENFILE) => Error::Temporary,
                _ => Error::Failed,
            }
        }

        /// getaddrinfo's addresses of name, as it orders them (RFC 6724).
        pub fn lookup(name: &[u8]) -> Result<Vec<Address>, Error> {
            let mut node = Vec::with_capacity(name.len() + 1);
            node.extend_from_slice(name);
            node.push(0);
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
            // rr: escape(unsafe): node is NUL-terminated; list is ours to fill.
            let code = unsafe {
                getaddrinfo(
                    node.as_ptr().cast(),
                    null(),
                    &raw const hints,
                    &raw mut list,
                )
            };
            if code != 0 {
                return Err(error(code, errno()));
            }
            let mut addresses = Vec::new();
            let mut next = list;
            while !next.is_null() {
                // rr: escape(unsafe): next is an entry of getaddrinfo's list.
                let info = unsafe { &*next };
                if let Some(found) = entry(info) {
                    addresses.push(found);
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

        /// The address of an entry: sockaddr_in or sockaddr_in6, whose
        /// family is the entry's.
        fn entry(info: &AddrInfo) -> Option<Address> {
            let size = usize::try_from(info.addrlen).ok()?;
            if info.addr.is_null() || size < 16 {
                return None;
            }
            // rr: escape(unsafe): addr holds addrlen bytes.
            let bytes = unsafe { core::slice::from_raw_parts(info.addr, size) };
            address(u16::try_from(info.family).ok()?, bytes)
        }
    }
    // rr: end(os = linux macos)

    // rr: section(os = windows)
    /// Windows: GetAddrInfoW, which sorts the addresses by RFC 6724.
    #[cfg(target_os = "windows")]
    mod os {
        use super::{Address, Error, address};
        use crate::base::io::{SOCK_STREAM, startup};
        use alloc::vec::Vec;
        use core::ptr::{null, null_mut};

        /// ADDRINFOW, from ws2def.h, as Go's syscall lays it out.
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
            #[must_use]
            fn GetAddrInfoW(
                name: *const u16,
                service: *const u16,
                hints: *const AddrInfo,
                result: *mut *mut AddrInfo,
            ) -> i32;
            fn FreeAddrInfoW(info: *mut AddrInfo);
        }

        // winerror.h's codes.
        const WSAHOST_NOT_FOUND: i32 = 11001;
        const WSATRY_AGAIN: i32 = 11002;
        const WSANO_DATA: i32 = 11004;

        fn error(code: i32) -> Error {
            match code {
                WSAHOST_NOT_FOUND | WSANO_DATA => Error::NotFound,
                WSATRY_AGAIN => Error::Temporary,
                _ => Error::Failed,
            }
        }

        /// GetAddrInfoW's addresses of name, ASCII here, as UTF-16.
        pub fn lookup(name: &[u8]) -> Result<Vec<Address>, Error> {
            startup();
            let mut node: Vec<u16> = Vec::with_capacity(name.len() + 1);
            for &byte in name {
                node.push(u16::from(byte));
            }
            node.push(0);
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
            // rr: escape(unsafe): node is NUL-terminated UTF-16; list is
            // ours to fill.
            let code =
                unsafe { GetAddrInfoW(node.as_ptr(), null(), &raw const hints, &raw mut list) };
            if code != 0 {
                return Err(error(code));
            }
            let mut addresses = Vec::new();
            let mut next = list;
            while !next.is_null() {
                // rr: escape(unsafe): next is an entry of GetAddrInfoW's list.
                let info = unsafe { &*next };
                if let Some(found) = entry(info) {
                    addresses.push(found);
                }
                next = info.next;
            }
            // rr: escape(unsafe): list came from GetAddrInfoW, freed once.
            unsafe { FreeAddrInfoW(list) };
            if addresses.is_empty() {
                return Err(Error::NotFound);
            }
            Ok(addresses)
        }

        fn entry(info: &AddrInfo) -> Option<Address> {
            if info.addr.is_null() || info.addrlen < 16 {
                return None;
            }
            // rr: escape(unsafe): addr holds addrlen bytes.
            let bytes = unsafe { core::slice::from_raw_parts(info.addr, info.addrlen) };
            address(u16::try_from(info.family).ok()?, bytes)
        }
    }
    // rr: end(os = windows)

    // rr: section(tests = yes)
    #[cfg(test)]
    mod tests {
        use super::{Address, Error, Lookup, answered, resolve};
        use crate::base::io::{Done, Io};
        use core::net::{IpAddr, SocketAddr};
        use core::time::Duration;

        fn loopback(addresses: &[Address]) -> bool {
            !addresses.is_empty() && addresses.iter().all(|address| address.ip.is_loopback())
        }

        /// localhost, blocking and through an Io, gives loopback addresses,
        /// from /etc/hosts or as RFC 6761 says.
        #[test]
        fn localhost() {
            assert!(loopback(&resolve(b"localhost").unwrap()));
            let mut io = Io::new(4).unwrap();
            let (lookup, _op) = Lookup::start(&mut io, b"localhost", 9).unwrap();
            for _ in 0..1000 {
                io.wait(Some(Duration::from_millis(10))).unwrap();
                if let Some(event) = io.next() {
                    assert_eq!(event.key, 9);
                    assert!(matches!(event.done, Done::Ran { result: Ok(()), .. }));
                    assert!(loopback(&lookup.take().unwrap().unwrap()));
                    assert!(lookup.take().is_none());
                    return;
                }
            }
            panic!("localhost did not resolve");
        }

        /// A lookup canceled in line never asks, and its Event says so;
        /// a lookup dropped lets go of what it would find.
        #[test]
        fn canceled_and_dropped() {
            let mut io = Io::new(4).unwrap();
            let (lookup, op) = Lookup::start(&mut io, b"localhost", 1).unwrap();
            let canceled = io.cancel(&op);
            for _ in 0..1000 {
                io.wait(Some(Duration::from_millis(10))).unwrap();
                if let Some(event) = io.next() {
                    let Done::Ran { result, .. } = event.done else {
                        panic!("not a run");
                    };
                    assert_eq!(result.is_err(), canceled);
                    drop(lookup);
                    return;
                }
            }
            panic!("no event");
        }

        /// A link-local address keeps its interface on the way to a socket.
        #[test]
        fn socket_addresses() {
            let local = Address {
                ip: IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
                scope: 7,
            };
            let SocketAddr::V6(v6) = local.socket_addr(443) else {
                panic!("an IPv6 address");
            };
            assert_eq!((v6.port(), v6.scope_id()), (443, 7));
            let v4 = resolve(b"192.0.2.1").unwrap()[0].socket_addr(80);
            assert_eq!(v4, SocketAddr::from(([192, 0, 2, 1], 80)));
        }

        /// Literal addresses are themselves.
        #[test]
        fn literals() {
            for name in [&b"192.0.2.1"[..], b"192.0.2.1."] {
                let found = resolve(name).unwrap();
                assert_eq!(found.len(), 1);
                assert_eq!(found[0].ip, IpAddr::from([192, 0, 2, 1]));
            }
            assert!(resolve(b"::1").unwrap()[0].ip.is_loopback());
            assert!(resolve(b"::ffff:192.0.2.1").is_ok());
        }

        /// Names each system would read its own way are not found, without
        /// asking it; localhost's are loopback, never DNS's.
        #[test]
        fn names_answered_here() {
            for bad in [
                &b""[..],
                b".",
                b"a..",
                b"127.1",
                b"0x7f.0.0.1",
                b"2130706433",
                b"1.2.3.04",
                b"host.0x1F",
                b"exa\xc3\xa9mple.com",
                b"\xff",
                b"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
                b"x.ONION.",
            ] {
                assert_eq!(resolve(bad), Err(Error::NotFound), "{bad:?}");
            }
            for name in [&b"localhost."[..], b"LocalHost", b"a.b.localhost"] {
                assert!(loopback(&resolve(name).unwrap()), "{name:?}");
            }
            assert!(answered(b"notlocalhost").is_none());
            assert!(answered(b"onion.example").is_none());
            assert!(answered(b"v4.123x").is_none());
        }

        /// A name that is not one is not found, without asking anyone.
        #[test]
        fn bad_names() {
            // Without a network, a resolver may say it could not ask (as glibc
            // does with only a nameserver in resolv.conf), not that the name
            // does not exist.
            for bad in [&b"a\0b"[..], b"bad..name", b"-x.invalid"] {
                assert!(
                    matches!(
                        resolve(bad),
                        Err(Error::NotFound | Error::Failed | Error::Temporary)
                    ),
                    "{bad:?}"
                );
            }
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
                Err(Error::NotFound | Error::Temporary)
            ));
        }
    }
    // rr: end(tests = yes)
}

pub use sys::*;
