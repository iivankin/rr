//! The system side of resolve: what mod.rs says it is, for each system.

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// What a lookup waits on: the type every component's poll loop takes.
pub use crate::base::wait::Wait;

/// An address, and for a link-local IPv6 one the interface it is on:
/// connect to socket_addr's, which keeps it, as a SocketAddr made of ip
/// alone does not.
#[derive(Clone, Copy)]
#[cfg_attr(any(target_os = "macos", test), derive(PartialEq))]
#[cfg_attr(test, derive(Debug))]
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

/// One name's lookup. Dropping it cancels it: one started and not kept
/// is gone at once.
#[must_use]
pub struct Lookup {
    /// What answered sees without asking the system, or the system's
    /// lookup.
    found: Result<Result<Vec<Address>, Error>, os::State>,
}

impl Lookup {
    /// Starts looking up name, a host name in ASCII (an
    /// internationalized one as its A-labels, xn--) or a literal address.
    pub fn start(name: &[u8]) -> Lookup {
        Lookup {
            found: answered(name).ok_or_else(|| os::State::start(name)),
        }
    }

    /// Does what is ready, without waiting: None while the lookup runs,
    /// then the addresses, best first, or why there are none.
    #[must_use]
    pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
        match &mut self.found {
            Ok(Ok(addresses)) => Some(Ok(addresses)),
            Ok(Err(error)) => Some(Err(*error)),
            Err(state) => state.poll(),
        }
    }

    /// What to wait on before polling again.
    pub fn wait(&self) -> Wait {
        match &self.found {
            Ok(_) => Wait::READY,
            Err(state) => state.wait(),
        }
    }

    /// Stops the lookup; what it had is released.
    pub fn cancel(self) {
        drop(self);
    }
}

/// Looks up name and waits for the answer: never on a poll loop's
/// thread; start a Lookup and poll it there.
#[cfg_attr(rr, rr::blocking)]
pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
    answered(name).unwrap_or_else(|| os::resolve(name))
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
                ip: IpAddr::V6(core::net::Ipv6Addr::LOCALHOST),
                scope: 0,
            },
            Address {
                ip: IpAddr::V4(core::net::Ipv4Addr::LOCALHOST),
                scope: 0,
            },
        ])));
    }
    if let Ok(v4) = bare.parse::<core::net::Ipv4Addr>() {
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
    if (hex || decimal) && bare.parse::<core::net::Ipv6Addr>().is_err() {
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

/// The addresses of a lookup that is over, for the caller to keep.
#[cfg(not(target_os = "linux"))]
fn owned(result: Result<&[Address], Error>) -> Result<Vec<Address>, Error> {
    let mut addresses = Vec::new();
    // rr: escape(copy): the lookup that holds them ends here.
    addresses.extend_from_slice(result?);
    Ok(addresses)
}

/// Polls the lookup and waits as it says, until it is over.
#[cfg(not(target_os = "linux"))]
fn finish(mut lookup: Lookup) -> Result<Vec<Address>, Error> {
    // The system ends each lookup at its own timeout, and wakes the wait
    // then.
    loop {
        if let Some(result) = lookup.poll() {
            return owned(result);
        }
        crate::base::wait::block(&lookup.wait());
    }
}

/// The name with a NUL after it, or None when it holds one.
#[cfg(unix)]
fn c_string(name: &[u8]) -> Option<Vec<u8>> {
    if name.contains(&0) {
        return None;
    }
    let mut text = Vec::with_capacity(name.len() + 1);
    text.extend_from_slice(name);
    text.push(0);
    Some(text)
}

/// Linux: the C library's getaddrinfo, which reads nsswitch.conf and
/// asks what it names (files, DNS, systemd-resolved, mDNS) and sorts the
/// addresses by RFC 6724. It blocks, and nothing asks the system without
/// blocking, so a lookup runs it on one of wait's threads. The thread
/// and the lookup share a block, which the last of the two to let go
/// frees, so a lookup dropped while the thread runs never waits; one
/// dropped while still in spawn's line never starts.
#[cfg(target_os = "linux")]
mod os {
    use super::{Address, Error, Wait, c_string};
    use crate::base::wait::{self, AF_INET, AF_INET6, SOCK_STREAM, Signal, errno};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::ffi::{c_char, c_int, c_void};
    use core::net::IpAddr;
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// struct addrinfo, as glibc's and musl's netdb.h lay it out.
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

    // netdb.h's errors, glibc's and musl's;
    // EAI_NODATA is glibc's, and musl keeps its number.
    const EAI_AGAIN: c_int = -3;
    const EAI_NODATA: c_int = -5;
    const EAI_NONAME: c_int = -2;
    const EAI_SYSTEM: c_int = -11;
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
    fn lookup(name: &[u8]) -> Result<Vec<Address>, Error> {
        let hints = AddrInfo {
            flags: 0,
            family: 0,
            socktype: SOCK_STREAM,
            protocol: 0,
            addrlen: 0,
            addr: null_mut(),
            canonname: null_mut(),
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
            return Err(error(code, errno()));
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

    /// The address of an entry: sockaddr_in or sockaddr_in6, after
    /// sa_family_t, two bytes in the host's order, which is little on
    /// x86_64 and aarch64, the only ones here.
    fn address(info: &AddrInfo) -> Option<Address> {
        let size = usize::try_from(info.addrlen).ok()?;
        if info.addr.is_null() || size < 16 {
            return None;
        }
        // rr: escape(unsafe): addr holds addrlen bytes.
        let bytes = unsafe { core::slice::from_raw_parts(info.addr, size) };
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

    /// The thread writes result, then sets done and the signal; the
    /// lookup reads result only after it saw done.
    struct Shared {
        holders: AtomicUsize,
        done: AtomicBool,
        /// The name, NUL-terminated.
        name: Vec<u8>,
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
        let result = lookup(&state.name);
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
            let Some(name) = c_string(name) else {
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
            // rr: escape(unsafe): run takes shared as its holder, which it
            // lets go; the ticket's cancel says when it never runs.
            state.ticket = unsafe { wait::spawn(run, raw.cast()) };
            if state.ticket.is_none() {
                // The thread never held it.
                release(raw);
                state.taken = Some(Err(Error::Failed));
            }
            state
        }

        #[must_use]
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
            if self.ticket.take().is_some_and(wait::Ticket::cancel) {
                release(self.shared);
            }
            // The thread, when it runs on, frees what is left.
            release(self.shared);
        }
    }

    /// getaddrinfo blocks the caller's thread, which is what was asked.
    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        lookup(&c_string(name).ok_or(Error::NotFound)?)
    }
}

/// macOS: the system's own resolver, mDNSResponder, which getaddrinfo
/// asks too and which knows VPN and split DNS, through dns_sd.h's
/// DNSServiceGetAddrInfo: a socket to it that the caller's poll waits
/// on, no thread, and a lookup dropped is cancelled there. It asks for
/// the families as getaddrinfo asks (no protocol: mDNSResponder leaves
/// out IPv6 where the host has no routable IPv6 address, and IPv4 where
/// none of that, as AI_ADDRCONFIG does, and answers the family it left
/// out with none at once). Its answers come one at a time, unsorted: the
/// lookup is over once IPv4 and IPv6 each answered, with addresses or
/// with none, and nothing more is on the way; or 50 ms after the first
/// address came, without the other family, as RFC 8305's resolution
/// delay waits for it, so that a DNS server that never answers AAAA (or
/// A) does not hold the lookup to the system's timeout. Then the
/// addresses are sorted as getaddrinfo sorts them (RFC 6724), on the
/// source the system would use for each.
#[cfg(target_os = "macos")]
mod os {
    use super::super::sort::{ADDRESSES_MAX, sort};
    use super::{Address, Error, Wait, c_string, finish};
    use crate::base::wait::{self, F_SETFD, FD_CLOEXEC, Fd, Instant, POLLIN};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::ffi::{c_char, c_int, c_void};
    use core::net::IpAddr;
    use core::ptr::null_mut;

    /// DNSServiceGetAddrInfoReply, from dns_sd.h.
    type Reply = extern "C" fn(
        service: *mut c_void,
        flags: u32,
        interface: u32,
        code: i32,
        hostname: *const c_char,
        address: *const u8,
        ttl: u32,
        context: *mut c_void,
    );

    #[link(name = "c")]
    // rr: escape(unsafe): each signature is the C library's, from its headers
    // (dns_sd.h, net/if.h, sys/socket.h, unistd.h).
    unsafe extern "C" {
        #[must_use]
        fn DNSServiceGetAddrInfo(
            service: *mut *mut c_void,
            flags: u32,
            interface: u32,
            protocol: u32,
            hostname: *const c_char,
            reply: Reply,
            context: *mut c_void,
        ) -> i32;
        #[must_use]
        fn DNSServiceRefSockFD(service: *mut c_void) -> c_int;
        #[must_use]
        fn DNSServiceProcessResult(service: *mut c_void) -> i32;
        fn DNSServiceRefDeallocate(service: *mut c_void);
        #[must_use]
        fn if_nametoindex(name: *const c_char) -> u32;
        #[must_use]
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        #[must_use]
        fn connect(fd: c_int, address: *const u8, length: u32) -> c_int;
        #[must_use]
        fn getsockname(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
        #[must_use]
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        #[must_use]
        fn close(fd: c_int) -> c_int;
    }

    // dns_sd.h's flags, protocols and errors.
    const MORE_COMING: u32 = 0x1;
    const ADD: u32 = 0x2;
    const RETURN_INTERMEDIATES: u32 = 0x1000;
    const TIMEOUT: u32 = 0x10000;
    /// No protocol: the families as the host can reach them.
    const FAMILIES: u32 = 0;
    const NO_ERROR: i32 = 0;
    const NO_SUCH_NAME: i32 = -65538;
    const NO_SUCH_RECORD: i32 = -65554;
    const TIMED_OUT: i32 = -65568;
    const SERVICE_NOT_RUNNING: i32 = -65563;
    const DEFUNCT_CONNECTION: i32 = -65569;
    // sys/socket.h's: BSD's sockaddr starts with its length, then the
    // family.
    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 30;
    const SOCK_DGRAM: c_int = 2;
    /// The bytes of a sockaddr_in6, the larger of the two.
    const SOCKADDR_BYTES: usize = 28;
    /// The replies read at one poll; more wait for the next.
    const REPLIES_MAX: usize = 64;
    /// How long the other family is waited for once one gave an address:
    /// RFC 8305's resolution delay.
    const DELAY_MS: u64 = 50;

    /// What the replies said so far.
    struct Answers {
        found: Vec<Address>,
        v4: bool,
        v6: bool,
        /// The last reply said more are on the way.
        more: bool,
        error: Option<Error>,
        /// When the other family stops being waited for, once an
        /// address came.
        until: Option<Instant>,
    }

    impl Answers {
        fn over(&self, now: Instant) -> bool {
            let waited = self.until.is_some_and(|until| until.reached_by(now));
            !self.more && (self.error.is_some() || (self.v4 && self.v6) || waited)
        }

        /// The milliseconds left to wait for the other family; none
        /// before an address came.
        fn left_ms(&self, now: Instant) -> Option<u64> {
            self.until.map(|until| until.since(now).div_ceil(1_000_000))
        }

        /// Marks the family a reply is about as answered; a reply about
        /// none answers both.
        fn answered(&mut self, family: Option<u8>) {
            match family {
                Some(AF_INET) => self.v4 = true,
                Some(AF_INET6) => self.v6 = true,
                Some(_) | None => {
                    self.v4 = true;
                    self.v6 = true;
                }
            }
        }
    }

    fn error(code: i32) -> Error {
        match code {
            NO_SUCH_NAME | NO_SUCH_RECORD => Error::NotFound,
            TIMED_OUT => Error::Timeout,
            SERVICE_NOT_RUNNING | DEFUNCT_CONNECTION => Error::Temporary,
            _ => Error::Failed,
        }
    }

    /// The bytes of a sockaddr, as long as its first byte says.
    ///
    /// # Safety
    /// address is null or a sockaddr of as many bytes as it says.
    // rr: escape(unsafe): the caller vouches for address.
    unsafe fn sockaddr<'a>(address: *const u8) -> Option<&'a [u8]> {
        if address.is_null() {
            return None;
        }
        // rr: escape(unsafe): a sockaddr's first byte is its length.
        let length = usize::from(unsafe { address.read() }).min(SOCKADDR_BYTES);
        // rr: escape(unsafe): the sockaddr holds length bytes.
        Some(unsafe { core::slice::from_raw_parts(address, length) })
    }

    /// The address in a sockaddr_in or sockaddr_in6; a link-local IPv6
    /// one without a scope is on interface.
    fn address(bytes: &[u8], interface: u32) -> Option<Address> {
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
            (AF_INET6, _, Some(v6), Some(scope)) => {
                // sin6_scope_id is in the host's order, little on every Mac.
                let scope = u32::from_le_bytes(<[u8; 4]>::try_from(scope).ok()?);
                let octets = <[u8; 16]>::try_from(v6).ok()?;
                // Only an address of the link takes the interface it came
                // on: a global one has no zone, and two answers of it from
                // two interfaces are one address.
                let linked = match octets {
                    [0xfe, second, ..] => second & 0xc0 == 0x80,
                    [0xff, second, ..] => second & 0x0f == 0x02,
                    _ => false,
                };
                Some(Address {
                    ip: IpAddr::from(octets),
                    scope: if scope == 0 && linked {
                        interface
                    } else {
                        scope
                    },
                })
            }
            _ => None,
        }
    }

    extern "C" fn reply(
        _service: *mut c_void,
        flags: u32,
        interface: u32,
        code: i32,
        _hostname: *const c_char,
        address: *const u8,
        _ttl: u32,
        context: *mut c_void,
    ) {
        // rr: escape(unsafe): context is the lookup's Answers, which live
        // while it runs, and replies come only inside its
        // DNSServiceProcessResult, on its thread.
        let answers = unsafe { &mut *context.cast::<Answers>() };
        answers.more = flags & MORE_COMING != 0;
        // rr: escape(unsafe): dns_sd.h hands a sockaddr or null.
        let bytes = unsafe { sockaddr(address) };
        let family = bytes.and_then(|bytes| bytes.get(1).copied());
        match code {
            NO_ERROR => {
                answers.answered(family);
                let Some(found) = bytes.and_then(|bytes| self::address(bytes, interface)) else {
                    return;
                };
                let known = answers.found.contains(&found);
                match (flags & ADD != 0, known) {
                    // An address taken back.
                    (false, _) => answers.found.retain(|other| *other != found),
                    (true, false) if answers.found.len() < ADDRESSES_MAX => {
                        answers.found.push(found);
                        if answers.until.is_none() {
                            answers.until = Some(Instant::now().after_ms(DELAY_MS));
                        }
                    }
                    (true, _) => {}
                }
            }
            NO_SUCH_NAME | NO_SUCH_RECORD => answers.answered(family),
            other => answers.error = Some(self::error(other)),
        }
    }

    /// A literal address, with a zone after % for IPv6: an interface's
    /// number or name.
    #[must_use]
    fn literal(name: &[u8]) -> Option<Address> {
        let text = core::str::from_utf8(name).ok()?;
        let Some((ip, zone)) = text.split_once('%') else {
            return Some(Address {
                ip: text.parse().ok()?,
                scope: 0,
            });
        };
        let ip = ip.parse::<core::net::Ipv6Addr>().ok()?;
        let scope = match zone.parse::<u32>() {
            Ok(number) => number,
            Err(_) => {
                let zone = c_string(zone.as_bytes())?;
                // rr: escape(unsafe): zone is NUL-terminated.
                let index = unsafe { if_nametoindex(zone.as_ptr().cast()) };
                if index == 0 {
                    return None;
                }
                index
            }
        };
        Some(Address {
            ip: IpAddr::V6(ip),
            scope,
        })
    }

    /// The source address the system would use to reach address, as Go
    /// and glibc learn it: connect a UDP socket, which sends nothing, and
    /// ask. None where there is no route.
    #[must_use]
    fn source(address: &Address) -> Option<IpAddr> {
        let mut peer = [0u8; SOCKADDR_BYTES];
        // The discard port: any port will do, as nothing is sent.
        let [high, low] = 9u16.to_be_bytes();
        let length = match address.ip {
            IpAddr::V4(v4) => {
                let [a, b, c, d] = v4.octets();
                let head = [16, AF_INET, high, low, a, b, c, d];
                peer.get_mut(..8)?.copy_from_slice(&head);
                16
            }
            IpAddr::V6(v6) => {
                let head = [28, AF_INET6, high, low];
                peer.get_mut(..4)?.copy_from_slice(&head);
                peer.get_mut(8..24)?.copy_from_slice(&v6.octets());
                peer.get_mut(24..28)?
                    .copy_from_slice(&address.scope.to_le_bytes());
                SOCKADDR_BYTES
            }
        };
        let family = c_int::from(*peer.get(1)?);
        // rr: escape(unsafe): a plain socket call.
        let fd = unsafe { socket(family, SOCK_DGRAM, 0) };
        if fd < 0 {
            return None;
        }
        // Closed on exec, at once: macOS has no SOCK_CLOEXEC.
        // rr: escape(unsafe): fd is this call's, open.
        let kept = unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } == 0;
        let mut local = [0u8; SOCKADDR_BYTES];
        let mut size = u32::try_from(SOCKADDR_BYTES).ok()?;
        let length = u32::try_from(length).ok()?;
        // rr: escape(unsafe): peer holds length bytes of a sockaddr.
        let connected = kept && unsafe { connect(fd, peer.as_ptr(), length) } == 0;
        // rr: escape(unsafe): local holds size bytes.
        let named = connected && unsafe { getsockname(fd, local.as_mut_ptr(), &raw mut size) } == 0;
        // rr: escape(unsafe): fd is this call's, closed once.
        unsafe {
            // rr: escape(discard): close releases the descriptor whatever it
            // answers; no one is left to tell.
            let _: c_int = close(fd);
        }
        if !named {
            return None;
        }
        self::address(local.get(..usize::try_from(size).ok()?)?, 0).map(|found| found.ip)
    }

    /// A lookup: the connection to mDNSResponder while it runs, what it
    /// said, and the outcome once over.
    pub struct State {
        service: *mut c_void,
        answers: *mut Answers,
        done: Option<Result<Vec<Address>, Error>>,
    }

    impl State {
        pub fn start(name: &[u8]) -> State {
            let mut state = State {
                service: null_mut(),
                answers: null_mut(),
                done: None,
            };
            if let Some(address) = literal(name) {
                state.done = Some(Ok(Vec::from([address])));
                return state;
            }
            let Some(text) = c_string(name) else {
                state.done = Some(Err(Error::NotFound));
                return state;
            };
            // rr: escape(leak): the replies write here while the lookup
            // runs; drop frees it.
            state.answers = Box::into_raw(Box::new(Answers {
                found: Vec::new(),
                v4: false,
                v6: false,
                more: false,
                error: None,
                until: None,
            }));
            // rr: escape(unsafe): text is NUL-terminated; answers lives until
            // the service is deallocated, in drop or once over.
            let code = unsafe {
                DNSServiceGetAddrInfo(
                    &raw mut state.service,
                    RETURN_INTERMEDIATES | TIMEOUT,
                    0,
                    FAMILIES,
                    text.as_ptr().cast(),
                    reply,
                    state.answers.cast(),
                )
            };
            if code != NO_ERROR {
                state.service = null_mut();
                state.done = Some(Err(error(code)));
            }
            state
        }

        #[must_use]
        fn fd(&self) -> c_int {
            // rr: escape(unsafe): service is live while the lookup runs.
            unsafe { DNSServiceRefSockFD(self.service) }
        }

        /// Reads the replies that wait, without blocking: each call to
        /// DNSServiceProcessResult reads one, and blocks when none is
        /// there.
        fn read(&mut self) {
            for _ in 0..REPLIES_MAX {
                // rr: escape(unsafe): answers is live while the lookup runs.
                if unsafe { &*self.answers }.over(Instant::now()) {
                    self.over();
                    return;
                }
                let mut ready = Wait::READY;
                ready.fds[0] = Fd {
                    fd: self.fd(),
                    events: POLLIN,
                };
                ready.count = 1;
                if wait::ready(&ready)[0] == 0 {
                    return;
                }
                // rr: escape(unsafe): service is live and has a reply to read.
                let code = unsafe { DNSServiceProcessResult(self.service) };
                if code != NO_ERROR {
                    // The connection to mDNSResponder failed: no reply comes
                    // after, whatever the last one said was on its way.
                    // rr: escape(unsafe): answers is live while the lookup runs.
                    let answers = unsafe { &mut *self.answers };
                    answers.error = Some(error(code));
                    answers.more = false;
                }
            }
            // The last turn's reply may have ended it.
            // rr: escape(unsafe): answers is live while the lookup runs.
            if unsafe { &*self.answers }.over(Instant::now()) {
                self.over();
            }
        }

        /// The lookup is over: mDNSResponder stops it, and the addresses
        /// are sorted.
        fn over(&mut self) {
            // rr: escape(unsafe): service is live, deallocated once.
            unsafe { DNSServiceRefDeallocate(self.service) };
            self.service = null_mut();
            // rr: escape(unsafe): answers came from Box::into_raw, freed
            // once, and no reply writes it now.
            let answers = unsafe { Box::from_raw(self.answers) };
            self.answers = null_mut();
            let Answers {
                mut found, error, ..
            } = *answers;
            if found.is_empty() {
                self.done = Some(Err(error.unwrap_or(Error::NotFound)));
                return;
            }
            let mut sources = [None; ADDRESSES_MAX];
            for (slot, address) in sources.iter_mut().zip(&found) {
                *slot = source(address);
            }
            let count = found.len();
            sort(&mut found, sources.get(..count).unwrap_or_default());
            self.done = Some(Ok(found));
        }

        #[must_use]
        pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
            if self.done.is_none() {
                self.read();
            }
            match &self.done {
                Some(Ok(addresses)) => Some(Ok(addresses)),
                Some(Err(error)) => Some(Err(*error)),
                None => None,
            }
        }

        pub fn wait(&self) -> Wait {
            if self.done.is_some() {
                return Wait::READY;
            }
            let mut wait = Wait::READY;
            wait.fds[0] = Fd {
                fd: self.fd(),
                events: POLLIN,
            };
            wait.count = 1;
            // mDNSResponder ends the lookup itself (TIMEOUT), with a reply;
            // the other family is waited for only so long.
            // rr: escape(unsafe): answers is live while the lookup runs.
            wait.timeout_ms = unsafe { &*self.answers }.left_ms(Instant::now());
            wait
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            if !self.service.is_null() {
                // rr: escape(unsafe): service is live, deallocated once; no
                // reply comes after.
                unsafe { DNSServiceRefDeallocate(self.service) };
            }
            if !self.answers.is_null() {
                // rr: escape(unsafe): answers came from Box::into_raw, freed
                // once.
                drop(unsafe { Box::from_raw(self.answers) });
            }
        }
    }

    /// The lookup, waited on.
    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        finish(super::Lookup::start(name))
    }

    #[cfg(test)]
    mod tests {
        use super::{
            ADD, AF_INET, AF_INET6, Answers, DELAY_MS, NO_ERROR, NO_SUCH_RECORD, SOCKADDR_BYTES,
            reply,
        };
        use crate::base::wait::Instant;
        use alloc::vec::Vec;
        use core::ptr::{null, null_mut};

        fn answers() -> Answers {
            Answers {
                found: Vec::new(),
                v4: false,
                v6: false,
                more: false,
                error: None,
                until: None,
            }
        }

        /// A reply as mDNSResponder gives it: an address of the family,
        /// added, or none of it.
        fn send(answers: &mut Answers, family: u8, code: i32) {
            let mut address = [0u8; SOCKADDR_BYTES];
            address[1] = family;
            if family == AF_INET {
                address[0] = 16;
                address[4..8].copy_from_slice(&[192, 0, 2, 1]);
            } else {
                address[0] = 28;
                address[8..10].copy_from_slice(&[0x20, 0x01]);
            }
            let flags = if code == NO_ERROR { ADD } else { 0 };
            let context = core::ptr::from_mut(answers).cast();
            reply(
                null_mut(),
                flags,
                0,
                code,
                null(),
                address.as_ptr(),
                0,
                context,
            );
        }

        /// An address of one family, and the other never answered, as a
        /// DNS server that swallows AAAA: over once the delay passed,
        /// not at the system's timeout.
        #[test]
        fn other_family_waited_for_briefly() {
            let mut one = answers();
            send(&mut one, AF_INET, NO_ERROR);
            let now = Instant::now();
            assert!(!one.over(now));
            assert!(one.left_ms(now).is_some_and(|ms| ms <= DELAY_MS));
            assert!(one.over(Instant::now().after_ms(DELAY_MS)));
            assert_eq!(one.found.len(), 1);
        }

        /// Both families answered, either with none: over at once.
        #[test]
        fn both_families_answered() {
            let mut none_first = answers();
            send(&mut none_first, AF_INET6, NO_SUCH_RECORD);
            assert!(!none_first.over(Instant::now()));
            send(&mut none_first, AF_INET, NO_ERROR);
            assert!(none_first.over(Instant::now()));
            let mut both = answers();
            send(&mut both, AF_INET, NO_ERROR);
            send(&mut both, AF_INET6, NO_ERROR);
            assert!(both.over(Instant::now()));
            assert_eq!(both.found.len(), 2);
        }
    }
}

/// Windows: GetAddrInfoExW, asynchronous since Windows 8, which answers
/// as GetAddrInfoW does, sorted by RFC 6724, and calls back on a thread
/// of the system's pool; the callback sets a Signal, which the caller's
/// WSAPoll waits on. A lookup dropped is cancelled there
/// (GetAddrInfoExCancel); the callback comes all the same, so the lookup
/// and the callback share a block, which the last of the two frees.
#[cfg(target_os = "windows")]
mod os {
    use super::{Address, Error, Wait, finish};
    use crate::base::wait::{self, AF_INET, AF_INET6, SOCK_STREAM, Signal};
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::ffi::c_void;
    use core::net::IpAddr;
    use core::ptr::{null, null_mut};
    use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

    /// ADDRINFOEXW, from ws2def.h.
    #[repr(C)]
    struct AddrInfo {
        flags: i32,
        family: i32,
        socktype: i32,
        protocol: i32,
        addrlen: usize,
        canonname: *mut u16,
        addr: *mut u8,
        blob: *mut c_void,
        bloblen: usize,
        provider: *mut c_void,
        next: *mut AddrInfo,
    }

    /// OVERLAPPED, from minwinbase.h: its union is one pointer on the
    /// 64-bit systems.
    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        pointer: *mut c_void,
        event: *mut c_void,
    }

    /// LPLOOKUPSERVICE_COMPLETION_ROUTINE, from ws2tcpip.h.
    type Completion = extern "system" fn(error: u32, bytes: u32, overlapped: *mut Overlapped);

    #[link(name = "ws2_32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is ws2_32's, from its documentation.
    unsafe extern "system" {
        #[must_use]
        fn GetAddrInfoExW(
            name: *const u16,
            service: *const u16,
            namespace: u32,
            provider: *mut c_void,
            hints: *const AddrInfo,
            result: *mut *mut AddrInfo,
            timeout: *mut c_void,
            overlapped: *mut Overlapped,
            completion: Completion,
            handle: *mut *mut c_void,
        ) -> i32;
        #[must_use]
        fn GetAddrInfoExCancel(handle: *mut *mut c_void) -> i32;
        fn FreeAddrInfoExW(info: *mut AddrInfo);
    }

    /// Every namespace, as GetAddrInfoW asks.
    const NS_ALL: u32 = 0;
    const WSA_IO_PENDING: i32 = 997;
    const WSAETIMEDOUT: u32 = 10060;
    const WSAHOST_NOT_FOUND: u32 = 11001;
    const WSATRY_AGAIN: u32 = 11002;
    const WSANO_DATA: u32 = 11004;

    /// The block's states: the system has it, the system is done with
    /// it, or the lookup let go first.
    const ASKED: u8 = 0;
    const ANSWERED: u8 = 1;
    const DROPPED: u8 = 2;

    /// What the lookup and the system's callback share. The overlapped
    /// comes first: the callback finds the block by it.
    #[repr(C)]
    struct Shared {
        overlapped: Overlapped,
        holders: AtomicUsize,
        state: AtomicU8,
        error: AtomicU32,
        /// The system writes the list here when it is done.
        list: UnsafeCell<*mut AddrInfo>,
        /// The system writes the cancel handle here before it returns.
        handle: UnsafeCell<*mut c_void>,
        signal: Signal,
        /// The name, kept until the system is done with it.
        name: Vec<u16>,
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

    /// Frees the system's list, once.
    fn free(list: *mut AddrInfo) {
        if !list.is_null() {
            // rr: escape(unsafe): list came from GetAddrInfoExW, freed once.
            unsafe { FreeAddrInfoExW(list) };
        }
    }

    extern "system" fn completed(error: u32, _bytes: u32, overlapped: *mut Overlapped) {
        let shared = overlapped.cast::<Shared>();
        // rr: escape(unsafe): the callback holds the block it was given.
        let state = unsafe { &*shared };
        state.error.store(error, Ordering::Relaxed);
        let done =
            state
                .state
                .compare_exchange(ASKED, ANSWERED, Ordering::AcqRel, Ordering::Acquire);
        if done.is_err() {
            // The lookup is gone: what the system found is no one's.
            // rr: escape(unsafe): the system is done writing the list.
            free(unsafe { *state.list.get() });
        }
        state.signal.set();
        release(shared);
    }

    fn error(code: u32) -> Error {
        match code {
            WSAHOST_NOT_FOUND | WSANO_DATA => Error::NotFound,
            WSATRY_AGAIN => Error::Temporary,
            WSAETIMEDOUT => Error::Timeout,
            _ => Error::Failed,
        }
    }

    /// A name as GetAddrInfoExW takes it: UTF-16, NUL-terminated.
    fn name(name: &[u8]) -> Option<Vec<u16>> {
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

    /// The address of an entry: SOCKADDR_IN or SOCKADDR_IN6, whose
    /// family and scope are in the host's order, little on Windows.
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

    /// The addresses of the system's list, in its order; the list is
    /// freed.
    fn addresses(list: *mut AddrInfo) -> Result<Vec<Address>, Error> {
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
        free(list);
        if found.is_empty() {
            return Err(Error::NotFound);
        }
        Ok(found)
    }

    pub struct State {
        shared: *mut Shared,
        /// The outcome, once taken from the block.
        taken: Option<Result<Vec<Address>, Error>>,
    }

    impl State {
        pub fn start(text: &[u8]) -> State {
            let mut state = State {
                shared: null_mut(),
                taken: None,
            };
            wait::startup();
            let Some(name) = name(text) else {
                state.taken = Some(Err(Error::NotFound));
                return state;
            };
            let Some(signal) = Signal::new() else {
                state.taken = Some(Err(Error::Failed));
                return state;
            };
            let hints = AddrInfo {
                flags: 0,
                family: 0,
                socktype: SOCK_STREAM,
                protocol: 0,
                addrlen: 0,
                canonname: null_mut(),
                addr: null_mut(),
                blob: null_mut(),
                bloblen: 0,
                provider: null_mut(),
                next: null_mut(),
            };
            // rr: escape(leak): the lookup and the callback hold it, and
            // release frees it.
            let shared = Box::into_raw(Box::new(Shared {
                overlapped: Overlapped {
                    internal: 0,
                    internal_high: 0,
                    pointer: null_mut(),
                    event: null_mut(),
                },
                // rr: escape(shared): the lookup and the callback hold it.
                holders: AtomicUsize::new(2),
                // rr: escape(shared): which of the two is done first.
                state: AtomicU8::new(ASKED),
                // rr: escape(shared): the callback's error, read after done.
                error: AtomicU32::new(0),
                // rr: escape(shared): the system's list, read after done.
                list: UnsafeCell::new(null_mut()),
                // rr: escape(shared): written by the call, before it returns.
                handle: UnsafeCell::new(null_mut()),
                signal,
                name,
            }));
            state.shared = shared;
            // rr: escape(unsafe): the block is live: the lookup holds it.
            let block = unsafe { &*shared };
            // The overlapped is the block's first field.
            let overlapped = shared.cast::<Overlapped>();
            // rr: escape(unsafe): the block lives until both let go; its
            // name is NUL-terminated.
            let code = unsafe {
                GetAddrInfoExW(
                    block.name.as_ptr(),
                    null(),
                    NS_ALL,
                    null_mut(),
                    &raw const hints,
                    block.list.get(),
                    null_mut(),
                    overlapped,
                    completed,
                    block.handle.get(),
                )
            };
            if code != WSA_IO_PENDING {
                // Done at once: no callback comes.
                block.error.store(code.cast_unsigned(), Ordering::Relaxed);
                block.state.store(ANSWERED, Ordering::Release);
                release(shared);
            }
            state
        }

        #[must_use]
        pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
            if self.taken.is_none() && !self.shared.is_null() {
                // rr: escape(unsafe): this lookup holds shared.
                let shared = unsafe { &*self.shared };
                if shared.state.load(Ordering::Acquire) != ANSWERED {
                    return None;
                }
                let code = shared.error.load(Ordering::Relaxed);
                // rr: escape(unsafe): the system is done writing the list.
                let list = unsafe { *shared.list.get() };
                self.taken = Some(if code == 0 {
                    addresses(list)
                } else {
                    free(list);
                    Err(error(code))
                });
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
            // rr: escape(unsafe): this lookup holds shared.
            let shared = unsafe { &*self.shared };
            let cancelled =
                shared
                    .state
                    .compare_exchange(ASKED, DROPPED, Ordering::AcqRel, Ordering::Acquire);
            if cancelled.is_ok() {
                // The callback comes all the same, and frees the list.
                // Should it have begun already, the handle is no longer
                // the system's, and GetAddrInfoExCancel says so.
                // rr: escape(unsafe): the handle the call wrote.
                unsafe {
                    // rr: escape(discard): refused, the lookup has begun and
                    // answers through its callback, as above.
                    let _: i32 = GetAddrInfoExCancel(shared.handle.get());
                }
            } else {
                // Done, never polled: the list is the lookup's to free.
                // rr: escape(unsafe): the system is done writing the list.
                free(unsafe { *shared.list.get() });
            }
            release(self.shared);
        }
    }

    /// The lookup, waited on.
    pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
        finish(super::Lookup::start(name))
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Lookup, resolve};
    use crate::base::wait::{Instant, Set, Watch};

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
            crate::base::wait::block(&lookup.wait());
        }
        panic!("localhost did not resolve");
    }

    /// localhost through a Set, as a loop that serves many connections
    /// runs a lookup beside them.
    #[test]
    fn in_a_set() {
        let mut set = Set::new().unwrap();
        let mut watch = Watch::NONE;
        let mut lookup = Lookup::start(b"localhost");
        let end = Instant::now().after_ms(10_000);
        loop {
            if let Some(result) = lookup.poll() {
                assert!(loopback(result.unwrap()));
                break;
            }
            set.follow(&mut watch, &lookup.wait(), 1).unwrap();
            set.wait(Some(end));
            assert!(!end.reached_by(Instant::now()), "localhost did not resolve");
        }
        set.unfollow(&mut watch);
    }

    /// A link-local address keeps its interface on the way to a socket.
    #[test]
    fn socket_addresses() {
        let local = super::Address {
            ip: core::net::IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
            scope: 7,
        };
        let core::net::SocketAddr::V6(v6) = local.socket_addr(443) else {
            panic!("an IPv6 address");
        };
        assert_eq!((v6.port(), v6.scope_id()), (443, 7));
        let v4 = resolve(b"192.0.2.1").unwrap()[0].socket_addr(80);
        assert_eq!(v4, core::net::SocketAddr::from(([192, 0, 2, 1], 80)));
    }

    /// Literal addresses are themselves.
    #[test]
    fn literals() {
        for name in [&b"192.0.2.1"[..], b"192.0.2.1."] {
            let found = resolve(name).unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].ip, core::net::IpAddr::from([192, 0, 2, 1]));
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
            let mut lookup = Lookup::start(bad);
            assert!(matches!(lookup.poll(), Some(Err(Error::NotFound))));
        }
        for name in [&b"localhost."[..], b"LocalHost", b"a.b.localhost"] {
            assert!(loopback(&resolve(name).unwrap()), "{name:?}");
        }
        assert!(super::answered(b"notlocalhost").is_none());
        assert!(super::answered(b"onion.example").is_none());
        assert!(super::answered(b"v4.123x").is_none());
    }

    /// A name that is not one is not found, without asking anyone; a
    /// lookup dropped while it runs is let go.
    #[test]
    fn bad_names_and_cancel() {
        // Without a network, a resolver may say it could not ask (as glibc
        // does with only a nameserver in resolv.conf), not that the name
        // does not exist.
        for bad in [&b"a\0b"[..], b"bad..name", b"-x.invalid"] {
            assert!(
                matches!(
                    resolve(bad),
                    Err(Error::NotFound | Error::Failed | Error::Temporary | Error::Timeout)
                ),
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
