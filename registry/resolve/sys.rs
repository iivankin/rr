//! The system side of resolve: what mod.rs says it is, for each system.

use crate::base::wait;
use alloc::vec::Vec;
use core::net::IpAddr;

/// What a lookup waits on: the type every component's poll loop takes.
pub use crate::base::wait::Wait;

/// An address, and for a link-local IPv6 one the interface it is on.
#[derive(Clone, Copy)]
pub struct Address {
    pub ip: IpAddr,
    pub scope: u32,
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

#[cfg(unix)]
mod os {
    use super::{Address, Error, c_string};
    use alloc::vec::Vec;
    use core::ffi::{c_char, c_int};
    use core::net::IpAddr;
    use core::ptr::null_mut;

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

    /// struct addrinfo, as glibc's and musl's netdb.h lay it out: the
    /// address before the name.
    #[cfg(not(target_os = "macos"))]
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
        fn getaddrinfo(
            node: *const c_char,
            service: *const c_char,
            hints: *const AddrInfo,
            result: *mut *mut AddrInfo,
        ) -> c_int;
        fn freeaddrinfo(info: *mut AddrInfo);
    }

    // sys/socket.h's families and netdb.h's errors: BSD's on macOS,
    // glibc's and musl's on Linux, where EAI_NODATA is glibc's and musl
    // keeps its number.
    const AF_INET: u16 = 2;
    #[cfg(target_os = "macos")]
    const AF_INET6: u16 = 30;
    #[cfg(not(target_os = "macos"))]
    const AF_INET6: u16 = 10;
    const SOCK_STREAM: c_int = 1;
    #[cfg(target_os = "macos")]
    const EAI_AGAIN: c_int = 2;
    #[cfg(target_os = "macos")]
    const EAI_NODATA: c_int = 7;
    #[cfg(target_os = "macos")]
    const EAI_NONAME: c_int = 8;
    #[cfg(not(target_os = "macos"))]
    const EAI_AGAIN: c_int = -3;
    #[cfg(not(target_os = "macos"))]
    const EAI_NODATA: c_int = -5;
    #[cfg(not(target_os = "macos"))]
    const EAI_NONAME: c_int = -2;

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

    /// The family a sockaddr starts with: BSD's length byte, then the
    /// family's; Linux's sa_family_t, two bytes in the host's order,
    /// which is little on x86_64 and aarch64, the only ones here.
    fn family(bytes: &[u8]) -> Option<u16> {
        #[cfg(target_os = "macos")]
        return bytes.get(1).copied().map(u16::from);
        #[cfg(not(target_os = "macos"))]
        return Some(u16::from_le_bytes(
            <[u8; 2]>::try_from(bytes.get(..2)?).ok()?,
        ));
    }

    /// The address of an entry: sockaddr_in or sockaddr_in6, whose
    /// address and scope sit at the same offsets on both systems.
    fn address(info: &AddrInfo) -> Option<Address> {
        let size = usize::try_from(info.addrlen).ok()?;
        if info.addr.is_null() || size < 16 {
            return None;
        }
        // rr: escape(unsafe): addr holds addrlen bytes.
        let bytes = unsafe { core::slice::from_raw_parts(info.addr, size) };
        match (
            family(bytes)?,
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
                // sin6_scope_id is in the host's order, little on x86_64
                // and aarch64.
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
    use super::{Address, Error};
    use crate::base::wait::{self, AF_INET, SOCK_STREAM};
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
mod thread {
    use super::os::{self, Name};
    use super::{Address, Error, Wait};
    use crate::base::wait::{self, Signal};
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
