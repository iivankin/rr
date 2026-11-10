//! Host lookup that never blocks the caller's loop, one API on Linux, macOS
//! and Windows: start, poll, take the addresses (socket_addr keeps a
//! link-local one's interface), drop to cancel. The system answers:
//! mDNSResponder through DNSServiceGetAddrInfo on macOS, on a socket the
//! caller's poll waits on, sorted by RFC 6724 as getaddrinfo sorts;
//! GetAddrInfoExW on Windows, asynchronous and cancellable, its callback
//! signalling the caller's poll; the C library's getaddrinfo on Linux, on
//! thread's pool, where a lookup cancelled after it started runs on to the
//! system's timeout.
//!
//! Looking up a host's addresses as the system would, without blocking
//! the caller's loop, the same on all three: start a lookup, poll it
//! until it is done, take the addresses; drop it to cancel. Connect to
//! an address's socket_addr, which keeps a link-local one's interface.
//! resolve waits for the answer, for a thread that may block: it is
//! `#[rr::blocking]`, which rr refuses on a poll loop's path (see poll).
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
//! - macOS: mDNSResponder, through dns_sd.h's DNSServiceGetAddrInfo,
//!   with VPN and split DNS as the system has them; a socket the
//!   caller's poll waits on, no thread. It asks for IPv6 only where the
//!   host has a routable IPv6 address, as getaddrinfo there does, and
//!   waits for the second family 50 ms once the first gave an address
//!   (RFC 8305). Its answers come unsorted, so resolve sorts them as
//!   getaddrinfo would (RFC 6724, the sort module).
//! - Windows: GetAddrInfoExW, asynchronous, sorted by the system; its
//!   callback sets a Signal that the caller's WSAPoll waits on.
//! - Linux: the C library's getaddrinfo, with nsswitch.conf, files, DNS,
//!   systemd-resolved and mDNS as the system has them. It blocks, and
//!   the C library has no other way, so it runs on thread's pool:
//!   at most thread::THREADS_MAX at once, the rest in line, and one
//!   cancelled once its thread took it runs on to the C library's
//!   timeout (resolv.conf's timeout and attempts), its answer dropped.
//!
//! A process out of descriptors may be told a name is not found: macOS's
//! getaddrinfo says EAI_NONAME then, as Go notes, and a C library on Linux
//! that cannot open its files or sockets may not say why either. resolve
//! keeps no answer, and takes what it can tell as for now (a system error
//! of EMFILE or ENFILE on Linux; mDNSResponder, unreachable, fails); a
//! caller that keeps NotFound keeps it no longer than such a moment.

// rr: checked(0.5.2)
// rr: needs(poll, thread)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
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

#[cfg(any(target_os = "macos", test))]
mod sort {
    //! Destination address selection (RFC 6724 section 6), as Go's
    //! addrselect.go does it: the rules that need no more than the
    //! destination and the source the system would use for it. Rules 3, 4
    //! and 7 need what Go does not know either, and are left out. macOS's
    //! own lookup that resolve waits on gives its addresses as they come,
    //! and getaddrinfo sorts them so there; resolve sorts them so too.

    use super::Address;
    use core::cmp::Ordering;
    use core::net::{IpAddr, Ipv4Addr};

    /// The most addresses sorted; a lookup gives fewer.
    pub const ADDRESSES_MAX: usize = 32;

    /// Sorts addresses, most preferred first. sources holds the source
    /// address the system picks for each destination, or None where it has
    /// no route (Go connects a UDP socket to learn it). Without sources, or
    /// with too few, nothing is known and the order stays as it was; so it
    /// does for more than ADDRESSES_MAX addresses, which no lookup gives.
    pub fn sort(addresses: &mut [Address], sources: &[Option<IpAddr>]) {
        let count = addresses.len();
        if count < 2 || sources.len() != count || count > ADDRESSES_MAX {
            return;
        }
        let mut table = [Ranked::NONE; ADDRESSES_MAX];
        for ((slot, address), source) in table.iter_mut().zip(addresses.iter()).zip(sources) {
            *slot = Ranked {
                address: *address,
                destination: Attributes::of(Some(address.ip)),
                source: *source,
                source_attributes: Attributes::of(*source),
            };
        }
        let ranked = table.get_mut(..count).unwrap_or_default();
        // Insertion sort, which is stable, so that addresses no rule tells
        // apart keep the order the server gave; there are few of them.
        for end in 1..count {
            for at in (1..=end).rev() {
                match (ranked.get(at - 1), ranked.get(at)) {
                    (Some(before), Some(after)) if compare(before, after) == Ordering::Greater => {
                        ranked.swap(at - 1, at);
                    }
                    (Some(_) | None, Some(_) | None) => break,
                }
            }
        }
        for (slot, item) in addresses.iter_mut().zip(ranked.iter()) {
            *slot = item.address;
        }
    }

    struct Ranked {
        address: Address,
        destination: Attributes,
        source: Option<IpAddr>,
        source_attributes: Attributes,
    }

    impl Ranked {
        const NONE: Ranked = Ranked {
            address: Address {
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                scope: 0,
            },
            destination: Attributes::NONE,
            source: None,
            source_attributes: Attributes::NONE,
        };
    }

    /// An address's scope, and its precedence and label in the policy table.
    struct Attributes {
        scope: u8,
        precedence: u8,
        label: u8,
    }

    const SCOPE_LINK_LOCAL: u8 = 0x2;
    const SCOPE_SITE_LOCAL: u8 = 0x5;
    const SCOPE_GLOBAL: u8 = 0xe;

    /// RFC 6724's default policy table, longest prefix first, so the first
    /// that matches is the one: prefix, its length, precedence, label.
    const POLICY: [([u8; 16], u32, u8, u8); 9] = [
        ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128, 50, 0),
        (
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
            96,
            35,
            4,
        ),
        ([0; 16], 96, 1, 3),
        (
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
            5,
            5,
        ),
        (
            [0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            16,
            30,
            2,
        ),
        (
            [0x3f, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            16,
            1,
            12,
        ),
        (
            [0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            10,
            1,
            11,
        ),
        (
            [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            7,
            3,
            13,
        ),
        ([0; 16], 0, 40, 1),
    ];

    impl Attributes {
        /// Go gives an address it does not have all zeros.
        const NONE: Attributes = Attributes {
            scope: 0,
            precedence: 0,
            label: 0,
        };

        fn of(ip: Option<IpAddr>) -> Attributes {
            let Some(ip) = ip else {
                return Attributes::NONE;
            };
            let bits = u128::from_be_bytes(sixteen(ip));
            let mut attributes = Attributes {
                scope: scope(ip),
                ..Attributes::NONE
            };
            for (prefix, length, precedence, label) in POLICY {
                // A length of 0 matches all; others shift by less than 128.
                let mask = u128::MAX.checked_shl(128 - length).unwrap_or(0);
                if bits & mask == u128::from_be_bytes(prefix) {
                    attributes.precedence = precedence;
                    attributes.label = label;
                    break;
                }
            }
            attributes
        }
    }

    /// An address as IPv6 has it: IPv4 mapped into ::ffff:0:0/96.
    fn sixteen(ip: IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    /// IPv4, or IPv4 mapped into IPv6, which Go reads as IPv4.
    fn four(ip: IpAddr) -> Option<[u8; 4]> {
        match ip {
            IpAddr::V4(v4) => Some(v4.octets()),
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(|v4| v4.octets()),
        }
    }

    /// Go's classifyScope: loopback and link-local are link-local, IPv6
    /// multicast says its own, site-local IPv6 is site-local, the rest
    /// global.
    fn scope(ip: IpAddr) -> u8 {
        if let Some([a, b, _, _]) = four(ip) {
            return if a == 127 || (a == 169 && b == 254) {
                SCOPE_LINK_LOCAL
            } else {
                SCOPE_GLOBAL
            };
        }
        let [first, second, ..] = sixteen(ip);
        let loopback = ip == IpAddr::V6(core::net::Ipv6Addr::LOCALHOST);
        if loopback || (first == 0xfe && second & 0xc0 == 0x80) {
            SCOPE_LINK_LOCAL
        } else if first == 0xff {
            second & 0xf
        } else if first == 0xfe && second & 0xc0 == 0xc0 {
            SCOPE_SITE_LOCAL
        } else {
            SCOPE_GLOBAL
        }
    }

    /// Go's compareByRFC6724: Less when a is preferred.
    fn compare(a: &Ranked, b: &Ranked) -> Ordering {
        let (Some(source_a), Some(source_b)) = (a.source, b.source) else {
            // Rule 1: a destination without a route goes last.
            return match (a.source, b.source) {
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), Some(_)) | (None, None) => Ordering::Equal,
            };
        };
        let (da, db) = (&a.destination, &b.destination);
        let (sa, sb) = (&a.source_attributes, &b.source_attributes);
        // Rule 2: prefer matching scope, then (5) matching label.
        let scope = (da.scope == sa.scope)
            .cmp(&(db.scope == sb.scope))
            .reverse();
        let label = (da.label == sa.label)
            .cmp(&(db.label == sb.label))
            .reverse();
        // Rule 6: higher precedence; rule 8: smaller scope.
        let precedence = db.precedence.cmp(&da.precedence);
        let smaller = da.scope.cmp(&db.scope);
        let rules = scope.then(label).then(precedence).then(smaller);
        if rules != Ordering::Equal {
            return rules;
        }
        // Rule 9: the longest prefix shared with the source, IPv6 only.
        if four(a.address.ip).is_some() || four(b.address.ip).is_some() {
            return Ordering::Equal;
        }
        common(source_b, b.address.ip).cmp(&common(source_a, a.address.ip))
    }

    /// The bits a source and destination share at the start, of their first
    /// 64 at most; 0 when one is IPv4 and the other is not.
    fn common(source: IpAddr, destination: IpAddr) -> u32 {
        match (four(source), four(destination)) {
            (Some(s), Some(d)) => (u32::from_be_bytes(s) ^ u32::from_be_bytes(d)).leading_zeros(),
            (None, None) => {
                let high = |ip| u128::from_be_bytes(sixteen(ip)) >> 64;
                (high(source) ^ high(destination))
                    .leading_zeros()
                    .saturating_sub(64)
            }
            (Some(_), None) | (None, Some(_)) => 0,
        }
    }

    // rr: section(tests = yes)
    #[cfg(test)]
    mod tests {
        use super::{Address, Attributes, common, scope, sort};
        use alloc::vec::Vec;
        use core::net::IpAddr;

        fn ip(text: &str) -> Address {
            Address {
                ip: text.parse().unwrap(),
                scope: 0,
            }
        }

        fn ips(texts: &[&str]) -> Vec<Address> {
            let mut out = Vec::new();
            for text in texts {
                out.push(ip(text));
            }
            out
        }

        fn source(text: &str) -> IpAddr {
            ip(text).ip
        }

        fn sources(texts: &[&str]) -> Vec<Option<IpAddr>> {
            let mut out = Vec::new();
            for text in texts {
                out.push(Some(source(text)));
            }
            out
        }

        /// Sorts a list given in text, as it is and backwards.
        fn check(input: &[&str], from: &[&str], want: &[&str], reverse: bool) {
            let mut addresses = ips(input);
            sort(&mut addresses, &sources(from));
            assert_eq!(addresses, ips(want), "{input:?}");
            if reverse {
                addresses = ips(input);
                addresses.reverse();
                let mut backwards = sources(from);
                backwards.reverse();
                sort(&mut addresses, &backwards);
                assert_eq!(addresses, ips(want), "{input:?} backwards");
            }
        }

        /// Go's TestSortByRFC6724, the examples of RFC 6724 section 10.2,
        /// forwards and backwards.
        #[test]
        fn sorts_as_go() {
            let (v6, v4) = ("2001:db8:1::1", "198.51.100.121");
            // Matching scope.
            check(
                &[v6, v4],
                &["2001:db8:1::2", "169.254.13.78"],
                &[v6, v4],
                true,
            );
            check(&[v6, v4], &["fe80::1", "198.51.100.117"], &[v4, v6], true);
            // Higher precedence.
            check(
                &[v6, "10.1.2.3"],
                &["2001:db8:1::2", "10.1.2.4"],
                &[v6, "10.1.2.3"],
                true,
            );
            // Smaller scope.
            check(
                &[v6, "fe80::1"],
                &["2001:db8:1::2", "fe80::2"],
                &["fe80::1", v6],
                true,
            );
            // Go's issue 13283: a 10/8 source prefers no 23/8 destination.
            let many = [
                "54.83.193.112",
                "184.72.238.214",
                "23.23.172.185",
                "75.101.148.21",
                "23.23.134.56",
                "23.21.50.150",
            ];
            check(&many, &["10.2.3.4"; 6], &many, false);
        }

        /// A destination without a source goes last; without any source, or
        /// with the wrong number, the order stays.
        #[test]
        fn unknown_sources() {
            let mut addresses = [ip("::1"), ip("127.0.0.1"), ip("2001:db8::1")];
            sort(&mut addresses, &[None, Some(source("127.0.0.1")), None]);
            assert_eq!(addresses, [ip("127.0.0.1"), ip("::1"), ip("2001:db8::1")]);
            sort(&mut addresses, &[None, None, None]);
            assert_eq!(addresses, [ip("127.0.0.1"), ip("::1"), ip("2001:db8::1")]);
            sort(&mut addresses, &[]);
            assert_eq!(addresses, [ip("127.0.0.1"), ip("::1"), ip("2001:db8::1")]);
            // Loopback on both sides: ::1's precedence wins.
            sort(
                &mut addresses,
                &[Some(source("127.0.0.1")), Some(source("::1")), None],
            );
            assert_eq!(addresses, [ip("::1"), ip("127.0.0.1"), ip("2001:db8::1")]);
            // Rule 9 between two global IPv6 destinations.
            let mut global = ips(&["2001:db8:2::1", "2001:db8:1::1"]);
            sort(&mut global, &sources(&["2001:db8:1::9"; 2]));
            assert_eq!(global, ips(&["2001:db8:1::1", "2001:db8:2::1"]));
        }

        /// Go's TestRFC6724PolicyTableClassify and TestRFC6724ClassifyScope.
        #[test]
        fn classifies() {
            for (text, precedence, label) in [
                ("127.0.0.1", 35, 4),
                ("2601:645:8002:a500:986f:1db8:c836:bd65", 40, 1),
                ("::1", 50, 0),
                ("2002::ab12", 30, 2),
                ("::2", 1, 3),
                ("fd00::1", 3, 13),
                ("fec0::1", 1, 11),
                ("3ffe::1", 1, 12),
                ("2001::1", 5, 5),
            ] {
                let found = Attributes::of(Some(source(text)));
                assert_eq!(
                    (found.precedence, found.label),
                    (precedence, label),
                    "{text}"
                );
            }
            for (text, want) in [
                ("127.0.0.1", 2),
                ("::1", 2),
                ("169.254.1.2", 2),
                ("fe80::1", 2),
                ("fec0::1", 5),
                ("8.8.8.8", 0xe),
                ("ff02::", 2),
                ("ff05::", 5),
                ("ff04::", 4),
                ("ff0e::", 0xe),
                ("::ffff:224.0.0.0", 0xe),
                ("::ffff:224.2.2.2", 0xe),
                ("224.0.0.0", 0xe),
                ("::ffff:127.0.0.1", 2),
            ] {
                assert_eq!(scope(ip(text).ip), want, "{text}");
            }
        }

        /// Go's TestRFC6724CommonPrefixLength.
        #[test]
        fn common_prefixes() {
            for (a, b, want) in [
                ("fe80::1", "fe80::2", 64),
                ("fe81::1", "fe80::2", 15),
                ("127.0.0.1", "fe80::1", 0),
                ("1.2.3.4", "1.2.3.4", 32),
                ("1.2.255.255", "1.2.0.0", 16),
                ("1.2.127.255", "1.2.0.0", 17),
                ("1.2.63.255", "1.2.0.0", 18),
                ("1.2.31.255", "1.2.0.0", 19),
                ("1.2.15.255", "1.2.0.0", 20),
                ("1.2.7.255", "1.2.0.0", 21),
                ("1.2.3.255", "1.2.0.0", 22),
                ("1.2.1.255", "1.2.0.0", 23),
                ("1.2.0.255", "1.2.0.0", 24),
            ] {
                assert_eq!(common(ip(a).ip, ip(b).ip), want, "{a} {b}");
            }
        }
    }
    // rr: end(tests = yes)
}
mod sys {
    //! The system side of resolve: what the top of the file says it is, for each system.

    use alloc::vec::Vec;
    use core::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

    /// What a lookup waits on: the type every component's poll loop takes.
    pub use crate::base::poll::Want;

    /// An address, and for a link-local IPv6 one the interface it is on:
    /// connect to socket_addr's, which keeps it, as a SocketAddr made of ip
    /// alone does not.
    #[derive(Clone, Copy)]
    #[cfg_attr(any(target_os = "macos", test), derive(PartialEq))]
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug))]
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
        pub fn want(&self) -> Want {
            match &self.found {
                Ok(_) => Want::READY,
                Err(state) => state.want(),
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

    // rr: section(os = macos windows)
    /// The addresses of a lookup that is over, for the caller to keep.
    #[cfg(not(target_os = "linux"))]
    fn owned(result: Result<&[Address], Error>) -> Result<Vec<Address>, Error> {
        let mut addresses = Vec::new();
        // rr: escape(copy): the lookup that holds them ends here.
        addresses.extend_from_slice(result?);
        Ok(addresses)
    }
    // rr: end(os = macos windows)

    // rr: section(os = macos windows)
    /// Polls the lookup and waits as it says, until it is over.
    #[cfg(not(target_os = "linux"))]
    fn finish(mut lookup: Lookup) -> Result<Vec<Address>, Error> {
        // The system ends each lookup at its own timeout, and wakes the wait
        // then.
        loop {
            if let Some(result) = lookup.poll() {
                return owned(result);
            }
            crate::base::poll::block(&lookup.want());
        }
    }
    // rr: end(os = macos windows)

    // rr: section(os = linux macos)
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
    // rr: end(os = linux macos)

    // rr: section(os = linux)
    /// Linux: the C library's getaddrinfo, which reads nsswitch.conf and
    /// asks what it names (files, DNS, systemd-resolved, mDNS) and sorts the
    /// addresses by RFC 6724. It blocks, and nothing asks the system without
    /// blocking, so a lookup runs it on thread's pool, which sets the
    /// lookup's Signal when it returned. A lookup dropped while its thread
    /// runs never waits: the thread drops the work; one dropped while still
    /// in the pool's line never starts.
    #[cfg(target_os = "linux")]
    mod os {
        use super::{Address, Error, Want, c_string};
        use crate::base::poll::{AF_INET, AF_INET6, SOCK_STREAM, Signal, errno};
        use crate::base::thread::{self, Done, Job, Work};
        use alloc::boxed::Box;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use core::ffi::{c_char, c_int};
        use core::net::IpAddr;
        use core::ptr::null_mut;

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

        /// A lookup for the pool: the name, NUL-terminated, in; what
        /// getaddrinfo answered, out.
        struct Lookup {
            name: Vec<u8>,
            result: Result<Vec<Address>, Error>,
        }

        impl Work for Lookup {
            fn run(&mut self) {
                self.result = lookup(&self.name);
            }
        }

        pub struct State {
            /// The lookup in the pool, until it is done; each job of it holds
            /// a Lookup, as start alone spawns them.
            job: Option<Job>,
            /// What the job sets when it is done, which want names.
            signal: Option<Arc<Signal>>,
            /// The result, once taken from the job.
            taken: Option<Result<Vec<Address>, Error>>,
        }

        impl State {
            pub fn start(name: &[u8]) -> State {
                let mut state = State {
                    job: None,
                    signal: None,
                    taken: None,
                };
                let Some(name) = c_string(name) else {
                    state.taken = Some(Err(Error::NotFound));
                    return state;
                };
                let Some(signal) = Signal::new() else {
                    state.taken = Some(Err(Error::Failed));
                    return state;
                };
                // rr: escape(shared): the lookup waits on it, the job sets it.
                let signal = Arc::new(signal);
                let work = Box::new(Lookup {
                    name,
                    result: Err(Error::Failed),
                });
                // rr: escape(copy): the job's holder of the signal.
                match thread::spawn(work, Done::Signal(Arc::clone(&signal))) {
                    Ok(job) => {
                        state.job = Some(job);
                        state.signal = Some(signal);
                    }
                    Err(_) => state.taken = Some(Err(Error::Failed)),
                }
                state
            }

            #[must_use]
            pub fn poll(&mut self) -> Option<Result<&[Address], Error>> {
                if let Some(job) = self.job.take() {
                    match job.take() {
                        Ok(work) => self.taken = Some(answer(work)),
                        Err(job) => self.job = Some(job),
                    }
                }
                match &self.taken {
                    Some(Ok(addresses)) => Some(Ok(addresses)),
                    Some(Err(error)) => Some(Err(*error)),
                    None => None,
                }
            }

            pub fn want(&self) -> Want {
                match (&self.job, &self.signal) {
                    (Some(_), Some(signal)) => signal.want(),
                    _ => Want::READY,
                }
            }
        }

        /// What a Lookup the pool gave back found.
        fn answer(work: Box<dyn Work + Send>) -> Result<Vec<Address>, Error> {
            // rr: escape(unsafe, cast, leak): State::start alone spawns the
            // jobs State keeps, each with a Box<Lookup>, and the pool gives
            // that Box back: the pointer is the Lookup's, which from_raw owns
            // again.
            let lookup = unsafe { Box::from_raw(Box::into_raw(work).cast::<Lookup>()) };
            lookup.result
        }

        /// getaddrinfo blocks the caller's thread, which is what was asked.
        pub fn resolve(name: &[u8]) -> Result<Vec<Address>, Error> {
            lookup(&c_string(name).ok_or(Error::NotFound)?)
        }
    }
    // rr: end(os = linux)

    // rr: section(os = macos)
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
        use super::{Address, Error, Want, c_string, finish};
        use crate::base::poll::{self, F_SETFD, FD_CLOEXEC, Fd, Instant, POLLIN};
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
                    let Some(found) = bytes.and_then(|bytes| self::address(bytes, interface))
                    else {
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
            let named =
                connected && unsafe { getsockname(fd, local.as_mut_ptr(), &raw mut size) } == 0;
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
                    let mut ready = Want::READY;
                    ready.fds[0] = Fd {
                        fd: self.fd(),
                        events: POLLIN,
                    };
                    ready.count = 1;
                    if poll::ready(&ready)[0] == 0 {
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

            pub fn want(&self) -> Want {
                if self.done.is_some() {
                    return Want::READY;
                }
                let mut want = Want::READY;
                want.fds[0] = Fd {
                    fd: self.fd(),
                    events: POLLIN,
                };
                want.count = 1;
                // mDNSResponder ends the lookup itself (TIMEOUT), with a reply;
                // the other family is waited for only so long.
                // rr: escape(unsafe): answers is live while the lookup runs.
                want.timeout_ms = unsafe { &*self.answers }.left_ms(Instant::now());
                want
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

        // rr: section(tests = yes)
        #[cfg(test)]
        mod tests {
            use super::{
                ADD, AF_INET, AF_INET6, Answers, DELAY_MS, NO_ERROR, NO_SUCH_RECORD,
                SOCKADDR_BYTES, reply,
            };
            use crate::base::poll::Instant;
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
        // rr: end(tests = yes)
    }
    // rr: end(os = macos)

    // rr: section(os = windows)
    /// Windows: GetAddrInfoExW, asynchronous since Windows 8, which answers
    /// as GetAddrInfoW does, sorted by RFC 6724, and calls back on a thread
    /// of the system's pool; the callback sets a Signal, which the caller's
    /// WSAPoll waits on. A lookup dropped is cancelled there
    /// (GetAddrInfoExCancel); the callback comes all the same, so the lookup
    /// and the callback share a block, which the last of the two frees.
    #[cfg(target_os = "windows")]
    mod os {
        use super::{Address, Error, Want, finish};
        use crate::base::poll::{self, AF_INET, AF_INET6, SOCK_STREAM, Signal};
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
                poll::startup();
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

            pub fn want(&self) -> Want {
                if self.taken.is_some() || self.shared.is_null() {
                    return Want::READY;
                }
                // rr: escape(unsafe): this lookup holds shared.
                let shared = unsafe { &*self.shared };
                shared.signal.want()
            }
        }

        impl Drop for State {
            fn drop(&mut self) {
                if self.shared.is_null() {
                    return;
                }
                // rr: escape(unsafe): this lookup holds shared.
                let shared = unsafe { &*self.shared };
                let cancelled = shared.state.compare_exchange(
                    ASKED,
                    DROPPED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
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
    // rr: end(os = windows)

    // rr: section(tests = yes)
    #[cfg(test)]
    mod tests {
        use super::{Error, Lookup, resolve};
        use crate::base::poll::{Follow, Instant, Poll};

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
                crate::base::poll::block(&lookup.want());
            }
            panic!("localhost did not resolve");
        }

        /// localhost through a Poll, as a loop that serves many connections
        /// runs a lookup beside them.
        #[test]
        fn in_a_poll() {
            let mut poll = Poll::new().unwrap();
            let mut follow = Follow::NONE;
            let mut lookup = Lookup::start(b"localhost");
            let end = Instant::now().after_ms(10_000);
            loop {
                if let Some(result) = lookup.poll() {
                    assert!(loopback(result.unwrap()));
                    break;
                }
                poll.follow(&mut follow, &lookup.want(), 1).unwrap();
                poll.poll(Some(end));
                assert!(!end.reached_by(Instant::now()), "localhost did not resolve");
            }
            poll.unfollow(&mut follow);
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
    // rr: end(tests = yes)
}

pub use sys::*;
