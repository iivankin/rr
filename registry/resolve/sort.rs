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
