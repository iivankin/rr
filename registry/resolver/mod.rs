//! A stub resolver that behaves as Go's own (package net without cgo),
//! without I/O: resolv.conf, /etc/hosts and nsswitch.conf read from
//! text the caller hands in, the order of files and DNS decided as Go
//! decides it, and a lookup of one name as a state machine that says
//! what to send to which server and when to wake it, and takes what
//! came back. Addresses are sorted by RFC 6724 from the sources the
//! caller found. Sockets, files, the clock and random bytes are the
//! caller's: sys/resolve.rs drives it on Linux.

pub mod conf;
pub mod hosts;
pub mod lookup;
pub mod nss;
pub mod sort;

use core::net::{IpAddr, Ipv6Addr};

/// The most bytes of a name in text, its final dot included, as Go's
/// isDomainName allows.
pub const NAME_MAX: usize = 254;
/// The most addresses a lookup gives, and of each family in a reply.
pub const ADDRESSES_MAX: usize = 32;
/// The most bytes of an IPv6 zone, an interface's name (IFNAMSIZ).
pub const ZONE_MAX: usize = 16;
/// The most bytes of the search list in all, as glibc long kept it (Go
/// keeps any): with SEARCH_MAX it bounds what a lookup holds.
pub const SEARCH_BYTES_MAX: usize = 256;

/// Why a lookup gave no address.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// No such host: NXDOMAIN, no address of either family, or a name
    /// that is not one.
    NotFound,
    /// No server answered in time.
    Timeout,
    /// A server failed (SERVFAIL), or could not be reached.
    Temporary,
    /// A server answered with nonsense: another RCODE, a malformed
    /// message, a lame referral.
    Misbehaving,
}

/// An IPv6 zone as written after `%`: an interface's name or number.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Zone {
    bytes: [u8; ZONE_MAX],
    length: u8,
}

/// An address and, for a link-local IPv6 one, its zone.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Address {
    pub ip: IpAddr,
    pub zone: Zone,
}

impl Zone {
    pub const NONE: Zone = Zone {
        bytes: [0; ZONE_MAX],
        length: 0,
    };

    fn new(text: &[u8]) -> Option<Zone> {
        let mut zone = Zone::NONE;
        zone.bytes.get_mut(..text.len())?.copy_from_slice(text);
        zone.length = u8::try_from(text.len()).ok()?;
        Some(zone)
    }

    /// The zone's text; empty when there is none.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
            .get(..usize::from(self.length))
            .unwrap_or_default()
    }
}

impl Address {
    pub const fn new(ip: IpAddr) -> Address {
        Address {
            ip,
            zone: Zone::NONE,
        }
    }
}

/// An address as Go's netip.ParseAddr reads one: IPv4 in four decimal
/// parts without leading zeros, IPv6 with a zone of 1 to ZONE_MAX bytes.
pub fn address(text: &[u8]) -> Option<Address> {
    let Some(at) = text.iter().position(|byte| *byte == b'%') else {
        let ip = core::str::from_utf8(text).ok()?.parse::<IpAddr>().ok()?;
        return Some(Address::new(ip));
    };
    let (ip, zone) = (text.get(..at)?, text.get(at + 1..)?);
    if zone.is_empty() {
        return None;
    }
    let ip = core::str::from_utf8(ip).ok()?.parse::<Ipv6Addr>().ok()?;
    Some(Address {
        ip: IpAddr::V6(ip),
        zone: Zone::new(zone)?,
    })
}

/// The fields of a line, split at spaces, tabs and line ends, as Go's
/// getFields splits them.
struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    fn new(line: &'a [u8]) -> Fields<'a> {
        Fields { rest: line }
    }

    fn field(&mut self) -> Option<&'a [u8]> {
        let start = self.rest.iter().position(|byte| !space(*byte))?;
        let rest = self.rest.get(start..)?;
        let end = rest.iter().position(|byte| space(*byte));
        let (field, after) = rest.split_at(end.unwrap_or(rest.len()));
        self.rest = after;
        Some(field)
    }
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// The decimal digits text starts with, as Go's dtoi reads them: 0 when
/// there are none, and no more than 0xffffff.
fn number(text: &[u8]) -> u32 {
    const BIG: u32 = 0x00ff_ffff;
    let mut value: u32 = 0;
    for byte in text {
        if !byte.is_ascii_digit() {
            break;
        }
        // value is under BIG, so ten times it and a digit fit.
        value = value * 10 + u32::from(byte - b'0');
        if value >= BIG {
            return BIG;
        }
    }
    value
}

/// Whether a ends with suffix, in any case.
fn ends_with(a: &[u8], suffix: &[u8]) -> bool {
    a.len() >= suffix.len()
        && a.get(a.len() - suffix.len()..)
            .is_some_and(|end| end.eq_ignore_ascii_case(suffix))
}

/// A search list: up to SEARCH_MAX names of SEARCH_BYTES_MAX bytes in
/// all, one after another in place.
#[derive(Clone)]
pub struct Search {
    text: [u8; SEARCH_BYTES_MAX],
    ends: [u16; conf::SEARCH_MAX],
    count: usize,
}

impl Search {
    const EMPTY: Search = Search {
        text: [0; SEARCH_BYTES_MAX],
        ends: [0; conf::SEARCH_MAX],
        count: 0,
    };

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, index: usize) -> Option<&[u8]> {
        if index >= self.count {
            return None;
        }
        let start = match index.checked_sub(1) {
            Some(before) => *self.ends.get(before)?,
            None => 0,
        };
        let end = *self.ends.get(index)?;
        self.text.get(usize::from(start)..usize::from(end))
    }

    /// Adds the name the parts make, unless it is longer than NAME_MAX
    /// or the list is full: false then.
    fn push(&mut self, parts: &[&[u8]]) -> bool {
        let length: usize = parts.iter().map(|part| part.len()).sum();
        let start = match self.count.checked_sub(1) {
            Some(last) => usize::from(self.ends.get(last).copied().unwrap_or(0)),
            None => 0,
        };
        let end = start + length;
        if length > NAME_MAX || self.count >= conf::SEARCH_MAX || end > SEARCH_BYTES_MAX {
            return false;
        }
        let mut at = start;
        for part in parts {
            if let Some(slot) = self.text.get_mut(at..at + part.len()) {
                slot.copy_from_slice(part);
            }
            at += part.len();
        }
        let (Ok(end), Some(slot)) = (u16::try_from(end), self.ends.get_mut(self.count)) else {
            return false;
        };
        *slot = end;
        self.count += 1;
        true
    }

    fn clear(&mut self) {
        self.count = 0;
    }
}

/// Helpers the tests and fuzz targets share: addresses from text, and
/// a server's side of DNS.
#[cfg(any(test, fuzzing))]
pub mod fake {
    use super::{Address, address};
    use alloc::vec::Vec;
    use core::net::IpAddr;

    pub fn ip(text: &str) -> Address {
        // rr: escape(panic): a test's addresses are written right.
        address(text.as_bytes()).unwrap()
    }

    pub fn ips(texts: &[&str]) -> Vec<Address> {
        let mut out = Vec::new();
        for text in texts {
            out.push(ip(text));
        }
        out
    }

    /// Where the question of a query (as UDP carries it) ends.
    fn question_end(query: &[u8]) -> usize {
        let mut at = 12;
        while let Some(&length) = query.get(at) {
            at += 1 + usize::from(length);
            if length == 0 {
                break;
            }
        }
        at + 4
    }

    /// The name a query asks, with its final dot.
    pub fn question(query: &[u8]) -> Vec<u8> {
        let mut name = Vec::new();
        let mut at = 12;
        while let Some(&length) = query.get(at) {
            if length == 0 {
                break;
            }
            let label = query
                .get(at + 1..at + 1 + usize::from(length))
                .unwrap_or_default();
            name.extend_from_slice(label);
            name.push(b'.');
            at += 1 + usize::from(length);
        }
        name
    }

    /// The answer to a query: its id and question, the flags given (QR,
    /// RD and RA added), and a record for each address of the type
    /// asked. No EDNS0 is echoed.
    pub fn answer(query: &[u8], flags: u16, ips: &[IpAddr]) -> Vec<u8> {
        let mut message = Vec::new();
        answer_into(&mut message, query, flags, ips);
        message
    }

    /// The answer into message, which is cleared first.
    pub fn answer_into(message: &mut Vec<u8>, query: &[u8], flags: u16, ips: &[IpAddr]) {
        let end = question_end(query);
        let aaaa = query.get(end - 4..end - 2) == Some(&[0, 28]);
        message.clear();
        message.extend_from_slice(query.get(..2).unwrap_or_default());
        message.extend_from_slice(&(flags | 0x8180).to_be_bytes());
        message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(query.get(12..end).unwrap_or_default());
        let mut count: u8 = 0;
        for ip in ips {
            let data: &[u8] = match ip {
                IpAddr::V4(v4) if !aaaa => &v4.octets(),
                IpAddr::V6(v6) if aaaa => &v6.octets(),
                IpAddr::V4(_) | IpAddr::V6(_) => continue,
            };
            let rtype = if aaaa { 28 } else { 1 };
            message.extend_from_slice(&[0xc0, 12, 0, rtype, 0, 1, 0, 0, 0, 60, 0]);
            message.push(u8::try_from(data.len()).unwrap_or(0));
            message.extend_from_slice(data);
            count += 1;
        }
        if let Some(answers) = message.get_mut(7) {
            *answers = count;
        }
    }

    /// Whether a query asks for name, given in wire form.
    pub fn asks(query: &[u8], wire: &[u8]) -> bool {
        query.get(12..12 + wire.len()) == Some(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::{Zone, address, number};
    use core::net::{IpAddr, Ipv4Addr};

    /// Addresses as Go's netip.ParseAddr takes them, and refuses them.
    #[test]
    fn addresses() {
        let v4 = address(b"192.0.2.1").unwrap();
        assert_eq!(v4.ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(v4.zone, Zone::NONE);
        let zoned = address(b"fe80::1%eth0").unwrap();
        assert_eq!(zoned.zone, Zone::new(b"eth0").unwrap());
        assert!(address(b"::ffff:1.2.3.4").is_some());
        let longest = b"fe80::1%abcdefghijklmnop";
        assert_eq!(address(longest).unwrap().zone.as_bytes().len(), 16);
        for bad in [
            &b""[..],
            b"1.2.3",
            b"01.2.3.4",
            b"1.2.3.4%eth0",
            b"fe80::1%",
            b"::1%abcdefghijklmnopq",
            b"[::1]",
            b"1.2.3.4 ",
        ] {
            assert!(address(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn numbers() {
        for (text, want) in [
            (&b"5"[..], 5),
            (b"", 0),
            (b"x1", 0),
            (b"12x", 12),
            (b"99999999999", 0x00ff_ffff),
        ] {
            assert_eq!(number(text), want);
        }
    }
}
