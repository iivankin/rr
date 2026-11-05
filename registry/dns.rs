//! DNS wire format (RFC 1035) for a stub resolver, without I/O: a query
//! for A or AAAA written into the caller's buffer, and the reply to it
//! checked and read into the caller's records. It opens no socket, reads
//! no resolv.conf and keeps no clock: servers, timeouts and retries are
//! the caller's. Most programs resolve with getaddrinfo in a thread; this
//! is for one that needs its own resolver, such as a poll loop that may
//! not block.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The bytes of a message's header.
pub const HEADER_BYTES: usize = 12;
/// The UDP payload EDNS0 offers (DNS flag day 2020): what fits in one
/// packet on almost any path, so that replies are not fragmented.
pub const UDP_SIZE: u16 = 1232;
/// The most bytes of a message: what TCP's two-byte length counts.
pub const MESSAGE_MAX: usize = 65535;
/// The most CNAMEs followed from the name asked to its addresses.
pub const CHAIN_MAX: usize = 8;
/// The most records a reply may carry in its three sections.
pub const RECORDS_MAX: usize = 512;
/// The most bytes of a name in wire form, length bytes and root included.
const NAME_MAX: usize = 255;
/// The most bytes of a query as TCP frames it: the length, the header,
/// the name, its type and class, and the OPT record.
pub const QUERY_MAX: usize = 2 + HEADER_BYTES + NAME_MAX + 4 + 11;
const LABEL_MAX: usize = 63;
/// The most compression pointers one name may follow.
const JUMPS_MAX: usize = 32;
/// The most labels of a name: each takes two bytes of NAME_MAX.
const LABELS_MAX: usize = NAME_MAX / 2;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u32 = 3;

#[cfg_attr(any(test, fuzzing), derive(Debug, PartialEq))]
pub enum Error {
    /// The name asked is not labels of 1 to 63 printable bytes, 255 in
    /// all in wire form.
    Name,
    /// Not the reply to this query: another id or question, or not a
    /// response. Over UDP, drop it and keep waiting.
    Mismatch,
    /// The header or the question cannot be read: cut short, or a name
    /// that does not parse. Nothing says it is the reply to this query,
    /// so over UDP drop it and keep waiting, as for Mismatch.
    Unreadable,
    /// The reply did not fit in UDP (TC): ask again over TCP.
    Truncated,
    /// The name does not exist (NXDOMAIN).
    NoName,
    /// Another RCODE, such as SERVFAIL (2) or REFUSED (5), with EDNS's
    /// upper bits.
    Server(u16),
    /// The reply to this query is malformed past its question: a record
    /// cut short, a bad label or pointer, a record of the wrong size, or
    /// bytes past its last record. Ask another server.
    Format,
    /// More CNAMEs than CHAIN_MAX, which a loop of them is too.
    Chain,
    /// More records than RECORDS_MAX.
    TooLarge,
}

#[derive(Clone, Copy)]
pub enum Kind {
    A,
    Aaaa,
}

/// How the reply came: over UDP a TC bit means the reply was cut and
/// is asked again over TCP; over TCP the reply is read as it is, as
/// glibc and Go read it.
#[derive(Clone, Copy)]
pub enum Transport {
    Udp,
    Tcp,
}

/// A message's header.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Header {
    pub id: u16,
    /// The flags word: QR, opcode, AA, TC, RD, RA, Z, AD, CD and RCODE.
    flags: u16,
    /// The RCODE, with EDNS's upper bits where reply read them.
    pub rcode: u16,
    pub questions: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additionals: u16,
}

/// What reply read of an answer.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Answer {
    pub header: Header,
    /// The addresses written into out.
    pub count: usize,
    /// The records of the answer section of the kind asked, of any
    /// owner: none of them is what Go calls no such host.
    pub answers_of_type: usize,
}

impl Header {
    /// Whether the server is the zone's authority (AA).
    pub fn authoritative(&self) -> bool {
        self.flags & 0x0400 != 0
    }

    /// Whether the message was cut to fit (TC).
    pub fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    /// Whether the server offers recursion (RA).
    pub fn recursion_available(&self) -> bool {
        self.flags & 0x0080 != 0
    }

    /// Whether the server says it checked the data with DNSSEC (AD).
    pub fn authentic(&self) -> bool {
        self.flags & 0x0020 != 0
    }
}

/// Reads a message's header: its id, flags, RCODE (without EDNS's
/// upper bits, which lie in a record) and section counts.
pub fn header(message: &[u8]) -> Result<Header, Error> {
    let field = |at: usize| match word(message, at) {
        Ok(value) => Ok(value),
        Err(_) => Err(Error::Unreadable),
    };
    let flags = field(2)?;
    Ok(Header {
        id: field(0)?,
        flags,
        rcode: flags & 0xf,
        questions: field(4)?,
        answers: field(6)?,
        authorities: field(8)?,
        additionals: field(10)?,
    })
}

/// A question to one server.
pub struct Query<'a> {
    /// The id the reply must carry: random, so that a forged reply has to
    /// guess it.
    pub id: u16,
    /// A host name such as b"example.com", with or without the final dot.
    pub name: &'a [u8],
    pub kind: Kind,
    /// Whether to offer EDNS0's UDP_SIZE, which lets larger replies come
    /// over UDP.
    pub edns: bool,
    /// Whether to set AD, asking whether the server checked the answer
    /// with DNSSEC (RFC 6840; resolv.conf's trust-ad).
    pub ad: bool,
}

/// An address of the name asked and the seconds it may be kept: the
/// least TTL of the record and the CNAMEs that led to it.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Record {
    pub address: IpAddr,
    pub ttl: u32,
}

impl Record {
    /// What a caller's array starts with.
    pub const EMPTY: Record = Record {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ttl: 0,
    };
}

impl Kind {
    fn code(self) -> u16 {
        match self {
            Kind::A => TYPE_A,
            Kind::Aaaa => TYPE_AAAA,
        }
    }
}

/// Writes the query as a message, as UDP carries it: recursion desired,
/// and EDNS0 when asked. A bad name is refused with out as it was.
pub fn query(out: &mut Vec<u8>, query: &Query<'_>) -> Result<(), Error> {
    let mut framed = [0; QUERY_MAX];
    let end = framed_query(&mut framed, query)?;
    out.extend_from_slice(framed.get(2..end).unwrap_or_default());
    Ok(())
}

/// Writes the query as TCP carries it, after its two-byte length.
pub fn tcp_query(out: &mut Vec<u8>, query: &Query<'_>) -> Result<(), Error> {
    let mut framed = [0; QUERY_MAX];
    let end = framed_query(&mut framed, query)?;
    out.extend_from_slice(framed.get(..end).unwrap_or_default());
    Ok(())
}

/// Writes the query into out as TCP frames it, and returns its end;
/// UDP sends out[2..end]. Nothing is allocated, so a caller may keep a
/// query of each kind in place.
pub fn framed_query(out: &mut [u8; QUERY_MAX], query: &Query<'_>) -> Result<usize, Error> {
    let mut writer = Writer { out, at: 2 };
    writer.put(&query.id.to_be_bytes());
    // Recursion desired, AD if asked; one question, and the OPT record
    // if any.
    let ad = u8::from(query.ad) << 5;
    writer.put(&[0x01, ad, 0, 1, 0, 0, 0, 0, 0, u8::from(query.edns)]);
    let name = query.name.strip_suffix(b".").unwrap_or(query.name);
    let mut wire = 1;
    for label in name.split(|byte| *byte == b'.') {
        let Ok(length) = u8::try_from(label.len()) else {
            return Err(Error::Name);
        };
        wire += label.len() + 1;
        if label.is_empty() || label.len() > LABEL_MAX || wire > NAME_MAX {
            return Err(Error::Name);
        }
        if !label.iter().all(|byte| (0x21..0x7f).contains(byte)) {
            return Err(Error::Name);
        }
        writer.put(&[length]);
        writer.put(label);
    }
    writer.put(&[0]);
    writer.put(&query.kind.code().to_be_bytes());
    writer.put(&CLASS_IN.to_be_bytes());
    if query.edns {
        // The root's OPT: the UDP size in the class, no flags, no data.
        let [high, low] = UDP_SIZE.to_be_bytes();
        writer.put(&[0, 0, 41, high, low, 0, 0, 0, 0, 0, 0]);
    }
    let end = writer.at;
    // A name of NAME_MAX in wire form at most: the query fits.
    assert!(end <= QUERY_MAX);
    let size = u16::try_from(end - 2).unwrap_or(u16::MAX);
    if let Some(prefix) = out.get_mut(..2) {
        prefix.copy_from_slice(&size.to_be_bytes());
    }
    Ok(end)
}

/// Bytes written one after another into a buffer sized for them.
struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let end = self.at + bytes.len();
        if let Some(slot) = self.out.get_mut(self.at..end) {
            slot.copy_from_slice(bytes);
        }
        self.at = end;
    }
}

/// The fields of a resource record, by their offsets in the message.
struct Resource {
    owner: usize,
    rtype: u16,
    class: u16,
    ttl: u32,
    data: usize,
    end: usize,
}

/// Reads the reply to query into out: the addresses of the name asked,
/// after the CNAMEs that lead from it, of the kind asked. The answer
/// says how many were written, none when the name has none of that kind
/// (or the reply gives only the CNAMEs, and the caller may ask for the
/// last one), and how many of that kind the answers hold for any name.
/// Addresses past out's length are left out.
pub fn reply(
    message: &[u8],
    query: &Query<'_>,
    transport: Transport,
    out: &mut [Record],
) -> Result<Answer, Error> {
    if message.len() > MESSAGE_MAX {
        return Err(Error::TooLarge);
    }
    let mut header = header(message)?;
    // A response (QR), to a standard query (opcode 0).
    if header.id != query.id || header.flags & 0xf800 != 0x8000 || header.questions != 1 {
        return Err(Error::Mismatch);
    }
    let after = match question(message, query) {
        Err(Error::Format) => return Err(Error::Unreadable),
        other => other?,
    };
    if header.truncated() && matches!(transport, Transport::Udp) {
        return Err(Error::Truncated);
    }
    let answers = usize::from(header.answers);
    let total = answers + usize::from(header.authorities) + usize::from(header.additionals);
    if total > RECORDS_MAX {
        return Err(Error::TooLarge);
    }
    // Every record is read once, so that a malformed one anywhere fails
    // the message and the answers can be read again without checks.
    let mut at = after;
    let mut extended = 0;
    let mut answers_of_type = 0;
    for index in 0..total {
        let record = resource(message, at)?;
        if index < answers && record.rtype == TYPE_CNAME {
            if name_end(message, record.data)? != record.end {
                return Err(Error::Format);
            }
        } else if index < answers && record.rtype == query.kind.code() {
            answers_of_type += 1;
        } else if index >= answers && record.rtype == TYPE_OPT {
            extended = record.ttl >> 24;
        } else {
            // Other records are passed over.
        }
        at = record.end;
    }
    if at != message.len() {
        return Err(Error::Format);
    }
    let rcode = (extended << 4) | u32::from(header.rcode);
    match rcode {
        0 => {}
        RCODE_NXDOMAIN => return Err(Error::NoName),
        rcode => return Err(Error::Server(u16::try_from(rcode).unwrap_or(u16::MAX))),
    }
    header.rcode = 0;
    let (name, ttl) = canonical(message, after, answers)?;
    let mut count = 0;
    let mut next = after;
    for _ in 0..answers {
        let record = resource(message, next)?;
        next = record.end;
        if record.rtype != query.kind.code()
            || record.class != CLASS_IN
            || !same_name(message, record.owner, name)?
        {
            continue;
        }
        let data = message.get(record.data..record.end).unwrap_or_default();
        let address = match query.kind {
            Kind::A => <[u8; 4]>::try_from(data).map(|octets| IpAddr::V4(Ipv4Addr::from(octets))),
            Kind::Aaaa => {
                <[u8; 16]>::try_from(data).map(|octets| IpAddr::V6(Ipv6Addr::from(octets)))
            }
        };
        let Ok(address) = address else {
            return Err(Error::Format);
        };
        if let Some(slot) = out.get_mut(count) {
            *slot = Record {
                address,
                ttl: record.ttl.min(ttl),
            };
            count += 1;
        }
    }
    Ok(Answer {
        header,
        count,
        answers_of_type,
    })
}

/// Checks the question echoed at the header's end; the offset after it.
fn question(message: &[u8], query: &Query<'_>) -> Result<usize, Error> {
    let name = query.name.strip_suffix(b".").unwrap_or(query.name);
    let mut cursor = Name::new(HEADER_BYTES);
    for label in name.split(|byte| *byte == b'.') {
        match cursor.label(message)? {
            Some(echoed) if echoed.eq_ignore_ascii_case(label) => {}
            Some(_) | None => return Err(Error::Mismatch),
        }
    }
    if cursor.label(message)?.is_some() {
        return Err(Error::Mismatch);
    }
    let end = cursor.end.ok_or(Error::Format)?;
    if word(message, end)? != query.kind.code() || word(message, end + 2)? != CLASS_IN {
        return Err(Error::Mismatch);
    }
    Ok(end + 4)
}

/// Follows the CNAMEs among the answers from the name asked: the offset
/// of the last name and the least TTL on the way.
fn canonical(message: &[u8], after: usize, answers: usize) -> Result<(usize, u32), Error> {
    let mut name = HEADER_BYTES;
    let mut ttl = u32::MAX;
    // Servers list a chain in order: each search starts after the CNAME
    // found last and wraps round, so that one pass reads such a chain.
    let (mut at, mut index) = (after, 0);
    for _ in 0..=CHAIN_MAX {
        let mut next = None;
        for _ in 0..answers {
            if index == answers {
                (at, index) = (after, 0);
            }
            let record = resource(message, at)?;
            at = record.end;
            index += 1;
            if record.rtype == TYPE_CNAME
                && record.class == CLASS_IN
                && same_name(message, record.owner, name)?
            {
                next = Some((record.data, record.ttl));
                break;
            }
        }
        let Some((target, step)) = next else {
            return Ok((name, ttl));
        };
        name = target;
        ttl = ttl.min(step);
    }
    Err(Error::Chain)
}

/// The record at at, its data checked to lie within the message.
fn resource(message: &[u8], at: usize) -> Result<Resource, Error> {
    // Offsets here are within a message of at most MESSAGE_MAX bytes, plus
    // a few: the additions cannot wrap.
    let fixed = name_end(message, at)?;
    let high = word(message, fixed.wrapping_add(4))?;
    let ttl = (u32::from(high) << 16) | u32::from(word(message, fixed.wrapping_add(6))?);
    let data = fixed.wrapping_add(10);
    let end = data.wrapping_add(usize::from(word(message, fixed.wrapping_add(8))?));
    if end > message.len() {
        return Err(Error::Format);
    }
    Ok(Resource {
        owner: at,
        rtype: word(message, fixed)?,
        class: word(message, fixed.wrapping_add(2))?,
        // A TTL with the top bit set is read as 0 (RFC 2181 section 8).
        ttl: if ttl >> 31 == 0 { ttl } else { 0 },
        data,
        end,
    })
}

/// The big-endian u16 at at. An at so large that the end wraps makes an
/// empty range, which get refuses.
fn word(message: &[u8], at: usize) -> Result<u16, Error> {
    match message.get(at..at.wrapping_add(2)) {
        Some(&[high, low]) => Ok(u16::from_be_bytes([high, low])),
        Some(_) | None => Err(Error::Format),
    }
}

/// Where the name at at ends in place: past its root or first pointer.
fn name_end(message: &[u8], at: usize) -> Result<usize, Error> {
    let mut cursor = Name::new(at);
    for _ in 0..=LABELS_MAX {
        if cursor.label(message)?.is_none() {
            return cursor.end.ok_or(Error::Format);
        }
    }
    Err(Error::Format)
}

/// Whether the names at a and b are the same, in any case.
fn same_name(message: &[u8], a: usize, b: usize) -> Result<bool, Error> {
    let (mut first, mut second) = (Name::new(a), Name::new(b));
    for _ in 0..=LABELS_MAX {
        match (first.label(message)?, second.label(message)?) {
            (None, None) => return Ok(true),
            (Some(one), Some(other)) if one.eq_ignore_ascii_case(other) => {}
            (Some(_) | None, Some(_) | None) => return Ok(false),
        }
    }
    Err(Error::Format)
}

/// A name read a label at a time, through compression pointers. Each
/// pointer must lead before the labels it ends, so a chain of them only
/// goes back and cannot loop; the length and the jumps are bounded too.
struct Name {
    at: usize,
    /// Pointers must lead before this: the start of the labels read last.
    limit: usize,
    /// Where the name ends in place, once its root or first pointer is read.
    end: Option<usize>,
    length: usize,
    jumps: usize,
}

impl Name {
    fn new(at: usize) -> Name {
        Name {
            at,
            limit: at,
            end: None,
            length: 0,
            jumps: 0,
        }
    }

    /// The next label, or None at the root.
    fn label<'a>(&mut self, message: &'a [u8]) -> Result<Option<&'a [u8]>, Error> {
        for _ in 0..=JUMPS_MAX {
            let size = *message.get(self.at).ok_or(Error::Format)?;
            match size >> 6 {
                // self.at was read from the message, so it and what is
                // added below stay far from usize::MAX, and length is
                // under NAME_MAX before a label adds at most 64.
                0 => {
                    let start = self.at.wrapping_add(1);
                    let end = start.wrapping_add(usize::from(size));
                    self.length = self.length.wrapping_add(1 + usize::from(size));
                    if self.length > NAME_MAX {
                        return Err(Error::Format);
                    }
                    if size == 0 {
                        if self.end.is_none() {
                            self.end = Some(start);
                        }
                        return Ok(None);
                    }
                    self.at = end;
                    return message.get(start..end).ok_or(Error::Format).map(Some);
                }
                3 => {
                    let target = usize::from(word(message, self.at)? & 0x3fff);
                    if target >= self.limit || target < HEADER_BYTES || self.jumps == JUMPS_MAX {
                        return Err(Error::Format);
                    }
                    if self.end.is_none() {
                        self.end = Some(self.at.wrapping_add(2));
                    }
                    self.jumps = self.jumps.wrapping_add(1);
                    self.limit = target;
                    self.at = target;
                }
                // 01 and 10 are label types RFC 6891 retired.
                1 | 2 => return Err(Error::Format),
                // rr: escape(panic): a byte shifted right by 6 is under 4.
                _ => unreachable!(),
            }
        }
        Err(Error::Format)
    }
}

/// A message read from TCP, where each is preceded by its length. It is
/// kept whole before it is read, since compression pointers may lead
/// anywhere in it.
pub struct Tcp {
    /// The length and the message; feed takes no more than the length
    /// announces.
    buffer: Vec<u8>,
}

impl Tcp {
    pub fn new() -> Tcp {
        Tcp { buffer: Vec::new() }
    }

    /// Takes the start of input, up to the message's end; how many bytes.
    /// Bytes past it belong to the next message: clear, then feed them.
    pub fn feed(&mut self, input: &[u8]) -> Result<usize, Error> {
        let mut taken = 0;
        // One allocation for the message, once its length is known, and
        // none for the next one of no greater size.
        if self.buffer.is_empty()
            && let Some(&[high, low]) = input.get(..2)
        {
            self.buffer
                .reserve(2 + usize::from(u16::from_be_bytes([high, low])));
        }
        if self.buffer.len() < 2 {
            taken = input.len().min(2 - self.buffer.len());
            self.buffer
                .extend_from_slice(input.get(..taken).unwrap_or_default());
            if self.buffer.len() < 2 {
                return Ok(taken);
            }
        }
        let size = usize::from(word(&self.buffer, 0)?);
        if size < HEADER_BYTES {
            return Err(Error::Format);
        }
        let rest = input.get(taken..).unwrap_or_default();
        let wanted = (2 + size).saturating_sub(self.buffer.len()).min(rest.len());
        // TCP brings the message in pieces, and it is read only once
        // whole.
        self.buffer
            .extend_from_slice(rest.get(..wanted).unwrap_or_default());
        Ok(taken + wanted)
    }

    /// The message, once all of it has come.
    pub fn message(&self) -> Option<&[u8]> {
        let size = usize::from(word(&self.buffer, 0).ok()?);
        self.buffer.get(2..).filter(|message| message.len() == size)
    }

    /// Readies it for the next message, keeping the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Any bytes as a reply to a query for a.b, whole and through TCP in
/// pieces: it reads the same, and never more addresses than out holds.
#[cfg(fuzzing)]
pub fn fuzz_reply(input: &[u8]) {
    let id = word(input, 0).unwrap_or(0);
    let mut out = [Record::EMPTY; 4];
    assert_eq!(header(input).is_ok(), input.len() >= HEADER_BYTES);
    for kind in [Kind::A, Kind::Aaaa] {
        let query = Query {
            id,
            name: b"a.b",
            kind,
            edns: true,
            ad: false,
        };
        let udp = reply(input, &query, Transport::Udp, &mut out);
        if let Ok(answer) = &udp {
            assert!(answer.count <= out.len() && answer.count <= answer.answers_of_type);
            assert!(answer.answers_of_type <= usize::from(answer.header.answers));
            assert!(!answer.header.truncated() && answer.header.rcode == 0);
        }
        // Over TCP the same, but a cut reply is read as it is.
        let tcp = reply(input, &query, Transport::Tcp, &mut out);
        match udp {
            Err(Error::Truncated) => assert!(header(input).is_ok_and(|head| head.truncated())),
            Err(Error::Unreadable) => {
                assert_eq!(tcp.map(|answer| answer.count), Err(Error::Unreadable));
            }
            other => assert_eq!(
                other.map(|answer| answer.count),
                tcp.map(|answer| answer.count)
            ),
        }
    }
    let Ok(size) = u16::try_from(input.len()) else {
        return;
    };
    let mut framed = Vec::new();
    framed.extend_from_slice(&size.to_be_bytes());
    framed.extend_from_slice(input);
    let mut tcp = Tcp::new();
    let piece = usize::from(input.first().copied().unwrap_or(0) % 7) + 1;
    let mut result = Ok(());
    for read in framed.chunks(piece) {
        match tcp.feed(read) {
            Ok(taken) => assert_eq!(taken, read.len()),
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }
    match result {
        Ok(()) => assert_eq!(tcp.message(), Some(input)),
        Err(error) => {
            assert_eq!(error, Error::Format);
            assert!(input.len() < HEADER_BYTES);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Answer, Error, Kind, Query, Record, Tcp, Transport, header, query, reply, tcp_query,
    };
    use alloc::vec::Vec;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use test::Bencher;

    fn unhex(text: &str) -> Vec<u8> {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte - b'a' + 10,
        };
        let mut bytes = Vec::new();
        for pair in text.as_bytes().chunks(2) {
            bytes.push((digit(pair[0]) << 4) | digit(pair[1]));
        }
        bytes
    }

    fn ask(id: u16, name: &str, kind: Kind, edns: bool) -> Query<'_> {
        Query {
            id,
            name: name.as_bytes(),
            kind,
            edns,
            ad: false,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, ttl: u32) -> Record {
        Record {
            address: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            ttl,
        }
    }

    fn read(message: &[u8], query: &Query<'_>) -> Result<Vec<Record>, Error> {
        let mut out = [Record::EMPTY; 8];
        let answer = reply(message, query, Transport::Udp, &mut out)?;
        // rr: escape(copy): the tests compare what was read as a list.
        Ok(out.into_iter().take(answer.count).collect())
    }

    /// The answer's header and counts, with no room for addresses.
    fn answer(message: &[u8], query: &Query<'_>, transport: Transport) -> Result<Answer, Error> {
        reply(message, query, transport, &mut [])
    }

    // Replies captured from 1.1.1.1 on 2026-11-04.
    const EXAMPLE_A: &str = "123481800001000200000001076578616d706c6503636f6d0000010001c00c000100010000008f00046814179ac00c000100010000008f0004ac4293f300002904d0000000000000";
    const GITHUB_A: &str = "beef81800001000200000001037777770667697468756203636f6d0000010001c00c0005000100000de90002c010c010000100010000001500048c52710400002904d0000000000000";
    const MICROSOFT_AAAA: &str = "01028180000100060000000103777777096d6963726f736f667403636f6d00001c0001c00c0005000100000df9002303777777096d6963726f736f667407636f6d2d632d3307656467656b6579036e657400c02f000500010000036d00190665313336373804647363620a616b616d616965646765c04dc05e001c00010000001100102a0226f034000184000000000000356ec05e001c00010000001100102a0226f03400019d000000000000356ec05e001c00010000001100102a0226f03400018d000000000000356ec05e001c00010000001100102a0226f03400019a000000000000356e00002904d0000000000000";
    const NODATA_A: &str = "7777818000010000000100010b6e6f6e6578697374656e74076578616d706c6503636f6d0000010001c0180006000100000708003207656c6c696f7474026e730a636c6f7564666c617265c02003646e73c040901fd090000027100000096000093a800000070800002904d0000000000000";
    const NXDOMAIN_A: &str = "5151818300010000000100010a6e782d72722d7465737406676f6f676c6503636f6d0000010001c017000600010000003c0026036e7331c01709646e732d61646d696ec0173c6bfdb70000038400000384000007080000003c00002904d0000000000000";
    const NXDOMAIN_AAAA: &str = "6161818300010000000100000a6e782d72722d7465737407696e76616c696400001c0001000006000100015180004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d0078c3fdc2000007080000038400093a8000015180";
    const EXAMPLE_AAAA: &str = "424281800001000200000000076578616d706c6503636f6d00001c0001c00c001c00010000004e00102606470000100000000000006814179ac00c001c00010000004e0010260647000010000000000000ac4293f3";

    /// The queries dig and Python's resolvers send, byte for byte.
    #[test]
    fn writes_queries() {
        let mut out = Vec::new();
        query(&mut out, &ask(0x1234, "example.com", Kind::A, true)).unwrap();
        assert_eq!(
            out,
            unhex(
                "123401000001000000000001076578616d706c6503636f6d000001000100002904d0000000000000"
            )
        );
        out.clear();
        query(&mut out, &ask(0x4242, "example.com.", Kind::Aaaa, false)).unwrap();
        assert_eq!(
            out,
            unhex("424201000001000000000000076578616d706c6503636f6d00001c0001")
        );
        let mut framed = Vec::new();
        tcp_query(&mut framed, &ask(0x4242, "example.com", Kind::Aaaa, false)).unwrap();
        assert_eq!(framed[..2], [0, 29]);
        assert_eq!(framed[2..], out[..]);
    }

    /// framed_query writes in place what tcp_query appends, and the
    /// longest name with EDNS0 fills QUERY_MAX.
    #[test]
    fn writes_in_place() {
        let mut framed = [0; super::QUERY_MAX];
        let query = ask(0x4242, "example.com", Kind::Aaaa, true);
        let end = super::framed_query(&mut framed, &query).unwrap();
        let mut appended = Vec::new();
        tcp_query(&mut appended, &query).unwrap();
        assert_eq!(framed[..end], appended[..]);
        let mut name = Vec::new();
        for _ in 0..3 {
            name.extend_from_slice(&[b'a'; 63]);
            name.push(b'.');
        }
        name.extend_from_slice(&[b'b'; 61]);
        let longest = core::str::from_utf8(&name).unwrap();
        let full = super::framed_query(&mut framed, &ask(1, longest, Kind::A, true)).unwrap();
        assert_eq!(full, super::QUERY_MAX);
    }

    #[test]
    fn refuses_bad_names() {
        let long = [b'a'; 64];
        let label = core::str::from_utf8(&long).unwrap();
        let mut name = Vec::new();
        for _ in 0..4 {
            name.extend_from_slice(&long[..63]);
            name.push(b'.');
        }
        let total = core::str::from_utf8(&name[..254]).unwrap();
        let mut out = b"kept".to_vec();
        for bad in ["", ".", "a..b", ".a", "a b", "a\0b", "a\rb", label, total] {
            let result = query(&mut out, &ask(1, bad, Kind::A, true));
            assert_eq!(result, Err(Error::Name), "{bad:?}");
            assert_eq!(
                tcp_query(&mut out, &ask(1, bad, Kind::A, true)),
                Err(Error::Name)
            );
            assert_eq!(out, b"kept");
        }
        // 253 bytes of text, 255 in wire form, is the longest name.
        query(
            &mut out,
            &ask(
                1,
                core::str::from_utf8(&name[..253]).unwrap(),
                Kind::A,
                true,
            ),
        )
        .unwrap();
        query(
            &mut out,
            &ask(1, core::str::from_utf8(&long[..63]).unwrap(), Kind::A, true),
        )
        .unwrap();
    }

    #[test]
    fn reads_captured_replies() {
        let example = [v4(104, 20, 23, 154, 143), v4(172, 66, 147, 243, 143)];
        assert_eq!(
            read(
                &unhex(EXAMPLE_A),
                &ask(0x1234, "example.com", Kind::A, true)
            )
            .unwrap(),
            example
        );
        // Names compare in any case, as servers echo them.
        assert_eq!(
            read(
                &unhex(EXAMPLE_A),
                &ask(0x1234, "ExAmple.COM.", Kind::A, true)
            )
            .unwrap(),
            example
        );
        // One CNAME, whose TTL is longer than the address's.
        assert_eq!(
            read(
                &unhex(GITHUB_A),
                &ask(0xbeef, "www.github.com", Kind::A, true)
            )
            .unwrap(),
            [v4(140, 82, 113, 4, 21)]
        );
        // Two CNAMEs, their targets compressed against each other.
        let microsoft = read(
            &unhex(MICROSOFT_AAAA),
            &ask(0x0102, "www.microsoft.com", Kind::Aaaa, true),
        )
        .unwrap();
        assert_eq!(microsoft.len(), 4);
        assert_eq!(
            microsoft[0],
            Record {
                address: IpAddr::V6(Ipv6Addr::new(
                    0x2a02, 0x26f0, 0x3400, 0x0184, 0, 0, 0, 0x356e
                )),
                ttl: 17,
            }
        );
        let aaaa = read(
            &unhex(EXAMPLE_AAAA),
            &ask(0x4242, "example.com", Kind::Aaaa, false),
        );
        assert_eq!(aaaa.unwrap().len(), 2);
        // The name exists without an address: no records, no error.
        let nodata = ask(0x7777, "nonexistent.example.com", Kind::A, true);
        assert_eq!(read(&unhex(NODATA_A), &nodata).unwrap(), []);
        let nx = ask(0x5151, "nx-rr-test.google.com", Kind::A, true);
        assert_eq!(read(&unhex(NXDOMAIN_A), &nx), Err(Error::NoName));
        let invalid = ask(0x6161, "nx-rr-test.invalid", Kind::Aaaa, false);
        assert_eq!(read(&unhex(NXDOMAIN_AAAA), &invalid), Err(Error::NoName));
        // Fewer slots than addresses: the first ones.
        let mut one = [Record::EMPTY; 1];
        let query = ask(0x1234, "example.com", Kind::A, true);
        let first = reply(&unhex(EXAMPLE_A), &query, Transport::Udp, &mut one);
        assert_eq!(
            first.map(|found| (found.count, found.answers_of_type)),
            Ok((1, 2))
        );
        assert_eq!(one[0], example[0]);
    }

    /// Another id, question, kind, or a message that is not a response,
    /// is not the reply.
    #[test]
    fn mismatches() {
        let message = unhex(EXAMPLE_A);
        for query in [
            ask(0x1235, "example.com", Kind::A, true),
            ask(0x1234, "example.org", Kind::A, true),
            ask(0x1234, "www.example.com", Kind::A, true),
            ask(0x1234, "com", Kind::A, true),
            ask(0x1234, "example.com", Kind::Aaaa, true),
        ] {
            assert_eq!(read(&message, &query), Err(Error::Mismatch));
        }
        let mut sent = Vec::new();
        let query = ask(0x1234, "example.com", Kind::A, true);
        super::query(&mut sent, &query).unwrap();
        // Over TCP a mismatch is a mismatch too.
        assert_eq!(
            answer(
                &message,
                &ask(1, "example.com", Kind::A, true),
                Transport::Tcp
            ),
            Err(Error::Mismatch)
        );
        assert_eq!(read(&sent, &query), Err(Error::Mismatch));
        let mut notify = message;
        notify[2] |= 4 << 3;
        assert_eq!(read(&notify, &query), Err(Error::Mismatch));
    }

    #[test]
    fn flags_and_codes() {
        let query = ask(0x1234, "example.com", Kind::A, true);
        let mut message = unhex(EXAMPLE_A);
        message[2] |= 0x02;
        assert_eq!(read(&message, &query), Err(Error::Truncated));
        // A truncated reply may end inside a record.
        assert_eq!(read(&message[..40], &query), Err(Error::Truncated));
        let mut failed = unhex(EXAMPLE_A);
        failed[3] = 0x82;
        assert_eq!(read(&failed, &query), Err(Error::Server(2)));
        // BADVERS: 1 in the OPT's extended RCODE, 0 in the header.
        let len = failed.len();
        failed[3] = 0x80;
        failed[len - 6] = 1;
        assert_eq!(read(&failed, &query), Err(Error::Server(16)));
        // A TTL with its top bit set is 0.
        let mut ttl = unhex(EXAMPLE_A);
        ttl[35] = 0x80;
        assert_eq!(read(&ttl, &query).unwrap()[0].ttl, 0);
    }

    /// Every prefix of a reply, and a byte past it, fail without a panic.
    #[test]
    fn cut_and_padded() {
        for (text, query) in [
            (EXAMPLE_A, ask(0x1234, "example.com", Kind::A, true)),
            (
                MICROSOFT_AAAA,
                ask(0x0102, "www.microsoft.com", Kind::Aaaa, true),
            ),
            (
                NXDOMAIN_A,
                ask(0x5151, "nx-rr-test.google.com", Kind::A, true),
            ),
        ] {
            let mut message = unhex(text);
            // The header, the name with its root, the type and class.
            let question = 12 + query.name.len() + 2 + 4;
            for cut in 0..message.len() {
                let result = read(&message[..cut], &query);
                let want = if cut < question {
                    Error::Unreadable
                } else {
                    Error::Format
                };
                assert_eq!(result, Err(want), "{cut}");
            }
            message.push(0);
            assert_eq!(read(&message, &query), Err(Error::Format));
        }
    }

    /// A header for id 7 with one question for a.b and the counts given.
    fn head(answers: u8, extra: u8) -> Vec<u8> {
        let mut message = unhex("000781800001");
        message.extend_from_slice(&[0, answers, 0, 0, 0, extra]);
        message.extend_from_slice(&unhex("016101620000010001"));
        message
    }

    fn ab() -> Query<'static> {
        ask(7, "a.b", Kind::A, true)
    }

    /// Pointers that lead forward, to themselves, into the header, or
    /// round a loop are refused, as is a name past 255 bytes.
    #[test]
    fn bad_pointers() {
        // Answer owner at 21: a pointer to itself, forward, to the header,
        // to a pointer that leads back to the first.
        for owner in ["c015", "c017", "c002", "0178c015"] {
            let mut message = head(1, 0);
            message.extend_from_slice(&unhex(owner));
            message.extend_from_slice(&unhex("00010001000000010004"));
            message.extend_from_slice(&[1, 2, 3, 4]);
            assert_eq!(read(&message, &ab()), Err(Error::Format), "{owner}");
        }
        // A pointer back to the question is the usual compression.
        let mut message = head(1, 0);
        message.extend_from_slice(&unhex("c00c00010001000000010004"));
        message.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(read(&message, &ab()).unwrap(), [v4(1, 2, 3, 4, 1)]);
        // Labels 0x40 and 0x80 are retired.
        message[21] = 0x40;
        assert_eq!(read(&message, &ab()), Err(Error::Format));
        // Three 63-byte labels before a.b make a name of 197 bytes; one
        // more before that, through a pointer, makes 261.
        let mut long = head(2, 0);
        for _ in 0..3 {
            long.push(63);
            long.extend_from_slice(&[b'x'; 63]);
        }
        long.extend_from_slice(&unhex("c00c00010001000000010004"));
        long.extend_from_slice(&[1, 2, 3, 4]);
        long[7] = 1;
        assert_eq!(read(&long, &ab()).unwrap(), []);
        long[7] = 2;
        long.push(63);
        long.extend_from_slice(&[b'y'; 63]);
        long.extend_from_slice(&unhex("c01500010001000000010004"));
        long.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(read(&long, &ab()), Err(Error::Format));
        // Four labels written out are 257 bytes.
        let mut written = head(1, 0);
        for _ in 0..4 {
            written.push(63);
            written.extend_from_slice(&[b'x'; 63]);
        }
        written.extend_from_slice(&unhex("0000010001000000010004"));
        written.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(read(&written, &ab()), Err(Error::Format));
    }

    /// CNAMEs are followed up to CHAIN_MAX, in any order; a loop fails.
    #[test]
    fn chains() {
        // The address of cN.b first, then a.b -> c1.b -> ... -> cN.b,
        // each CNAME owned by the target before it.
        for (links, expected) in [(1, Ok(1)), (8, Ok(1)), (9, Err(Error::Chain))] {
            let mut message = head(links + 1, 0);
            message.extend_from_slice(&[2, b'c', b'0' + links, 0xc0, 14]);
            message.extend_from_slice(&unhex("0001000100000e100004"));
            message.extend_from_slice(&[9, 9, 9, 9]);
            let mut owner = 12;
            for link in 1..=links {
                message.extend_from_slice(&[0xc0, owner]);
                message.extend_from_slice(&unhex("0005000100000e100005"));
                owner = u8::try_from(message.len()).unwrap();
                message.extend_from_slice(&[2, b'c', b'0' + link, 0xc0, 14]);
            }
            let count = read(&message, &ab()).map(|records| records.len());
            assert_eq!(count, expected, "{links}");
        }
        // a.b -> a.b.
        let mut message = head(1, 0);
        message.extend_from_slice(&unhex("c00c0005000100000e100002c00c"));
        assert_eq!(read(&message, &ab()), Err(Error::Chain));
        // The address under the CNAME's own name is not the answer.
        let mut aliased = head(2, 0);
        aliased.extend_from_slice(&unhex("c00c0005000100000e1000040178c00e"));
        aliased.extend_from_slice(&unhex("c00c000100010000000100040a000001"));
        assert_eq!(read(&aliased, &ab()).unwrap(), []);
        // A wrong-sized address, and a CNAME whose name runs past its data.
        let mut short = head(1, 0);
        short.extend_from_slice(&unhex("c00c00010001000000010003010203"));
        assert_eq!(read(&short, &ab()), Err(Error::Format));
        let mut over = head(1, 0);
        over.extend_from_slice(&unhex("c00c0005000100000001000201780000"));
        assert_eq!(read(&over, &ab()), Err(Error::Format));
    }

    /// AD asked for in the query, and the header's flags and counts read
    /// from replies.
    #[test]
    fn headers() {
        let mut out = Vec::new();
        let mut trusting = ask(0x1234, "example.com", Kind::A, true);
        trusting.ad = true;
        query(&mut out, &trusting).unwrap();
        assert_eq!(out[2..4], [0x01, 0x20]);
        let example = answer(
            &unhex(EXAMPLE_A),
            &ask(0x1234, "example.com", Kind::A, true),
            Transport::Udp,
        )
        .unwrap();
        let head = example.header;
        assert_eq!(
            (
                head.id,
                head.rcode,
                head.questions,
                head.answers,
                head.authorities,
                head.additionals
            ),
            (0x1234, 0, 1, 2, 0, 1)
        );
        assert!(
            head.recursion_available()
                && !head.authoritative()
                && !head.authentic()
                && !head.truncated()
        );
        let nx = header(&unhex(NXDOMAIN_A)).unwrap();
        assert_eq!((nx.rcode, nx.answers, nx.authorities), (3, 0, 1));
        let mut flagged = unhex(EXAMPLE_A);
        flagged[2] |= 0x04;
        flagged[3] |= 0x20;
        let both = header(&flagged).unwrap();
        assert!(both.authoritative() && both.authentic());
        assert_eq!(header(&flagged[..11]), Err(Error::Unreadable));
    }

    /// A reply with TC is asked again over TCP when it came over UDP,
    /// and read as it is when it came over TCP.
    #[test]
    fn truncated_by_transport() {
        let query = ask(0x1234, "example.com", Kind::A, true);
        let mut message = unhex(EXAMPLE_A);
        message[2] |= 0x02;
        assert_eq!(
            answer(&message, &query, Transport::Udp),
            Err(Error::Truncated)
        );
        let mut out = [Record::EMPTY; 4];
        let tcp = reply(&message, &query, Transport::Tcp, &mut out).unwrap();
        assert!(tcp.header.truncated());
        assert_eq!(tcp.count, 2);
        // Cut inside a record, it is malformed over TCP.
        assert_eq!(
            answer(&message[..40], &query, Transport::Tcp),
            Err(Error::Format)
        );
    }

    /// The answers of the kind asked, whoever owns them: none for a name
    /// without that kind, some where only another name has them.
    #[test]
    fn answers_of_type() {
        let nodata = ask(0x7777, "nonexistent.example.com", Kind::A, true);
        assert_eq!(
            answer(&unhex(NODATA_A), &nodata, Transport::Udp)
                .unwrap()
                .answers_of_type,
            0
        );
        let github = ask(0xbeef, "www.github.com", Kind::A, true);
        let found = answer(&unhex(GITHUB_A), &github, Transport::Udp).unwrap();
        assert_eq!((found.count, found.answers_of_type), (0, 1));
        // An A under another owner than the chain: not an address of the
        // name, but an answer of the type.
        let mut aliased = head(2, 0);
        aliased.extend_from_slice(&unhex("c00c0005000100000e1000040178c00e"));
        aliased.extend_from_slice(&unhex("c00c000100010000000100040a000001"));
        let other = answer(&aliased, &ab(), Transport::Udp).unwrap();
        assert_eq!((other.count, other.answers_of_type), (0, 1));
        // A question that does not parse is unreadable, not malformed.
        let mut bad = head(0, 0);
        bad[12] = 0x40;
        assert_eq!(answer(&bad, &ab(), Transport::Udp), Err(Error::Unreadable));
    }

    #[test]
    fn tcp_frames() {
        let first = unhex(EXAMPLE_A);
        let second = unhex(GITHUB_A);
        let mut stream = Vec::new();
        for message in [&first, &second] {
            stream.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
            stream.extend_from_slice(message);
        }
        for piece in [1, 2, 3, 64, stream.len()] {
            let mut tcp = Tcp::new();
            let mut got = 0;
            for read in stream.chunks(piece) {
                let mut at = 0;
                while at < read.len() {
                    at += tcp.feed(&read[at..]).unwrap();
                    if let Some(message) = tcp.message() {
                        assert_eq!(message, [&first, &second][got]);
                        got += 1;
                        tcp.clear();
                    }
                }
            }
            assert_eq!(got, 2);
        }
        let mut tcp = Tcp::new();
        assert_eq!(tcp.feed(&[0]), Ok(1));
        assert_eq!(tcp.message(), None);
        assert_eq!(tcp.feed(&[11, 0]), Err(Error::Format));
    }

    /// The reply with two CNAMEs and four AAAA records.
    #[bench]
    fn reply_cname_aaaa(b: &mut Bencher) {
        let message = unhex(MICROSOFT_AAAA);
        let query = ask(0x0102, "www.microsoft.com", Kind::Aaaa, true);
        let mut out = [Record::EMPTY; 8];
        b.iter(|| {
            let found = reply(&message, &query, Transport::Udp, &mut out);
            assert_eq!(found.map(|answer| answer.count), Ok(4));
        });
    }
}
