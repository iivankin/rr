//! One record of the log: a header, then the key, then the value. The
//! header holds, little-endian, the CRC-32 of all that follows it, the
//! key's length (u16), the kind (u8), a zero byte, and the value's
//! length (u32). A delete has no value.

/// The header's length.
pub const HEADER: usize = 12;
/// The longest key.
pub const KEY_MAX: usize = 255;
/// The longest value.
pub const VALUE_MAX: usize = 65536;
/// The longest record.
pub const RECORD_MAX: usize = HEADER + KEY_MAX + VALUE_MAX;

const _: () = assert!(KEY_MAX <= u16::MAX as usize);
const _: () = assert!(VALUE_MAX <= u32::MAX as usize);

/// What a record does to its key.
pub enum Kind {
    Put,
    Delete,
}

impl Kind {
    fn code(&self) -> u8 {
        match self {
            Kind::Put => 1,
            Kind::Delete => 2,
        }
    }
}

/// A record read from the log, lent from the bytes it was read in.
pub struct Record<'a> {
    pub kind: Kind,
    pub key: &'a [u8],
    pub value: &'a [u8],
}

/// What reading a record at the start of some bytes found.
pub enum Read<'a> {
    /// A whole record, and the bytes it used.
    Whole(Record<'a>, usize),
    /// The start of one: more bytes are needed.
    Short,
    /// Not a record: a bad header or checksum. The log ends here.
    Bad,
}

/// The CRC-32 (IEEE) table, made when the program compiles.
const TABLE: [u32; 256] = table();

const fn table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
}

/// The CRC-32 of the pieces of p in turn.
pub fn crc32(p: &[&[u8]]) -> u32 {
    let mut c = !0u32;
    for piece in p {
        for b in *piece {
            c = TABLE[usize::from(c.to_le_bytes()[0] ^ b)] ^ (c >> 8);
        }
    }
    !c
}

/// The header of a record of kind for key and value, which must be
/// within their limits.
pub fn header(kind: &Kind, key: &[u8], value: &[u8]) -> [u8; HEADER] {
    assert!(key.len() <= KEY_MAX);
    assert!(value.len() <= VALUE_MAX);
    let mut h = [0u8; HEADER];
    let key_len = u16::try_from(key.len()).unwrap_or(u16::MAX);
    let value_len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    h[4..6].copy_from_slice(&key_len.to_le_bytes());
    h[6] = kind.code();
    h[8..12].copy_from_slice(&value_len.to_le_bytes());
    let crc = crc32(&[&h[4..], key, value]);
    h[..4].copy_from_slice(&crc.to_le_bytes());
    h
}

/// The record at the start of p.
pub fn read(p: &[u8]) -> Read<'_> {
    let Some(h) = p.first_chunk::<HEADER>() else {
        return Read::Short;
    };
    let crc = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    let key_len = usize::from(u16::from_le_bytes([h[4], h[5]]));
    let kind = match h[6] {
        1 => Kind::Put,
        2 => Kind::Delete,
        _ => return Read::Bad,
    };
    let Ok(value_len) = usize::try_from(u32::from_le_bytes([h[8], h[9], h[10], h[11]])) else {
        return Read::Bad;
    };
    if h[7] != 0 || key_len > KEY_MAX || value_len > VALUE_MAX {
        return Read::Bad;
    }
    if let Kind::Delete = kind {
        if value_len != 0 {
            return Read::Bad;
        }
    }
    let end = HEADER + key_len + value_len;
    if p.len() < end {
        return Read::Short;
    }
    let key = &p[HEADER..HEADER + key_len];
    let value = &p[HEADER + key_len..end];
    if crc32(&[&h[4..], key, value]) != crc {
        return Read::Bad;
    }
    Read::Whole(Record { kind, key, value }, end)
}

/// Any bytes as a record: one read lies within them, and its header is
/// the one written for what it holds.
#[cfg(fuzzing)]
pub fn fuzz_record(input: &[u8]) {
    if let Read::Whole(r, n) = read(input) {
        assert!(n <= input.len());
        assert!(input[..HEADER] == header(&r.kind, r.key, r.value));
    }
}

#[cfg(test)]
mod tests {
    use super::{HEADER, Kind, Read, crc32, header, read};
    use alloc::vec::Vec;
    use test::Bencher;

    fn record(kind: &Kind, key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&header(kind, key, value));
        p.extend_from_slice(key);
        p.extend_from_slice(value);
        p
    }

    #[test]
    fn crc32_of_check_string() {
        assert_eq!(crc32(&[b"1234", b"56789"]), 0xcbf4_3926);
    }

    #[test]
    fn reads_what_was_written() {
        let p = record(&Kind::Put, b"key", b"value");
        let Read::Whole(r, n) = read(&p) else {
            panic!("not whole");
        };
        let Kind::Put = r.kind else {
            panic!("not a put");
        };
        assert_eq!((r.key, r.value, n), (&b"key"[..], &b"value"[..], p.len()));
    }

    #[test]
    fn short_and_bad() {
        let mut p = record(&Kind::Put, b"key", b"value");
        let Read::Short = read(&p[..HEADER - 1]) else {
            panic!("a header cut short");
        };
        let Read::Short = read(&p[..p.len() - 1]) else {
            panic!("a value cut short");
        };
        p[HEADER] ^= 1;
        let Read::Bad = read(&p) else {
            panic!("a damaged key");
        };
        let mut d = record(&Kind::Delete, b"key", b"");
        d[6] = 3;
        let Read::Bad = read(&d) else {
            panic!("an unknown kind");
        };
    }

    /// One record of a hundred-byte value, checked as the log is read.
    #[bench]
    fn read_one(b: &mut Bencher) {
        let p = record(&Kind::Put, b"key", &[7; 100]);
        b.iter(|| read(&p));
    }
}
