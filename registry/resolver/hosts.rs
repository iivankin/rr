//! /etc/hosts, read as Go reads it: an address and its names on each
//! line, a `#` to the line's end a comment, names in any case, and a
//! name with a dot the same with or without its final one. The text is
//! searched for one name and nothing is kept, so a long file costs one
//! pass and no memory.

#[cfg(fuzzing)]
use super::ADDRESSES_MAX;
use super::{Address, Fields, address};
#[cfg(fuzzing)]
use alloc::vec::Vec;

/// Writes into out the addresses text gives name, in the file's order,
/// as many as out holds; how many.
pub fn hosts(text: &[u8], name: &[u8], out: &mut [Address]) -> usize {
    let mut count = 0;
    for line in text.split(|byte| *byte == b'\n') {
        let line = match line.iter().position(|byte| *byte == b'#') {
            Some(at) => line.get(..at).unwrap_or_default(),
            None => line,
        };
        let mut fields = Fields::new(line);
        let Some(first) = fields.field() else {
            continue;
        };
        let Some(found) = address(first) else {
            continue;
        };
        while let Some(alias) = fields.field() {
            if !same(alias, name) {
                continue;
            }
            let Some(slot) = out.get_mut(count) else {
                return count;
            };
            *slot = found;
            count += 1;
        }
    }
    count
}

/// Whether two names are the same as Go's absDomainName makes them: in
/// any case, and a name with a dot has its final one.
fn same(a: &[u8], b: &[u8]) -> bool {
    let (a_dotted, b_dotted) = (a.contains(&b'.'), b.contains(&b'.'));
    let a = if a_dotted {
        a.strip_suffix(b".").unwrap_or(a)
    } else {
        a
    };
    let b = if b_dotted {
        b.strip_suffix(b".").unwrap_or(b)
    } else {
        b
    };
    a_dotted == b_dotted && a.eq_ignore_ascii_case(b)
}

/// Any bytes as /etc/hosts: what is found for a name is found again for
/// it in another case, and never past the limit.
#[cfg(fuzzing)]
pub fn fuzz_hosts(input: &[u8]) {
    let (name, text) =
        input.split_at(usize::from(input.first().copied().unwrap_or(0) % 16).min(input.len()));
    let none = Address::new(core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED));
    let mut found = [none; ADDRESSES_MAX];
    let count = hosts(text, name, &mut found);
    assert!(count <= ADDRESSES_MAX);
    let mut upper = Vec::new();
    upper.extend_from_slice(name);
    upper.make_ascii_uppercase();
    let mut again = [none; ADDRESSES_MAX];
    assert_eq!(hosts(text, &upper, &mut again), count);
    let same_address =
        |(a, b): (&Address, &Address)| a.ip == b.ip && a.zone.as_bytes() == b.zone.as_bytes();
    assert!(found.iter().zip(&again).take(count).all(same_address));
}

#[cfg(test)]
mod tests {
    use super::super::fake::ip;
    use super::super::{ADDRESSES_MAX, Address};
    use super::hosts;
    use alloc::vec::Vec;

    /// Go's testdata/hosts.
    const HOSTS: &[u8] = b"255.255.255.255\tbroadcasthost\n127.0.0.2\todin\n127.0.0.3\todin  # inline comment \n::2             odin\n127.1.1.1\tthor\n# aliases\n127.1.1.2\tullr ullrhost\nfe80::1%lo0\tlocalhost\n# Bogus entries that must be ignored.\n123.123.123\tloki\n321.321.321.321\n";

    fn find(text: &[u8], name: &str) -> Vec<Address> {
        let mut out = [ip("0.0.0.0"); ADDRESSES_MAX];
        let count = hosts(text, name.as_bytes(), &mut out);
        // rr: escape(copy): the test compares what was found as a list.
        out.get(..count).unwrap().to_vec()
    }

    /// The cases of Go's TestLookupStaticHost.
    #[test]
    fn reads_go_testdata() {
        assert_eq!(
            find(HOSTS, "odin"),
            [ip("127.0.0.2"), ip("127.0.0.3"), ip("::2")]
        );
        assert_eq!(find(HOSTS, "thor"), [ip("127.1.1.1")]);
        assert_eq!(find(HOSTS, "ullrhost"), [ip("127.1.1.2")]);
        assert_eq!(find(HOSTS, "localhost"), [ip("fe80::1%lo0")]);
        assert_eq!(find(HOSTS, "loki"), []);
        assert_eq!(find(HOSTS, "broadcasthost"), [ip("255.255.255.255")]);
        let ipv6 = b"::1\t\t\t\t\t\tlocalhost\t# inline comment separated by tab\nfe80:0000:0000:0000:0000:0000:0000:0001\t\tlocalhost       # inline comment separated by space\n\nfe80:0000:0000:0000:0000:0000:0000:0002%lo0\tlocalhost\n\nfe80::3%lo0\t\t\t\t\tlocalhost\tlocalhost.localdomain\n";
        assert_eq!(
            find(ipv6, "localhost"),
            [
                ip("::1"),
                ip("fe80::1"),
                ip("fe80::2%lo0"),
                ip("fe80::3%lo0")
            ]
        );
        assert_eq!(find(ipv6, "localhost.localdomain"), [ip("fe80::3%lo0")]);
        // A file of one line without its newline.
        assert_eq!(find(b"127.0.0.2\todin", "odin"), [ip("127.0.0.2")]);
    }

    /// Names in any case, and the final dot of a name with a dot.
    #[test]
    fn cases_and_dots() {
        let text =
            b"127.0.0.1\tPreserveMe\tPreserveMe.local\n::1\t\tPreserveMe\tPreserveMe.local\n";
        for name in [
            "preserveme",
            "PRESERVEME",
            "preserveme.local",
            "PreserveMe.Local.",
        ] {
            assert_eq!(find(text, name), [ip("127.0.0.1"), ip("::1")], "{name}");
        }
        // Without a dot, the final one makes another name.
        assert_eq!(find(text, "preserveme."), []);
        assert_eq!(find(b"1.2.3.4 a.b.\n", "a.b"), [ip("1.2.3.4")]);
        assert_eq!(find(b"1.2.3.4 a.b\n", "a.b."), [ip("1.2.3.4")]);
        assert_eq!(find(b"1.2.3.4 ab\n", "a"), []);
    }

    /// Lines Go passes over, and the limit on what is found.
    #[test]
    fn bad_lines_and_limit() {
        for line in [
            &b"1.2.3.4\n"[..],
            b"#1.2.3.4 x\n",
            b"1.2.3.4#x\n",
            b"1.2.3.4% x\n",
            b"1.2.3.4%eth0 x\n",
            b"fe80::1%abcdefghijklmnopq x\n",
            b"x 1.2.3.4\n",
        ] {
            assert_eq!(find(line, "x"), [], "{line:?}");
        }
        let mut many = Vec::new();
        for _ in 0..ADDRESSES_MAX + 3 {
            many.extend_from_slice(b"10.0.0.1 x x\n");
        }
        assert_eq!(find(&many, "x").len(), ADDRESSES_MAX);
    }
}
