//! resolv.conf, read as Go's dnsReadConfig reads it: up to three
//! nameservers (127.0.0.1 and ::1 when it names none), the search list
//! from search or domain (else the domain of the host's name), and the
//! options Go knows. What Go does not know is noted, so that a program
//! that has the system's resolver may leave the file to it.

use super::{Address, Fields, Search, address, number};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The most nameservers, as every resolver since BIND's (MAXNS).
pub const SERVERS_MAX: usize = 3;
/// The most search domains: glibc's old MAXDNSRCH. Go keeps any number.
pub const SEARCH_MAX: usize = 6;
/// The most dots that options ndots takes, as Go and glibc cap it.
pub const NDOTS_MAX: u8 = 15;
/// The longest wait for one answer: glibc's cap, which Go has not.
pub const TIMEOUT_MS_MAX: u64 = 30_000;
/// The most rounds over the servers: glibc's cap, which Go has not.
pub const ATTEMPTS_MAX: u8 = 5;

const NDOTS: u8 = 1;
const TIMEOUT_MS: u64 = 5_000;
const ATTEMPTS: u8 = 2;

/// How a query goes: options use-vc asks for TCP alone.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Transport {
    /// UDP, and TCP when the answer did not fit.
    Udp,
    Tcp,
}

/// Whether A and AAAA are asked at once: options single-request asks
/// one after the other, for servers that drop one of two at once.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Queries {
    Parallel,
    Sequential,
}

/// Whether each query starts at the first server or at the next one.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Rotation {
    InOrder,
    Rotate,
}

pub struct Config {
    servers: [Address; SERVERS_MAX],
    servers_count: usize,
    search: Search,
    /// A name with at least this many dots is asked as it is first.
    pub ndots: u8,
    /// How long one exchange with a server may take.
    pub timeout_ms: u64,
    /// How many times each server is asked.
    pub attempts: u8,
    pub rotation: Rotation,
    pub queries: Queries,
    pub transport: Transport,
    /// Whether queries ask for the AD bit (options trust-ad).
    pub trust_ad: bool,
    /// Whether the file has a line or an option Go does not know.
    pub unknown: bool,
}

impl Config {
    /// The configuration from resolv.conf's text, or None when there is
    /// no such file; hostname is the host's own name, whose domain is
    /// the search list when the file gives none.
    pub fn parse(text: Option<&[u8]>, hostname: &[u8]) -> Config {
        let mut config = Config {
            servers: [Address::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED)); SERVERS_MAX],
            servers_count: 0,
            search: Search::EMPTY,
            ndots: NDOTS,
            timeout_ms: TIMEOUT_MS,
            attempts: ATTEMPTS,
            rotation: Rotation::InOrder,
            queries: Queries::Parallel,
            transport: Transport::Udp,
            trust_ad: false,
            unknown: false,
        };
        for line in text.unwrap_or_default().split(|byte| *byte == b'\n') {
            config.line(line);
        }
        if config.servers_count == 0 {
            config.server(Address::new(IpAddr::V4(Ipv4Addr::LOCALHOST)));
            config.server(Address::new(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        }
        if config.search.is_empty() {
            // The part after the first dot, unless the dot ends the name.
            let dot = hostname.iter().position(|byte| *byte == b'.');
            if let Some(domain) = dot.and_then(|at| hostname.get(at + 1..))
                && !domain.is_empty()
            {
                config.search_push(domain);
            }
        }
        config
    }

    pub fn servers(&self) -> &[Address] {
        self.servers.get(..self.servers_count).unwrap_or_default()
    }

    /// The search list, each name ending in a dot.
    pub fn search(&self) -> &Search {
        &self.search
    }

    /// Adds a nameserver, while there are fewer than SERVERS_MAX.
    fn server(&mut self, server: Address) {
        if let Some(slot) = self.servers.get_mut(self.servers_count) {
            *slot = server;
            self.servers_count += 1;
        }
    }

    fn line(&mut self, line: &[u8]) {
        if matches!(line.first(), Some(b';' | b'#')) {
            return;
        }
        let mut fields = Fields::new(line);
        let Some(keyword) = fields.field() else {
            return;
        };
        match keyword {
            b"nameserver" => {
                if let Some(server) = fields.field().and_then(address) {
                    self.server(server);
                }
            }
            b"domain" => {
                if let Some(domain) = fields.field() {
                    self.search.clear();
                    self.search_push(domain);
                }
            }
            b"search" => {
                self.search.clear();
                while let Some(domain) = fields.field() {
                    self.search_push(domain);
                }
            }
            b"options" => {
                while let Some(option) = fields.field() {
                    self.option(option);
                }
            }
            // OpenBSD's order of files and DNS, which nsswitch.conf
            // gives elsewhere.
            b"lookup" => {}
            _ => self.unknown = true,
        }
    }

    /// Adds a search domain with its final dot; the root adds nothing,
    /// and a name past the limits is left out.
    fn search_push(&mut self, domain: &[u8]) {
        if domain == b"." {
            return;
        }
        let dot: &[u8] = if domain.ends_with(b".") { b"" } else { b"." };
        self.search.push(&[domain, dot]);
    }

    fn option(&mut self, option: &[u8]) {
        if let Some(value) = option.strip_prefix(b"ndots:") {
            self.ndots = u8::try_from(number(value)).map_or(NDOTS_MAX, |n| n.min(NDOTS_MAX));
        } else if let Some(value) = option.strip_prefix(b"timeout:") {
            let seconds = u64::from(number(value).max(1));
            self.timeout_ms = seconds.saturating_mul(1000).min(TIMEOUT_MS_MAX);
        } else if let Some(value) = option.strip_prefix(b"attempts:") {
            let attempts = number(value).max(1);
            self.attempts = u8::try_from(attempts).map_or(ATTEMPTS_MAX, |n| n.min(ATTEMPTS_MAX));
        } else {
            match option {
                b"rotate" => self.rotation = Rotation::Rotate,
                b"single-request" | b"single-request-reopen" => {
                    self.queries = Queries::Sequential;
                }
                // Linux's, FreeBSD's and OpenBSD's names for it.
                b"use-vc" | b"usevc" | b"tcp" => self.transport = Transport::Tcp,
                b"trust-ad" => self.trust_ad = true,
                // Go always offers EDNS0, and reads the file again
                // only when it changed.
                b"edns0" | b"no-reload" => {}
                _ => self.unknown = true,
            }
        }
    }
}

/// Any bytes as resolv.conf: what it gives stays within the limits.
#[cfg(fuzzing)]
pub fn fuzz_config(input: &[u8]) {
    let config = Config::parse(Some(input), b"host.example");
    assert!(!config.servers().is_empty() && config.servers().len() <= SERVERS_MAX);
    assert!(config.search.len() <= SEARCH_MAX);
    for index in 0..config.search.len() {
        let name = config.search.get(index).unwrap();
        assert!(name.ends_with(b".") && name.len() <= super::NAME_MAX);
    }
    assert!(config.ndots <= NDOTS_MAX);
    assert!((1000..=TIMEOUT_MS_MAX).contains(&config.timeout_ms));
    assert!((1..=ATTEMPTS_MAX).contains(&config.attempts));
}

#[cfg(test)]
mod tests {
    use super::super::fake::ip;
    use super::{Config, Queries, Rotation, Transport};
    use alloc::vec::Vec;

    const HOSTNAME: &[u8] = b"host.domain.local";

    fn search(config: &Config) -> Vec<&[u8]> {
        let mut names = Vec::new();
        for index in 0..config.search().len() {
            names.push(config.search().get(index).unwrap());
        }
        names
    }

    fn parse(text: &[u8]) -> Config {
        Config::parse(Some(text), HOSTNAME)
    }

    /// Go's testdata/resolv.conf: three servers, one with a zone, the
    /// domain, options, and a line Go does not know.
    #[test]
    fn reads_go_testdata() {
        let text = b"# /etc/resolv.conf\n\ndomain localdomain\nnameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\nnameserver fe80::1%lo0\noptions ndots:5 timeout:10 attempts:3 rotate\noptions attempts 3\n";
        let config = Config::parse(Some(text), HOSTNAME);
        assert_eq!(
            config.servers(),
            [ip("8.8.8.8"), ip("2001:4860:4860::8888"), ip("fe80::1%lo0")]
        );
        assert_eq!(config.servers()[2].zone.as_bytes(), b"lo0");
        assert_eq!(search(&config), [b"localdomain.".as_slice()]);
        assert_eq!(config.ndots, 5);
        assert_eq!(config.timeout_ms, 10_000);
        assert_eq!(config.attempts, 3);
        assert_eq!(config.rotation, Rotation::Rotate);
        assert!(config.unknown);
    }

    /// No file, an empty one, and one without nameservers: Go's
    /// defaults, the search list from the host's name.
    #[test]
    fn defaults() {
        for text in [None, Some(&b""[..]), Some(b"options ndots:invalid\n")] {
            let config = Config::parse(text, HOSTNAME);
            assert_eq!(config.servers(), [ip("127.0.0.1"), ip("::1")]);
            assert_eq!(search(&config), [b"domain.local.".as_slice()]);
            assert_eq!(config.timeout_ms, 5000);
            assert_eq!(config.attempts, 2);
            assert_eq!(config.queries, Queries::Parallel);
            assert_eq!(config.transport, Transport::Udp);
            assert!(!config.unknown);
        }
        assert_eq!(Config::parse(None, HOSTNAME).ndots, 1);
        assert_eq!(
            Config::parse(Some(b"options ndots:invalid"), HOSTNAME).ndots,
            0
        );
        // A name without a domain, or with only a final dot, gives none.
        for hostname in [&b"host"[..], b"host.", b""] {
            assert!(Config::parse(None, hostname).search().is_empty());
        }
    }

    #[test]
    fn search_lists() {
        let two = parse(b"nameserver 8.8.8.8\nsearch test invalid\n");
        assert_eq!(search(&two), [&b"test."[..], b"invalid."]);
        // The root is no domain: the host's is used.
        let root = parse(b"search .\n");
        assert_eq!(search(&root), [b"domain.local.".as_slice()]);
        // The last of domain and search wins.
        let last = parse(b"search a b\ndomain c.\n");
        assert_eq!(search(&last), [b"c.".as_slice()]);
        let many = parse(b"search 1 2 3 4 5 6 7 8\n");
        assert_eq!(search(&many).len(), super::SEARCH_MAX);
        // 256 bytes of names in all: a 254-byte domain and b. fill it,
        // and c. is left out.
        let long = parse(b"search aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa b c\n");
        assert_eq!(search(&long).len(), 2);
        // OpenBSD's lookup line is known.
        let openbsd = parse(b"search c.symbolic-datum-552.internal.\nnameserver 169.254.169.254\nnameserver 10.240.0.1\nlookup file bind\n");
        assert_eq!(
            search(&openbsd),
            [b"c.symbolic-datum-552.internal.".as_slice()]
        );
        assert_eq!(openbsd.servers().len(), 2);
        assert!(!openbsd.unknown);
    }

    /// Bad and extra nameservers are passed over.
    #[test]
    fn servers() {
        let text = b"nameserver\nnameserver dns.example\nnameserver 01.2.3.4\nnameserver fe80::1%\nnameserver 1.1.1.1\nnameserver 1.0.0.1 9.9.9.9\nnameserver 2606:4700::1111\nnameserver 8.8.8.8\n";
        let config = Config::parse(Some(text), HOSTNAME);
        assert_eq!(
            config.servers(),
            [ip("1.1.1.1"), ip("1.0.0.1"), ip("2606:4700::1111")]
        );
        assert!(!config.unknown);
    }

    #[test]
    fn options() {
        for (text, ndots, timeout_ms, attempts) in [
            (&b"options ndots:16 timeout:0 attempts:0"[..], 15, 1000, 1),
            (b"options ndots:-1 timeout:99 attempts:99", 0, 30_000, 5),
            (
                b"options ndots:99999999999 timeout:2x attempts:4",
                15,
                2000,
                4,
            ),
        ] {
            let config = Config::parse(Some(text), HOSTNAME);
            assert_eq!(
                (config.ndots, config.timeout_ms, config.attempts),
                (ndots, timeout_ms, attempts)
            );
        }
        for text in [
            &b"options single-request"[..],
            b"options single-request-reopen",
        ] {
            let config = Config::parse(Some(text), HOSTNAME);
            assert_eq!(config.queries, Queries::Sequential);
        }
        for text in [&b"options use-vc"[..], b"options usevc", b"options tcp"] {
            let config = Config::parse(Some(text), HOSTNAME);
            assert_eq!(config.transport, Transport::Tcp);
        }
        let known = parse(b"options trust-ad edns0 no-reload\r\n");
        assert!(known.trust_ad && !known.unknown);
        for text in [
            &b"options inet6"[..],
            b"sortlist 10.0.0.0",
            b"nameservers 1.1.1.1",
        ] {
            assert!(parse(text).unknown);
        }
        // A comment starts a line; elsewhere it is a field.
        assert!(parse(b"; x\n# y\n  # z\n").unknown);
    }
}
