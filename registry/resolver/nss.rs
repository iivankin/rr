//! nsswitch.conf's hosts line, and the choice Go's hostLookupOrder makes
//! from it: files and DNS in some order, which this resolver does, or
//! the system's resolver for what it cannot do (mDNS, myhostname,
//! systemd's resolve, criteria other than the defaults). A program
//! without the system's resolver gets Go's netgo answer instead: an
//! unknown source counts as DNS when no dns follows it.

use super::conf::Config;
use super::ends_with;
#[cfg(fuzzing)]
use alloc::vec::Vec;

/// The most sources the hosts line may name; a longer one is read as a
/// file that did not parse.
pub const SOURCES_MAX: usize = 16;

/// Where a lookup looks, and in which order.
#[derive(Clone, Copy)]
#[cfg_attr(any(test, fuzzing), derive(PartialEq))]
#[cfg_attr(test, derive(Debug))]
pub enum Order {
    FilesDns,
    DnsFiles,
    Files,
    Dns,
}

/// Who resolves the name.
#[derive(Clone, Copy)]
#[cfg_attr(any(test, fuzzing), derive(PartialEq))]
#[cfg_attr(test, derive(Debug))]
pub enum Plan {
    /// This resolver, in this order.
    Own(Order),
    /// The system's resolver (getaddrinfo), which knows the rest.
    System,
}

/// What Go asks of the host when it may use the system's resolver.
pub struct System<'a> {
    /// The host's own name, which myhostname answers.
    pub hostname: &'a [u8],
    /// Whether /etc/mdns.allow exists: mDNS may then take any name.
    pub mdns_allow: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Service {
    Files,
    Dns,
    MyHostname,
    Mdns,
    Other,
}

struct Source {
    service: Service,
    /// Whether its criteria, if any, are the defaults.
    standard: bool,
}

/// The hosts line of nsswitch.conf.
pub struct Nss {
    sources: [Source; SOURCES_MAX],
    count: usize,
    /// Whether the file did not parse: a line without a colon, a bad
    /// criterion, or too many sources.
    malformed: bool,
}

impl Source {
    const NONE: Source = Source {
        service: Service::Other,
        standard: true,
    };
}

impl Nss {
    fn sources(&self) -> &[Source] {
        self.sources.get(..self.count).unwrap_or_default()
    }

    /// The hosts sources of nsswitch.conf's text. A file without the
    /// line has none, and Go then looks in files, then DNS.
    pub fn parse(text: &[u8]) -> Nss {
        let mut nss = Nss {
            sources: [Source::NONE; SOURCES_MAX],
            count: 0,
            malformed: false,
        };
        for line in text.split(|byte| *byte == b'\n') {
            let line = match line.iter().position(|byte| *byte == b'#') {
                Some(at) => line.get(..at).unwrap_or_default(),
                None => line,
            };
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                nss.malformed = true;
                return nss;
            };
            let (database, sources) = line.split_at(colon);
            if database.trim_ascii() == b"hosts"
                && !nss.sources_line(sources.get(1..).unwrap_or_default())
            {
                nss.malformed = true;
                return nss;
            }
        }
        nss
    }

    /// Reads the sources after hosts's colon; false when they do not
    /// parse. Sources part at spaces only, as Go parts them.
    fn sources_line(&mut self, mut rest: &[u8]) -> bool {
        for _ in 0..=SOURCES_MAX {
            rest = rest.trim_ascii();
            if rest.is_empty() {
                return true;
            }
            let end = rest
                .iter()
                .position(|byte| *byte == b' ')
                .unwrap_or(rest.len());
            let (name, after) = rest.split_at(end);
            rest = after.trim_ascii();
            let mut standard = true;
            if let Some(inside) = rest.strip_prefix(b"[") {
                let Some(close) = inside.iter().position(|byte| *byte == b']') else {
                    return false;
                };
                let (criteria, tail) = inside.split_at(close);
                let Some(criteria) = standard_criteria(criteria) else {
                    return false;
                };
                standard = criteria;
                rest = tail.get(1..).unwrap_or_default();
            }
            let Some(slot) = self.sources.get_mut(self.count) else {
                return false;
            };
            *slot = Source {
                service: service(name),
                standard,
            };
            self.count += 1;
        }
        false
    }
}

fn service(name: &[u8]) -> Service {
    match name {
        b"files" => Service::Files,
        b"dns" => Service::Dns,
        b"myhostname" => Service::MyHostname,
        _ if name.starts_with(b"mdns") => Service::Mdns,
        _ => Service::Other,
    }
}

/// Whether criteria such as `NOTFOUND=return !UNAVAIL=continue` are the
/// defaults: success returns, the rest continue, and the last may
/// return. None when one does not parse.
fn standard_criteria(text: &[u8]) -> Option<bool> {
    let mut fields = text
        .split(|byte| *byte == b' ')
        .map(<[u8]>::trim_ascii)
        .filter(|field| !field.is_empty())
        .peekable();
    let mut standard = true;
    // Each turn takes a field, of which there are fewer than bytes.
    for _ in 0..=text.len() {
        let Some(field) = fields.next() else {
            break;
        };
        let last = fields.peek().is_none();
        let (negate, field) = match field.strip_prefix(b"!") {
            Some(rest) => (true, rest),
            None => (false, field),
        };
        if field.len() < 3 {
            return None;
        }
        let equal = field.iter().position(|byte| *byte == b'=')?;
        let (status, action) = field.split_at(equal);
        let action = action.get(1..).unwrap_or_default();
        let default: &[u8] = if status.eq_ignore_ascii_case(b"success") {
            b"return"
        } else if [&b"notfound"[..], b"unavail", b"tryagain"]
            .iter()
            .any(|known| status.eq_ignore_ascii_case(known))
        {
            b"continue"
        } else {
            standard = false;
            continue;
        };
        let returns = action.eq_ignore_ascii_case(b"return");
        if negate || !(action.eq_ignore_ascii_case(default) || last && returns) {
            standard = false;
        }
    }
    Some(standard)
}

/// Who resolves name, as Go's hostLookupOrder decides: from
/// nsswitch.conf (None when there is no such file) and resolv.conf, and
/// whether the system's resolver is there to take what Go leaves to it
/// (None when it is not, as in a Go program built with netgo).
pub fn plan(nss: Option<&Nss>, config: &Config, name: &[u8], system: Option<&System<'_>>) -> Plan {
    let fallback = if system.is_some() {
        // Escapes and zones are glibc's to read, as is what resolv.conf
        // has that Go does not know.
        if name.contains(&b'\\') || name.contains(&b'%') || config.unknown {
            return Plan::System;
        }
        Plan::System
    } else {
        Plan::Own(Order::FilesDns)
    };
    let Some(nss) = nss else {
        return Plan::Own(Order::FilesDns);
    };
    if nss.malformed {
        return fallback;
    }
    let sources = nss.sources();
    if sources.is_empty() {
        return Plan::Own(Order::FilesDns);
    }
    let name = name.strip_suffix(b".").unwrap_or(name);
    let (mut files, mut dns, mut first) = (false, false, None);
    for (index, source) in sources.iter().enumerate() {
        match source.service {
            Service::Files | Service::Dns => {
                if system.is_some() && !source.standard {
                    return Plan::System;
                }
                if source.service == Service::Files {
                    files = true;
                } else {
                    dns = true;
                }
                first = first.or(Some(source.service));
                continue;
            }
            Service::MyHostname | Service::Mdns | Service::Other => {}
        }
        if let Some(system) = system {
            if !system_passes(source.service, name, system) {
                return Plan::System;
            }
            continue;
        }
        // Without the system's resolver an unknown source is read as
        // DNS, unless dns comes later.
        let later = sources.get(index + 1..).unwrap_or_default();
        if !dns && !later.iter().any(|next| next.service == Service::Dns) {
            dns = true;
            first = first.or(Some(Service::Dns));
        }
    }
    match (files, dns) {
        (true, true) if first == Some(Service::Files) => Plan::Own(Order::FilesDns),
        (true, true) => Plan::Own(Order::DnsFiles),
        (true, false) => Plan::Own(Order::Files),
        (false, true) => Plan::Own(Order::Dns),
        (false, false) => fallback,
    }
}

/// Whether a source other than files and dns cannot answer name, so
/// that this resolver may skip it: myhostname answers only the host's
/// own names, mDNS only .local ones unless mdns.allow widens it.
fn system_passes(service: Service, name: &[u8], system: &System<'_>) -> bool {
    if name.is_empty() {
        return false;
    }
    match service {
        Service::MyHostname => {
            let own = name.eq_ignore_ascii_case(system.hostname);
            !(localhost(name)
                || name.eq_ignore_ascii_case(b"_gateway")
                || name.eq_ignore_ascii_case(b"_outbound")
                || own
                || system.hostname.is_empty())
        }
        Service::Mdns => !ends_with(name, b".local") && !system.mdns_allow,
        Service::Files | Service::Dns | Service::Other => false,
    }
}

/// Whether name is one of localhost's, as Go's isLocalhost and RFC 6761
/// say: localhost, localhost.localdomain and the names under them.
pub fn localhost(name: &[u8]) -> bool {
    let name = name.strip_suffix(b".").unwrap_or(name);
    name.eq_ignore_ascii_case(b"localhost")
        || name.eq_ignore_ascii_case(b"localhost.localdomain")
        || ends_with(name, b".localhost")
        || ends_with(name, b".localhost.localdomain")
}

/// Any bytes as nsswitch.conf: the plan for a name is the same with and
/// without its final dot.
#[cfg(fuzzing)]
pub fn fuzz_nss(input: &[u8]) {
    let nss = Nss::parse(input);
    assert!(nss.count <= SOURCES_MAX);
    let config = Config::parse(None, b"");
    let host = System {
        hostname: b"host",
        mdns_allow: input.len().is_multiple_of(2),
    };
    let mut dotted = Vec::new();
    for name in [&b"x.com"[..], b"host", b"a.local", b"localhost"] {
        dotted.clear();
        dotted.extend_from_slice(name);
        dotted.push(b'.');
        for system in [None, Some(&host)] {
            assert!(
                plan(Some(&nss), &config, name, system)
                    == plan(Some(&nss), &config, &dotted, system)
            );
        }
        // Without the system's resolver, the plan is always this one's.
        assert!(matches!(
            plan(Some(&nss), &config, name, None),
            Plan::Own(_)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::conf::Config;
    use super::{Nss, Order, Plan, System, localhost, plan};

    fn decide(nss: &str, name: &str, system: bool) -> Plan {
        let config = Config::parse(None, b"");
        let host = System {
            hostname: b"myhostname",
            mdns_allow: false,
        };
        let nss = Nss::parse(nss.as_bytes());
        plan(
            Some(&nss),
            &config,
            name.as_bytes(),
            system.then_some(&host),
        )
    }

    const SYSTEM: Plan = Plan::System;
    const FILES_DNS: Plan = Plan::Own(Order::FilesDns);
    const DNS_FILES: Plan = Plan::Own(Order::DnsFiles);

    /// The cases of Go's TestConfHostLookupOrder, with the system's
    /// resolver there.
    #[test]
    fn with_the_system() {
        for (nss, name, want) in [
            (
                "hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4",
                "foo.local",
                SYSTEM,
            ),
            (
                "hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4",
                "foo.LOCAL.",
                SYSTEM,
            ),
            (
                "hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4",
                "google.com",
                FILES_DNS,
            ),
            ("foo: bar", "google.com", FILES_DNS),
            ("", "google.com", FILES_DNS),
            ("hosts: files mdns dns", "x.com", FILES_DNS),
            ("hosts: files mdns dns", "x.local", SYSTEM),
            ("hosts: dns", "x.com", Plan::Own(Order::Dns)),
            ("hosts: dns", "x\\.com", SYSTEM),
            ("hosts: dns", "foo.com%en0", SYSTEM),
            ("hosts: files dns", "x", FILES_DNS),
            ("hosts: dns files", "x.local", DNS_FILES),
            ("hosts: dns files something_custom", "x.com", SYSTEM),
            ("hosts: files dns myhostname", "x.com", FILES_DNS),
            ("hosts: files dns myhostname", "myHostname", SYSTEM),
            ("hosts: files dns myhostname", "_Gateway", SYSTEM),
            ("hosts: files dns myhostname", "_outbound", SYSTEM),
            (
                "hosts: files dns myhostname",
                "Anything.Localhost.Localdomain",
                SYSTEM,
            ),
            ("hosts: files dns myhostname", "somehostname", FILES_DNS),
            (
                "hosts: files myhostname mdns4_minimal [NOTFOUND=return] dns mdns4",
                "x.com",
                FILES_DNS,
            ),
            (
                "hosts: dns [success=return notfound=continue unavail=continue tryagain=continue] files [notfound=return]",
                "x.com",
                DNS_FILES,
            ),
            ("hosts: dns [!UNAVAIL=return] files", "x.com", SYSTEM),
            // The last criterion may return.
            ("hosts: dns [NOTFOUND=return] files", "x.com", DNS_FILES),
            (
                "hosts: dns [NOTFOUND=return UNAVAIL=continue] files",
                "x.com",
                SYSTEM,
            ),
            ("hosts: files [SUCCESS=continue] dns", "x.com", SYSTEM),
            ("hosts: files [weird=return] dns", "x.com", SYSTEM),
            ("hosts: resolve [!UNAVAIL=return] files", "x.com", SYSTEM),
            ("hosts: files\ngarbage", "x.com", SYSTEM),
            ("hosts: files [NOTFOUND=return", "x.com", SYSTEM),
            ("hosts: files [=x] dns", "x.com", SYSTEM),
        ] {
            assert_eq!(decide(nss, name, true), want, "{nss} {name}");
        }
        let unknown = Config::parse(Some(b"options inet6"), b"");
        assert_eq!(
            plan(
                None,
                &unknown,
                b"x.com",
                Some(&System {
                    hostname: b"",
                    mdns_allow: false
                })
            ),
            SYSTEM
        );
        let allow = System {
            hostname: b"h",
            mdns_allow: true,
        };
        let nss = Nss::parse(b"hosts: files mdns dns");
        assert_eq!(
            plan(
                Some(&nss),
                &Config::parse(None, b""),
                b"x.com",
                Some(&allow)
            ),
            SYSTEM
        );
    }

    /// Go built with netgo: never the system's.
    #[test]
    fn without_the_system() {
        for (nss, want) in [
            ("hosts: dns files", DNS_FILES),
            ("hosts: dns files something_custom", DNS_FILES),
            ("hosts: resolve files", DNS_FILES),
            ("hosts: mymachines files dns", FILES_DNS),
            ("hosts: dns mymachines files", DNS_FILES),
            ("hosts: files", Plan::Own(Order::Files)),
            (
                "hosts: files mdns4_minimal [NOTFOUND=return] dns",
                FILES_DNS,
            ),
            ("hosts: dns [!UNAVAIL=return] files", DNS_FILES),
            ("hosts:\nfoo: bar", FILES_DNS),
            ("hosts files", FILES_DNS),
        ] {
            assert_eq!(decide(nss, "x.com", false), want, "{nss}");
        }
        let config = Config::parse(Some(b"options inet6"), b"");
        assert_eq!(plan(None, &config, b"x\\y", None), FILES_DNS);
        // Only files: a name hosts does not have is not found.
        let Plan::Own(order) = decide("hosts: files [NOTFOUND=return]", "x", false) else {
            panic!("the system's resolver without one");
        };
        assert_eq!(order, Order::Files);
    }

    #[test]
    fn localhost_names() {
        for name in [
            "localhost",
            "LOCALHOST.",
            "a.localhost",
            "localhost.localdomain",
            "b.Localhost.Localdomain",
        ] {
            assert!(localhost(name.as_bytes()), "{name}");
        }
        for name in ["localhost.com", "xlocalhost", "localdomain", ""] {
            assert!(!localhost(name.as_bytes()), "{name}");
        }
    }
}
