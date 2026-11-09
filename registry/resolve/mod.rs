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
//!   getaddrinfo would (RFC 6724, sort.rs).
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

#[cfg(any(target_os = "macos", test))]
mod sort;
mod sys;

pub use sys::*;
