//! Looking up a host's addresses as the system would, without blocking
//! the caller's loop, the same on all three: start a lookup, poll it
//! until it is done, take the addresses; drop it to cancel.
//!
//! The system answers, as it answers every program there:
//!
//! - macOS: mDNSResponder, through dns_sd.h's DNSServiceGetAddrInfo,
//!   with VPN and split DNS as the system has them; a socket the
//!   caller's poll waits on, no thread. Its answers come unsorted, so
//!   resolve sorts them as getaddrinfo would (RFC 6724, sort.rs).
//! - Windows: GetAddrInfoExW, asynchronous, sorted by the system; its
//!   callback sets a Signal that the caller's WSAPoll waits on.
//! - Linux: the C library's getaddrinfo, with nsswitch.conf, files, DNS,
//!   systemd-resolved and mDNS as the system has them. It blocks, and
//!   the C library has no other way, so it runs on a thread of wait's:
//!   at most wait::THREADS_MAX at once, the rest in line, and one
//!   cancelled once its thread took it runs on to the C library's
//!   timeout (resolv.conf's timeout and attempts), its answer dropped.
//!
//! A program that looks up many names at once on Linux, such as a
//! crawler, wants its own resolver on the dns component in its own loop
//! instead.

#[cfg(any(target_os = "macos", test))]
mod sort;
mod sys;

pub use sys::*;
