//! Looking up a host's addresses as the system would, without blocking
//! the caller's loop, the same on all three: start a lookup, poll it
//! until it is done, take the addresses; drop it to cancel.
//!
//! The system answers, as it answers every program there: the C
//! library's getaddrinfo on Linux and macOS, with nsswitch.conf,
//! systemd-resolved, VPN and split DNS as the system has them, and
//! GetAddrInfoW on Windows. Each blocks, so it runs on a thread of
//! wait's, and a Signal says it is done, which the caller's poll loop
//! waits on beside its own descriptors.
//!
//! What that costs: a lookup in flight holds a thread, and at most
//! wait::THREADS_MAX run at once, the rest in line; a lookup cancelled
//! once its thread took it runs on to the system's own timeout (with
//! glibc, resolv.conf's timeout and attempts), and its answer is
//! dropped. A program that looks up many names at once, such as a
//! crawler, wants its own resolver on the dns component in its own
//! loop instead.

mod sys;

pub use sys::*;
