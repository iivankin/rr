//! TCP for a loop that serves many connections, over the system's own
//! sockets: a Listener accepts Streams, a Stream connects out, and each
//! reads and writes what the system takes now, without blocking. The
//! loop waits for them in a wait Set: watch puts a socket in it with an
//! interest and a key, close hands it to the Set, which takes it out and
//! closes it, so that nothing the system still holds of it is reported
//! for the socket that takes its number next. A
//! socket dropped without close is closed all the same, and the system
//! stops watching it; its entry in the Set stays until a new socket
//! takes its number, so a loop closes with close. Small writes go at
//! once (TCP_NODELAY), as in Go.
//!
//! Every socket is non-blocking and is not handed to child processes
//! (close-on-exec on Linux and macOS, not inherited on Windows); a write
//! to a peer that is gone is an error, not SIGPIPE. An IPv6 listener
//! takes IPv6 alone (IPV6_V6ONLY), the same on every system: a server
//! for both listens on both. A listener's address may be taken again
//! while old connections to it linger (SO_REUSEADDR on Linux and macOS),
//! and never while another listens on it (SO_EXCLUSIVEADDRUSE on
//! Windows, where SO_REUSEADDR would let another take it).
//!
//! Errors come as the kinds a loop acts on: refused, reset, timed out,
//! unreachable, the address in use, and the system's code for the rest.
//! A listener that runs out of descriptors keeps its connections waiting
//! and stays readable: the loop stops watching it for a while (watch it
//! with no interest), or it spins.

mod sys;
#[cfg(test)]
mod tests;

pub use sys::*;
