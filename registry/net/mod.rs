//! TCP for a loop that serves many connections, over the system's own
//! sockets: a Listener accepts Streams, a Stream connects out, and each
//! reads and writes what the system takes now, without blocking. The
//! loop waits for them in a poll::Poll: watch puts a socket in it with an
//! Interest and a key, close hands it to the Poll, which takes it out and
//! closes it, so that nothing the system still holds of it is reported
//! for the socket that takes its number next. The entry is Owned: the
//! token a stream lends for deadlines cannot remove or close it, so the
//! socket is closed once, by close or by its drop. A socket dropped
//! without close is closed all the same, and the system stops watching
//! it; its entry in the Poll stays until a new socket takes its number,
//! so a loop closes with close. A socket watched in one Poll is refused
//! by another (PollError::Foreign). Small writes go at once
//! (TCP_NODELAY), as in Go.
//!
//! A Stream that connects out remembers how the connection went:
//! connected says it the same way every time, and a read or write before
//! it is made is NotConnected on every system. A read into no room is
//! refused (NoRoom): its Done(0) would read as the peer's end.
//!
//! Every socket is non-blocking and is not handed to child processes
//! (close-on-exec on Linux and macOS, not inherited on Windows); a write
//! to a peer that is gone is an error, not SIGPIPE. An IPv6 listener
//! takes IPv6 alone (IPV6_V6ONLY), the same on every system: a server
//! for both listens on both. A listener's address may be taken again
//! while old connections to it linger, as a server that restarts needs,
//! and not while another listens on it: SO_REUSEADDR on Linux and macOS;
//! on Windows, which takes it so by itself, no option, as in Go and
//! libuv (SO_REUSEADDR would let another take it while it listens, and
//! SO_EXCLUSIVEADDRUSE would refuse it while old connections linger).
//!
//! Errors come as the kinds a loop acts on: refused, reset, timed out,
//! unreachable, the address in use, not connected yet, and the system's
//! code for the rest.
//! A listener that runs out of descriptors keeps its connections waiting
//! and stays readable: the loop stops watching it for a while (watch it
//! with Interest::None), or it spins.
//!
//! More cores, more loops: a loop on each thread, each with its own Poll
//! (thread::start), and a socket in one of them alone. On Linux each
//! loop listens itself with Listener::bind_shared on the same address
//! (SO_REUSEPORT), and the kernel spreads the connections among them. On
//! macOS and Windows no system spreads them (macOS gives every one to
//! the listener bound last; socket notifications take a socket in one
//! completion port alone), and bind_shared says so (Unbalanced): one
//! loop accepts with accept_handoff, sends each Handoff to a worker's
//! queue (queue), which wakes that worker's Poll, and the worker makes it
//! its own Stream with Stream::adopt, then watches it. A Handoff is in no
//! Poll by its type: a stream watched in one cannot be handed to
//! another. queue's tests run such a server on each system.
//!
//! Nothing here blocks the loop, which a program marks `#[cfg_attr(rr,
//! rr::poll)]` (as the echo test does) so that rr refuses on its path a
//! call that would: see poll.

mod sys;
#[cfg(test)]
mod tests;

pub use sys::*;
