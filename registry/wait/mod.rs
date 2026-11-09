//! What a poll loop waits on, one type on every system and for every
//! component that works while the caller's loop runs (resolve, trust):
//! descriptors, sockets on Windows, and a timeout. The loop waits on a
//! component's Wait, or adds its descriptors to its own poll (poll on
//! Linux and macOS, WSAPoll on Windows), then polls the component again.
//!
//! A component may run blocking work, such as the C library's
//! getaddrinfo, on a thread: spawn runs it on one of at most THREADS_MAX,
//! and a Signal says it is done: a pipe on Linux and macOS; on Windows,
//! where WSAPoll takes only sockets, a connected pair of loopback
//! sockets, as Python's asyncio does there. spawn is unsafe: the work
//! reaches its argument from another thread, which its Safety says how
//! to keep alive. Its Ticket cancels work still in line when dropped;
//! detach lets it run.
//!
//! A loop that serves many connections waits on a Set (set.rs): any
//! number of descriptors, each with what the loop wants of it (an
//! Interest) and a key, and deadlines on the monotonic clock; what is
//! ready comes as Ready, the same on every system, and a call the Set
//! refuses says why (SetError). It takes what scales on each
//! system: epoll on Linux, kqueue on macOS, socket notifications on
//! Windows 11 and Server 2022 and WSAPoll on the Windows before them.
//! follow keeps a component's Wait in a Set.
//!
//! A program marks the function its loop runs `#[cfg_attr(rr,
//! rr::poll)]`, as net's echo test marks its own: rr then follows each
//! call from there and refuses one that blocks whatever it is given, a C
//! function such as getaddrinfo or sleep, or one marked
//! `#[rr::blocking]`: block here, resolve::resolve and
//! trust::Trust::verify_blocking, which wait for an answer. Nothing here
//! is `#[rr::poll]`: the loop is the program's, and Set::wait is the one
//! wait it makes.

mod set;
mod sys;

pub use set::*;
pub use sys::*;
