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
//! sockets, as Python's asyncio does there.
//!
//! A loop that serves many connections waits on a Set (set.rs): any
//! number of descriptors, each with what the loop wants of it and a key,
//! and deadlines on the monotonic clock. It takes what scales on each
//! system: epoll on Linux, kqueue on macOS, socket notifications on
//! Windows 11 and Server 2022 and WSAPoll on the Windows before them.
//! follow keeps a component's Wait in a Set.

mod set;
mod sys;

pub use set::*;
pub use sys::*;
