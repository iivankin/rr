//! What a program's loop waits on, in mio's words: a Poll of many
//! descriptors (sockets on Windows), each with an Interest and a key,
//! whose poll says what is Ready as Events the loop dispatches by key,
//! and a Waker that wakes it from another thread. As in libuv, the loop
//! keeps its deadlines in the Poll too, and runs on one thread; a
//! program with more cores runs a loop on each (thread::start), as
//! net's multi-core server shows (queue's tests). Nothing calls back.
//!
//! The Poll (entries.rs) takes what scales on each system: epoll on
//! Linux, kqueue on macOS, socket notifications on Windows from build
//! 20348 (Server 2022, Windows 11), and WSAPoll on the Windows before it
//! (Windows 10 to 22H2, Server 2019) or where a layered provider sits
//! over TCP; Interest in and Ready out are the same on every system,
//! and a call it refuses says why (PollError).
//!
//! A component that works while the caller's loop runs (resolve, trust)
//! says what it wants the loop to wait for before it polls the component
//! again: a Want, up to two descriptors and a timeout. A Poll keeps a
//! Want's entries in step by follow, into the component's Follow; block
//! waits on one Want alone, for a thread that may block, and ready says
//! what came of it, for a loop of the program's own (poll on Linux and
//! macOS, WSAPoll on Windows). A Signal is a descriptor another thread
//! makes readable when its work is done: a pipe on Linux and macOS; on
//! Windows, where WSAPoll takes only sockets, a connected pair of
//! loopback sockets, as Python's asyncio does there.
//!
//! A program marks the function its loop runs `#[cfg_attr(rr,
//! rr::poll)]`, as net's echo test marks its own: rr then follows each
//! call from there and refuses one that blocks whatever it is given, a C
//! function such as getaddrinfo or sleep, or one marked
//! `#[rr::blocking]`: block here, resolve::resolve,
//! trust::Trust::verify_blocking and thread's joins and blocking pops,
//! which wait for an answer. Nothing here is `#[rr::poll]`: the loop is
//! the program's, and Poll::poll is the one wait it makes.
//!
//! This component was called wait before; `rr add wait` no longer
//! exists: `rr add poll`, and its Set, SetError, Wait and Watch are now
//! Poll, PollError, Want and Follow, Set::wait Poll::poll. Its pool of
//! threads is thread's.

mod entries;
mod sys;

pub use entries::*;
pub use sys::*;
