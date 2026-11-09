//! A queue between threads, for a loop on each core: it carries an
//! accepted connection (net's Handoff, a socket in no Poll) and a tag
//! from the thread that accepts to a worker's loop, whose Poll each push
//! wakes (WOKEN); the worker pops it, makes it its own with
//! Stream::adopt and watches it in its Poll, the only one the socket is
//! ever in. That is how a server spreads its connections over its cores
//! on macOS and Windows, which do not do it themselves (net's
//! bind_shared says why); on Linux each worker listens itself, and the
//! queue only tells it to end.
//!
//! As libuv's queues, it is a line under a mutex, with condition
//! variables for the threads that may block (push_blocking,
//! pop_blocking, `#[rr::blocking]`): no lock-free code. It is bounded:
//! a push to a full queue is refused at once and gives the connection
//! back (Push::Full), for another worker or to close, so that a loop
//! that accepts never waits on one that is behind. Its element is one
//! type, as rr has no generics: a program that hands off something
//! else copies the component and changes the type.
//!
//! A Sender may be cloned for more threads; when the last is dropped the
//! receiver's loop is woken, and pop says Closed once the queue is
//! empty: the worker ends. A Receiver dropped closes what is still in
//! line, and a push after is refused (Push::Closed). Each push wakes the
//! loop, which pops until None after each WOKEN: a loop that pops fewer
//! is woken again only by the next push.
//!
//! The tests run such a server on N threads, a Poll each, and count
//! the connections each worker served: on Linux by SO_REUSEPORT
//! listeners, on macOS and Windows by an accept thread that hands off,
//! round robin; and a bench of connections a second.

mod sys;
#[cfg(test)]
mod tests;

pub use sys::*;
