//! Threads for a program whose loops wait on a poll::Poll, as libuv
//! gives a loop its threads: a pool for work that blocks, and threads of
//! their own for loops on other cores. No callback runs on a loop: a job
//! that is done tells it (a Waker or a Signal), and the loop takes it.
//!
//! The pool (spawn) is libuv's threadpool.c: at most THREADS_MAX
//! threads, started as work comes and none is idle, which then sleep on
//! a condition variable for the next; one line of work, first in first
//! out, under a mutex. A Job cancels work still in line when it is
//! dropped (cancel gives it back), never work a thread took, which runs
//! to its end, as uv_cancel. Once the work returned, the job's Done
//! wakes the loop's Poll (WOKEN) or sets a Signal a component's Want
//! names, and take gives the work back.
//!
//! Work is moved in and given back: a `Box<dyn Work + Send>`, owned, so
//! it holds no reference into the caller's stack and nothing that may
//! not cross threads, which the compiler checks; no pointer goes in that
//! could dangle, and nothing is unsafe to call. It comes back as the
//! trait object: rr has no generics, and Rust's Any, which would give
//! back the type, is dyn of a trait of another crate, which rr refuses.
//! A caller that needs its own type back (resolve's lookups, trust's
//! checks) keeps its jobs in a field that it alone fills, each with
//! its one type of work, and turns the Box back into that type in its
//! sys.rs, whose Safety says so; a program can keep what its work finds
//! in atomics shared with it instead.
//!
//! start runs one Work on a thread of its own, with a stack of 2 MiB:
//! such as a loop with its own Poll, made on the starting thread and
//! moved in, with the Waker that tells it to end; join waits for it, for
//! a thread that may block. Lock and Cond are the system's mutex and
//! condition variable, pthread's on Linux and macOS, SRWLOCK and
//! CONDITION_VARIABLE on Windows, for the pool and queue: a guard holds
//! the lock while it lives, and a wait on a Cond is `#[rr::blocking]`, as
//! join is, which rr refuses on a poll loop's path.

mod sys;
#[cfg(test)]
mod tests;

pub use sys::*;
