//! What the CPU has of the instructions the components use, asked once
//! for the process: what the target promises, and on aarch64 Linux and
//! Windows and on x86_64 what the CPU says it has besides. A component
//! asks has() before it runs code built for more than its target.

mod sys;

pub use sys::*;
