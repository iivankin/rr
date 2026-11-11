//! server: the bench server of ../SPEC.md on rr's io, one crate, built
//! by build.sh from this directory and the registry's io and thread.

#![no_std]
#![no_main]

extern crate alloc;

mod base;
mod env;
mod server;
// The operating system: macOS and Linux through their C library, Windows
// through its own; the rest of the crate calls the same functions on all.
#[cfg_attr(unix, path = "sys/unix.rs")]
#[cfg_attr(windows, path = "sys/windows.rs")]
mod sys;

use core::ffi::c_char;

#[global_allocator]
static HEAP: sys::Heap = sys::Heap;

/// A panic is a bug: say where, and end the process.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    sys::stderr(b"server: panic");
    if let Some(at) = info.location() {
        sys::stderr(b" at ");
        sys::stderr(at.file().as_bytes());
    }
    sys::stderr(b"\n");
    sys::die()
}

/// The standard library rustup installs is built to unwind, and its alloc
/// names the routine that would unwind a panic. A panic here aborts, so
/// nothing calls it; the linker only needs it to exist when the build
/// keeps alloc's code whole, as a test build does.
// rr: escape(unsafe): the name is the one alloc calls, and no other crate
// of the program defines it.
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}

/// The program on its arguments: SCENARIO PORT.
fn run(args: &[&[u8]]) -> i32 {
    let (Some(scenario), Some(port)) = (args.get(1), args.get(2)) else {
        sys::stderr(b"usage: server SCENARIO PORT\n");
        return 2;
    };
    server::serve(scenario, port)
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const c_char) -> i32 {
    // rr: escape(unsafe): argc and argv are main's own.
    let args = unsafe { sys::args(argc, argv) };
    run(&args)
}
