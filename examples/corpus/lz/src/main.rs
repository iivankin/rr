//! lz: an LZ77 codec for blocks of bytes. Its tests and benches sit
//! beside the code they check, under cfg(test); its fuzz targets are
//! functions under cfg(fuzzing).

#![no_std]
#![no_main]

extern crate alloc;

mod codec;
// The operating system, one file for each: the rest of the crate calls
// the same functions on all of them.
#[cfg_attr(target_os = "macos", path = "sys/macos.rs")]
#[cfg_attr(target_os = "linux", path = "sys/linux.rs")]
#[cfg_attr(target_os = "windows", path = "sys/windows.rs")]
mod sys;

use alloc::vec::Vec;
use core::ffi::c_char;

use codec::Compressor;

#[global_allocator]
static HEAP: sys::Heap = sys::Heap;

/// A panic is a bug: say where, and end the process.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    sys::stderr(b"lz: panic");
    if let Some(at) = info.location() {
        sys::stderr(b" at ");
        sys::stderr(at.file().as_bytes());
    }
    sys::stderr(b"\n");
    sys::die()
}

/// The program on its arguments: `lz c` compresses standard input to
/// standard output, `lz d` decompresses it. The exit status: 0 done, 1
/// bad compressed input, 2 a usage error or input too long.
fn run(args: &[&[u8]]) -> i32 {
    let mut input = Vec::new();
    if !sys::stdin(&mut input, codec::BLOCK_MAX) {
        sys::stderr(b"lz: the input is too long or cannot be read\n");
        return 2;
    }
    let mut out = Vec::new();
    match args.get(1).copied() {
        Some(b"c") => Compressor::new().compress(&input, &mut out),
        Some(b"d") => {
            if codec::decompress(&input, &mut out, codec::BLOCK_MAX).is_err() {
                sys::stderr(b"lz: not compressed input\n");
                return 1;
            }
        }
        _ => {
            sys::stderr(b"usage: lz c|d < in > out\n");
            return 2;
        }
    }
    sys::stdout(&out);
    0
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const c_char) -> i32 {
    // rr: escape(unsafe): argc and argv are main's own.
    let args = unsafe { sys::args(argc, argv) };
    run(&args)
}
