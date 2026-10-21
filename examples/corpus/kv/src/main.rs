//! kv: a key-value store kept as a log on disk. Its tests and benches
//! sit beside the code they check, under cfg(test); its fuzz targets are
//! functions under cfg(fuzzing).

#![no_std]
#![no_main]

extern crate alloc;

mod record;
mod store;
// The operating system, one file for each: the rest of the crate calls
// the same functions on all of them.
#[cfg_attr(target_os = "macos", path = "sys/macos.rs")]
#[cfg_attr(target_os = "linux", path = "sys/linux.rs")]
#[cfg_attr(target_os = "windows", path = "sys/windows.rs")]
mod sys;

use alloc::vec::Vec;
use core::ffi::c_char;

use store::Store;

#[global_allocator]
static HEAP: sys::Heap = sys::Heap;

/// A panic is a bug: say where, and end the process.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    sys::stderr(b"kv: panic");
    if let Some(at) = info.location() {
        sys::stderr(b" at ");
        sys::stderr(at.file().as_bytes());
    }
    sys::stderr(b"\n");
    sys::die()
}

/// What the program says when it is used wrongly.
const USAGE: &[u8] = b"usage: kv FILE (get KEY | put KEY VALUE | del KEY | keys | compact)\n";

/// The program on its arguments; the exit status: 0 done, 1 a key not
/// held, 2 a usage error, 3 the store failed.
fn run(args: &[&[u8]]) -> i32 {
    let [_, path, command, rest @ ..] = args else {
        sys::stderr(USAGE);
        return 2;
    };
    let mut s = match Store::open(path) {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let mut out = Vec::new();
    let r = match (*command, rest) {
        (b"get", [key]) => {
            let r = s.get(key, &mut out);
            out.push(b'\n');
            r
        }
        (b"put", [key, value]) => s.put(key, value).map(|()| true),
        (b"del", [key]) => s.delete(key),
        (b"keys", []) => {
            for k in s.keys() {
                out.extend_from_slice(k);
                out.push(b'\n');
            }
            Ok(true)
        }
        (b"compact", []) => s.compact().map(|()| true),
        _ => {
            sys::stderr(USAGE);
            return 2;
        }
    };
    match r {
        Ok(true) => {
            sys::stdout(&out);
            0
        }
        Ok(false) => 1,
        Err(e) => fail(&e),
    }
}

/// Say why the store failed; the exit status for it.
fn fail(e: &store::Error) -> i32 {
    sys::stderr(match e {
        store::Error::Sys => b"kv: the system refused\n",
        store::Error::TooLong => b"kv: a key or value is too long\n",
        store::Error::Full => b"kv: the store holds too many keys\n",
    });
    3
}

#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const c_char) -> i32 {
    // rr: escape(unsafe): argc and argv are main's own.
    let args = unsafe { sys::args(argc, argv) };
    run(&args)
}
