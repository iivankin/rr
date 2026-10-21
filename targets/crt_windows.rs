//! rr's start for Windows without a C runtime: the process enters at
//! `mainCRTStartup`; the command line is split into arguments as the
//! Microsoft C runtime splits it, in UTF-8, and the program's
//! `main(argc, argv)` runs; what it returns is the process's exit code.

#![no_std]

use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetCommandLineW() -> *const u16;
    fn GetProcessHeap() -> *mut c_void;
    fn HeapAlloc(heap: *mut c_void, flags: u32, size: usize) -> *mut c_void;
    fn WideCharToMultiByte(
        page: u32,
        flags: u32,
        wide: *const u16,
        wide_len: i32,
        out: *mut u8,
        out_len: i32,
        default: *const u8,
        used_default: *mut i32,
    ) -> i32;
    fn ExitProcess(code: u32) -> !;
}

unsafe extern "C" {
    fn main(argc: i32, argv: *const *const c_char) -> i32;
}

const CP_UTF8: u32 = 65001;

/// LLVM's MinGW convention has `main` call `__main` first, to run the C
/// runtime's constructors; an rr program has none.
#[unsafe(no_mangle)]
extern "C" fn __main() {}

#[unsafe(no_mangle)]
extern "C" fn mainCRTStartup() -> ! {
    // SAFETY: each call is given what its documentation asks; the
    // command line lives as long as the process.
    unsafe {
        let wide = GetCommandLineW();
        // A length of -1: the line ends at its NUL, which is counted.
        let with_nul = WideCharToMultiByte(CP_UTF8, 0, wide, -1, null_mut(), 0, null_mut(), null_mut());
        let n = usize::try_from(with_nul).unwrap_or(1).max(1) - 1;
        // The UTF-8 line and its NUL, then the arguments, each with its NUL
        // (no more bytes than the line has), then argv: at most one
        // argument per two bytes, the program's name, and a null.
        let pointers = n / 2 + 2;
        let size = 2 * (n + 1) + pointers * size_of::<*const c_char>() + 8;
        let block = HeapAlloc(GetProcessHeap(), 0, size).cast::<u8>();
        if block.is_null() {
            ExitProcess(3);
        }
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, block, with_nul, null_mut(), null_mut());
        let line = core::slice::from_raw_parts(block, n);
        let out_at = block.add(n + 1);
        let out = core::slice::from_raw_parts_mut(out_at, n + 1);
        let argv_at = (out_at.add(n + 1) as usize).next_multiple_of(8) as *mut *const c_char;
        let argv = core::slice::from_raw_parts_mut(argv_at, pointers);
        let argc = split(line, out, out_at, argv);
        let code = main(i32::try_from(argc).unwrap_or(i32::MAX), argv_at.cast_const());
        ExitProcess(code.cast_unsigned())
    }
}

/// line split into out, each argument ending in a NUL; argv gets where
/// each starts, base being out's address, then a null. The count.
fn split(line: &[u8], out: &mut [u8], base: *mut u8, argv: &mut [*const c_char]) -> usize {
    let mut i = 0;
    let mut o = 0;
    let mut argc = 0;
    // The program's name: up to a space, or within quotes, as it is.
    argv[argc] = base.cast_const().cast();
    argc += 1;
    if line.first() == Some(&b'"') {
        i = 1;
        while i < line.len() && line[i] != b'"' {
            out[o] = line[i];
            o += 1;
            i += 1;
        }
        i += 1;
    } else {
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
            out[o] = line[i];
            o += 1;
            i += 1;
        }
    }
    out[o] = 0;
    o += 1;
    loop {
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
            i += 1;
        }
        if i >= line.len() || argc + 1 >= argv.len() {
            break;
        }
        argv[argc] = base.wrapping_add(o).cast_const().cast();
        argc += 1;
        let mut quoted = false;
        while i < line.len() {
            let mut slashes = 0;
            while i < line.len() && line[i] == b'\\' {
                slashes += 1;
                i += 1;
            }
            if i < line.len() && line[i] == b'"' {
                for _ in 0..slashes / 2 {
                    out[o] = b'\\';
                    o += 1;
                }
                if slashes % 2 == 1 {
                    out[o] = b'"';
                    o += 1;
                } else if quoted && line.get(i + 1) == Some(&b'"') {
                    out[o] = b'"';
                    o += 1;
                    i += 1;
                } else {
                    quoted = !quoted;
                }
                i += 1;
                continue;
            }
            for _ in 0..slashes {
                out[o] = b'\\';
                o += 1;
            }
            if i >= line.len() || (!quoted && (line[i] == b' ' || line[i] == b'\t')) {
                break;
            }
            out[o] = line[i];
            o += 1;
            i += 1;
        }
        out[o] = 0;
        o += 1;
    }
    argv[argc] = core::ptr::null();
    argc
}
