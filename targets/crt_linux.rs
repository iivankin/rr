//! rr's start for Linux without libc: the kernel enters at `_start` with
//! argc, then argv and the environment, on the stack; the program's
//! `main(argc, argv)` runs, and what it returns is the process's exit
//! status. `rr_crt_environ` gives the environment to whoever asks, as
//! rr prof's runtime does.

#![no_std]

use core::ffi::c_char;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

unsafe extern "C" {
    fn main(argc: i32, argv: *const *const c_char) -> i32;
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!("xor ebp, ebp", "mov rdi, rsp", "and rsp, -16", "call {}", "ud2", sym start);
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mov x29, #0", "mov x30, #0", "mov x0, sp", "bl {}", "brk #1", sym start);
}

static ENVIRON: AtomicPtr<*const c_char> = AtomicPtr::new(null_mut());

/// The environment: pointers to `NAME=value` strings, then a null.
#[unsafe(no_mangle)]
pub extern "C" fn rr_crt_environ() -> *const *const c_char {
    ENVIRON.load(Ordering::Relaxed)
}

/// sp: argc, then argv's pointers and a null, then the environment's.
unsafe extern "C" fn start(sp: *const usize) -> ! {
    // SAFETY: the kernel lays out argc, argv and the environment at the
    // initial stack pointer.
    let status = unsafe {
        let argc = *sp;
        let argv = sp.add(1).cast::<*const c_char>();
        ENVIRON.store(argv.add(argc + 1).cast_mut(), Ordering::Relaxed);
        main(i32::try_from(argc).unwrap_or(i32::MAX), argv)
    };
    exit_group(status)
}

fn exit_group(status: i32) -> ! {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: exit_group ends the process and does not return.
    unsafe {
        core::arch::asm!("syscall", in("rax") 231, in("rdi") status, options(noreturn, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: exit_group ends the process and does not return.
    unsafe {
        core::arch::asm!("svc #0", in("x8") 94, in("x0") status, options(noreturn, nostack));
    }
}
