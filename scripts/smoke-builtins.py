"""Exercise actual packaged binaries without Cargo, rustc or loader overrides."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

# A real aligned allocator catches sysroot/link failures that an empty Vec misses.
NATIVE_SOURCE = r'''#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use alloc::vec::Vec;
use core::ffi::c_void;

struct Heap;

#[link(name = "c")]
// rr: escape(unsafe): each signature is the C library's, from its headers.
unsafe extern "C" {
    fn posix_memalign(output: &mut *mut c_void, alignment: usize, size: usize) -> i32;
    fn free(pointer: *mut c_void);
    fn abort() -> !;
}

/* rr: escape(unsafe): posix_memalign supplies aligned storage and free releases it;
all GlobalAlloc layouts are supported, not just the byte vector below. */
unsafe impl GlobalAlloc for Heap {
    // rr: escape(unsafe): the caller supplies a nonzero valid layout as required by GlobalAlloc.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut output = core::ptr::null_mut();
        let alignment = layout.align().max(core::mem::size_of::<*mut c_void>());
        // rr: escape(unsafe): output is writable and the alignment meets POSIX's pointer-size requirement.
        let status = unsafe { posix_memalign(&mut output, alignment, layout.size()) };
        if status == 0 {
            output.cast()
        } else {
            core::ptr::null_mut()
        }
    }

    // rr: escape(unsafe): GlobalAlloc's caller guarantees this pointer came from this allocator.
    unsafe fn dealloc(&self, pointer: *mut u8, _: Layout) {
        // rr: escape(unsafe): this is the original posix_memalign allocation, with no live owners.
        unsafe { free(pointer.cast()) };
    }
}

#[global_allocator]
static HEAP: Heap = Heap;

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    let mut values: Vec<u8> = Vec::new();
    values.push(41);
    let answer: Option<u8> = Some(values[0] + 1);
    assert_eq!(answer, Some(42));
    assert_eq!(assembly_value(), 7);
    assert_eq!(concat!("restricted", " rust"), "restricted rust");
    assert!(cfg!(target_pointer_width = "64"));
    let _ = core::format_args!("answer={:?}", answer);
    // rr: escape(copy): this independent snapshot tests Vec allocation and element cloning.
    let snapshot = values.clone();
    assert_eq!(snapshot[0], 41);
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // rr: escape(unsafe): abort terminates this native process when an assertion or allocation fails.
    unsafe { abort() }
}

fn assembly_value() -> u64 {
    let value: u64;
    #[cfg(target_arch = "aarch64")]
    // rr: escape(unsafe): the assembly writes one output register and has no memory or stack effects.
    unsafe {
        core::arch::asm!("mov {value}, #7", value = out(reg) value,
            options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    // rr: escape(unsafe): the assembly writes one output register and has no memory or stack effects.
    unsafe {
        core::arch::asm!("mov {value}, 7", value = out(reg) value,
            options(nomem, nostack, preserves_flags));
    }
    value
}
'''

bundle = Path(sys.argv[1]).resolve()
system = platform.system()
rr = bundle / ('rr.exe' if system == 'Windows' else 'rr')
env = {key: value for key, value in os.environ.items()
       if not key.startswith(('RUST', 'CARGO', 'CLIPPY', 'DYLD_')) and key != 'SYSROOT'}
if system == 'Windows':
    env['PATH'] = os.pathsep.join(d for d in os.environ['PATH'].split(os.pathsep)
                                  if not any(shutil.which(t, path=d) for t in ('rustc', 'cargo')))
else:
    env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
with tempfile.TemporaryDirectory(prefix='rr-builtins-', dir=env.get('TMPDIR')) as directory:
    work = Path(directory)

    def run(*args, good=True, rule=None):
        result = subprocess.run([str(rr), *map(str, args)], cwd=work, env=env,
                                text=True, capture_output=True)
        assert (result.returncode == 0) == good, result.stderr
        if rule:
            assert rule in result.stderr, result.stderr
        return result

    (work / 'included.rs').write_text('pub fn value() -> u8 { 42 }\n')
    (work / 'data.txt').write_text('builtins work\n')
    source = work / 'lib.rs'
    source.write_text('''#![no_std]
include!("included.rs");
pub const TEXT: &str = include_str!("data.txt");
pub const BYTES: &[u8] = include_bytes!("data.txt");
pub fn builtins() -> &'static str {
    assert!(cfg!(target_pointer_width = "64"));
    let _ = (file!(), line!(), column!(), module_path!());
    let _ = option_env!("RR_OPTIONAL_VAR");
    let _ = env!("PATH");
    let _ = stringify!(Option<u8>);
    let _ = core::format_args!("value={}", value());
    concat!("builtin", " macros")
}
''')
    run('check', source)
    run('lint', source)
    run('build', source, '-O', '-o', work / 'builtins.rlib')
    source.write_text('#![no_std]\ninclude!("included.rs");\n')
    for included, rule in (
            ('pub fn generic<T>(value:T)->T { value }', 'rr-no-generics'),
            ('pub fn copied(value:u8)->u8 { value.clone() }', 'rr-unexplained-escape'),
            ('pub unsafe fn unchecked() {}', 'rr-unexplained-escape')):
        (work / 'included.rs').write_text(included)
        run('check', source, good=False, rule=rule)
    for text in (
            '#![no_std]\n#[derive(Copy, Clone)] pub struct Data;',
            '#![no_std]\nextern crate alloc; pub fn f() { let _ = alloc::vec![1]; }',
            '#![no_std]\nuse core::matches as concat; pub fn f()->bool { concat!(1, 1) }'):
        source.write_text(text)
        run('check', source, good=False, rule='rr-no-macros')
    # A program of the C library: on Linux, the host's own target and its
    # cc; Windows has no C library of that kind.
    if system != 'Windows':
        (work / 'main.rs').write_text(NATIVE_SOURCE)
        host = run('--print', 'host-tuple').stdout.strip()
        native = ['--target', host] if system == 'Linux' else []
        result = run(work / 'main.rs', *native, '-O', '-Cstrip=debuginfo', '-Ztime-passes', '-o', work / 'app')
        subprocess.run([str(work / 'app')], env=env, check=True)
        print(result.stderr)
    print('PASS: packaged builtin macros, checked include source, forbidden derive/library macros, native Option/Vec/clone/assert/assembly execution')
