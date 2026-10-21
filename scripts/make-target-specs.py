#!/usr/bin/env python3
"""Write targets/*.json, rr's Linux and Windows targets, from the pinned
compiler's own specs: Linux without libc, a static executable that calls
the kernel; Windows without a C runtime, calling kernel32.dll through
raw-dylib imports. Both link with the bundled rust-lld and start in
rr_crt (targets/crt_*.rs), which hands argc and argv to the program's
`main`. Run again when the compiler changes."""
import json
from pathlib import Path
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit('Usage: scripts/make-target-specs.py RUSTC')
rustc = sys.argv[1]
out = Path(__file__).resolve().parent.parent / 'targets'


def spec(target):
    text = subprocess.check_output([rustc, '-Zunstable-options', '--print', 'target-spec-json',
                                    '--target', target], text=True)
    return json.loads(text)


def linux(arch):
    s = spec(f'{arch}-unknown-linux-gnu')
    for key in ('pre-link-args', 'supported-sanitizers', 'supports-fentry', 'supports-xray', 'has-rpath',
                'relro-level', 'static-position-independent-executables', 'default-uwtable',
                'crt-objects-fallback', 'supported-split-debuginfo'):
        s.pop(key, None)
    s.update({
        'metadata': {'description': f'{arch} Linux without libc: rr programs call the kernel', 'std': False},
        'vendor': 'rr', 'env': '', 'linker': 'rust-lld', 'linker-flavor': 'gnu-lld',
        # Each load segment on pages of its own in the file: Rosetta, which
        # runs x86_64 Linux on Apple silicon, refuses a segment of only .bss.
        'pre-link-args': {'gnu-lld': ['-static', '-z', 'separate-loadable-segments']},
        'dynamic-linking': False, 'position-independent-executables': False,
        'relocation-model': 'static', 'crt-static-default': True,
        'has-thread-local': False, 'panic-strategy': 'abort', 'no-default-libraries': True,
    })
    return s


def windows(arch):
    s = spec(f'{arch}-pc-windows-gnullvm')
    for key in ('late-link-args', 'crt-objects-fallback', 'pre-link-objects-fallback', 'linker',
                'dll-tls-export', 'target-mcount', 'crt-static-allows-dylibs'):
        s.pop(key, None)
    machine = s['pre-link-args']['gnu-lld']
    s.update({
        'metadata': {'description': f'{arch} Windows without a C runtime: rr programs call kernel32.dll',
                     'std': False},
        # env gnu and abi llvm stay: the ABI is MinGW's, with LLVM's runtime
        # pieces, and compiler_builtins gives its stack probes for it.
        'vendor': 'rr', 'linker': 'rust-lld', 'linker-flavor': 'gnu-lld',
        'pre-link-args': {'gnu-lld': [*machine, '--subsystem', 'console']},
        'has-thread-local': False, 'panic-strategy': 'abort', 'no-default-libraries': True,
    })
    return s


out.mkdir(exist_ok=True)
for arch in ('x86_64', 'aarch64'):
    for name, s in ((f'{arch}-rr-linux', linux(arch)), (f'{arch}-rr-windows', windows(arch))):
        (out / f'{name}.json').write_text(json.dumps(s, indent=2, sort_keys=True) + '\n')
        print(out / f'{name}.json')
