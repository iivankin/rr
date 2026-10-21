#!/usr/bin/env python3
"""Verify a distribution: rr embeds rustc_driver and LLVM with the host's
backend only, depends on nothing but the system's own libraries, and on
Linux and Windows carries the sysroot of the host's rr target and the
rust-lld that links it."""
from pathlib import Path
import platform
import subprocess
import sys

bundle = Path(sys.argv[1]).resolve()
system = platform.system()
rr = bundle / ('rr.exe' if system == 'Windows' else 'rr')

if system == 'Darwin':
    links = subprocess.check_output(['otool', '-L', str(rr)], text=True)
    asan = next(bundle.glob('lib/rustlib/*/lib/librustc-nightly_rt.asan.dylib'), None)
    if any(file != asan for file in bundle.rglob('*.dylib')):
        raise SystemExit('Unexpected dynamic library in standalone bundle')
    if asan is not None:
        if subprocess.check_output(['lipo', '-archs', asan], text=True).strip() != 'arm64':
            raise SystemExit('ASan runtime is not ARM64-only')
        subprocess.run(['codesign', '--verify', asan], check=True)
        for line in subprocess.check_output(['otool', '-L', asan], text=True).splitlines()[2:]:
            dependency = line.strip().split(' (', 1)[0]
            if not dependency.startswith(('/usr/lib/', '/System/Library/')):
                raise SystemExit(f'Non-system ASan dependency: {dependency}')
    for line in links.splitlines()[1:]:
        dependency = line.strip().split(' (', 1)[0]
        if not dependency.startswith(('/usr/lib/', '/System/Library/')):
            raise SystemExit(f'Non-system dynamic dependency: {dependency}')
elif system == 'Linux':
    links = subprocess.check_output(['readelf', '-d', str(rr)], text=True)
    # glibc's, libgcc's, and zlib's, which LLVM compresses debug sections
    # with: every distribution has them.
    allowed = ('libc.so', 'libm.so', 'libdl.so', 'libpthread.so', 'librt.so', 'ld-linux', 'libgcc_s.so',
               'libz.so')
    for line in links.splitlines():
        if '(NEEDED)' in line:
            dependency = line.split('[', 1)[1].rstrip(']')
            if not dependency.startswith(allowed):
                raise SystemExit(f'Non-system dynamic dependency: {dependency}')
else:
    links = ''
    if any(bundle.rglob('*.dll')):
        raise SystemExit('Unexpected dynamic library in standalone bundle')

# Static linking and stripping need not preserve LLVM's C entry-point names.
# Use llvm-config's backend list, recorded from the pinned build before packaging.
version = (bundle / 'compiler-version.txt').read_text()
host = next(line.split(': ', 1)[1].strip() for line in version.splitlines() if line.startswith('host: '))
arch = host.split('-', 1)[0]
backend = {'x86_64': 'X86', 'aarch64': 'AArch64'}[arch]
if (bundle / 'llvm-targets.txt').read_text().split() != [backend]:
    raise SystemExit(f'LLVM build does not contain exactly the {backend} backend')
targets = sorted(p.name for p in (bundle / 'lib/rustlib').iterdir() if p.name != host)
expected = {'Linux': [f'{arch}-rr-linux'], 'Windows': [f'{arch}-rr-windows']}.get(system, [])
if targets != expected:
    raise SystemExit(f'Sysroots besides the host\'s: {targets}, expected {expected}')
for target in expected:
    lib = bundle / 'lib/rustlib' / target
    if not (lib / 'target.json').is_file() or not any((lib / 'lib').glob('librr_crt*.rlib')):
        raise SystemExit(f'No sysroot for {target}')
    if not any(bundle.glob(f'lib/rustlib/{host}/bin/rust-lld*')):
        raise SystemExit(f'No rust-lld to link {target}')
size = sum(file.stat().st_size for file in bundle.rglob('*') if file.is_file())
print(f'PASS static rustc_driver and LLVM; {backend} only; sysroots for {host} {" ".join(expected)}; '
      f'unpacked size {size / 1024**2:.2f} MiB')
print(links)
