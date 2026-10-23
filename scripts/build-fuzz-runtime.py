"""Build pinned libFuzzer for the toolchain's host, and keep its matching
AddressSanitizer runtime: macOS with Xcode's clang++, Linux with the
system's c++, Windows with Visual Studio's cl."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

RUST = '58cf8f9c35b355199727627d07ae34a4e2846d67'
LLVM = '1b9c0d5ff9bbe7634aead059efe6b11a7eeba145'


def compile_command(host, file, output):
    if host.endswith('-apple-darwin'):
        return ['xcrun', 'clang++', '-std=c++17', '-O2', '-gline-tables-only', '-fPIC',
                '-fno-omit-frame-pointer', '-arch', 'arm64', '-mmacosx-version-min=11.0',
                '-c', file, '-o', output]
    if host.endswith('-windows-msvc'):
        include = Path(file).parent.parent  # compiler-rt/lib, for sanitizer_common's headers
        return ['cl', '/nologo', '/std:c++17', '/O2', '/MD', '/EHsc', f'/I{include}', '/c', file, f'/Fo{output}']
    return ['c++', '-std=c++17', '-O2', '-g1', '-fPIC', '-fno-omit-frame-pointer', '-c', file,
            '-o', output]


def build(source, toolchain, destination):
    version = subprocess.check_output([toolchain / 'bin/rustc', '-vV'], text=True)
    host = next(line[len('host: '):] for line in version.splitlines() if line.startswith('host: '))
    if f'commit-hash: {RUST}' not in version:
        raise SystemExit('Expected the pinned toolchain')
    if destination.exists():
        raise SystemExit(f'Destination already exists: {destination}')
    # The normal caller uses the exact LLVM submodule of the pinned Rust checkout.
    # The standalone source-directory caller records every source hash below.
    sources = sorted(p for p in source.glob('*.cpp') if p.name != 'FuzzerInterceptors.cpp')
    if len(sources) != 25:
        raise SystemExit('Expected the 25 sources in the pinned LLVM fuzzer runtime')
    if host.endswith('-windows-msvc'):
        # On COFF, coverage's section bounds are defined by compiler-rt, not
        # by the linker: libFuzzer's archive carries them.
        sources.append(source.parent / 'sanitizer_common/sanitizer_coverage_win_sections.cpp')
    toolchain_lib = toolchain / 'lib/rustlib' / host / 'lib'
    asan_sources = sorted(toolchain_lib.glob('librustc-nightly_rt.asan.*'))
    if not asan_sources and not host.endswith('-windows-msvc'):
        raise SystemExit('Toolchain is missing ASan; enable build.sanitizers in bootstrap')
    lib = destination / 'lib/rustlib' / host / 'lib'
    lib.mkdir(parents=True)
    windows = host.endswith('-windows-msvc')
    archive = lib / ('Fuzzer.lib' if windows else 'libFuzzer.a')
    with tempfile.TemporaryDirectory(prefix='fuzzer-objects-', dir=destination.parent) as temporary:
        objects = Path(temporary)

        def compile_source(file):
            output = objects / (file.stem + ('.obj' if windows else '.o'))
            subprocess.run(compile_command(host, file, output), check=True)
            return output

        # Follow compiler-rt's fuzzer target: its interceptors are a separate library.
        with ThreadPoolExecutor(max_workers=3) as pool:
            outputs = list(pool.map(compile_source, sources))
        if windows:
            subprocess.run(['lib', '/nologo', f'/OUT:{archive}', *outputs], check=True)
        elif host.endswith('-apple-darwin'):
            subprocess.run(['xcrun', 'ar', 'rcs', archive, *outputs], check=True)
        else:
            subprocess.run(['ar', 'rcs', archive, *outputs], check=True)
    hashes = {'libfuzzer_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
    for asan_source in asan_sources:
        asan = lib / asan_source.name
        if host.endswith('-apple-darwin'):
            architectures = subprocess.check_output(['xcrun', 'lipo', '-archs', asan_source], text=True).split()
            if 'arm64' not in architectures:
                raise SystemExit('Toolchain ASan runtime has no ARM64 architecture')
            # lipo -thin accepts only universal files; native bootstrap may already be thin.
            if architectures == ['arm64']:
                shutil.copy2(asan_source, asan)
            else:
                subprocess.run(['xcrun', 'lipo', asan_source, '-thin', 'arm64', '-output', asan], check=True)
            subprocess.run(['codesign', '--force', '--sign', '-', asan], check=True)
        else:
            shutil.copy2(asan_source, asan)
        hashes['asan_sha256'] = hashlib.sha256(asan.read_bytes()).hexdigest()
    files = sorted(p for p in source.iterdir() if p.is_file())
    provenance = {'rust_commit': RUST, 'llvm_commit': LLVM, 'host': host,
                  'source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
                  **hashes}
    (destination / 'fuzz-runtime.json').write_text(json.dumps(provenance, indent=2) + '\n')
    license = source / 'LICENSE.TXT'
    if not license.is_file():
        license = source.parent.parent / 'LICENSE.TXT'
    (destination / 'LICENSE-libFuzzer.txt').write_bytes(license.read_bytes())


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('Usage: build-fuzz-runtime.py LIBFUZZER_SOURCE TOOLCHAIN NEW_RUNTIME')
    build(*(Path(arg).resolve() for arg in sys.argv[1:]))
