#!/usr/bin/env python3
"""Build sysroots for a compiler: core, alloc and compiler_builtins, all
panic=abort. For one of rr's Linux and Windows targets (targets/*.json),
compiler_builtins has its memory functions, since no C library gives
them, and rr_crt, the start that calls the program's `main`, comes too.
Any other target, such as the host's own, is built as it is. The
library crates are built
by Cargo's -Zbuild-std, so that compiler_builtins gets the configuration
its own build script gives it; Cargo takes their source from the
compiler's rust-src component, which must be installed."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parent.parent


def build(rustc, destination, target):
    lib = destination / 'lib/rustlib' / target
    if lib.exists():
        raise SystemExit(f'Destination already has {target}: {lib}')
    (lib / 'lib').mkdir(parents=True)
    spec = REPO / 'targets' / f'{target}.json'
    rr_target = spec.is_file()
    if rr_target:
        # rustc finds a target by name in its sysroot, as lib/rustlib/NAME/target.json.
        shutil.copy2(spec, lib / 'target.json')
    with tempfile.TemporaryDirectory(prefix='rr-sysroot-', dir=os.environ.get('TMPDIR')) as scratch:
        scratch = Path(scratch)
        crate = scratch / 'crate'
        (crate / 'src').mkdir(parents=True)
        (crate / 'Cargo.toml').write_text(
            '[package]\nname = "rr_sysroot"\nversion = "0.0.0"\nedition = "2024"\n\n'
            '[profile.release]\npanic = "abort"\nopt-level = 2\ncodegen-units = 1\n')
        (crate / 'src/lib.rs').write_text('#![no_std]\n')
        flags = '-Cembed-bitcode=yes'
        if rr_target:
            flags += f' -Zunstable-options --sysroot={destination}'
        env = dict(os.environ, RUSTC=str(rustc), CARGO_TARGET_DIR=str(scratch / 'target'), RUSTFLAGS=flags)
        env.pop('CARGO_ENCODED_RUSTFLAGS', None)
        features = ['-Zbuild-std-features=compiler-builtins-mem'] if rr_target else []
        subprocess.run(['cargo', 'build', '--release', '--quiet', '-Zbuild-std=core,alloc', *features,
                        '--target', target], cwd=crate, env=env, check=True)
        built = scratch / 'target' / target / 'release'
        for name in ('core', 'alloc', 'compiler_builtins'):
            found = list(built.glob(f'build/{name}/*/out/lib{name}-*.rlib')) or \
                list(built.glob(f'deps/lib{name}-*.rlib'))
            if len(found) != 1:
                raise SystemExit(f'Expected one {name} for {target}, found {found}')
            shutil.copy2(found[0], lib / 'lib')
    if not rr_target:
        return
    os_name = target.rsplit('-', 1)[1]
    subprocess.run([rustc, REPO / 'targets' / f'crt_{os_name}.rs', '--crate-name=rr_crt',
                    '--crate-type=rlib', '--edition=2024', '-Zunstable-options', '--target', target,
                    '--sysroot', destination, '-Cpanic=abort', '-Copt-level=2', '-Cembed-bitcode=yes',
                    '--out-dir', lib / 'lib'], check=True)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        raise SystemExit('Usage: build-target-sysroot.py RUSTC SYSROOT TARGET...')
    rustc, destination = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
    library = Path(subprocess.check_output([rustc, '--print', 'sysroot'], text=True).strip())
    if not (library / 'lib/rustlib/src/rust/library/core').is_dir():
        raise SystemExit(f'{rustc} has no rust-src component')
    for name in sys.argv[3:]:
        build(rustc, destination, name)
