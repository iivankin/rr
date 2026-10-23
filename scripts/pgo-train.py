#!/usr/bin/env python3
"""Run an instrumented compiler (scripts/build-toolchain.sh with RR_PGO set)
over the work rr's compiler does, so that it writes its raw profiles into
PROFILE_DIR: checking rr's own crates and building them and their
dependencies for debugging and for release, building core and alloc, and
compiling rr's example programs as rr does. Cargo is RUSTUP_TOOLCHAIN's,
which must be a nightly."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parent.parent


def main():
    if len(sys.argv) != 3:
        raise SystemExit('Usage: scripts/pgo-train.py TOOLCHAIN PROFILE_DIR')
    toolchain = Path(sys.argv[1]).resolve()
    profiles = Path(sys.argv[2]).resolve()
    profiles.mkdir(parents=True, exist_ok=True)
    rustc = toolchain / 'bin' / ('rustc.exe' if os.name == 'nt' else 'rustc')
    version = subprocess.check_output([rustc, '-vV'], text=True)
    host = next(line[len('host: '):] for line in version.splitlines() if line.startswith('host: '))
    with tempfile.TemporaryDirectory(prefix='rr-pgo-', dir=os.environ.get('TMPDIR')) as scratch:
        scratch = Path(scratch)
        env = dict(os.environ, RUSTC=str(rustc), SYSROOT=str(toolchain),
                   CARGO_TARGET_DIR=str(scratch / 'target'),
                   # Each compiler process writes its own raw profile.
                   LLVM_PROFILE_FILE=str(profiles / 'rr-%m-%p.profraw'))
        for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER'):
            env.pop(name, None)

        def run(*command, cwd=REPO):
            print('+', ' '.join(str(c) for c in command), flush=True)
            subprocess.run(command, cwd=cwd, env=env, check=True)

        run('cargo', 'check', '--locked', '--workspace', '--all-targets')
        # rr's libraries, not its executables, which would link the
        # instrumented compiler without its profiling runtime.
        run('cargo', 'build', '--locked', '-p', 'clippy_lints', '-p', 'rustfmt-nightly')
        run('cargo', 'build', '--locked', '--release', '-p', 'clippy_utils', '-p', 'rustfmt-nightly')
        run(sys.executable, REPO / 'scripts/build-target-sysroot.py', rustc, scratch / 'sysroot', host)
        programs = [REPO / 'examples/corpus/kv/src/main.rs', REPO / 'examples/corpus/lz/src/main.rs']
        for program in programs:
            out = scratch / program.parent.parent.name
            out.mkdir()
            common = [rustc, program, '--edition=2024', '-Cpanic=abort', '--out-dir', out]
            run(*common, '--emit=metadata')
            run(*common, '--emit=obj', '-Copt-level=0', '-Cdebuginfo=1')
            run(*common, '--emit=obj', '-Copt-level=s', '-Ccodegen-units=1')
    raw = list(profiles.glob('*.profraw'))
    if not raw:
        raise SystemExit(f'The compiler wrote no profiles into {profiles}')
    print(f'{len(raw)} raw profiles in {profiles}')


if __name__ == '__main__':
    main()
