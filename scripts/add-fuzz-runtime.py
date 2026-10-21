"""Add the host's fuzzing libraries, flags and a harness to an existing rr
distribution."""
import json
from pathlib import Path
import shutil
import subprocess
import sys


def install(runtime, bundle):
    host = json.loads((runtime / 'fuzz-runtime.json').read_text())['host']
    source = runtime / 'lib/rustlib' / host / 'lib'
    destination = bundle / 'lib/rustlib' / host / 'lib'
    if not destination.is_dir() or not any(bundle.glob('rr*')):
        raise SystemExit(f'Expected a standalone rr distribution with a {host} sysroot')
    for library in source.iterdir():
        shutil.copy2(library, destination / library.name)
        if library.name.endswith('.dylib'):
            subprocess.run(['codesign', '--verify', destination / library.name], check=True)
    shutil.copy2(runtime / 'LICENSE-libFuzzer.txt', bundle / 'licenses/LICENSE-libFuzzer.txt')
    shutil.copy2(runtime / 'fuzz-runtime.json', bundle / 'fuzz-runtime.json')
    templates = Path(__file__).resolve().parent.parent / 'examples/fuzz'
    system = 'macos' if host.endswith('-apple-darwin') else 'windows' if 'windows' in host else 'linux'
    fuzz = bundle / 'fuzz'
    fuzz.mkdir(exist_ok=True)
    shutil.copy2(templates / 'fuzz.rs.in', fuzz / 'fuzz.rs')
    flags = (templates / f'fuzz-{system}.flags').read_text().splitlines()
    if host == 'aarch64-pc-windows-msvc':
        # There each function's counters are padded to an alignment, so a
        # table of one PC per counter cannot match them: counters only.
        flags.remove('-Cllvm-args=-sanitizer-coverage-pc-table')
    (fuzz / 'fuzz.flags').write_text('\n'.join(flags) + '\n')
    shutil.copy2(templates / 'asan.flags', fuzz / 'asan.flags')
    shutil.copy2(templates / 'USAGE.txt', fuzz / 'USAGE.txt')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Usage: add-fuzz-runtime.py RUNTIME DISTRIBUTION')
    install(*(Path(arg).resolve() for arg in sys.argv[1:]))
