"""Verify real coverage, crash discovery/replay and ASan with rr as
installed in a toolchain: its libFuzzer, and the toolchain's ASan, on a
fuzz target of a project as rr init lays it out."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

HEALTHY = '''    if let Ok(text) = core::str::from_utf8(input) {
        assert!(text.len() == input.len());
    }'''

TARGET = '''//! A fuzz target for rr fuz's checks.

/// Each input libFuzzer makes.
#[cfg(fuzzing)]
pub fn fuzz_bytes(input: &[u8]) {
BODY
}

/// What a deliberate memory error needs.
#[cfg(fuzzing)]
mod sys {
    /// A byte index bytes past the start of an array of 8, which ASan
    /// must catch.
    pub fn read_past(index: usize) -> u8 {
        let bytes = [0u8; 8];
        // rr: escape(unsafe): intentional invalid access verifies this negative ASan smoke test.
        unsafe { *bytes.as_ptr().wrapping_add(index) }
    }
}
'''


def verify(installed):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('RUST', 'CARGO', 'CLIPPY', 'DYLD_', 'ASAN_', 'LSAN_'))
           and key != 'SYSROOT'}
    env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
    # Negative ASan tests must report failure without generating macOS crash logs.
    env['ASAN_OPTIONS'] = 'abort_on_error=0:exitcode=77'
    with tempfile.TemporaryDirectory(prefix='rr-fuzz-check-', dir=env.get('TMPDIR')) as temporary:
        work = Path(temporary)
        # Through a link, as install.sh puts rr on PATH.
        rr = work / 'rr'
        rr.symlink_to(installed)
        scratch = work / 'temporary executables'
        scratch.mkdir()
        env['TMPDIR'] = str(scratch)
        initialized = subprocess.run([str(rr), 'init', 'project'], env=env, cwd=work,
                                     text=True, capture_output=True)
        assert initialized.returncode == 0, initialized.stderr
        project = work / 'project'
        main = project / 'src/main.rs'
        main_text = main.read_text()
        main.write_text(main_text.replace('mod greet;\n', 'mod greet;\nmod target;\n', 1))
        source = project / 'src/target.rs'
        root = project / 'fuzz/target_fuzz_bytes'

        def execute(body, *args, asan=False):
            source.write_text(TARGET.replace('BODY', body))
            command = [str(rr), 'fuz', 'src/main.rs', '--target', 'target::fuzz_bytes', '--crate-name', 'project']
            if asan:
                command += ['--asan']
            result = subprocess.run([*command, '--', *map(str, args)], env=env, cwd=project,
                                    text=True, capture_output=True, timeout=60)
            assert not list(scratch.iterdir()), 'rr fuz left temporary compiler output'
            return result

        healthy = execute(HEALTHY, '-runs=1000', '-seed=1')
        assert healthy.returncode == 0, healthy.stderr
        assert 'inline 8-bit counters' in healthy.stderr, healthy.stderr
        assert 'cov:' in healthy.stderr, healthy.stderr
        print('PASS: a crate\'s fuzz target and real coverage; rr launched through a link without Cargo')

        broken = '    assert!(input != b"RR", "intentional fuzz smoke failure");'
        (root / 'corpus').mkdir(parents=True, exist_ok=True)
        (root / 'corpus/seed').write_bytes(b'RA')
        found = execute(broken, '-runs=100000', '-seed=1', '-max_len=8')
        crashes = list((root / 'artifacts').glob('crash-*'))
        assert found.returncode != 0 and crashes, found.stderr
        crash = next((p for p in crashes if p.read_bytes() == b'RR'), None)
        assert crash is not None, found.stderr
        replay = execute(broken, crash, '-runs=1')
        assert replay.returncode != 0 and 'libFuzzer: deadly signal' in replay.stderr, replay.stderr
        print('PASS: mutated input discovers RR crash; artifact survives and reproduces')

        memory_bug = '''    if input == b"RR" {
        // Prevent optimization from folding a provably invalid access away.
        core::hint::black_box(sys::read_past(core::hint::black_box(input.len() + 6)));
    }'''
        detected = execute(memory_bug, crash, '-runs=1', asan=True)
        assert detected.returncode != 0, detected.stderr
        assert 'AddressSanitizer: stack-buffer-overflow' in detected.stderr, detected.stderr
        print('PASS: the toolchain\'s ASan detects the deliberate stack-buffer-overflow')

        main.write_text(main.read_text().replace('#![no_std]\n', '', 1))
        rejected = execute(HEALTHY, '-runs=1')
        assert rejected.returncode != 0 and 'rr-no-std' in rejected.stderr, rejected.stderr
        assert 'rr fuz: running' not in rejected.stderr, rejected.stderr
        main.write_text(main_text.replace('mod greet;\n', 'mod greet;\nmod target;\n', 1))
        print('PASS: compiler failure retains rr restrictions, does not run the target and cleans temporary output')

        source.write_text(TARGET.replace('BODY', HEALTHY))
        stopped = subprocess.Popen([str(rr), 'fuz', 'src/main.rs', '--target', 'target::fuzz_bytes',
                                    '--crate-name', 'project'], env=env, cwd=project,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    _, stderr = stopped.communicate(timeout=0.2)
                    raise AssertionError(f'Unbounded fuzzer exited before interrupt: {stderr}')
                except subprocess.TimeoutExpired as waiting:
                    if b'inline 8-bit counters' in (waiting.stderr or b''):
                        break
                    assert time.monotonic() < deadline, 'Fuzzer never started'
            # Match a terminal Ctrl-C: signal both the rr parent and its fuzzer child.
            os.killpg(stopped.pid, signal.SIGINT)
            _, stderr = stopped.communicate(timeout=10)
            # Pinned FuzzerOptions.h sets InterruptExitCode=72; rr preserves it.
            assert stopped.returncode == 72 and 'run interrupted; exiting' in stderr, stderr
            assert not list(scratch.iterdir()), 'Ctrl-C left a temporary executable'
        finally:
            if stopped.poll() is None:
                os.killpg(stopped.pid, signal.SIGKILL)
                stopped.wait()
        assert not list(work.rglob('Cargo.toml'))
        assert not list(work.rglob('Cargo.lock'))
        print('PASS: Ctrl-C stops libFuzzer and removes the temporary executable while retaining corpus/crashes')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: smoke-fuzz.py RR')
    verify(Path(sys.argv[1]).resolve())
