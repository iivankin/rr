"""Verify real coverage, crash discovery/replay and ASan with the shipped runtime."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def verify(bundle):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('RUST', 'CARGO', 'CLIPPY', 'DYLD_', 'ASAN_', 'LSAN_'))
           and key != 'SYSROOT'}
    env['PATH'] = '/usr/bin:/bin:/usr/sbin:/sbin'
    # Negative ASan tests must report failure without generating macOS crash logs.
    env['ASAN_OPTIONS'] = 'abort_on_error=0:exitcode=77'
    with tempfile.TemporaryDirectory(prefix='rr-fuzz-check-', dir=env.get('TMPDIR')) as temporary:
        work = Path(temporary)
        relocated = work / 'tool with spaces'
        shutil.copytree(bundle, relocated)
        rr = work / 'rr'
        rr.symlink_to(relocated / 'rr')
        scratch = work / 'temporary executables'
        scratch.mkdir()
        env['TMPDIR'] = str(scratch)
        initialized = subprocess.run([str(rr), 'fuz', 'init'], env=env, cwd=work,
                                     text=True, capture_output=True)
        assert initialized.returncode == 0, initialized.stderr
        source = work / 'fuz.rs'
        template = source.read_text()
        marker = '''    if let Ok(text) = core::str::from_utf8(input) {
        assert!(text.len() == input.len());
    }'''
        assert template.count(marker) == 1
        corpus = work / 'corpus'
        (corpus / 'seed').write_bytes(b'RA')
        artifacts = work / 'artifacts'

        def execute(text, *args, asan=False):
            source.write_text(text)
            command = [str(rr), 'fuz', str(source)]
            if asan:
                command += ['--asan']
            result = subprocess.run([*command, '--', *map(str, args)], env=env, cwd=work,
                                    text=True, capture_output=True, timeout=30)
            assert not list(scratch.iterdir()), 'rr fuz left temporary compiler output'
            return result

        healthy = execute(template, '-runs=1000', '-seed=1')
        assert healthy.returncode == 0, healthy.stderr
        assert 'inline 8-bit counters' in healthy.stderr, healthy.stderr
        assert 'cov:' in healthy.stderr, healthy.stderr
        print('PASS: rr fuz init and real coverage; relocated bundle launched through a symlink without Cargo')

        broken = template.replace(marker, '    assert!(input != b"RR", "intentional fuzz smoke failure");')
        found = execute(broken, '-runs=100000', '-seed=1', '-max_len=8')
        crashes = list(artifacts.glob('crash-*'))
        assert found.returncode != 0 and crashes, found.stderr
        crash = next((p for p in crashes if p.read_bytes() == b'RR'), None)
        assert crash is not None, found.stderr
        replay = execute(broken, crash, '-runs=1')
        assert replay.returncode != 0 and 'libFuzzer: deadly signal' in replay.stderr, replay.stderr
        print('PASS: mutated input discovers RR crash; artifact survives and reproduces')

        memory_bug = template.replace(marker, '''    if input == b"RR" {
        let bytes = [0u8; 8];
        // Prevent optimization from folding a provably invalid access away.
        let index = core::hint::black_box(input.len() + 6);
        // rr: escape(unsafe): intentional invalid access verifies this negative ASan smoke test.
        let value = unsafe { *bytes.as_ptr().wrapping_add(index) };
        core::hint::black_box(value);
    }''')
        detected = execute(memory_bug, crash, '-runs=1', asan=True)
        assert detected.returncode != 0, detected.stderr
        assert 'AddressSanitizer: stack-buffer-overflow' in detected.stderr, detected.stderr
        print('PASS: bundled ARM64 ASan detects the deliberate stack-buffer-overflow')

        rejected = execute(template.replace('#![no_std]', ''), '-runs=1')
        assert rejected.returncode != 0 and 'rr-no-std' in rejected.stderr, rejected.stderr
        assert 'rr fuz: running' not in rejected.stderr, rejected.stderr
        print('PASS: compiler failure retains rr restrictions, does not run the harness and cleans temporary output')

        source.write_text(template)
        stopped = subprocess.Popen([str(rr), 'fuz', str(source)], env=env, cwd=work,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 20
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
        raise SystemExit('Usage: smoke-fuzz.py DISTRIBUTION')
    verify(Path(sys.argv[1]).resolve())
