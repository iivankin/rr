#!/usr/bin/env python3
"""Exercise a relocated bundle without Rust/Cargo tools or loader overrides."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    raise SystemExit("Usage: scripts/smoke-distribution.py DISTRIBUTION")
source = Path(sys.argv[1]).resolve()
# An explicitly selected build volume must fail if unavailable, rather than
# falling back to the system disk through tempfile's default directory search.
with tempfile.TemporaryDirectory(prefix="rr-relocated-", dir=os.environ.get("TMPDIR")) as scratch:
    root = Path(scratch)
    bundle = root / "tool with spaces"
    shutil.copytree(source, bundle)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("DYLD_", "RUST", "CARGO", "CLIPPY")) and key != "SYSROOT"}
    windows = platform.system() == "Windows"
    if windows:
        # The system's own directories, and make's: nothing of Rust's.
        env["PATH"] = os.pathsep.join(d for d in os.environ["PATH"].split(os.pathsep)
                                      if not any(shutil.which(t, path=d) for t in ("rustc", "cargo")))
    else:
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    for tool in ("rustc", "rustup", "cargo"):
        if shutil.which(tool, path=env["PATH"]):
            raise SystemExit(f"Smoke test PATH unexpectedly contains {tool}")
    exe = ".exe" if windows else ""
    rr = bundle / f"rr{exe}"

    def run(*args, good=True):
        result = subprocess.run([str(rr), *args], cwd=root, env=env,
                                text=True, capture_output=True)
        if (result.returncode == 0) != good:
            raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
        return result

    run("--version")
    sysroot = run("--print", "sysroot").stdout.strip()
    assert Path(sysroot).resolve() == bundle.resolve(), sysroot
    run("init", "native")
    run("native/src/main.rs", "--crate-name", "native", "-O", "-o", f"native/app{exe}")
    run("lint", "native/src/main.rs", "--crate-name", "native", "-Dwarnings")
    subprocess.run([str(root / f"native/app{exe}")], env=env, check=True)
    # A project as rr init lays it out: every check its Makefile offers.
    run("init", "project")
    # make splits a variable at spaces: reach the bundle through a link,
    # or on Windows, where a link takes privileges, a copy.
    if windows:
        shutil.copytree(bundle, root / "rr-copy")
        link = root / "rr-copy" / f"rr{exe}"
    else:
        (root / "rr-link").symlink_to(rr)
        link = root / "rr-link"
    fuzzing = (bundle / "fuzz/fuzz.flags").is_file()
    make = lambda *targets: subprocess.run(["make", f"RR={link}", *targets], cwd=root / "project",
                                           env=env, check=True, text=True, capture_output=True)
    make()
    tested = make("test").stdout
    assert "4 passed, 0 failed" in tested, tested
    benched = make("bench").stdout
    assert "bench greet::tests::into_one_buffer ... " in benched and "0 allocations/iter" in benched, benched
    make("format", "check", "lint")
    if fuzzing:
        make("fuzz", "FUZZTIME=5")
    profiled = make("prof").stdout
    assert "greet  src/greet.rs:" in profiled and "<- run  src/main.rs:" in profiled, profiled
    over = subprocess.run(["make", f"RR={link}", "prof", "PROFMAX=1"], cwd=root / "project", env=env,
                          text=True, capture_output=True)
    assert over.returncode != 0 and "above the budget" in over.stdout, over.stdout
    copies = profiled.split("copies through memcpy and memmove", 1)
    assert len(copies) == 2 and "greet  src/greet.rs:" in copies[1], profiled
    over = subprocess.run(["make", f"RR={link}", "prof", "PROFCOPIED=1"], cwd=root / "project", env=env,
                          text=True, capture_output=True)
    assert over.returncode != 0 and "bytes copied, above the budget" in over.stdout, over.stdout
    # The programs in examples/corpus: every check their Makefiles offer,
    # and a short run of each fuzz target, on this bundle.
    corpus = Path(__file__).resolve().parent.parent / "examples" / "corpus"
    for program in sorted(p for p in corpus.iterdir() if (p / "Makefile").is_file()):
        copy = root / f"corpus-{program.name}"
        shutil.copytree(program, copy, ignore=shutil.ignore_patterns("build", program.name, "fuzz"))
        steps = [("all", "test"), ("bench",), ("format", "check", "lint")]
        if fuzzing:
            steps.append(("fuzz", "FUZZTIME=5"))
        for targets in steps:
            done = subprocess.run(["make", f"RR={link}", *targets], cwd=copy, env=env,
                                  text=True, capture_output=True)
            if done.returncode != 0:
                raise AssertionError(f"{program.name}: make {' '.join(targets)}\n{done.stdout}\n{done.stderr}")
    run("init", "library", "--lib")
    run("build", "library/src/lib.rs", "--crate-name", "dep", "-o", "libdep.rlib")
    (root / "local.rs").write_text("pub fn offset() -> u32 { 1 }\n")
    (root / "lib.rs").write_text("#![no_std]\nmod local;\npub fn value() -> u32 { dep::answer() + local::offset() }\n")
    run("lib.rs", "--extern", "dep=libdep.rlib", "-o", "libapp.rlib")
    (root / "alloc.rs").write_text("#![no_std]\nextern crate alloc;\npub fn bytes() -> alloc::vec::Vec<u8> { alloc::vec::Vec::new() }\n")
    run("alloc.rs", "--crate-type=rlib", "--crate-name", "alloc_fixture", "-o", "liballoc_fixture.rlib")
    (root / "lib.rs").write_text("#![no_std]\npub fn copy(v: u8) -> u8 { v.clone() }\n")
    assert "rr-unexplained-escape" in run("check", "lib.rs", good=False).stderr
    (root / "lib.rs").write_text("#![no_std]\npub fn copy(v: u8) -> u8 {\n// rr: escape(copy): this API deliberately exercises Clone on a scalar.\nv.clone()\n}\n")
    run("check", "lib.rs")
    (root / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    assert "rr-no-std" in run("check", "lib.rs", "--cap-lints=allow", "--force-warn=rr", good=False).stderr
    assert not list(root.rglob("Cargo.toml"))
    assert not list(root.rglob("Cargo.lock"))
    assert not list((root / "native").glob("*.rmeta"))
    print("PASS: relocated bundle; no Rust/Cargo PATH or DYLD/SYSROOT overrides; init project make/test/bench/format/check/lint/fuzz/prof, corpus programs make/test/bench/format/check/lint/fuzz, check/lint/build/native execution/extern/local modules/alloc/restrictions")
