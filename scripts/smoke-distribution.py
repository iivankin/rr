#!/usr/bin/env python3
"""Exercise a relocated bundle without Rust/Cargo tools or loader overrides."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    raise SystemExit("Usage: scripts/smoke-distribution.py DISTRIBUTION")
source = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="rr-relocated-") as scratch:
    root = Path(scratch)
    bundle = root / "tool with spaces"
    shutil.copytree(source, bundle)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("DYLD_", "RUST", "CARGO", "CLIPPY")) and key != "SYSROOT"}
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    for tool in ("rustc", "rustup", "cargo"):
        if shutil.which(tool, path=env["PATH"]):
            raise SystemExit(f"Smoke test PATH unexpectedly contains {tool}")
    rr = bundle / "rr"

    def run(*args, good=True):
        result = subprocess.run([str(rr), *args], cwd=root, env=env,
                                text=True, capture_output=True)
        if (result.returncode == 0) != good:
            raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
        return result

    run("--version")
    sysroot = run("--print", "sysroot").stdout.strip()
    assert Path(sysroot) == bundle, sysroot
    run("init", "native")
    run("check", "native/main.rs")
    run("lint", "native/main.rs", "-Dwarnings", "-Wclippy::cargo")
    run("native/main.rs", "-O", "-o", "native/app")
    subprocess.run([str(root / "native/app")], env=env, check=True)
    run("init", "library", "--lib")
    run("build", "library/lib.rs", "--crate-name", "dep", "-o", "libdep.rlib")
    (root / "local.rs").write_text("pub fn offset() -> u32 { 1 }\n")
    (root / "lib.rs").write_text("#![no_std]\nmod local;\npub fn value() -> u32 { dep::answer() + local::offset() }\n")
    run("lib.rs", "--extern", "dep=libdep.rlib", "-o", "libapp.rlib")
    (root / "alloc.rs").write_text("#![no_std]\nextern crate alloc;\npub fn bytes() -> alloc::vec::Vec<u8> { alloc::vec::Vec::new() }\n")
    run("alloc.rs", "--crate-type=rlib", "--crate-name", "alloc_fixture", "-o", "liballoc_fixture.rlib")
    (root / "lib.rs").write_text("#![no_std]\npub fn copy(v: u8) -> u8 { v.clone() }\n")
    assert "rr-unexplained-escape" in run("check", "lib.rs", good=False).stderr
    (root / "lib.rs").write_text("#![no_std]\npub fn copy(v: u8) -> u8 {\n// rr: escape: this API deliberately exercises Clone on a scalar.\nv.clone()\n}\n")
    run("check", "lib.rs")
    (root / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    assert "rr-no-std" in run("check", "lib.rs", "--cap-lints=allow", "--force-warn=rr", good=False).stderr
    assert not list(root.rglob("Cargo.toml"))
    assert not list(root.rglob("Cargo.lock"))
    assert not list((root / "native").glob("*.rmeta"))
    print("PASS: relocated bundle; no Rust/Cargo PATH or DYLD/SYSROOT overrides; init/check/lint/build/native execution/extern/local modules/alloc/restrictions")
