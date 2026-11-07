#!/usr/bin/env python3
"""Exercise rr as installed in a toolchain, with that toolchain's rustc
and nothing else of Rust's on PATH: a project as rr init lays it out, the
corpus programs and every registry component, through their Makefiles."""
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    raise SystemExit("Usage: scripts/smoke-distribution.py RR")
rr = Path(sys.argv[1]).resolve()
toolchain = rr.parent.parent
# An explicitly selected build volume must fail if unavailable, rather than
# falling back to the system disk through tempfile's default directory search.
with tempfile.TemporaryDirectory(prefix="rr-smoke-", dir=os.environ.get("TMPDIR")) as scratch:
    root = Path(scratch)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("DYLD_", "RUST", "CARGO", "CLIPPY")) and key != "SYSROOT"}
    windows = platform.system() == "Windows"
    # The toolchain's own tools (rustc for make's build), the system's, and
    # on Windows make's: nothing else of Rust's.
    if windows:
        system = [d for d in os.environ["PATH"].split(os.pathsep)
                  if not any(shutil.which(t, path=d) for t in ("rustc", "cargo"))]
    else:
        system = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    env["PATH"] = os.pathsep.join([str(rr.parent), *system])
    # The toolchain has cargo beside rustc; nothing here runs it, which the
    # check below for its files confirms.
    if shutil.which("rustup", path=env["PATH"]):
        raise SystemExit("Smoke test PATH unexpectedly contains rustup")
    exe = ".exe" if windows else ""

    def run(*args, good=True):
        result = subprocess.run([str(rr), *args], cwd=root, env=env,
                                text=True, encoding="utf-8", errors="replace", capture_output=True)
        if (result.returncode == 0) != good:
            raise AssertionError(f"{args}: {result.stdout}\n{result.stderr}")
        return result

    run("--version")
    sysroot = run("--print", "sysroot").stdout.strip()
    assert Path(sysroot).resolve() == toolchain.resolve(), sysroot
    run("init", "project")
    # make splits a variable at spaces: reach rr through a link, as
    # install.sh does, or on Windows, where a link takes privileges, by its
    # path, with forward slashes, which a recipe run through sh keeps.
    if windows:
        link = rr.as_posix()
    else:
        (root / "rr-link").symlink_to(rr)
        link = root / "rr-link"
    fuzzing = (toolchain / "lib/rustlib/rr/fuzz.flags").is_file()
    def make(*targets):
        done = subprocess.run(["make", f"RR={link}", *targets], cwd=root / "project",
                              env=env, text=True, encoding="utf-8", errors="replace", capture_output=True)
        if done.returncode != 0:
            raise AssertionError(f"make {' '.join(targets)}\n{done.stdout}\n{done.stderr}")
        return done
    make()
    tested = make("test").stdout
    assert "5 passed, 0 failed" in tested, tested
    benched = make("bench").stdout
    assert "bench greet::tests::into_one_buffer ... " in benched and "0 allocations/iter" in benched, benched
    make("format", "check", "lint")
    if fuzzing:
        make("fuzz", "FUZZTIME=5")
    profiled = make("prof").stdout
    # A function as its line tables name it: alone in DWARF's, by its path
    # (project::greet::greet) in a PDB's.
    def named(function):
        return r"(\S+::)?" + function
    assert re.search(named("greet") + "  src/greet.rs:", profiled), profiled
    assert re.search("<- " + named("run") + "  src/main.rs:", profiled), profiled
    over = subprocess.run(["make", f"RR={link}", "prof", "PROFMAX=1"], cwd=root / "project", env=env,
                          text=True, encoding="utf-8", errors="replace", capture_output=True)
    assert over.returncode != 0 and "above the budget" in over.stdout, over.stdout
    copies = profiled.split("copies through memcpy and memmove", 1)
    assert len(copies) == 2 and "greet  src/greet.rs:" in copies[1], profiled
    assert "the places that copy most often" in copies[1], profiled
    assert re.search(" each  " + named("greet") + "  src/greet.rs:", copies[1]), profiled
    over = subprocess.run(["make", f"RR={link}", "prof", "PROFCOPIED=1"], cwd=root / "project", env=env,
                          text=True, encoding="utf-8", errors="replace", capture_output=True)
    assert over.returncode != 0 and "bytes copied, above the budget" in over.stdout, over.stdout
    peak = profiled.split("the heap held at most ", 1)
    assert len(peak) == 2 and int(peak[1].split(" ", 1)[0]) > 0, profiled
    over = subprocess.run(["make", f"RR={link}", "prof", "PROFHEAP=1"], cwd=root / "project", env=env,
                          text=True, encoding="utf-8", errors="replace", capture_output=True)
    assert over.returncode != 0 and "at once, above the budget" in over.stdout, over.stdout
    timed = subprocess.run(["make", f"RR={link}", "time"], cwd=root / "project", env=env,
                           text=True, encoding="utf-8", errors="replace", capture_output=True)
    assert timed.returncode == 0 and "5 runs, the fastest" in timed.stdout, timed.stdout + timed.stderr
    over = subprocess.run(["make", f"RR={link}", "time", "TIMEMS=0"], cwd=root / "project", env=env,
                          text=True, encoding="utf-8", errors="replace", capture_output=True)
    assert over.returncode != 0 and "above the budget of 0 ms" in over.stdout, over.stdout
    # The programs in examples/corpus: every check their Makefiles offer,
    # and a short run of each fuzz target.
    corpus = Path(__file__).resolve().parent.parent / "examples" / "corpus"
    for program in sorted(p for p in corpus.iterdir() if (p / "Makefile").is_file()):
        copy = root / f"corpus-{program.name}"
        shutil.copytree(program, copy, ignore=shutil.ignore_patterns("build", program.name, "fuzz"))
        steps = [("all", "test"), ("bench",), ("time",), ("prof",), ("format", "check", "lint")]
        if fuzzing:
            steps.append(("fuzz", "FUZZTIME=5"))
        for targets in steps:
            done = subprocess.run(["make", f"RR={link}", *targets], cwd=copy, env=env,
                                  text=True, encoding="utf-8", errors="replace", capture_output=True)
            if done.returncode != 0:
                raise AssertionError(f"{program.name}: make {' '.join(targets)}\n{done.stdout}\n{done.stderr}")
    # Every component of the registry in one project, on this machine's
    # CPU: rr add, then the template's checks. Their tests compare the
    # paths on CPU instructions with the portable ones.
    registry = Path(__file__).resolve().parent.parent / "registry"
    run("init", "components")
    components = root / "components"
    names = sorted(p.stem for p in registry.glob("*.json") if p.name != "index.json")
    # The index rr add --list reads is the components' own.
    subprocess.run([sys.executable, str(registry.parent / "scripts" / "registry-index.py"), "--check"], check=True)
    listed = run("add", "--list", str(registry / "index.json")).stdout
    assert all(f"{name}  " in listed for name in names) and "asks: --option roots=" in listed, listed
    for name in names:
        done = subprocess.run([str(rr), "add", str(registry / f"{name}.json")], cwd=components, env=env,
                              text=True, encoding="utf-8", errors="replace", capture_output=True)
        if done.returncode != 0:
            raise AssertionError(f"rr add {name}\n{done.stdout}\n{done.stderr}")
    main = components / "src" / "main.rs"
    roots = sorted({(p.parts[0][:-3] if p.parts[0].endswith(".rs") else p.parts[0]) for p in
                    (f.relative_to(components / "src") for f in (components / "src").rglob("*.rs"))
                    if p.parts[0] not in ("main.rs", "greet.rs", "sys")})
    text = main.read_text()
    main.write_text(text.replace("mod greet;\n", "mod greet;\n" + "".join(f"mod {m};\n" for m in roots), 1))
    for system in ("unix", "windows"):
        own = components / "src" / "sys" / f"{system}.rs"
        added = sorted(p.stem for p in (components / "src" / "sys").glob("*.rs")
                       if p.stem not in ("unix", "windows"))
        own.write_text(own.read_text() + "".join(f"\npub mod {m};\n" for m in added))
    run("fmt", "components/src/main.rs")
    for f in (components / "src").rglob("*.rs"):
        source = registry / f.relative_to(components / "src")
        if source.is_file() and source.read_text() != f.read_text():
            raise AssertionError(f"rr fmt changes registry/{source.relative_to(registry)}")
    for targets in (("check", "lint"), ("test",), ("bench",)):
        done = subprocess.run(["make", f"RR={link}", *targets], cwd=components, env=env,
                              text=True, encoding="utf-8", errors="replace", capture_output=True)
        if done.returncode != 0:
            raise AssertionError(f"components: make {' '.join(targets)}\n{done.stdout}\n{done.stderr}")
        if targets == ("bench",):
            # The numbers of this CPU, for the log.
            print("\n".join(l for l in done.stdout.splitlines() if l.startswith("bench ")))
    # rustc builds a library, rr checks a crate against it, and builds none.
    run("init", "library", "--lib")
    subprocess.run([str(rr.parent / f"rustc{exe}"), "--edition=2024", "library/src/lib.rs", "--crate-name", "dep",
                    "--crate-type=rlib", "-Cpanic=abort", "-o", "libdep.rlib"], cwd=root, env=env, check=True)
    (root / "local.rs").write_text("pub fn offset() -> u32 { 1 }\n")
    (root / "lib.rs").write_text("#![no_std]\nmod local;\npub fn value() -> u32 { dep::answer() + local::offset() }\n")
    run("check", "lib.rs", "--extern", "dep=libdep.rlib")
    assert "build it with rustc" in run("lib.rs", "--extern", "dep=libdep.rlib", "-o", "libapp.rlib", good=False).stderr
    (root / "lib.rs").write_text("#![no_std]\npub fn copy(v: u8) -> u8 { v.clone() }\n")
    assert "rr-unexplained-escape" in run("check", "lib.rs", good=False).stderr
    (root / "lib.rs").write_text("#![no_std]\npub fn copy(v: u8) -> u8 {\n// rr: escape(copy): this API deliberately exercises Clone on a scalar.\nv.clone()\n}\n")
    run("check", "lib.rs")
    (root / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    assert "rr-no-std" in run("check", "lib.rs", "--cap-lints=allow", "--force-warn=rr", good=False).stderr
    assert not list(root.rglob("Cargo.toml"))
    assert not list(root.rglob("Cargo.lock"))
    print("PASS: rr in its toolchain; only that toolchain on PATH, no DYLD/SYSROOT overrides; init project make/test/bench/format/check/lint/fuzz/prof/time, corpus programs make/test/bench/format/check/lint/fuzz/prof/time, registry components, check against a rustc-built dependency, restrictions")
