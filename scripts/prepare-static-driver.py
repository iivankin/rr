#!/usr/bin/env python3
"""Apply the two required, checked changes to the pinned Rust source in CI."""
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest = root / "compiler/rustc_driver/Cargo.toml"
old = 'crate-type = ["dylib"]'
new = '''# rr embeds the compiler driver; do not export a separate compiler dylib.
crate-type = ["rlib"]'''
source = manifest.read_text()
if source.count(old) != 1:
    raise SystemExit("Pinned rustc_driver crate-type changed; refusing an unverified patch")
manifest.write_text(source.replace(old, new))

bootstrap = root / "src/bootstrap/src/core/build_steps/compile.rs"
old = '''                    // Distribute the rest of the rustc crates as rmeta files only to reduce
                    // the tarball sizes by about 50%. The object files are linked into
                    // librustc_driver.so, so it is still possible to link against them.
                    filename.ends_with(".rmeta")'''
new = '''                    // rr statically links rustc_driver, so private compiler crates
                    // need their object archives as well as separate type metadata.
                    filename.ends_with(".rmeta") || filename.ends_with(".rlib")'''
source = bootstrap.read_text()
if source.count(old) != 1:
    raise SystemExit("Pinned bootstrap artifact filter changed; refusing an unverified patch")
bootstrap.write_text(source.replace(old, new))
