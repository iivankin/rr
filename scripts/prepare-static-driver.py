#!/usr/bin/env python3
"""Apply the two required, checked changes to the pinned Rust source."""
from pathlib import Path
import sys


def patch(path, old, new):
    source = path.read_text()
    # A local build may resume after a failed compile or download. Accept only
    # the exact original text or our exact already-applied replacement.
    if source.count(new) == 1 and old not in source:
        return
    if source.count(old) != 1 or new in source:
        raise SystemExit(f"Pinned source changed: {path}; refusing an unverified patch")
    path.write_text(source.replace(old, new))


root = Path(sys.argv[1])
manifest = root / "compiler/rustc_driver/Cargo.toml"
old = 'crate-type = ["dylib"]'
new = '''# rr embeds the compiler driver; do not export a separate compiler dylib.
crate-type = ["rlib"]'''
patch(manifest, old, new)

bootstrap = root / "src/bootstrap/src/core/build_steps/compile.rs"
old = '''                    // Distribute the rest of the rustc crates as rmeta files only to reduce
                    // the tarball sizes by about 50%. The object files are linked into
                    // librustc_driver.so, so it is still possible to link against them.
                    filename.ends_with(".rmeta")'''
new = '''                    // rr statically links rustc_driver, so private compiler crates
                    // need their object archives as well as separate type metadata.
                    filename.ends_with(".rmeta") || filename.ends_with(".rlib")'''
patch(bootstrap, old, new)
