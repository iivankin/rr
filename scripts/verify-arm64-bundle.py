#!/usr/bin/env python3
"""Verify the CI artifact embeds rustc_driver and its AArch64-only LLVM."""
from pathlib import Path
import subprocess
import sys

bundle = Path(sys.argv[1]).resolve()
links = subprocess.check_output(["otool", "-L", str(bundle / "rr")], text=True)
if list(bundle.rglob("*.dylib")):
    raise SystemExit("Unexpected compiler dylib in standalone bundle")
for line in links.splitlines()[1:]:
    dependency = line.strip().split(" (", 1)[0]
    if not dependency.startswith(("/usr/lib/", "/System/Library/")):
        raise SystemExit(f"Non-system dynamic dependency: {dependency}")
# Static linking and stripping need not preserve LLVM's C entry-point names.
# Use llvm-config's backend list, recorded from the pinned build before packaging.
if (bundle / "llvm-targets.txt").read_text().strip() != "AArch64":
    raise SystemExit("LLVM build does not contain exactly the AArch64 backend")
size = sum(file.stat().st_size for file in bundle.rglob("*") if file.is_file())
print(f"PASS static rustc_driver and LLVM; AArch64-only; unpacked size {size / 1024**2:.2f} MiB")
print(links)
