#!/usr/bin/env python3
"""Verify the CI artifact embeds rustc_driver and exposes only AArch64 LLVM."""
from pathlib import Path
import subprocess
import sys

bundle = Path(sys.argv[1]).resolve()
links = subprocess.check_output(["otool", "-L", str(bundle / "rr")], text=True)
if "librustc_driver" in links or list((bundle / "lib").glob("librustc_driver*")):
    raise SystemExit("rustc_driver is still dynamically linked")
exports = subprocess.check_output(["nm", "-gU", str(bundle / "lib/libLLVM.dylib")], text=True)
if "_LLVMInitializeAArch64Target" not in exports:
    raise SystemExit("AArch64 backend missing")
for backend in ("X86", "ARM", "RISCV", "WebAssembly", "AMDGPU", "NVPTX", "BPF"):
    if f"_LLVMInitialize{backend}Target" in exports:
        raise SystemExit(f"Unexpected LLVM backend: {backend}")
size = sum(file.stat().st_size for file in bundle.rglob("*") if file.is_file())
print(f"PASS static rustc_driver; AArch64-only LLVM; unpacked size {size / 1024**2:.2f} MiB")
print(links)
