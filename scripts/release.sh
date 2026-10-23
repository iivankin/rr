#!/bin/bash
# Build rr's distribution for this machine from the toolchain that
# build-toolchain.sh made, then verify and archive it: rr, the sysroots of
# the host and, on Linux and Windows, of the host's rr target, libFuzzer,
# the smoke checks. Linux, macOS and Windows (Git Bash) hosts.
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo 'Usage: scripts/release.sh RUST_SOURCE TOOLCHAIN SCRATCH NAME' >&2
    exit 1
fi
rr_source="$1"
rr_toolchain="$2"
rr_scratch="$3"
rr_name="$4"
rr_host="$("$rr_toolchain/bin/rustc" -vV | sed -n 's/^host: //p' | tr -d '\r')"
# The host's own rr target: programs on Linux and Windows need no C library.
case "$rr_host" in
*-windows-*) rr_exe=.exe rr_target="${rr_host%%-*}-rr-windows" ;;
*-linux-*) rr_exe= rr_target="${rr_host%%-*}-rr-linux" ;;
*) rr_exe= rr_target= ;;
esac
mkdir -p "$rr_scratch" dist
# Windows has python, not always python3.
rr_python="$(command -v python3 || command -v python)"
python3() { "$rr_python" "$@"; }
export RUSTC="$rr_toolchain/bin/rustc$rr_exe" RUSTDOC="$rr_toolchain/bin/rustdoc$rr_exe"
export SYSROOT="$rr_toolchain" CARGO_TARGET_DIR="$rr_scratch/target"
# Bootstrap controls compiler LTO through rr-bootstrap.toml; this applies
# only to rr. The driver embeds rustc and LLVM: one executable at a time.
# On Linux LLVM's ThinLTO objects are bitcode, which lld reads and the
# GNU linker does not.
# On Windows LLVM's lld-link, beside the clang-cl in CC that compiled
# LLVM, reads them; Visual Studio's linker does not. On Linux x86_64 rr
# keeps its relocations for BOLT, below.
rr_link= rr_lto=thin
case "$rr_host" in
x86_64-*-linux-*) rr_link='-Clink-arg=-fuse-ld=lld -Clink-arg=-Wl,--emit-relocs' ;;
*-linux-*) rr_link=-Clink-arg=-fuse-ld=lld ;;
*-windows-*) rr_link="-Clinker=$(dirname "${CC:?CC must name clang-cl}")/lld-link.exe" ;;
esac
RUSTFLAGS="$rr_link" CARGO_PROFILE_RELEASE_LTO=$rr_lto CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    cargo build --locked --release --bin rr
python3 scripts/build-target-sysroot.py "$RUSTC" "$rr_scratch/client" "$rr_host" $rr_target
python3 scripts/build-fuzz-runtime.py "$rr_source/src/llvm-project/compiler-rt/lib/fuzzer" \
    "$rr_toolchain" "$rr_scratch/fuzz-runtime"
rr_bundle="dist/$rr_name"
scripts/package-rr.sh "$CARGO_TARGET_DIR/release/rr$rr_exe" "$rr_toolchain" "$rr_scratch/client" "$rr_bundle"
python3 scripts/add-fuzz-runtime.py "$rr_scratch/fuzz-runtime" "$rr_bundle"
cp .github/rr-bootstrap.toml "$rr_bundle/bootstrap.toml"
# On Linux x86_64 BOLT lays out rr's code by a profile of rr at its smoke
# work, as official builds lay out rustc's and LLVM's; BOLT on AArch64 is
# not reliable yet.
if [ "$rr_host" = x86_64-unknown-linux-gnu ]; then
    rr_bolt="$rr_scratch/bolt"
    rm -rf "$rr_bolt"
    mkdir -p "$rr_bolt/profiles"
    cp "$rr_bundle/rr" "$rr_bolt/rr"
    llvm-bolt "$rr_bolt/rr" -instrument --instrumentation-file="$rr_bolt/profiles/rr.fdata" \
        --instrumentation-file-append-pid -o "$rr_bundle/rr"
    (unset RUSTC RUSTDOC SYSROOT; python3 scripts/smoke-distribution.py "$rr_bundle" > "$rr_bolt/train.log")
    merge-fdata "$rr_bolt"/profiles/*.fdata > "$rr_bolt/rr.fdata"
    llvm-bolt "$rr_bolt/rr" -data "$rr_bolt/rr.fdata" -o "$rr_bundle/rr" \
        -reorder-blocks=ext-tsp -reorder-functions=cdsort -split-functions \
        -split-strategy=cdsplit -split-all-cold -jump-tables=move -icf=all -dyno-stats
fi
python3 scripts/verify-bundle.py "$rr_bundle" | tee "dist/$rr_name-verification.txt"
unset RUSTC RUSTDOC SYSROOT
python3 scripts/smoke-distribution.py "$rr_bundle" | tee -a "dist/$rr_name-verification.txt"
python3 scripts/smoke-builtins.py "$rr_bundle" | tee -a "dist/$rr_name-verification.txt"
case "$rr_host" in
*-windows-*)
    (cd dist && 7z a -tzip -mx=9 "$rr_name.zip" "$rr_name" >/dev/null)
    ;;
*)
    python3 scripts/smoke-fuzz.py "$rr_bundle" | tee -a "dist/$rr_name-verification.txt"
    tar -C dist -czf "dist/$rr_name.tar.gz" "$rr_name"
    ;;
esac
du -sh "$rr_bundle" dist/"$rr_name".*
