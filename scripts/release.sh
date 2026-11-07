#!/bin/bash
# Build rr for this machine on the official Rust release in
# rust-toolchain.toml, which rustup installs, then package it, install it
# into that toolchain, run the smoke checks there and archive it: rr,
# libFuzzer built from the LLVM of that release, and rr fuz's flags.
# Linux, macOS and Windows (Git Bash, with Visual Studio's tools on PATH).
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo 'Usage: scripts/release.sh SCRATCH NAME' >&2
    exit 1
fi
rr_scratch="$1"
rr_name="$2"
# The LLVM that Rust 1.99.1 is built with, whose libFuzzer rr fuz links.
rr_llvm=1b9c0d5ff9bbe7634aead059efe6b11a7eeba145
rr_toolchain="$(rustc --print sysroot | tr -d '\r')"
rr_host="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
case "$rr_host" in
*-windows-*) rr_exe=.exe ;;
*) rr_exe= ;;
esac
mkdir -p "$rr_scratch" dist
# Windows has python, not always python3.
rr_python="$(command -v python3 || command -v python)"
python3() { "$rr_python" "$@"; }
export CARGO_TARGET_DIR="$rr_scratch/target"
# rr uses the compiler's private crates, as Clippy does.
RUSTC_BOOTSTRAP=1 cargo build --locked --release --bin rr
# libFuzzer's source alone, at the LLVM commit of the release: a sparse,
# blobless checkout, set up by configuration, which Ubuntu 20.04's git
# (2.25) reads as well as a new one; its paths in a file, which Git for
# Windows's bash does not rewrite as it rewrites arguments.
rr_llvm_source="$rr_scratch/llvm"
if [ ! -d "$rr_llvm_source/compiler-rt/lib/fuzzer" ]; then
    rm -rf "$rr_llvm_source"
    git init -q "$rr_llvm_source"
    rr_git() { git -C "$rr_llvm_source" "$@"; }
    rr_git remote add origin https://github.com/rust-lang/llvm-project.git
    rr_git config core.repositoryformatversion 1
    rr_git config extensions.partialClone origin
    rr_git config remote.origin.promisor true
    rr_git config core.sparseCheckout true
    printf '%s\n' /compiler-rt/lib/fuzzer/ /compiler-rt/LICENSE.TXT \
        /compiler-rt/lib/sanitizer_common/sanitizer_coverage_win_sections.cpp \
        > "$rr_llvm_source/.git/info/sparse-checkout"
    rr_git -c protocol.version=2 fetch -q --depth 1 --filter=blob:none origin "$rr_llvm"
    rr_git checkout -q FETCH_HEAD
fi
rm -rf "$rr_scratch/fuzz"
python3 scripts/build-fuzz-runtime.py "$rr_llvm_source/compiler-rt/lib/fuzzer" "$rr_toolchain" "$rr_scratch/fuzz"
rr_bundle="dist/$rr_name"
rm -rf "$rr_bundle"
scripts/package-rr.sh "$CARGO_TARGET_DIR/release/rr$rr_exe" "$rr_scratch/fuzz" "$rr_bundle"
# Installed as install.sh installs it, into the toolchain, and checked
# there.
cp -R "$rr_bundle/." "$rr_toolchain/"
rr="$rr_toolchain/bin/rr$rr_exe"
"$rr" --version | tee "dist/$rr_name-verification.txt"
python3 scripts/smoke-distribution.py "$rr" | tee -a "dist/$rr_name-verification.txt"
case "$rr_host" in
*-windows-*)
    (cd "$rr_bundle" && 7z a -tzip -mx=9 "../$rr_name.zip" . >/dev/null)
    ;;
*)
    python3 scripts/smoke-fuzz.py "$rr" | tee -a "dist/$rr_name-verification.txt"
    tar -C "$rr_bundle" -czf "dist/$rr_name.tar.gz" .
    ;;
esac
du -sh "$rr_bundle" dist/"$rr_name".*
