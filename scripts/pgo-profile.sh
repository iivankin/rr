#!/bin/bash
# Gather one of the two PGO profiles of rr's compiler, as official Rust builds
# do: build the compiler with its Rust half (rustc) or its C++ half (llvm)
# instrumented, run it over scripts/pgo-train.py's work, and merge the raw
# profiles into OUT/KIND.profdata, which build-toolchain.sh's RR_PGO=use
# reads. The Rust half's profiles are merged by the compiler's own LLVM;
# the C++ half's by the llvm-profdata of the C++ compiler that built LLVM.
set -euo pipefail
if [ "$#" -ne 4 ] || { [ "$1" != rustc ] && [ "$1" != llvm ]; }; then
    echo 'Usage: scripts/pgo-profile.sh rustc|llvm RUST_SOURCE SCRATCH OUT' >&2
    exit 1
fi
rr_kind="$1"
rr_source="$2"
rr_scratch="$3"
rr_out="$4"
rr_python="$(command -v python3 || command -v python)"
mkdir -p "$rr_scratch" "$rr_out"
rr_prefix="$rr_scratch/toolchain"
rr_raw="$rr_scratch/profiles"
RR_PGO="generate-$rr_kind" RR_PGO_DIR="$rr_scratch/build-profiles" \
    scripts/build-toolchain.sh "$rr_source" "$rr_scratch/build" "$rr_prefix"
# Profiles the compiler wrote while it was being built are not rr's work.
rm -rf "$rr_raw"
"$rr_python" scripts/pgo-train.py "$rr_prefix" "$rr_raw"
rr_host="$("$rr_prefix/bin/rustc" -vV | sed -n 's/^host: //p' | tr -d '\r')"
if [ "$rr_kind" = rustc ]; then
    rr_profdata=("$(find "$rr_source/build" -path '*/llvm/build/bin/llvm-profdata*' -type f -print -quit)")
else
    case "$rr_host" in
    *-apple-darwin) rr_profdata=(xcrun llvm-profdata) ;;
    *-windows-*) rr_profdata=("$(dirname "${CC:?CC must name clang-cl}")/llvm-profdata.exe") ;;
    *) rr_profdata=(llvm-profdata) ;;
    esac
fi
"${rr_profdata[@]}" merge -o "$rr_out/$rr_kind.profdata" "$rr_raw"
"${rr_profdata[@]}" show "$rr_out/$rr_kind.profdata" | tail -n 4
ls -l "$rr_out/$rr_kind.profdata"
