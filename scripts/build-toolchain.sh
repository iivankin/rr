#!/bin/bash
# Build the pinned compiler for this machine with rr's changes: the driver
# as a static library, LLVM with the host's own backend only, rust-lld, and
# the library source. Linux, macOS and Windows (Git Bash) hosts.
#
# Profile-guided optimization, as official Rust builds have it, takes three
# builds (see scripts/pgo-profile.sh): RR_PGO=generate-rustc and
# RR_PGO=generate-llvm build a compiler, without LTO, whose Rust or C++ half
# writes raw profiles into RR_PGO_DIR; RR_PGO=use builds the release compiler
# with RR_PGO_DIR/rustc.profdata and llvm.profdata. Cargo's cc passes the
# Rust half's profile flags to C and C++ code that clang compiles, such as
# the compiler's LLVM wrapper and jemalloc, so clang must be the same LLVM
# version as the compiler's, as on Linux (clang 23); clang-cl takes none.
set -euo pipefail
if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/build-toolchain.sh RUST_SOURCE SCRATCH_DIRECTORY INSTALL_PREFIX' >&2
    exit 1
fi
rr_source="$1"
rr_scratch="$2"
rr_prefix="$3"
rr_revision='58cf8f9c35b355199727627d07ae34a4e2846d67'
[ "$(git -C "$rr_source" rev-parse HEAD)" = "$rr_revision" ]
cmake --version
ninja --version
df -h .
cp .github/rr-bootstrap.toml "$rr_source/bootstrap.toml"
"$(command -v python3 || command -v python)" scripts/prepare-static-driver.py "$rr_source"
# Fetch only LLVM explicitly. Bootstrap initializes its other required
# submodules; unrelated tools such as Cargo/Clippy are not rebuilt here.
git -C "$rr_source" submodule update --init --depth 1 src/llvm-project
cd "$rr_source"
mkdir -p "$rr_scratch"
# Windows has python, not always python3.
rr_python="$(command -v python3 || command -v python)"
# rr builds for its host only. The installed toolchain names the host: on
# Windows on ARM, bash itself may be an emulated x86_64 program.
rr_build="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
case "$rr_build" in
x86_64-*) rr_backend=X86 ;;
aarch64-*) rr_backend=AArch64 ;;
*) echo "Unsupported host: $(rustc -vV)" >&2; exit 1 ;;
esac
# LLVM's ThinLTO objects are bitcode: the compiler links with lld, which
# reads them. On Windows LLVM is compiled with LLVM's clang-cl, in CC, and
# archived and linked with the llvm-lib and lld-link beside it; clang's
# runtime directory, with its profiling runtime, must be on LIB. Elsewhere
# the compiler allocates with jemalloc, as official builds do.
# The instrumented compilers below allocate with the system's malloc:
# jemalloc, instrumented, profiles its own start and recurses into itself.
rr_windows=
rr_allocator=jemalloc
case "${RR_PGO:-}" in
generate-*) rr_allocator=system ;;
esac
case "$(uname -s)" in
Linux) rr_set=(--set rust.bootstrap-override-lld=external --set "build.allocator=$rr_allocator") ;;
MINGW* | MSYS* | CYGWIN*)
    rr_windows=1
    rr_llvm_bin="$(dirname "${CC:?CC must name clang-cl}")"
    test -x "$rr_llvm_bin/lld-link.exe"
    test -x "$rr_llvm_bin/llvm-lib.exe"
    rr_set=(--set "target.$rr_build.linker=$rr_llvm_bin/lld-link.exe"
        --set "target.$rr_build.ar=$rr_llvm_bin/llvm-lib.exe")
    ;;
*) rr_set=(--set "build.allocator=$rr_allocator") ;;
esac
rr_set+=(--set "llvm.targets=$rr_backend")
rr_pgo_dir="${RR_PGO_DIR:-}"
if [ -n "$rr_windows" ] && [ -n "$rr_pgo_dir" ]; then
    rr_pgo_dir="$(cygpath -m "$rr_pgo_dir")"
fi
case "${RR_PGO:-}" in
'') ;;
generate-rustc | generate-llvm)
    test -n "$rr_pgo_dir"
    # The instrumented compiler only gathers profiles: no LTO, and as many
    # codegen units as usual. A dynamic LLVM carries the profiling runtime
    # of the C++ compiler that instrumented it; Windows links it statically.
    rr_set+=(--set llvm.thin-lto=false --set rust.lto=off --set rust.codegen-units=16)
    if [ -z "$rr_windows" ]; then
        rr_set+=(--set llvm.link-shared=true)
    fi
    if [ "$RR_PGO" = generate-rustc ]; then
        rr_set+=(--set build.profiler=true --set "pgo.rustc.generate=\"$rr_pgo_dir\"")
    else
        rr_set+=(--set "pgo.llvm.generate=\"$rr_pgo_dir\"")
        # The profiling runtime's value profiles are lists that the
        # compiler's codegen threads extend without ordering their
        # memory: on AArch64 a thread can loop in one forever. Branch
        # counts, the bulk of the profile, need no such lists.
        if [ "$rr_backend" = AArch64 ]; then
            rr_set+=(--set 'llvm.cflags="-mllvm -disable-vp=true"'
                --set 'llvm.cxxflags="-mllvm -disable-vp=true"')
        fi
    fi
    ;;
use)
    test -f "$rr_pgo_dir/rustc.profdata"
    test -f "$rr_pgo_dir/llvm.profdata"
    rr_rustc_profile="$rr_pgo_dir/rustc.profdata"
    rr_llvm_profile="$rr_pgo_dir/llvm.profdata"
    # On Linux clang compiles the LLVM wrapper with the Rust half's profile
    # and LLVM with its own, and the static driver's ThinLTO link, which
    # takes both, needs one profile summary: both halves use the union of
    # the two profiles, whose functions are disjoint.
    if [ "$(uname -s)" = Linux ]; then
        rr_rustc_profile="$rr_pgo_dir/compiler.profdata"
        rr_llvm_profile="$rr_rustc_profile"
        llvm-profdata merge -o "$rr_rustc_profile" \
            "$rr_pgo_dir/rustc.profdata" "$rr_pgo_dir/llvm.profdata"
    fi
    rr_set+=(--set "pgo.rustc.use=\"$rr_rustc_profile\""
        --set "pgo.llvm.use=\"$rr_llvm_profile\"")
    ;;
*) echo "Unknown RR_PGO: $RR_PGO" >&2; exit 1 ;;
esac
"$rr_python" x.py dist --stage 2 -j "${RR_BUILD_JOBS:-6}" ${rr_set[@]+"${rr_set[@]}"} rustc rust-std rustc-dev rust-src
# The host is in the name of the compiler archive bootstrap made.
rr_host="$(ls build/dist/rustc-nightly-*.tar.gz | sed 's|.*/rustc-nightly-||; s|\.tar\.gz$||')"
test -n "$rr_host"
for rr_component in rustc rust-std rustc-dev; do
    rr_archive="build/dist/$rr_component-nightly-$rr_host.tar.gz"
    test -f "$rr_archive"
    tar -xzf "$rr_archive" -C "$rr_scratch"
    "$rr_scratch/$rr_component-nightly-$rr_host/install.sh" \
        --prefix="$rr_prefix" --disable-ldconfig
done
tar -xzf build/dist/rust-src-nightly.tar.gz -C "$rr_scratch"
"$rr_scratch/rust-src-nightly/install.sh" --prefix="$rr_prefix" --disable-ldconfig
"$rr_prefix/bin/rustc" -vV
# Record the backend list from the LLVM that bootstrap actually built.
rr_llvm_config="$(find build -path '*/llvm/build/bin/llvm-config*' -type f -print -quit)"
test -n "$rr_llvm_config"
"$rr_llvm_config" --targets-built | tr -d '\r' > "$rr_prefix/llvm-targets.txt"
test "$(cat "$rr_prefix/llvm-targets.txt")" = "$rr_backend"
rr_tools="$rr_prefix/lib/rustlib/$rr_host/bin"
mkdir -p "$rr_tools"
# rust-lld, in the compiler's component, links rr's Linux and Windows targets.
ls "$rr_tools"/rust-lld*
rr_llvm_build="$(dirname "$(dirname "$rr_llvm_config")")"
case "$rr_host" in
*-apple-darwin)
    # -Cstrip on Darwin needs this real LLVM helper even in the minimal distribution.
    cmake --build "$rr_llvm_build" --target llvm-objcopy -j "${RR_BUILD_JOBS:-6}"
    cp "$rr_llvm_build/bin/llvm-objcopy" "$rr_tools/rust-objcopy"
    ;;
esac
if [ "${RR_PGO:-}" = generate-rustc ]; then
    # The compiler's own LLVM reads the raw profiles of its profiling
    # runtime; scripts/pgo-profile.sh runs it where it is built.
    cmake --build "$rr_llvm_build" --target llvm-profdata -j "${RR_BUILD_JOBS:-6}"
fi
# Fail before building rr if the bootstrap change did not retain static objects.
test -n "$(find "$rr_prefix/lib/rustlib/$rr_host/lib" -name 'librustc_driver-*.rlib' -print -quit)"
