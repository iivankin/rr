#!/bin/bash
# Build the pinned compiler for this machine with rr's changes: the driver
# as a static library, LLVM with the host's own backend only, rust-lld, and
# the library source. Linux, macOS and Windows (Git Bash) hosts.
set -euo pipefail
if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/build-toolchain.sh RUST_SOURCE SCRATCH_DIRECTORY INSTALL_PREFIX' >&2
    exit 1
fi
rr_source="$1"
rr_scratch="$2"
rr_prefix="$3"
rr_revision='84b36a78a28a63f134171c670be1932ffa2485f8'
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
# reads them. On Windows LLVM is compiled with Visual Studio's clang-cl, in
# CC, and archived and linked with the llvm-lib and lld-link beside it.
case "$(uname -s)" in
Linux) rr_set=(--set rust.bootstrap-override-lld=external) ;;
MINGW* | MSYS* | CYGWIN*)
    rr_llvm_bin="$(dirname "${CC:?CC must name clang-cl}")"
    test -x "$rr_llvm_bin/lld-link.exe"
    test -x "$rr_llvm_bin/llvm-lib.exe"
    rr_set=(--set "target.$rr_build.linker=$rr_llvm_bin/lld-link.exe"
        --set "target.$rr_build.ar=$rr_llvm_bin/llvm-lib.exe")
    ;;
*) rr_set=() ;;
esac
rr_set+=(--set "llvm.targets=$rr_backend")
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
case "$rr_host" in
*-apple-darwin)
    # -Cstrip on Darwin needs this real LLVM helper even in the minimal distribution.
    rr_llvm_build="$(dirname "$(dirname "$rr_llvm_config")")"
    cmake --build "$rr_llvm_build" --target llvm-objcopy -j "${RR_BUILD_JOBS:-6}"
    cp "$rr_llvm_build/bin/llvm-objcopy" "$rr_tools/rust-objcopy"
    ;;
esac
# Fail before building rr if the bootstrap change did not retain static objects.
test -n "$(find "$rr_prefix/lib/rustlib/$rr_host/lib" -name 'librustc_driver-*.rlib' -print -quit)"
