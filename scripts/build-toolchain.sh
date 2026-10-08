#!/bin/bash
set -euo pipefail
if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/build-toolchain.sh RUST_SOURCE SCRATCH_DIRECTORY INSTALL_PREFIX' >&2
    exit 1
fi
rr_source="$1"
rr_scratch="$2"
rr_prefix="$3"
rr_revision='84b36a78a28a63f134171c670be1932ffa2485f8'
[ "$(uname -m)" = arm64 ]
[ "$(git -C "$rr_source" rev-parse HEAD)" = "$rr_revision" ]
cmake --version
ninja --version
df -h .
cp .github/rr-bootstrap.toml "$rr_source/bootstrap.toml"
python3 scripts/prepare-static-driver.py "$rr_source"
# Fetch only LLVM explicitly. Bootstrap initializes its other required
# submodules; unrelated tools such as Cargo/Clippy are not rebuilt here.
git -C "$rr_source" submodule update --init --depth 1 src/llvm-project
cd "$rr_source"
./x dist --stage 2 -j "${RR_BUILD_JOBS:-6}" rustc rust-std rustc-dev
for rr_component in rustc rust-std rustc-dev; do
    rr_archive="build/dist/$rr_component-nightly-aarch64-apple-darwin.tar.gz"
    test -f "$rr_archive"
    tar -xzf "$rr_archive" -C "$rr_scratch"
    "$rr_scratch/$rr_component-nightly-aarch64-apple-darwin/install.sh" \
        --prefix="$rr_prefix" --disable-ldconfig
done
"$rr_prefix/bin/rustc" -vV
# Record the backend list from the LLVM that bootstrap actually built.
rr_llvm_config="$(find build -path '*/llvm/build/bin/llvm-config' -type f -print -quit)"
test -n "$rr_llvm_config"
"$rr_llvm_config" --targets-built > "$rr_prefix/llvm-targets.txt"
test "$(cat "$rr_prefix/llvm-targets.txt")" = AArch64
# Fail before building rr if the bootstrap change did not retain static objects.
test -n "$(find "$rr_prefix/lib/rustlib/aarch64-apple-darwin/lib" -name 'librustc_driver-*.rlib' -print -quit)"
if [ -n "${GITHUB_ENV:-}" ]; then
    # A static development driver has no compiler dylib path to locate its sysroot.
    cat >> "$GITHUB_ENV" <<ENV
RR_TOOLCHAIN=$rr_prefix
RUSTC=$rr_prefix/bin/rustc
RUSTDOC=$rr_prefix/bin/rustdoc
SYSROOT=$rr_prefix
DYLD_LIBRARY_PATH=$rr_prefix/lib
ENV
fi
