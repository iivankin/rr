#!/bin/bash
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ]; then
    echo 'This compiler/LLVM build must run in GitHub Actions.' >&2
    exit 1
fi
rr_project="$PWD"
rr_source="$rr_project/ci-rust"
rr_prefix="$RUNNER_TEMP/rr-toolchain"
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
./x dist --stage 2 rustc rust-std rustc-dev
for rr_component in rustc rust-std rustc-dev; do
    rr_archive="build/dist/$rr_component-nightly-aarch64-apple-darwin.tar.gz"
    test -f "$rr_archive"
    tar -xzf "$rr_archive" -C "$RUNNER_TEMP"
    "$RUNNER_TEMP/$rr_component-nightly-aarch64-apple-darwin/install.sh" \
        --prefix="$rr_prefix" --disable-ldconfig
 done
"$rr_prefix/bin/rustc" -vV
# Fail before building rr if the bootstrap change did not retain static objects.
test -n "$(find "$rr_prefix/lib/rustlib/aarch64-apple-darwin/lib" -name 'librustc_driver-*.rlib' -print -quit)"
cat >> "$GITHUB_ENV" <<ENV
RR_TOOLCHAIN=$rr_prefix
RUSTC=$rr_prefix/bin/rustc
RUSTDOC=$rr_prefix/bin/rustdoc
DYLD_LIBRARY_PATH=$rr_prefix/lib
ENV
