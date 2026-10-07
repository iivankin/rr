#!/bin/bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/package-rr.sh BUILT_RR TOOLCHAIN_ROOT NEW_DESTINATION' >&2
    exit 1
fi
rr_binary="$1"
rr_toolchain="$2"
rr_destination="$3"
rr_host="$("$rr_toolchain/bin/rustc" -vV | sed -n 's/^host: //p')"
if [ "$rr_host" != 'aarch64-apple-darwin' ]; then
    echo "This packaging script currently supports macOS arm64; got $rr_host" >&2
    exit 1
fi
if [ -e "$rr_destination" ]; then
    echo "Destination already exists: $rr_destination" >&2
    exit 1
fi
rr_library="$rr_destination/lib/rustlib/$rr_host/lib"
mkdir -p "$rr_library" "$rr_destination/licenses"
cp "$rr_binary" "$rr_destination/rr"
cp "$rr_toolchain/llvm-targets.txt" "$rr_destination/"
# In this pinned toolchain, these rlibs refer to separate rmeta files. Both are required
# for type checking and compilation; copying only object archives is insufficient.
for rr_crate in core alloc compiler_builtins; do
    cp "$rr_toolchain/lib/rustlib/$rr_host/lib/lib$rr_crate"-*.rlib "$rr_library/"
    cp "$rr_toolchain/lib/rustlib/$rr_host/lib/lib$rr_crate"-*.rmeta "$rr_library/"
done
# LLVM and the compiler driver are already embedded in rr. Only target library
# objects and metadata remain external; they are inputs for compiling user code.
chmod u+w "$rr_destination/rr"
xcrun strip -S -x "$rr_destination/rr"
codesign --force --sign - "$rr_destination/rr"
cp LICENSE-MIT LICENSE-APACHE "$rr_destination/licenses/"
cp "$rr_toolchain/share/doc/rust/COPYRIGHT.html" "$rr_toolchain/share/doc/rust/COPYRIGHT-library.html" "$rr_destination/licenses/"
cp -R "$rr_toolchain/share/doc/rust/licenses" "$rr_destination/licenses/rust-dependencies"
cp RR.md "$rr_destination/README.md"
"$rr_toolchain/bin/rustc" -vV > "$rr_destination/compiler-version.txt"
"$rr_destination/rr" --version
