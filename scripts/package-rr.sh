#!/bin/bash
# Lay out an rr distribution: the rr executable, which embeds the compiler
# and LLVM; the sysroots it compiles against, for the host and on Linux
# and Windows for the host's rr target; rust-lld, which links that; and
# licenses.
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo 'Usage: scripts/package-rr.sh BUILT_RR TOOLCHAIN_ROOT CLIENT_SYSROOT NEW_DESTINATION' >&2
    exit 1
fi
rr_binary="$1"
rr_toolchain="$2"
rr_client_sysroot="$3"
rr_destination="$4"
rr_host="$("$rr_toolchain/bin/rustc" -vV | sed -n 's/^host: //p' | tr -d '\r')"
if [ -e "$rr_destination" ]; then
    echo "Destination already exists: $rr_destination" >&2
    exit 1
fi
case "$rr_host" in
*-windows-*) rr_exe=.exe ;;
*) rr_exe= ;;
esac
mkdir -p "$rr_destination/licenses"
cp "$rr_binary" "$rr_destination/rr$rr_exe"
cp "$rr_toolchain/llvm-targets.txt" "$rr_destination/"
# The client sysroots are rebuilt with panic=abort, separately from the
# compiler runtime: the host's, and the host's rr target's, with its
# target.json and start. Their rlibs and rmeta files are inputs for
# compiling user code; nothing of the compiler's own runtime is needed.
for rr_target in "$rr_client_sysroot"/lib/rustlib/*/; do
    rr_name="$(basename "$rr_target")"
    mkdir -p "$rr_destination/lib/rustlib/$rr_name/lib"
    cp "$rr_target"lib/*.rlib "$rr_destination/lib/rustlib/$rr_name/lib/"
    cp "$rr_target"lib/*.rmeta "$rr_destination/lib/rustlib/$rr_name/lib/" 2>/dev/null || true
    if [ -f "$rr_target/target.json" ]; then
        cp "$rr_target/target.json" "$rr_destination/lib/rustlib/$rr_name/"
    fi
done
test -d "$rr_destination/lib/rustlib/$rr_host/lib"
rr_tools="$rr_destination/lib/rustlib/$rr_host/bin"
mkdir -p "$rr_tools"
case "$rr_host" in
*-apple-darwin)
    # Darwin rustc uses this utility for -Cstrip; without it rr clients
    # requesting stripped output fail after linking.
    cp "$rr_toolchain/lib/rustlib/$rr_host/bin/rust-objcopy" "$rr_tools/"
    for rr_tool in "$rr_tools/rust-objcopy" "$rr_destination/rr"; do
        chmod u+w "$rr_tool"
        xcrun strip -S -x "$rr_tool"
        codesign --force --sign - "$rr_tool"
    done
    ;;
*-linux-*)
    # rust-lld links the host's rr target; through gcc-ld/ld.lld it is
    # also the linker cc runs for x86_64-unknown-linux-gnu, as rustc
    # links that by default, for fuzz targets.
    cp "$rr_toolchain/lib/rustlib/$rr_host/bin/rust-lld" "$rr_tools/"
    mkdir -p "$rr_tools/gcc-ld"
    cp "$rr_toolchain/lib/rustlib/$rr_host/bin/gcc-ld/ld.lld" "$rr_tools/gcc-ld/"
    # LLVM and the compiler driver are embedded in rr; keep the symbols
    # its panics name, drop the debug information.
    chmod u+w "$rr_destination/rr" "$rr_tools/rust-lld"
    strip -S "$rr_destination/rr" "$rr_tools/rust-lld"
    ;;
*-windows-*)
    # rust-lld links the host's rr target.
    cp "$rr_toolchain/lib/rustlib/$rr_host/bin/rust-lld.exe" "$rr_tools/"
    ;;
esac
cp LICENSE-MIT LICENSE-APACHE "$rr_destination/licenses/"
cp "$rr_toolchain/share/doc/rust/COPYRIGHT.html" "$rr_toolchain/share/doc/rust/COPYRIGHT-library.html" "$rr_destination/licenses/"
cp -R "$rr_toolchain/share/doc/rust/licenses" "$rr_destination/licenses/rust-dependencies"
cp RR.md "$rr_destination/README.md"
"$rr_toolchain/bin/rustc" -vV > "$rr_destination/compiler-version.txt"
"$rr_destination/rr$rr_exe" --version
