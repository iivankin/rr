#!/bin/bash
# Lay out rr for a toolchain: unpacked into the official Rust toolchain
# it was built on, bin/rr sits beside rustc, as clippy-driver does, and
# loads that toolchain's compiler; lib/rustlib/rr/ holds what is rr's own:
# libFuzzer and rr fuz's flags, the Rust release it needs, licenses.
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo 'Usage: scripts/package-rr.sh BUILT_RR FUZZ_RUNTIME NEW_DESTINATION' >&2
    exit 1
fi
rr_binary="$1"
rr_fuzz="$2"
rr_destination="$3"
if [ -e "$rr_destination" ]; then
    echo "Destination already exists: $rr_destination" >&2
    exit 1
fi
rr_host="$(rustc -vV | sed -n 's/^host: //p' | tr -d '\r')"
rr_release="$(rustc -V | sed -n 's/^rustc \([0-9.]*\) .*/\1/p')"
case "$rr_host" in
*-windows-*) rr_exe=.exe ;;
*) rr_exe= ;;
esac
rr_own="$rr_destination/lib/rustlib/rr"
mkdir -p "$rr_destination/bin" "$rr_own/licenses"
cp "$rr_binary" "$rr_destination/bin/rr$rr_exe"
cp "$rr_fuzz"/* "$rr_own/"
mv "$rr_own/LICENSE-libFuzzer.txt" "$rr_own/licenses/"
# install.sh reads which release to install before it unpacks rr into it.
echo "$rr_release" > "$rr_own/rust-version"
cp LICENSE-MIT LICENSE-APACHE COPYRIGHT "$rr_own/licenses/"
cp RR.md "$rr_own/README.md"
case "$rr_host" in
*-apple-darwin)
    chmod u+w "$rr_destination/bin/rr"
    xcrun strip -S -x "$rr_destination/bin/rr"
    codesign --force --sign - "$rr_destination/bin/rr"
    ;;
*-linux-*)
    chmod u+w "$rr_destination/bin/rr"
    strip -S "$rr_destination/bin/rr"
    ;;
esac
