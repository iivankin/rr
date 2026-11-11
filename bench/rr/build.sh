#!/bin/sh
# Builds the rr server: an rr project in build/ of this directory's src
# and the registry's thread and io, cut for Linux; rustc as the
# template's Makefile builds the program. RR runs rr init and rr add
# (an rr that adds a component from its path).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
registry=$(cd "$here/../../registry" && pwd)
RR=${RR:-rr}
out=$here/build
rm -rf "$out"
"$RR" init "$out" >/dev/null
cd "$out"
rm -f src/greet.rs
cp "$here/src/main.rs" "$here/src/env.rs" "$here/src/server.rs" src/
"$RR" add --yes --option os=${OS_OPTION:-linux} "$registry/thread.rs" "$registry/io.rs" >/dev/null
# PREPARE_ONLY: the project alone, for a machine whose rr cannot add
# from a path, which then runs the rustc line below in build/.
[ -n "${PREPARE_ONLY:-}" ] && exit 0
rustc src/main.rs --edition 2024 --crate-name server -C panic=abort \
	-C opt-level=3 -C codegen-units=1 -C lto=fat -C strip=symbols -o server
echo "$out/server"
