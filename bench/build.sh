#!/bin/sh
# Builds every server and the load generator on the Linux box the runs
# use. TOOLS holds go/, node-*/ and zig-*/ (see README); cargo and rustc come from
# PATH (rr's toolchain for rr: rr/build/ is made beforehand by
# PREPARE_ONLY=1 rr/build.sh on a machine whose rr adds from a path).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
TOOLS=${TOOLS:-$here/../tools}
export PATH="$TOOLS/go/bin:$PATH"
cd "$here"
log() { printf '== %s\n' "$*"; }
log load
gcc -O2 -std=gnu11 -Wall -Wextra -Werror -o load/load load/load.c
log c-epoll; sh c-epoll/build.sh
log c-uring; sh c-uring/build.sh
log rr
(cd rr/build && rustc src/main.rs --edition 2024 --crate-name server -C panic=abort \
	-C opt-level=3 -C codegen-units=1 -C lto=fat -C strip=symbols -o server)
log tokio
(cd tokio && cargo build --release -q && cp "${CARGO_TARGET_DIR:-target}/release/server" server)
log monoio
(cd monoio && cargo build --release -q && cp "${CARGO_TARGET_DIR:-target}/release/server" server)
log go; (cd go && go build -o server .)
log zig; ZIG_TOOLS=$TOOLS sh zig/build.sh
log done
