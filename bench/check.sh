#!/bin/sh
# Checks that a stack's server does what SPEC.md says, scenario by
# scenario, against the bytes SPEC gives:
#
#   sh check.sh STACK...        (rr tokio monoio go node zig c-epoll c-uring)
#
# Each server runs on its own port; the proxy's backend is c-epoll json.
# One line for each check that fails; the last line counts them.
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/stacks.sh"
work=${TMPDIR:-/tmp}/bench-check
rm -rf "$work"; mkdir -p "$work/files"
head -c 4096 /dev/urandom > "$work/files/4k"
head -c 65536 /dev/urandom > "$work/files/64k"
head -c 1048576 /dev/urandom > "$work/files/1m"
head -c 256 /dev/zero | tr '\0' 'z' > "$work/body"
bio=$(head -c 900 /dev/zero | tr '\0' 'a')
want() {
	printf '{"id":%s,"name":"user%s","email":"user%s@example.com","active":true,"roles":["reader","writer"],"balance":1234.56,"bio":"%s"}' "$1" "$1" "$1" "$bio"
}
failed=0
fail() { echo "FAIL $stack $*"; failed=$((failed + 1)); }
pids=
start() { # scenario port [env]
	scenario=$1 port=$2; shift 2
	env "$@" sh -c "exec $(command_of "$stack") $scenario $port" > "$work/$stack-$scenario-$port.out" 2>&1 &
	pids="$pids $!"
	i=0
	while ! grep -q ready "$work/$stack-$scenario-$port.out" 2>/dev/null; do
		i=$((i + 1)); [ $i -gt 100 ] && { fail "$scenario: no ready"; return 1; }
		sleep 0.05
	done
}
stop() { for p in $pids; do kill "$p" 2>/dev/null; done; for p in $pids; do wait "$p" 2>/dev/null; done; pids=; }

stack=c-epoll
start json 19000 || exit 1
backend_pid=$pids; pids=

for stack in "$@"; do
	base=19100
	start json $((base + 1)) && {
		[ "$(curl -s -m 5 localhost:$((base + 1))/user/7)" = "$(want 7)" ] || fail "json body"
		got=$(curl -s -m 5 -o /dev/null -o /dev/null -w '%{num_connects}' localhost:$((base + 1))/user/1 localhost:$((base + 1))/user/2)
		[ "$got" = "10" ] || fail "json keep-alive ($got)"
		[ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:$((base + 1))/nope)" = 404 ] || fail "json 404"
		kind=$(curl -s -m 5 -o /dev/null -w '%{content_type}' localhost:$((base + 1))/user/3)
		[ "$kind" = application/json ] || fail "json type ($kind)"
	}
	start static $((base + 2)) FILES="$work/files" && for f in 4k 64k 1m; do
		curl -s -m 10 localhost:$((base + 2))/file/$f -o "$work/got"
		cmp -s "$work/got" "$work/files/$f" || fail "static $f"
	done
	start proxy $((base + 3)) BACKEND=127.0.0.1:19000 && {
		[ "$(curl -s -m 5 localhost:$((base + 3))/proxy/42)" = "$(want 42)" ] || fail "proxy body"
		got=$(curl -s -m 5 localhost:$((base + 3))/proxy/1 localhost:$((base + 3))/proxy/2)
		[ "$got" = "$(want 1)$(want 2)" ] || fail "proxy keep-alive"
	}
	rm -f "$work/log"
	start wal $((base + 4)) LOG="$work/log" && {
		[ "$(curl -s -m 5 -X POST --data-binary @"$work/body" localhost:$((base + 4))/log)" = ok ] || fail "wal ok"
		i=0 posts=
		while [ $i -lt 32 ]; do
			curl -s -m 5 -o /dev/null -X POST --data-binary @"$work/body" localhost:$((base + 4))/log &
			posts="$posts $!"; i=$((i + 1))
		done
		for p in $posts; do wait "$p"; done
		size=$(wc -c < "$work/log")
		[ "$size" -eq $((33 * 256)) ] || fail "wal size ($size)"
	}
	start cpu $((base + 5)) && {
		[ "$(curl -s -m 30 localhost:$((base + 5))/hash/200)" = 17515195554806768421 ] || fail "cpu hash"
		[ "$(curl -s -m 5 localhost:$((base + 5))/user/9)" = "$(want 9)" ] || fail "cpu json"
	}
	stop
	echo "checked $stack"
done
kill $backend_pid 2>/dev/null; wait $backend_pid 2>/dev/null
echo "failed: $failed"
[ $failed -eq 0 ]
