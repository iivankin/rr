#!/bin/sh
# Check every scenario of bench/zig/server against ../SPEC.md with curl. Linux only.
#
#   ./test.sh                  builds with ./build.sh unless SERVER=path is given
#   PORT_BASE=18400 ./test.sh  first of the five ports used
set -eu

here=$(cd "$(dirname "$0")" && pwd)
port=${PORT_BASE:-18400}

if [ -z "${SERVER:-}" ]; then
	"$here/build.sh"
	SERVER=$here/server
fi

# FNV over 64 KiB of zeroes, 200 rounds: the offset basis times the prime^(200 * 65536), mod
# 2^64, from python3 -c 'print(14695981039346656037 * pow(1099511628211, 200 * 65536, 2**64)
# % 2**64)', and checked against the loop itself by the test in server.zig.
hash200=17515195554806768421

tmp=$(mktemp -d)
pids=
cleanup() {
	for pid in $pids; do kill "$pid" 2>/dev/null || true; done
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

failures=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; failures=$((failures + 1)); }
check() { # name expected actual
	if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: want '$2', got '$3'"; fi
}

# start NAME SCENARIO PORT [VAR=value...]: run the server, wait for its `ready` line.
start() {
	name=$1 scenario=$2 p=$3
	shift 3
	env "$@" "$SERVER" "$scenario" "$p" >"$tmp/$name.out" 2>"$tmp/$name.err" &
	pids="$pids $!"
	i=0
	until [ "$(cat "$tmp/$name.out")" = ready ]; do
		i=$((i + 1))
		if [ $i -gt 100 ]; then
			echo "server $name did not print ready:" >&2
			cat "$tmp/$name.err" >&2
			exit 1
		fi
		sleep 0.05
	done
}

url() { echo "http://127.0.0.1:$1$2"; }
# get PORT PATH: body on stdout; `type` and `status` saved for the checks.
get() {
	curl -sS -o "$tmp/body" -w '%{http_code} %{content_type}' "$(url "$1" "$2")" >"$tmp/meta"
	cat "$tmp/body"
}
status() { cut -d' ' -f1 "$tmp/meta"; }
ctype() { cut -d' ' -f2- "$tmp/meta"; }

bio=$(head -c 900 /dev/zero | tr '\0' a)
user_json() {
	printf '{"id":%s,"name":"user%s","email":"user%s@example.com","active":true,' "$1" "$1" "$1"
	printf '"roles":["reader","writer"],"balance":1234.56,"bio":"%s"}' "$bio"
}

# Two requests in one segment on one connection: both must be answered.
two_in_one() { # PORT PATH
	r="GET $2 HTTP/1.1\r\nHost: t\r\n\r\n"
	timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; printf '$r$r' >&3; cat <&3" \
		>"$tmp/two" 2>/dev/null || true
	grep -ac '^HTTP/1.1 200 OK' "$tmp/two" || true
}

# json --------------------------------------------------------------------------------------
json_port=$port
start json json "$json_port"
check "json /user/42 body" "$(user_json 42)" "$(get "$json_port" /user/42)"
check "json content type" application/json "$(ctype)"
check "json /user/4294967295" "$(user_json 4294967295)" "$(get "$json_port" /user/4294967295)"
get "$json_port" /user/4294967296 >/dev/null
check "json u32 overflow is 404" 404 "$(status)"
get "$json_port" /nope >/dev/null
check "json unknown path is 404" 404 "$(status)"
check "json empty 404 body" 0 "$(wc -c <"$tmp/body" | tr -d ' ')"
check "json keep-alive, two requests in one segment" 2 "$(two_in_one "$json_port" /user/1)"
n=$(curl -sS "$(url "$json_port" /user/1)" "$(url "$json_port" /user/2)" \
	"$(url "$json_port" /nope)" "$(url "$json_port" /user/3)" -o /dev/null -o /dev/null \
	-o /dev/null -o /dev/null -w '%{num_connects}\n' | awk '{ n += $1 } END { print n }')
check "json one connection for four requests" 1 "$n"

# static ------------------------------------------------------------------------------------
files=$tmp/files
mkdir "$files"
head -c 4096 /dev/urandom >"$files/4k"
head -c 65536 /dev/urandom >"$files/64k"
head -c 1048576 /dev/urandom >"$files/1m"
static_port=$((port + 1))
start static static "$static_port" FILES="$files"
for f in 4k 64k 1m; do
	get "$static_port" "/file/$f" >/dev/null
	if cmp -s "$tmp/body" "$files/$f"; then pass "static /file/$f bytes"; else
		fail "static /file/$f: $(wc -c <"$tmp/body") bytes differ from the file"; fi
	check "static /file/$f content type" application/octet-stream "$(ctype)"
done
get "$static_port" /file/missing >/dev/null
check "static missing file is 404" 404 "$(status)"
get "$static_port" /file/.. >/dev/null
check "static .. is 404" 404 "$(status)"
# The file is read on every request: a change shows up at once.
head -c 4096 /dev/urandom >"$files/4k"
get "$static_port" /file/4k >/dev/null
if cmp -s "$tmp/body" "$files/4k"; then pass "static no caching"; else fail "static cached"; fi
check "static keep-alive, two 1m in one segment" 2 "$(two_in_one "$static_port" /file/1m)"

# proxy -------------------------------------------------------------------------------------
proxy_port=$((port + 2))
start proxy proxy "$proxy_port" BACKEND="127.0.0.1:$json_port"
check "proxy /proxy/7 body" "$(user_json 7)" "$(get "$proxy_port" /proxy/7)"
check "proxy content type" application/json "$(ctype)"
check "proxy status" 200 "$(status)"
curl -sS "$(url "$proxy_port" /proxy/8)" "$(url "$proxy_port" /proxy/9)" \
	-o "$tmp/p8" -o "$tmp/p9"
check "proxy keep-alive upstream, second request" "$(user_json 9)" "$(cat "$tmp/p9")"
get "$proxy_port" /user/1 >/dev/null
check "proxy /user is 404" 404 "$(status)"

# wal ---------------------------------------------------------------------------------------
wal_port=$((port + 3))
log=$tmp/wal.log
echo stale >"$log"
start wal wal "$wal_port" LOG="$log"
check "wal truncates at start" 0 "$(wc -c <"$log" | tr -d ' ')"
head -c 256 /dev/urandom >"$tmp/rec"
reply=$(curl -sS -w ' %{content_type}' --data-binary @"$tmp/rec" \
	-H 'Content-Type: application/octet-stream' "$(url "$wal_port" /log)")
check "wal POST /log answers ok" "ok text/plain" "$reply"
if cmp -s "$log" "$tmp/rec"; then pass "wal record on disk"; else fail "wal record differs"; fi
# Concurrent appends, so that some share an fdatasync.
i=0 curls=
while [ $i -lt 32 ]; do
	curl -sS --data-binary @"$tmp/rec" "$(url "$wal_port" /log)" >"$tmp/wal.$i" &
	curls="$curls $!"
	i=$((i + 1))
done
for pid in $curls; do wait "$pid" || true; done
oks=$(for f in "$tmp"/wal.[0-9]*; do cat "$f"; echo; done | grep -c '^ok$' || true)
check "wal 32 concurrent POSTs answered" 32 "$oks"
check "wal log size" $((33 * 256)) "$(wc -c <"$log" | tr -d ' ')"
get "$wal_port" /log >/dev/null
check "wal GET /log is 404" 404 "$(status)"

# cpu ---------------------------------------------------------------------------------------
cpu_port=$((port + 4))
start cpu cpu "$cpu_port"
check "cpu /hash/200" "$hash200" "$(get "$cpu_port" /hash/200)"
check "cpu hash content type" text/plain "$(ctype)"
check "cpu /user/5" "$(user_json 5)" "$(get "$cpu_port" /user/5)"
i=0 curls=
while [ $i -lt 8 ]; do
	curl -sS "$(url "$cpu_port" /hash/200)" >"$tmp/h.$i" &
	curls="$curls $!"
	i=$((i + 1))
done
check "cpu /user/6 while hashing" "$(user_json 6)" "$(get "$cpu_port" /user/6)"
for pid in $curls; do wait "$pid" || true; done
same=$(for f in "$tmp"/h.[0-9]*; do cat "$f"; echo; done | grep -c "^$hash200\$" || true)
check "cpu 8 concurrent hashes" 8 "$same"

for pid in $pids; do
	kill -0 "$pid" 2>/dev/null || fail "server $pid died"
done
if [ $failures -ne 0 ]; then
	echo "$failures check(s) failed" >&2
	exit 1
fi
echo "all checks passed"
