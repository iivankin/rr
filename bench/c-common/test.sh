#!/bin/bash
# Functional check of one bench server against ../SPEC.md, on Linux.
# usage: test.sh SERVER EPOLL_SERVER
# EPOLL_SERVER (c-epoll/server) is the proxy backend. Needs curl,
# coreutils (timeout, head, cmp, stat) and bash (/dev/tcp).
set -u

if [ $# -ne 2 ] || [ ! -x "$1" ] || [ ! -x "$2" ]; then
	echo "usage: test.sh SERVER EPOLL_SERVER (both built)" >&2
	exit 2
fi
SRV=$(realpath "$1")
BE=$(realpath "$2")
command -v curl >/dev/null || { echo "test.sh: needs curl" >&2; exit 2; }

T=$(mktemp -d)
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$T"
}
trap cleanup EXIT

pass=0
fails=0
ok() { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fails=$((fails + 1)); echo "FAIL $1"; }
short() { printf %s "$1" | head -c 160; }
check() {   # name expected actual
	if [ "$2" = "$3" ]; then
		ok "$1"
	else
		bad "$1: expected [$(short "$2")] got [$(short "$3")]"
	fi
}

port=$((20000 + RANDOM % 30000))
nextport() { port=$((port + 1)); }

# start BIN SCENARIO PORT [VAR=value...]: run it, wait for "ready".
start() {
	local bin=$1 sc=$2 p=$3 _
	shift 3
	env "$@" "$bin" "$sc" "$p" >"$T/out.$p" 2>"$T/err.$p" &
	pids+=($!)
	for _ in $(seq 200); do
		grep -qx ready "$T/out.$p" 2>/dev/null && return 0
		kill -0 "${pids[-1]}" 2>/dev/null || break
		sleep 0.05
	done
	echo "server $bin $sc $p did not print ready:" >&2
	cat "$T/err.$p" >&2
	exit 1
}

A900=$(head -c 900 /dev/zero | tr '\0' a)
json_for() {
	printf '{"id":%s,"name":"user%s","email":"user%s@example.com","active":true,"roles":["reader","writer"],"balance":1234.56,"bio":"%s"}' \
		"$1" "$1" "$1" "$A900"
}

# get URL: "<code> <content-type> <bytes>" and the body in $T/body.
get() {
	curl -s --path-as-is -o "$T/body" \
		-w '%{http_code} %{content_type} %{size_download}' "$@"
}

# raw PORT: send stdin's bytes on one connection, print what comes back
# within 1 s (the server keeps the connection open).
raw() {
	local r
	exec 3<>"/dev/tcp/127.0.0.1/$1"
	cat >&3
	r=$(timeout 1 cat <&3)
	exec 3<&-
	printf %s "$r"
}

count() { grep -o "$1" | wc -l | tr -d ' '; }

alive() {   # every server still running
	local p
	for p in "${pids[@]}"; do
		kill -0 "$p" 2>/dev/null || { bad "server pid $p died"; return; }
	done
	ok "servers alive"
}

# ---------------------------------------------------------------- json
nextport; PJ=$port
start "$SRV" json "$PJ"
U=http://127.0.0.1:$PJ

for id in 42 0 4294967295; do
	b=$(json_for "$id")
	r=$(get "$U/user/$id")
	check "json /user/$id status" "200 application/json ${#b}" "$r"
	check "json /user/$id body" "$b" "$(cat "$T/body")"
done
check "json /user/007 is id 7" "$(json_for 7)" "$(curl -s "$U/user/007")"
for p in /user/4294967296 /user/abc /user/ /user /nope /file/4k /hash/1 /log; do
	check "json GET $p is 404" "404 0" "$(curl -s -o /dev/null -w '%{http_code} %{size_download}' "$U$p")"
done
check "json POST /user/1 is 404" 404 \
	"$(curl -s -o /dev/null -w '%{http_code}' -d x "$U/user/1")"

b=$(json_for 9)
exp=$(printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s' "${#b}" "$b")
got=$(printf 'GET /user/9 HTTP/1.1\r\nHost: x\r\n\r\n' | raw "$PJ")
check "json exact response bytes" "$exp" "$got"
got=$(printf 'GET /nope HTTP/1.1\r\nHost: x\r\n\r\n' | raw "$PJ")
check "404 exact response bytes" \
	"$(printf 'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')" "$got"

check "json keep-alive: one connection for 3" "1 0 0 " \
	"$(curl -s -o /dev/null -o /dev/null -o /dev/null -w '%{num_connects} ' "$U/user/1" "$U/user/2" "$U/user/3")"
check "json keep-alive bodies" "$(json_for 1)$(json_for 2)" \
	"$(curl -s "$U/user/1" "$U/user/2")"

got=$(printf 'GET /user/1 HTTP/1.1\r\nHost: x\r\n\r\nGET /user/2 HTTP/1.1\r\nHost: x\r\n\r\nGET /nope HTTP/1.1\r\n\r\n' | raw "$PJ")
check "json pipelined: 2x200 + 404" "2 1" \
	"$(printf %s "$got" | count 'HTTP/1.1 200 OK') $(printf %s "$got" | count 'HTTP/1.1 404')"
check "json pipelined: second body" 1 "$(printf %s "$got" | count '"id":2,')"

got=$( { printf 'GET /user/5 HT'; sleep 0.2; printf 'TP/1.1\r\nHo'; sleep 0.2; printf 'st: x\r\n\r\n'; } | raw "$PJ")
check "json request in 3 pieces" 1 "$(printf %s "$got" | count '"id":5,')"

got=$(seq 1 400 | xargs -P 64 -I{} curl -s -o /dev/null -w '%{http_code}\n' "$U/user/{}" | sort | uniq -c | tr -s ' ')
check "json 400 requests over 64 parallel clients" " 400 200" "$got"

# -------------------------------------------------------------- static
mkdir "$T/files"
head -c 4096 /dev/urandom >"$T/files/4k"
head -c 65536 /dev/urandom >"$T/files/64k"
head -c 1048576 /dev/urandom >"$T/files/1m"
nextport; PS=$port
start "$SRV" static "$PS" FILES="$T/files"
U=http://127.0.0.1:$PS
for f in 4k 64k 1m; do
	n=$(stat -c %s "$T/files/$f")
	check "static /file/$f status" "200 application/octet-stream $n" "$(get "$U/file/$f")"
	if cmp -s "$T/body" "$T/files/$f"; then ok "static /file/$f bytes"; else bad "static /file/$f bytes"; fi
done
for p in /file/nope /file/ /file/../files/4k /file/.hidden /user/1; do
	check "static GET $p is 404" 404 "$(curl -s --path-as-is -o /dev/null -w '%{http_code}' "$U$p")"
done
check "static keep-alive: 1m 4k 64k on one connection" "1 0 0 " \
	"$(curl -s -o /dev/null -o /dev/null -o /dev/null -w '%{num_connects} ' "$U/file/1m" "$U/file/4k" "$U/file/64k")"
got=$(seq 1 64 | xargs -P 16 -I{} curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$U/file/1m" | sort | uniq -c | tr -s ' ')
check "static 64 x 1m over 16 parallel clients" " 64 200 1048576" "$got"
echo changed >"$T/files/4k"
check "static reads the file each time" "changed" "$(curl -s "$U/file/4k")"

# --------------------------------------------------------------- proxy
nextport; PB=$port
start "$BE" json "$PB"
nextport; PP=$port
start "$SRV" proxy "$PP" BACKEND="127.0.0.1:$PB"
U=http://127.0.0.1:$PP
b=$(json_for 7)
check "proxy /proxy/7 status" "200 application/json ${#b}" "$(get "$U/proxy/7")"
check "proxy /proxy/7 body" "$b" "$(cat "$T/body")"
got=$(printf 'GET /proxy/8 HTTP/1.1\r\nHost: x\r\n\r\n' | raw "$PP")
b=$(json_for 8)
check "proxy exact response bytes" \
	"$(printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s' "${#b}" "$b")" "$got"
check "proxy keep-alive bodies" "$(json_for 1)$(json_for 2)$(json_for 3)" \
	"$(curl -s "$U/proxy/1" "$U/proxy/2" "$U/proxy/3")"
for p in /proxy/x /proxy/ /user/1; do
	check "proxy GET $p is 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$U$p")"
done
got=$(seq 1 400 | xargs -P 64 -I{} curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$U/proxy/1000{}" | sort | uniq -c | awk '{print $2}' | sort -u | tr '\n' ' ')
check "proxy 400 requests over 64 parallel clients" "200 " "$got"
got=$(printf 'GET /proxy/1 HTTP/1.1\r\n\r\nGET /proxy/2 HTTP/1.1\r\n\r\n' | raw "$PP")
check "proxy pipelined: both answered" 2 "$(printf %s "$got" | count 'HTTP/1.1 200 OK')"

# ----------------------------------------------------------------- wal
nextport; PW=$port
start "$SRV" wal "$PW" LOG="$T/wal.log"
U=http://127.0.0.1:$PW
head -c 192 /dev/urandom | base64 -w0 | head -c 256 >"$T/rec"
check "wal record is 256 bytes" 256 "$(stat -c %s "$T/rec")"
check "wal empty after start" 0 "$(stat -c %s "$T/wal.log")"
check "wal POST /log" "200 text/plain 2" "$(get --data-binary @"$T/rec" "$U/log")"
check "wal POST /log body" ok "$(cat "$T/body")"
check "wal log has the record" "$(cat "$T/rec")" "$(cat "$T/wal.log")"
got=$(curl -s --data-binary @"$T/rec" "$U/log" "$U/log" "$U/log")
check "wal 3 more on one connection" okokok "$got"
got=$(seq 1 200 | xargs -P 64 -I{} curl -s --data-binary @"$T/rec" "$U/log" | tr -d '\n')
check "wal 200 more over 64 parallel clients" "$(printf 'ok%.0s' $(seq 200))" "$got"
for _ in $(seq 204); do cat "$T/rec"; done >"$T/expect"
if cmp -s "$T/wal.log" "$T/expect"; then ok "wal log is 204 whole records"; else bad "wal log is not 204 whole records ($(stat -c %s "$T/wal.log") bytes)"; fi
got=$( { printf 'POST /log HTTP/1.1\r\ncontent-length: 256\r\n\r\n'; head -c 100 "$T/rec"; sleep 0.2; tail -c 156 "$T/rec"; } | raw "$PW")
check "wal body in 2 pieces, lower-case header" "$(printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok')" "$got"
got=$( { printf 'POST /log HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdPOST /log HTTP/1.1\r\nContent-Length: 2\r\n\r\nef'; } | raw "$PW")
check "wal pipelined posts" 2 "$(printf %s "$got" | count 'ok')"
check "wal log tail" "abcdef" "$(tail -c 6 "$T/wal.log")"
check "wal GET /log is 404" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$U/log")"

# ----------------------------------------------------------------- cpu
nextport; PC=$port
start "$SRV" cpu "$PC"
U=http://127.0.0.1:$PC
# h = 14695981039346656037 * 1099511628211^(n * 65536) mod 2^64, from
# python3 -c 'P=1099511628211;print(14695981039346656037*pow(P,200*65536,2**64)%2**64)'
check "cpu /hash/200" "200 text/plain 20" "$(get "$U/hash/200")"
check "cpu /hash/200 value" 17515195554806768421 "$(cat "$T/body")"
check "cpu /hash/1" 16934947671703429925 "$(curl -s "$U/hash/1")"
check "cpu /hash/0" 14695981039346656037 "$(curl -s "$U/hash/0")"
check "cpu /user/3" "$(json_for 3)" "$(curl -s "$U/user/3")"
check "cpu hash then json on one connection" "17515195554806768421$(json_for 4)" \
	"$(curl -s "$U/hash/200" "$U/user/4")"
got=$(seq 1 32 | xargs -P 32 -I{} curl -s "$U/hash/200" | sort | uniq -c | tr -s ' ')
check "cpu 32 parallel /hash/200" " 32 17515195554806768421" "$got"
# Light requests must not wait behind heavy ones (soft: needs free cores).
heavy=()
for _ in 1 2 3 4; do curl -s -o /dev/null "$U/hash/5000" & heavy+=($!); done
sleep 0.1
t=$(curl -s -o /dev/null -w '%{time_total}' "$U/user/1")
wait "${heavy[@]}"
if awk "BEGIN { exit !($t < 0.05) }"; then
	ok "cpu json answered in ${t}s while 4 heavy hashes run"
else
	echo "WARN cpu json took ${t}s while 4 heavy hashes ran (few cores?)"
fi

alive
echo "$pass passed, $fails failed"
[ "$fails" -eq 0 ]
