#!/bin/sh
# Runs every case of CASES for every stack of STACKS, ROUNDS times, in
# turn (one server at a time), and appends one JSON line for each run to
# results/results.jsonl: what load measured, and the server's CPU time
# per request and peak RSS over the measured seconds.
#
#   SERVER_CPU=7 LOAD_CPU=6 ROUNDS=3 sh run.sh
#
# The server runs on SERVER_CPU, the load generator (and the proxy's
# backend) on LOAD_CPU, both niced, as the box serves other work too.
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/stacks.sh"
SERVER_CPU=${SERVER_CPU:-7}
LOAD_CPU=${LOAD_CPU:-6}
ROUNDS=${ROUNDS:-1}
SECONDS_=${MEASURE:-10}
WARMUP=${WARMUP:-3}
STACKS=${ONLY:-$STACKS}
work=${TMPDIR:-/tmp}/bench-run
out=$here/results/results.jsonl
mkdir -p "$here/results" "$work/files"
head -c 4096 /dev/urandom > "$work/files/4k"
head -c 65536 /dev/urandom > "$work/files/64k"
head -c 1048576 /dev/urandom > "$work/files/1m"
ulimit -n 65536
tick=$(getconf CLK_TCK)

# name scenario conns rate mix...
CASES=${CASES:-"json-100 json-1000 json-open static proxy wal cpu"}
case_args() {
	case $1 in
	json-100) echo "json 100 0 1:GET:/user/{i}" ;;
	json-1000) echo "json 1000 0 1:GET:/user/{i}" ;;
	json-open) echo "json 1000 20000 1:GET:/user/{i}" ;;
	static) echo "static 64 0 6:GET:/file/4k 3:GET:/file/64k 1:GET:/file/1m" ;;
	proxy) echo "proxy 100 0 1:GET:/proxy/{i}" ;;
	wal) echo "wal 100 0 1:POST:/log:256" ;;
	cpu) echo "cpu 200 2000 99:GET:/user/{i} 1:GET:/hash/200" ;;
	esac
}

cpu_ticks() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

taskset -c "$LOAD_CPU" nice -n 10 "$here/c-epoll/server" json 19000 > "$work/backend.out" 2>&1 &
backend=$!
sleep 0.5

# A port of its own for each run: an io_uring server's listener may
# outlive its process a moment, as the kernel tears its ring down later.
port=20000
round=1
while [ $round -le "$ROUNDS" ]; do
	for name in $CASES; do
		set -- $(case_args "$name")
		scenario=$1 conns=$2 rate=$3; shift 3
		for stack in $STACKS; do
			rm -f "$work/log"
			port=$((port + 1))
			FILES=$work/files LOG=$work/log BACKEND=127.0.0.1:19000 \
				taskset -c "$SERVER_CPU" nice -n 10 sh -c "exec $(command_of "$stack") $scenario $port" \
				> "$work/server.out" 2>&1 &
			pid=$!
			i=0
			while ! grep -q ready "$work/server.out" 2>/dev/null && [ $i -lt 200 ]; do
				i=$((i + 1)); sleep 0.05
			done
			WARMUP=$WARMUP taskset -c "$LOAD_CPU" nice -n 10 "$here/load/load" 127.0.0.1:$port \
				"$conns" "$SECONDS_" "$rate" "$@" > "$work/load.out" 2> "$work/load.err" &
			load=$!
			sleep "$WARMUP"
			before=$(cpu_ticks $pid)
			wait $load
			after=$(cpu_ticks $pid)
			rss=$(awk '/VmHWM/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
			kill $pid 2>/dev/null; wait $pid 2>/dev/null
			result=$(cat "$work/load.out")
			[ -n "$result" ] || result='{}'
			printf '{"round":%d,"case":"%s","stack":"%s","cpu_ms":%s,"rss_kb":%s,"load":%s}\n' \
				$round "$name" "$stack" "$(( (after - before) * 1000 / tick ))" "${rss:-0}" "$result" >> "$out"
			echo "round $round $name $stack done"
		done
	done
	round=$((round + 1))
done
kill $backend 2>/dev/null; wait $backend 2>/dev/null
