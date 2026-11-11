# bench: rr's io against other stacks, in the same conditions

One server program for each stack, every one doing what `SPEC.md` says
(the same hand-written HTTP/1.1 and the same five scenarios: json, static,
proxy, wal, cpu), one load generator (`load/load.c`), and scripts that run
them one at a time on pinned cores of one Linux box.

| stack | what |
|---|---|
| rr | rr's io and thread, from `../registry` (io_uring) |
| c-uring | C on liburing 2.15: multishot accept and recv, buffer ring |
| c-epoll | C on epoll, level-triggered; also the proxy's backend |
| zig | Zig 0.17.1, a TigerBeetle-style completion loop on io_uring |
| monoio | Rust monoio 0.2.4, thread-per-core, io_uring |
| tokio | Rust tokio 1.54.1, current_thread runtime |
| go | Go, goroutine per connection, GOMAXPROCS=1 (`nethttp-` variants too) |
| node | Node.js 26.1, `net` (and `http` for `nethttp-`) |

## Running

On a Linux box (6.1 or later) with gcc, cargo and rustc (rr's toolchain),
and Go, Node and Zig unpacked in `TOOLS` (default `../tools`):

```
PREPARE_ONLY=1 rr/build.sh   # on a machine whose rr adds from a path
sh build.sh                  # every server, and load
sh check.sh rr tokio ...     # each does what SPEC says
ROUNDS=3 sh run.sh           # results/results.jsonl
```

`run.sh` puts the server on `SERVER_CPU` and the load generator (and the
proxy's backend) on `LOAD_CPU`, warms up, measures, and records what load
saw (throughput, latency percentiles, errors) with the server's CPU time
per request and peak RSS. `CASES`, `ONLY`, `MEASURE` and `WARMUP` narrow a
run.
