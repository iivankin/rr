# Bench harness: what every server does

Every stack in this directory builds one server program that serves the
same scenarios over the same minimal HTTP/1.1, so that what differs is the
I/O layer and the runtime, not the protocol code. One event loop on one
core (`THREADS=1`) unless a scenario says otherwise; each runtime is told
so (tokio `current_thread`, monoio one thread, `GOMAXPROCS=1`, Node as it
is). Blocking work goes where that stack puts it (tokio `spawn_blocking`,
rr `io.run`, Go a goroutine, Node `worker_threads`, C a thread pool).

## Command line

```
server SCENARIO PORT
```

Environment: `BACKEND=host:port` (proxy), `FILES=dir` (static),
`LOG=path` (wal). The server listens on `0.0.0.0:PORT` (backlog 4096,
SO_REUSEADDR) and prints `ready\n` to stdout once it accepts. It runs until
killed (SIGTERM/SIGKILL). No logging on the request path.

## HTTP

Requests come one at a time on each keep-alive connection (no pipelining
is needed, but bytes of the next request after the current one must not
be lost). A request is the bytes up to and including `\r\n\r\n`; the
request line is `METHOD SP PATH SP HTTP/1.1`. Header names are matched
case-insensitively; the only header read is `Content-Length` (POST).
Requests and their headers are at most 8 KiB; a POST body at most 64 KiB.

Every response is:

```
HTTP/1.1 200 OK\r\n
Content-Type: <type>\r\n
Content-Length: <n>\r\n
\r\n
<body>
```

A path no scenario knows gets `404 Not Found` with an empty body. The
server never closes a connection itself unless the peer did, or a read or
write failed.

## Scenarios

### json

`GET /user/<id>` (id a decimal u32). Body, `application/json`, built per
request by filling the id into this template (no JSON library: the same
byte copying everywhere), with `<id>` replaced in all three places:

```
{"id":<id>,"name":"user<id>","email":"user<id>@example.com","active":true,"roles":["reader","writer"],"balance":1234.56,"bio":"<900 x 'a'>"}
```

### static

`GET /file/<name>` where name is one of the files in `$FILES` (4k, 64k,
1m: 4096, 65536 and 1048576 bytes). Each request opens the file, reads all
of it (up to 1 MiB) with the stack's file I/O, closes it, and sends it as
`application/octet-stream`. No caching of descriptors or contents.

### proxy

`GET /proxy/<id>`: the server forwards `GET /user/<id> HTTP/1.1\r\nHost:
b\r\n\r\n` to `$BACKEND` on an upstream connection of its own for that
client connection (opened at the first proxied request, kept alive),
reads the upstream response (status line, headers, Content-Length body),
and sends the client `200` with that body and its Content-Type. The
backend is `c-epoll json`, the same for every stack.

### wal

`POST /log` with a body of 256 bytes. The server appends the body to
`$LOG` (opened once at start, O_CREAT|O_TRUNC, writes at the offset it
keeps), and answers `200` with body `ok` (`text/plain`) only after the
bytes are on the disk: group commit, one `fdatasync` (or the stack's
sync) for all the appends of one loop turn / batch, never one for each
request when several wait. A write that fails ends the process.

### cpu

`GET /user/<id>` as json, and `GET /hash/<n>`: the work of n rounds of
this loop over a 64 KiB buffer of zeroes (n is 200 in the runs), done off
the event loop, answered with the result in decimal (`text/plain`):

```
h = 14695981039346656037 (u64)
for round in 0..n: for byte b in buffer: h = (h ^ b) * 1099511628211 (wrapping)
```

What it measures is how much the light requests wait behind the heavy.

## Load generator

`load/load.c` (C, epoll, one thread): `load HOST:PORT CONNS SECONDS RATE
MIX...`, where RATE 0 is closed loop (each connection sends its next
request when the last answer came) and RATE > 0 an open loop of so many
requests a second over all connections, with latency measured from each
request's intended start (no coordinated omission). MIX is
`weight:METHOD:PATH[:bodybytes]`, with `{i}` in PATH replaced by a
counter. It prints one JSON line: requests, errors, throughput, latency
percentiles (p50, p90, p99, p99.9, max) in microseconds, overall and for
each mix entry.

`run.sh` starts each server pinned to one core, the load generator (and
the proxy's backend) on another, warms up, measures, and reads the
server's CPU time from `/proc/PID/stat` before and after: CPU per request
and the server's peak RSS (VmHWM) go into the result line.
