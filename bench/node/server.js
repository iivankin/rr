'use strict';
// Node entry of the cross-stack bench (see ../SPEC.md). Written for and
// tested with Node v26.1.0; standard library only (net, fs, worker_threads,
// and http for the nethttp- reference variant).
//
// Model: one event loop. A hand-written HTTP/1.1 parser per connection
// that keeps unconsumed bytes across reads; one request in flight per
// connection, the rest buffered until its answer is written. File I/O goes
// through libuv's thread pool (fs callbacks), /hash runs on a pool of four
// worker threads, wal group-commits everything queued in one loop turn with
// one writev and one fdatasync.
//
// usage: node server.js SCENARIO PORT

const fs = require('fs');
const net = require('net');
const path = require('path');
const {
	Worker, isMainThread, parentPort,
} = require('worker_threads');

const MAX_HEAD = 8 << 10;
const MAX_BODY = 64 << 10;
const MAX_FILE = 1 << 20;
const BACKLOG = 4096;
const CPU_WORKERS = 4;

if (!isMainThread) {
	workerMain();
} else {
	main();
}

// FNV-1a-style loop of SPEC cpu over 64 KiB of zeroes, in u64 wrapping
// arithmetic on two u32 halves (BigInt would be ~100x slower). The prime
// is 2^40 + 0x1b3, so h * p = (h << 40) + h * 0x1b3; every partial
// product stays below 2^53 and is exact as a double.
function fnv(n, buf) {
	let hi = 0xcbf29ce4, lo = 0x84222325;
	const len = buf.length;
	for (let r = 0; r < n; r++) {
		for (let i = 0; i < len; i++) {
			lo = (lo ^ buf[i]) >>> 0;
			const l = lo * 0x1b3;
			const carry = Math.floor(l / 4294967296);
			hi = (hi * 0x1b3 + carry + ((lo << 8) >>> 0)) >>> 0;
			lo = l >>> 0;
		}
	}
	return ((BigInt(hi) << 32n) | BigInt(lo)).toString();
}

function workerMain() {
	const buf = new Uint8Array(64 << 10);
	parentPort.on('message', (m) => {
		parentPort.postMessage({ id: m.id, h: fnv(m.n, buf) });
	});
}

function fatal(msg) {
	process.stderr.write('server: ' + msg + '\n');
	process.exit(1);
}

function mustEnv(k) {
	const v = process.env[k];
	if (!v)
		fatal(k + ' is not set');
	return v;
}

function parseU32(s) {
	if (s.length === 0 || s.length > 10)
		return -1;
	let v = 0;
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i) - 48;
		if (c < 0 || c > 9)
			return -1;
		v = v * 10 + c;
	}
	return v > 0xffffffff ? -1 : v;
}

function head200(type, n) {
	return 'HTTP/1.1 200 OK\r\nContent-Type: ' + type +
		'\r\nContent-Length: ' + n + '\r\n\r\n';
}

const NOT_FOUND = 'HTTP/1.1 404 Not Found\r\n' +
	'Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n';
const OK = head200('text/plain', 2) + 'ok';
const BIO = 'a'.repeat(900);
const U1 = '{"id":';
const U2 = ',"name":"user';
const U3 = '","email":"user';
const U4 = '@example.com","active":true,"roles":["reader","writer"],' +
	'"balance":1234.56,"bio":"' + BIO + '"}';
const UFIXED = U1.length + U2.length + U3.length + U4.length;

function userBody(id) {
	return U1 + id + U2 + id + U3 + id + U4;
}

// userResponse: the whole response as one latin1 string, one write.
function userResponse(id) {
	const ds = String(id);
	return head200('application/json', UFIXED + 3 * ds.length) +
		userBody(ds);
}

// findHeader returns the trimmed value of header lname (lowercase) in the
// latin1 head string, or null.
function findHeader(head, lname) {
	let i = head.indexOf('\r\n');
	while (i >= 0 && i + 2 < head.length) {
		const s = i + 2;
		const e = head.indexOf('\r\n', s);
		if (e < 0)
			return null;
		const c = head.indexOf(':', s);
		if (c > s && c < e && c - s === lname.length &&
			head.slice(s, c).toLowerCase() === lname)
			return head.slice(c + 1, e).trim();
		i = e;
	}
	return null;
}

// Reader accumulates chunks and cuts heads and bodies out of them.
class Reader {
	constructor() {
		this.buf = null;
		this.scan = 0;
	}

	push(chunk) {
		if (this.buf === null || this.buf.length === 0) {
			this.buf = chunk;
		} else {
			this.buf = Buffer.concat([this.buf, chunk]);
		}
	}

	// head returns the head as a latin1 string (without the bytes) or
	// null when incomplete; throws when too long.
	head() {
		const b = this.buf;
		if (b === null)
			return null;
		const i = b.indexOf('\r\n\r\n', this.scan, 'latin1');
		if (i < 0) {
			if (b.length >= MAX_HEAD)
				throw new Error('head too long');
			this.scan = b.length > 3 ? b.length - 3 : 0;
			return null;
		}
		this.scan = 0;
		const h = b.latin1Slice(0, i + 4);
		this.consume(i + 4);
		return h;
	}

	take(n) {
		const b = this.buf;
		if (b === null || b.length < n)
			return null;
		const r = b.subarray(0, n);
		this.consume(n);
		return r;
	}

	consume(n) {
		this.buf = n === this.buf.length ? null : this.buf.subarray(n);
	}
}

function startCPU() {
	const idle = [];
	const queue = [];
	const pending = new Map();
	let seq = 0;
	for (let i = 0; i < CPU_WORKERS; i++) {
		const w = new Worker(__filename);
		w.on('message', (m) => {
			const cb = pending.get(m.id);
			pending.delete(m.id);
			const next = queue.shift();
			if (next !== undefined) {
				w.postMessage(next);
			} else {
				idle.push(w);
			}
			cb(m.h);
		});
		w.on('error', (e) => fatal('worker: ' + e.message));
		w.unref();
		idle.push(w);
	}
	return (n, cb) => {
		const job = { id: seq++, n };
		pending.set(job.id, cb);
		const w = idle.pop();
		if (w !== undefined) {
			w.postMessage(job);
		} else {
			queue.push(job);
		}
	};
}

// startWAL: appends queued during one loop turn are flushed together from
// setImmediate with one writev at the kept offset and one fdatasync;
// arrivals during a flush form the next batch.
function startWAL(file) {
	let fd;
	try {
		fd = fs.openSync(file, fs.constants.O_WRONLY |
			fs.constants.O_CREAT | fs.constants.O_TRUNC, 0o644);
	} catch (e) {
		fatal('open ' + file + ': ' + e.message);
	}
	let off = 0;
	let queue = [];
	let busy = false;

	function flush() {
		const batch = queue;
		queue = [];
		const bufs = batch.map((q) => q.data);
		let n = 0;
		for (const b of bufs)
			n += b.length;
		writeAll(bufs, n, () => {
			off += n;
			fs.fdatasync(fd, (err) => {
				if (err)
					fatal('wal sync: ' + err.message);
				for (const q of batch)
					q.cb();
				if (queue.length > 0) {
					setImmediate(flush);
				} else {
					busy = false;
				}
			});
		});
	}

	function writeAll(bufs, n, cb) {
		fs.writev(fd, bufs, off, (err, w) => {
			if (err)
				fatal('wal write: ' + err.message);
			if (w === n)
				return cb();
			/* Short write: retry the rest at its offset. */
			const rest = Buffer.concat(bufs).subarray(w);
			fs.write(fd, rest, 0, rest.length, off + w, (err2, w2) => {
				if (err2 || w2 !== rest.length)
					fatal('wal write: ' + (err2 ? err2.message : 'short'));
				cb();
			});
		});
	}

	return (data, cb) => {
		queue.push({ data, cb });
		if (!busy) {
			busy = true;
			setImmediate(flush);
		}
	};
}

function serveRaw(scenario, port) {
	let files, backend, wal, cpu;
	switch (scenario) {
	case 'json':
		break;
	case 'static':
		files = mustEnv('FILES');
		break;
	case 'proxy': {
		const b = mustEnv('BACKEND');
		const c = b.lastIndexOf(':');
		if (c < 0)
			fatal('BACKEND must be host:port');
		backend = { host: b.slice(0, c), port: Number(b.slice(c + 1)),
			noDelay: true };
		break;
	}
	case 'wal':
		wal = startWAL(mustEnv('LOG'));
		break;
	case 'cpu':
		cpu = startCPU();
		break;
	default:
		fatal('unknown scenario: ' + scenario);
	}

	const server = net.createServer({ noDelay: true }, (sock) => {
		const rd = new Reader();
		let busy = false;
		let need = -1; /* body bytes awaited, -1 when reading a head */
		let reqHead = null;
		let up = null;

		function done(resp) {
			if (sock.destroyed)
				return;
			if (resp !== null)
				sock.write(resp, 'latin1');
			busy = false;
			pump();
		}

		function pump() {
			while (!busy && !sock.destroyed) {
				if (need < 0) {
					let h;
					try {
						h = rd.head();
					} catch (e) {
						sock.destroy();
						return;
					}
					if (h === null)
						return;
					reqHead = h;
					need = 0;
					if (h.charCodeAt(0) === 80 /* P */) {
						const cl = findHeader(h, 'content-length');
						if (cl !== null) {
							need = parseU32(cl);
							if (need < 0 || need > MAX_BODY) {
								sock.destroy();
								return;
							}
						}
					}
				}
				let body = null;
				if (need > 0) {
					body = rd.take(need);
					if (body === null)
						return;
				}
				const h = reqHead;
				need = -1;
				reqHead = null;
				busy = true;
				handle(h, body);
			}
		}

		function handle(h, body) {
			const sp = h.indexOf(' ');
			const sp2 = sp < 0 ? -1 : h.indexOf(' ', sp + 1);
			if (sp2 < 0) {
				sock.destroy();
				return;
			}
			const method = h.slice(0, sp);
			const p = h.slice(sp + 1, sp2);
			if (method === 'GET') {
				if ((scenario === 'json' || scenario === 'cpu') &&
					p.startsWith('/user/')) {
					const id = parseU32(p.slice(6));
					if (id >= 0)
						return done(userResponse(id));
				} else if (scenario === 'cpu' && p.startsWith('/hash/')) {
					const n = parseU32(p.slice(6));
					if (n >= 0) {
						return cpu(n, (r) =>
							done(head200('text/plain', r.length) + r));
					}
				} else if (scenario === 'static' &&
					p.startsWith('/file/')) {
					return staticFile(p.slice(6));
				} else if (scenario === 'proxy' &&
					p.startsWith('/proxy/')) {
					const ids = p.slice(7);
					if (parseU32(ids) >= 0)
						return proxy(ids);
				}
			} else if (method === 'POST' && scenario === 'wal' &&
				p === '/log') {
				return wal(body === null ? Buffer.alloc(0) : body,
					() => done(OK));
			}
			done(NOT_FOUND);
		}

		function staticFile(name) {
			if (name.length === 0 || name[0] === '.' ||
				name.indexOf('/') >= 0 || name.indexOf('\0') >= 0)
				return done(NOT_FOUND);
			fs.readFile(path.join(files, name), (err, data) => {
				if (err || data.length > MAX_FILE)
					return done(NOT_FOUND);
				if (sock.destroyed)
					return;
				sock.cork();
				sock.write(head200('application/octet-stream',
					data.length), 'latin1');
				sock.write(data);
				sock.uncork();
				done(null);
			});
		}

		let upRd = null;
		let upHead = null;
		let upNeed = -1;
		let upCb = null;

		function upPump() {
			if (upCb === null)
				return;
			if (upNeed < 0) {
				let h;
				try {
					h = upRd.head();
				} catch (e) {
					return upFail();
				}
				if (h === null)
					return;
				const cl = findHeader(h, 'content-length');
				upNeed = cl === null ? -1 : parseU32(cl);
				if (!h.startsWith('HTTP/1.1 ') || upNeed < 0 ||
					upNeed > MAX_FILE)
					return upFail();
				upHead = h;
			}
			const b = upRd.take(upNeed);
			if (b === null)
				return;
			const ct = findHeader(upHead, 'content-type') || '';
			upNeed = -1;
			upHead = null;
			const cb = upCb;
			upCb = null;
			cb(ct, b);
		}

		function upFail() {
			if (up !== null)
				up.destroy();
			sock.destroy();
		}

		function proxy(ids) {
			if (up === null) {
				up = net.connect(backend);
				upRd = new Reader();
				up.on('data', (c) => {
					upRd.push(c);
					upPump();
				});
				up.on('error', upFail);
				up.on('close', upFail);
			}
			upCb = (ct, b) => {
				if (sock.destroyed)
					return;
				sock.cork();
				sock.write(head200(ct, b.length), 'latin1');
				sock.write(b);
				sock.uncork();
				done(null);
			};
			up.write('GET /user/' + ids + ' HTTP/1.1\r\nHost: b\r\n\r\n',
				'latin1');
		}

		sock.on('data', (c) => {
			rd.push(c);
			pump();
		});
		sock.on('error', () => sock.destroy());
		sock.on('end', () => sock.destroy());
		sock.on('close', () => {
			if (up !== null)
				up.destroy();
		});
	});
	listen(server, port);
}

function listen(server, port) {
	server.on('error', (e) => fatal('listen: ' + e.message));
	server.listen({ port, host: '0.0.0.0', backlog: BACKLOG }, () => {
		process.stdout.write('ready\n');
	});
}

// serveHTTP: json or static on the http module with its defaults, the
// reference for what an ordinary Node service does.
function serveHTTP(name, port) {
	const http = require('http');
	let files;
	if (name === 'static')
		files = mustEnv('FILES');
	else if (name !== 'json')
		fatal('unknown scenario: nethttp-' + name);

	function notFound(res) {
		res.writeHead(404, { 'Content-Type': 'text/plain',
			'Content-Length': 0 });
		res.end();
	}

	const server = http.createServer((req, res) => {
		const u = req.url;
		if (req.method !== 'GET')
			return notFound(res);
		if (name === 'json' && u.startsWith('/user/')) {
			const id = parseU32(u.slice(6));
			if (id < 0)
				return notFound(res);
			const body = userBody(String(id));
			res.writeHead(200, { 'Content-Type': 'application/json',
				'Content-Length': body.length });
			return res.end(body, 'latin1');
		}
		if (name === 'static' && u.startsWith('/file/')) {
			const f = u.slice(6);
			if (f.length === 0 || f[0] === '.' || f.indexOf('/') >= 0 ||
				f.indexOf('\0') >= 0)
				return notFound(res);
			return fs.readFile(path.join(files, f), (err, data) => {
				if (err || data.length > MAX_FILE)
					return notFound(res);
				res.writeHead(200, {
					'Content-Type': 'application/octet-stream',
					'Content-Length': data.length });
				res.end(data);
			});
		}
		notFound(res);
	});
	listen(server, port);
}

function main() {
	if (process.argv.length !== 4) {
		process.stderr.write('usage: node server.js SCENARIO PORT\n');
		process.exit(2);
	}
	const scenario = process.argv[2];
	const port = parseU32(process.argv[3]);
	if (port < 0 || port > 65535)
		fatal('bad port: ' + process.argv[3]);
	if (scenario.startsWith('nethttp-')) {
		serveHTTP(scenario.slice(8), port);
	} else {
		serveRaw(scenario, port);
	}
}
