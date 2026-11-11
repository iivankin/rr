//! Bench server (see ../SPEC.md) on io_uring, in the style of TigerBeetle's IO layer
//! (src/io/linux.zig): every operation owns a `Completion` with a type-erased callback,
//! callbacks only queue SQEs, and each tick enters the kernel exactly once to submit the
//! whole batch and wait for completions. Completions are copied out of the ring into a FIFO
//! first and run afterwards, so callbacks never recurse into the ring.
//!
//! One thread runs the loop. Only `cpu` adds a pool of four hashing threads, whose results
//! come back through an eventfd that the loop keeps a read armed on.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const linux = std.os.linux;
const IoUring = linux.IoUring;
const fd_t = linux.fd_t;

comptime {
    if (builtin.os.tag != .linux and !builtin.is_test) {
        @compileError("server.zig is Linux-only (io_uring)");
    }
}

// Sizes from the spec.
const head_max = 8 * 1024; // Request line and headers, including the blank line.
const body_max = 64 * 1024; // POST body.
const request_max = head_max + body_max;
const file_max = 1024 * 1024; // Largest file `static` serves.

const ring_entries = 4096;
const cq_entries = 4 * ring_entries;
const listen_backlog = 4096;
const pool_threads = 4;
const hash_buffer_size = 64 * 1024;

// Room for a response head in front of a body that is read or copied straight into place.
const head_room = 256;
// Inline response buffer: enough for json, hash, ok and 404 (and most proxied bodies).
const small_size = 4096;
// Heap response buffer, allocated on first need: a whole file or proxied body plus head.
const big_size = head_room + file_max;

// ---------------------------------------------------------------------------------------------
// IO: a small completion-based loop over io_uring.

fn QueueType(comptime T: type) type {
    // Intrusive FIFO through `T.next`.
    return struct {
        head: ?*T = null,
        tail: ?*T = null,

        const Queue = @This();

        fn push(queue: *Queue, elem: *T) void {
            assert(elem.next == null);
            if (queue.tail) |tail| tail.next = elem else queue.head = elem;
            queue.tail = elem;
        }

        fn pop(queue: *Queue) ?*T {
            const head = queue.head orelse return null;
            queue.head = head.next;
            if (queue.head == null) queue.tail = null;
            head.next = null;
            return head;
        }

        fn empty(queue: *const Queue) bool {
            return queue.head == null;
        }
    };
}

const IO = struct {
    ring: IoUring,
    /// Completions copied out of the CQ whose callbacks are yet to run.
    completed: QueueType(Completion) = .{},

    const Error = error{
        Canceled,
        ConnectionRefused,
        ConnectionResetByPeer,
        BrokenPipe,
        FileNotFound,
        AccessDenied,
        NoSpaceLeft,
        InputOutput,
        Unexpected,
    };
    /// Bytes transferred, a new fd, or 0.
    const Result = Error!usize;
    const Callback = *const fn (context: *anyopaque, completion: *Completion, result: Result) void;

    const Operation = union(enum) {
        accept: struct { socket: fd_t },
        connect: struct { socket: fd_t, address: linux.sockaddr.in },
        recv: struct { socket: fd_t, buffer: []u8 },
        send: struct { socket: fd_t, buffer: []const u8 },
        openat: struct { dir: fd_t, path: [*:0]const u8, flags: linux.O },
        read: struct { fd: fd_t, buffer: []u8, offset: u64 },
        write: struct { fd: fd_t, buffer: []const u8, offset: u64 },
        fdatasync: struct { fd: fd_t },
        close: struct { fd: fd_t },
    };

    /// Everything one operation needs; it must stay put until its callback has run.
    const Completion = struct {
        io: *IO = undefined,
        next: ?*Completion = null,
        result: i32 = 0,
        /// IOSQE_* flags, e.g. IOSQE_IO_LINK to chain the next SQE after this one.
        sqe_flags: u8 = 0,
        operation: Operation = undefined,
        context: *anyopaque = undefined,
        callback: Callback = undefined,

        fn prep(completion: *Completion, sqe: *linux.io_uring_sqe) void {
            switch (completion.operation) {
                .accept => |op| sqe.prep_accept(op.socket, null, null, linux.SOCK.CLOEXEC),
                .connect => |*op| sqe.prep_connect(
                    op.socket,
                    @ptrCast(&op.address),
                    @sizeOf(linux.sockaddr.in),
                ),
                .recv => |op| sqe.prep_recv(op.socket, op.buffer, 0),
                .send => |op| sqe.prep_send(op.socket, op.buffer, linux.MSG.NOSIGNAL),
                .openat => |op| sqe.prep_openat(op.dir, op.path, op.flags, 0),
                .read => |op| sqe.prep_read(op.fd, op.buffer, op.offset),
                .write => |op| sqe.prep_write(op.fd, op.buffer, op.offset),
                .fdatasync => |op| sqe.prep_fsync(op.fd, linux.IORING_FSYNC_DATASYNC),
                .close => |op| sqe.prep_close(op.fd),
            }
            sqe.flags |= completion.sqe_flags;
            sqe.user_data = @intFromPtr(completion);
        }

        fn complete(completion: *Completion) void {
            const res = completion.result;
            const result: Result = if (res >= 0) @intCast(res) else switch (errno(res)) {
                // Retry in place, as TigerBeetle does. EAGAIN cannot come from our blocking
                // fds through io_uring except spuriously from some file systems.
                .INTR, .AGAIN => {
                    // A close interrupted by a signal has still closed the fd.
                    if (completion.operation == .close) {
                        return completion.callback(completion.context, completion, 0);
                    }
                    return completion.io.enqueue(completion);
                },
                .CANCELED => error.Canceled,
                .CONNREFUSED => error.ConnectionRefused,
                .CONNRESET => error.ConnectionResetByPeer,
                .PIPE => error.BrokenPipe,
                .NOENT, .NOTDIR, .ISDIR => error.FileNotFound,
                .ACCES, .PERM => error.AccessDenied,
                .NOSPC, .DQUOT, .FBIG => error.NoSpaceLeft,
                .IO => error.InputOutput,
                else => error.Unexpected,
            };
            completion.callback(completion.context, completion, result);
        }
    };

    fn init() !IO {
        // SINGLE_ISSUER (6.0) and COOP_TASKRUN (5.19) save the kernel work when it is told
        // that only this thread submits; fall back to a plain ring on older kernels.
        const fast = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_COOP_TASKRUN;
        return .{ .ring = setup(fast) catch |err| switch (err) {
            error.ArgumentsInvalid => try setup(0),
            else => return err,
        } };
    }

    fn setup(flags: u32) !IoUring {
        var params = mem.zeroInit(linux.io_uring_params, .{
            .flags = flags | linux.IORING_SETUP_CQSIZE,
            .cq_entries = cq_entries,
        });
        return IoUring.init_params(ring_entries, &params);
    }

    /// One loop turn: submit every SQE queued since the last turn and wait for at least one
    /// completion in a single io_uring_enter, then run all the callbacks that are ready.
    /// Something is always in flight (the accept), so waiting cannot hang.
    fn tick(io: *IO) void {
        io.flush_submissions(1);
        io.flush_completions();
        while (io.completed.pop()) |completion| completion.complete();
    }

    fn flush_submissions(io: *IO, wait_nr: u32) void {
        var wait = wait_nr;
        while (true) {
            _ = io.ring.submit_and_wait(wait) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                // The CQ is overcommitted: make room by draining it, then submit again. The
                // drained completions count as the ones we wanted to wait for.
                error.CompletionQueueOvercommitted, error.SystemResources => {
                    io.flush_completions();
                    wait = 0;
                    continue;
                },
                else => fatal("io_uring_enter", err),
            };
            return;
        }
    }

    fn flush_completions(io: *IO) void {
        var cqes: [256]linux.io_uring_cqe = undefined;
        while (true) {
            const count = io.ring.copy_cqes(&cqes, 0) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => fatal("io_uring_enter", err),
            };
            for (cqes[0..count]) |cqe| {
                const completion: *Completion = @ptrFromInt(cqe.user_data);
                completion.result = cqe.res;
                io.completed.push(completion);
            }
            if (count < cqes.len) return;
        }
    }

    fn enqueue(io: *IO, completion: *Completion) void {
        const sqe = io.ring.get_sqe() catch blk: {
            // The SQ is full: submit what is there without waiting, then take the slot.
            io.flush_submissions(0);
            break :blk io.ring.get_sqe() catch unreachable;
        };
        completion.prep(sqe);
    }

    /// Make sure that `count` SQEs can be queued without a flush in between, so that a chain
    /// of linked SQEs reaches the kernel in one submission.
    fn reserve(io: *IO, count: u32) void {
        assert(count <= io.ring.sq.sqes.len);
        const free = io.ring.sq.sqes.len - io.ring.sq_ready();
        if (free < count) io.flush_submissions(0);
    }

    fn submit(
        io: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (context: Context, completion: *Completion, result: Result) void,
        completion: *Completion,
        operation: Operation,
        sqe_flags: u8,
    ) void {
        completion.* = .{
            .io = io,
            .sqe_flags = sqe_flags,
            .operation = operation,
            .context = context,
            .callback = erase_types(Context, callback),
        };
        io.enqueue(completion);
    }

    fn erase_types(
        comptime Context: type,
        comptime callback: fn (context: Context, completion: *Completion, result: Result) void,
    ) Callback {
        comptime assert(@typeInfo(Context) == .pointer);
        return &struct {
            fn erased(context: *anyopaque, completion: *Completion, result: Result) void {
                callback(@ptrCast(@alignCast(context)), completion, result);
            }
        }.erased;
    }
};

fn errno(res: i32) linux.E {
    return @fromBackingInt(@intCast(-res));
}

// ---------------------------------------------------------------------------------------------
// Server.

const Scenario = enum { json, static, proxy, wal, cpu };

const Server = struct {
    io: *IO,
    scenario: Scenario,
    listener: fd_t,
    accept_completion: IO.Completion = .{},
    /// Released connections, kept with their buffers for the next accept.
    free: QueueType(Connection) = .{},
    files: fd_t = -1,
    backend: linux.sockaddr.in = undefined,
    wal: Wal = .{},
    pool: ?*Pool = null,

    fn accept(server: *Server) void {
        server.io.submit(*Server, server, on_accept, &server.accept_completion, .{
            .accept = .{ .socket = server.listener },
        }, 0);
    }

    fn on_accept(server: *Server, _: *IO.Completion, result: IO.Result) void {
        server.accept();
        const fd: fd_t = @intCast(result catch return);
        set_nodelay(fd);
        const conn = server.free.pop() orelse blk: {
            const conn = std.heap.page_allocator.create(Connection) catch {
                _ = linux.close(fd);
                return;
            };
            conn.big = null;
            break :blk conn;
        };
        conn.init(server, fd);
        conn.receive();
    }

    fn release(server: *Server, conn: *Connection) void {
        server.free.push(conn);
    }

    /// Called once per tick after the callbacks: group-commit this tick's appends.
    fn on_tick(server: *Server) void {
        if (server.scenario == .wal) server.wal.commit(server.io);
    }
};

const Request = struct {
    method: []const u8,
    path: []const u8,
    head_len: usize,
    body_len: usize,
};

const Parse = union(enum) { incomplete, invalid, request: Request };

const ConnectionCallback = fn (
    conn: *Connection,
    completion: *IO.Completion,
    result: IO.Result,
) void;

const Connection = struct {
    server: *Server,
    fd: fd_t,
    next: ?*Connection,
    /// Completions in flight that point into this struct; it is released at zero.
    pending: u32,
    closing: bool,

    /// Socket recv/send and the final close.
    completion: IO.Completion,
    /// static: openat, read and close of the file.
    file_completion: IO.Completion,
    file: fd_t,

    recv_len: usize,
    /// How far `\r\n\r\n` has been searched for.
    scanned: usize,
    /// Bytes the request being served takes in `recv_buffer` (head and body).
    request_len: usize,

    send_buffer: []const u8,
    send_done: usize,

    /// wal: the body to append, in `recv_buffer`.
    wal_body: []const u8,
    wal_written: bool,

    /// cpu: rounds in, hash out.
    hash_rounds: u32,
    hash: u64,

    upstream: Upstream,

    path: [256]u8,
    small: [small_size]u8,
    big: ?[]u8,
    recv_buffer: [request_max]u8,

    fn init(conn: *Connection, server: *Server, fd: fd_t) void {
        // `big` is kept across reuse.
        conn.server = server;
        conn.fd = fd;
        conn.next = null;
        conn.pending = 0;
        conn.closing = false;
        conn.completion = .{};
        conn.file_completion = .{};
        conn.file = -1;
        conn.recv_len = 0;
        conn.scanned = 0;
        conn.request_len = 0;
        conn.wal_written = false;
        conn.upstream.reset();
    }

    fn submit(
        conn: *Connection,
        comptime callback: ConnectionCallback,
        completion: *IO.Completion,
        operation: IO.Operation,
    ) void {
        conn.submit_flags(callback, completion, operation, 0);
    }

    fn submit_flags(
        conn: *Connection,
        comptime callback: ConnectionCallback,
        completion: *IO.Completion,
        operation: IO.Operation,
        sqe_flags: u8,
    ) void {
        conn.pending += 1;
        conn.server.io.submit(*Connection, conn, callback, completion, operation, sqe_flags);
    }

    /// Every callback on a connection's completion goes through here first.
    fn settle(conn: *Connection) void {
        assert(conn.pending > 0);
        conn.pending -= 1;
        if (conn.closing and conn.pending == 0) conn.server.release(conn);
    }

    fn close(conn: *Connection) void {
        assert(!conn.closing);
        conn.closing = true;
        // Hold a reference so that the closes below cannot release the connection early.
        conn.pending += 1;
        conn.submit(on_close, &conn.completion, .{ .close = .{ .fd = conn.fd } });
        if (conn.upstream.fd >= 0) {
            conn.submit(on_close, &conn.upstream.completion, .{
                .close = .{ .fd = conn.upstream.fd },
            });
            conn.upstream.fd = -1;
        }
        conn.settle();
    }

    fn on_close(conn: *Connection, _: *IO.Completion, _: IO.Result) void {
        conn.settle();
    }

    fn receive(conn: *Connection) void {
        conn.submit(on_receive, &conn.completion, .{ .recv = .{
            .socket = conn.fd,
            .buffer = conn.recv_buffer[conn.recv_len..],
        } });
    }

    fn on_receive(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        const n = result catch return conn.close();
        if (n == 0) return conn.close();
        conn.recv_len += n;
        conn.process();
    }

    /// Serve the request at the front of `recv_buffer` if all of it is there.
    fn process(conn: *Connection) void {
        switch (conn.parse()) {
            .incomplete => {
                if (conn.recv_len == conn.recv_buffer.len) return conn.close();
                conn.receive();
            },
            .invalid => conn.close(),
            .request => |request| {
                conn.request_len = request.head_len + request.body_len;
                conn.route(request);
            },
        }
    }

    fn parse(conn: *Connection) Parse {
        const data = conn.recv_buffer[0..conn.recv_len];
        const end = mem.indexOfPos(u8, data, conn.scanned, "\r\n\r\n") orelse {
            if (data.len >= head_max) return .invalid;
            conn.scanned = data.len -| 3;
            return .incomplete;
        };
        const head_len = end + 4;
        if (head_len > head_max) return .invalid;
        conn.scanned = end;

        const line_end = mem.indexOf(u8, data[0..head_len], "\r\n").?;
        const line = data[0..line_end];
        const sp1 = mem.indexOfScalar(u8, line, ' ') orelse return .invalid;
        const sp2 = mem.indexOfScalarPos(u8, line, sp1 + 1, ' ') orelse return .invalid;
        const method = line[0..sp1];

        var body_len: usize = 0;
        if (mem.eql(u8, method, "POST")) {
            const value = header_value(data[@min(line_end + 2, end)..end], "content-length") orelse
                return .invalid;
            body_len = parse_decimal(value, body_max) orelse return .invalid;
            if (data.len < head_len + body_len) return .incomplete;
        }
        return .{ .request = .{
            .method = method,
            .path = line[sp1 + 1 .. sp2],
            .head_len = head_len,
            .body_len = body_len,
        } };
    }

    fn route(conn: *Connection, request: Request) void {
        const get = mem.eql(u8, request.method, "GET");
        const path = request.path;
        const scenario = conn.server.scenario;
        if (get and (scenario == .json or scenario == .cpu)) {
            if (suffix(path, "/user/")) |id| return conn.respond_user(id);
        }
        if (get and scenario == .cpu) {
            if (suffix(path, "/hash/")) |n| return conn.hash_start(n);
        }
        if (get and scenario == .static) {
            if (suffix(path, "/file/")) |name| return conn.file_start(name);
        }
        if (get and scenario == .proxy) {
            if (suffix(path, "/proxy/")) |id| return conn.proxy_start(id);
        }
        if (scenario == .wal and mem.eql(u8, request.method, "POST") and
            mem.eql(u8, path, "/log"))
        {
            const body = conn.recv_buffer[request.head_len..][0..request.body_len];
            return conn.server.wal.append(conn, body);
        }
        conn.respond_not_found();
    }

    fn send(conn: *Connection, buffer: []const u8) void {
        conn.send_buffer = buffer;
        conn.send_done = 0;
        conn.send_more();
    }

    fn send_more(conn: *Connection) void {
        conn.submit(on_send, &conn.completion, .{ .send = .{
            .socket = conn.fd,
            .buffer = conn.send_buffer[conn.send_done..],
        } });
    }

    fn on_send(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        conn.send_done += result catch return conn.close();
        if (conn.send_done < conn.send_buffer.len) return conn.send_more();

        // Done: drop the request, keep whatever of the next one has already arrived.
        const rest = conn.recv_len - conn.request_len;
        mem.copyForwards(
            u8,
            conn.recv_buffer[0..rest],
            conn.recv_buffer[conn.request_len..conn.recv_len],
        );
        conn.recv_len = rest;
        conn.request_len = 0;
        conn.scanned = 0;
        conn.process();
    }

    fn respond(conn: *Connection, content_type: []const u8, body: []const u8) void {
        assert(body.len + head_room <= conn.small.len);
        const head = write_head(&conn.small, content_type, body.len);
        @memcpy(conn.small[head..][0..body.len], body);
        conn.send(conn.small[0 .. head + body.len]);
    }

    fn respond_not_found(conn: *Connection) void {
        conn.send(not_found);
    }

    /// json: fill the id into the template, byte copying only.
    fn respond_user(conn: *Connection, id_text: []const u8) void {
        const id = parse_decimal(id_text, std.math.maxInt(u32)) orelse
            return conn.respond_not_found();
        conn.send(conn.small[0..write_user(&conn.small, @intCast(id))]);
    }

    fn big_buffer(conn: *Connection) ?[]u8 {
        if (conn.big == null) conn.big = std.heap.page_allocator.alloc(u8, big_size) catch null;
        return conn.big;
    }

    // static ------------------------------------------------------------------------------

    fn file_start(conn: *Connection, name: []const u8) void {
        if (name.len == 0 or name.len >= conn.path.len or
            mem.indexOfAny(u8, name, "/\x00") != null or
            mem.eql(u8, name, ".") or mem.eql(u8, name, ".."))
        {
            return conn.respond_not_found();
        }
        @memcpy(conn.path[0..name.len], name);
        conn.path[name.len] = 0;
        conn.submit(on_file_open, &conn.file_completion, .{ .openat = .{
            .dir = conn.server.files,
            .path = conn.path[0..name.len :0],
            .flags = .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        } });
    }

    fn on_file_open(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        conn.file = @intCast(result catch return conn.respond_not_found());
        const big = conn.big_buffer() orelse {
            conn.file_close(0);
            return conn.close();
        };
        // A regular file gives all it has up to the length asked for in one read; a short
        // read is the end of the file. Files over 1 MiB are cut at 1 MiB.
        conn.submit(on_file_read, &conn.file_completion, .{ .read = .{
            .fd = conn.file,
            .buffer = big[head_room..][0..file_max],
            .offset = 0,
        } });
    }

    fn on_file_read(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        // Hard-linked: the kernel runs the send right after the close, whatever the close
        // returns, in the same submission. The close's CQE comes first, so
        // `file_completion` is free again before the next request can need it. Reserve both
        // SQEs so that no flush splits the link.
        conn.server.io.reserve(2);
        conn.file_close(linux.IOSQE_IO_HARDLINK);
        const n = result catch return conn.respond_not_found();
        const big = conn.big.?;
        var head: [head_room]u8 = undefined;
        const head_len = write_head(&head, "application/octet-stream", n);
        const start = head_room - head_len;
        @memcpy(big[start..head_room], head[0..head_len]);
        conn.send(big[start .. head_room + n]);
    }

    fn file_close(conn: *Connection, sqe_flags: u8) void {
        conn.submit_flags(on_close, &conn.file_completion, .{
            .close = .{ .fd = conn.file },
        }, sqe_flags);
        conn.file = -1;
    }

    // cpu ---------------------------------------------------------------------------------

    fn hash_start(conn: *Connection, text: []const u8) void {
        const rounds = parse_decimal(text, std.math.maxInt(u32)) orelse
            return conn.respond_not_found();
        conn.hash_rounds = @intCast(rounds);
        conn.server.pool.?.push(conn);
    }

    fn hash_done(conn: *Connection) void {
        var digits_buffer: [20]u8 = undefined;
        conn.respond("text/plain", format_decimal(&digits_buffer, conn.hash));
    }

    // proxy -------------------------------------------------------------------------------

    fn proxy_start(conn: *Connection, id_text: []const u8) void {
        const id = parse_decimal(id_text, std.math.maxInt(u32)) orelse
            return conn.respond_not_found();
        const up = &conn.upstream;
        var digits_buffer: [20]u8 = undefined;
        const digits = format_decimal(&digits_buffer, id);
        var at: usize = 0;
        for ([_][]const u8{ "GET /user/", digits, " HTTP/1.1\r\nHost: b\r\n\r\n" }) |part| {
            @memcpy(up.request[at..][0..part.len], part);
            at += part.len;
        }
        up.request_len = at;
        up.request_done = 0;

        if (up.fd >= 0) return conn.upstream_send();
        // First proxied request on this connection: open its upstream connection.
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return conn.close();
        up.fd = @intCast(rc);
        set_nodelay(up.fd);
        conn.submit(on_upstream_connect, &up.completion, .{ .connect = .{
            .socket = up.fd,
            .address = conn.server.backend,
        } });
    }

    fn on_upstream_connect(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        _ = result catch return conn.close();
        conn.upstream_send();
    }

    fn upstream_send(conn: *Connection) void {
        const up = &conn.upstream;
        conn.submit(on_upstream_send, &up.completion, .{ .send = .{
            .socket = up.fd,
            .buffer = up.request[up.request_done..up.request_len],
        } });
    }

    fn on_upstream_send(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        const up = &conn.upstream;
        up.request_done += result catch return conn.close();
        if (up.request_done < up.request_len) return conn.upstream_send();
        conn.upstream_receive();
    }

    fn upstream_receive(conn: *Connection) void {
        const up = &conn.upstream;
        conn.submit(on_upstream_receive, &up.completion, .{ .recv = .{
            .socket = up.fd,
            .buffer = up.buffer[up.len..],
        } });
    }

    fn on_upstream_receive(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        const up = &conn.upstream;
        const n = result catch return conn.close();
        if (n == 0) return conn.close();
        up.len += n;

        const data = up.buffer[0..up.len];
        const end = mem.indexOfPos(u8, data, up.scanned, "\r\n\r\n") orelse {
            if (data.len >= head_max) return conn.close();
            up.scanned = data.len -| 3;
            return conn.upstream_receive();
        };
        up.scanned = end;
        const head_len = end + 4;
        if (head_len > head_max or !mem.startsWith(u8, data, "HTTP/1.1 ")) return conn.close();
        const line_end = mem.indexOf(u8, data[0..head_len], "\r\n").?;
        const headers = data[@min(line_end + 2, end)..end];
        const length_text = header_value(headers, "content-length") orelse return conn.close();
        const body_len = parse_decimal(length_text, body_max) orelse return conn.close();
        const content_type = header_value(headers, "content-type") orelse
            "application/octet-stream";
        if (data.len < head_len + body_len) return conn.upstream_receive();
        const body = data[head_len..][0..body_len];

        // Build the client's response, then drop the upstream response.
        if (content_type.len > head_room - 80) return conn.close();
        const out: []u8 = if (head_room + body_len <= conn.small.len)
            &conn.small
        else
            conn.big_buffer() orelse return conn.close();
        const at = write_head(out, content_type, body_len);
        @memcpy(out[at..][0..body_len], body);

        const used = head_len + body_len;
        mem.copyForwards(u8, up.buffer[0 .. up.len - used], up.buffer[used..up.len]);
        up.len -= used;
        up.scanned = 0;
        conn.send(out[0 .. at + body_len]);
    }
};

const Upstream = struct {
    fd: fd_t,
    completion: IO.Completion,
    request: [64]u8,
    request_len: usize,
    request_done: usize,
    len: usize,
    scanned: usize,
    buffer: [request_max]u8,

    fn reset(up: *Upstream) void {
        up.fd = -1;
        up.completion = .{};
        up.len = 0;
        up.scanned = 0;
    }
};

// ---------------------------------------------------------------------------------------------
// wal: group commit. Appends gather during a tick; at its end they go out as one chain of
// linked SQEs, the writes then a single fdatasync, and every request in the chain is
// answered when the fdatasync completes. A failed write ends the process.

const Wal = struct {
    fd: fd_t = -1,
    offset: u64 = 0,
    /// Appends of the current tick.
    gathered: QueueType(Connection) = .{},
    gathered_count: u32 = 0,
    free: QueueType(Batch) = .{},

    /// Longest chain: leaves the SQ room for everything else queued in the same tick.
    const chain_max = ring_entries / 2;

    const Batch = struct {
        next: ?*Batch = null,
        wal: *Wal = undefined,
        conns: QueueType(Connection) = .{},
        completion: IO.Completion = .{},
    };

    fn append(wal: *Wal, conn: *Connection, body: []const u8) void {
        conn.wal_body = body;
        conn.wal_written = false;
        wal.gathered.push(conn);
        wal.gathered_count += 1;
    }

    fn commit(wal: *Wal, io: *IO) void {
        while (!wal.gathered.empty()) {
            const count = @min(wal.gathered_count, chain_max);
            wal.gathered_count -= count;
            const batch = wal.free.pop() orelse
                std.heap.page_allocator.create(Batch) catch fatal("wal", error.OutOfMemory);
            batch.* = .{ .wal = wal };

            io.reserve(count + 1);
            for (0..count) |_| {
                const conn = wal.gathered.pop().?;
                conn.submit_flags(on_write, &conn.completion, .{ .write = .{
                    .fd = wal.fd,
                    .buffer = conn.wal_body,
                    .offset = wal.offset,
                } }, linux.IOSQE_IO_LINK);
                wal.offset += conn.wal_body.len;
                batch.conns.push(conn);
            }
            io.submit(*Batch, batch, on_sync, &batch.completion, .{
                .fdatasync = .{ .fd = wal.fd },
            }, 0);
        }
    }

    fn on_write(conn: *Connection, _: *IO.Completion, result: IO.Result) void {
        conn.settle();
        const n = result catch |err| fatal("wal write", err);
        // A short write to a regular file means the disk is full.
        if (n != conn.wal_body.len) fatal("wal write", error.NoSpaceLeft);
        conn.wal_written = true;
    }

    fn on_sync(batch: *Batch, _: *IO.Completion, result: IO.Result) void {
        _ = result catch |err| fatal("wal fdatasync", err);
        while (batch.conns.pop()) |conn| {
            // The chain's CQEs arrive in order, so every write has been seen already.
            assert(conn.wal_written);
            conn.respond("text/plain", "ok");
        }
        batch.wal.free.push(batch);
    }
};

// ---------------------------------------------------------------------------------------------
// cpu: four threads take jobs off a locked queue and hand results back through an eventfd.

const Mutex = struct {
    // 0 unlocked, 1 locked, 2 locked with waiters (Drepper, "Futexes Are Tricky").
    state: std.atomic.Value(u32) = .init(0),

    fn lock(mutex: *Mutex) void {
        if (mutex.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) return;
        while (mutex.state.swap(2, .acquire) != 0) futex_wait(&mutex.state, 2);
    }

    fn unlock(mutex: *Mutex) void {
        if (mutex.state.swap(0, .release) == 2) futex_wake(&mutex.state, 1);
    }
};

fn futex_wait(word: *const std.atomic.Value(u32), expected: u32) void {
    _ = linux.futex_4arg(&word.raw, .{ .cmd = .WAIT, .private = true }, expected, null);
}

fn futex_wake(word: *const std.atomic.Value(u32), count: u32) void {
    _ = linux.futex_3arg(&word.raw, .{ .cmd = .WAKE, .private = true }, count);
}

const Pool = struct {
    jobs_lock: Mutex = .{},
    jobs: QueueType(Connection) = .{},
    /// Bumped under `jobs_lock` on every push; idle workers sleep on it.
    jobs_seq: std.atomic.Value(u32) = .init(0),

    done_lock: Mutex = .{},
    done: QueueType(Connection) = .{},

    eventfd: fd_t,
    eventfd_count: u64 = 0,
    eventfd_completion: IO.Completion = .{},
    io: *IO,

    fn start(pool: *Pool) !void {
        for (0..pool_threads) |_| {
            const thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, worker, .{pool});
            thread.detach();
        }
        pool.arm();
    }

    fn push(pool: *Pool, conn: *Connection) void {
        pool.jobs_lock.lock();
        pool.jobs.push(conn);
        _ = pool.jobs_seq.fetchAdd(1, .monotonic);
        pool.jobs_lock.unlock();
        futex_wake(&pool.jobs_seq, 1);
    }

    fn worker(pool: *Pool) void {
        // Zeroes straight from mmap: the compiler cannot see them, so it cannot fold the
        // loop (an allocator would memset in safe builds, and a memset is visible).
        const rc = linux.mmap(
            null,
            hash_buffer_size,
            .{ .READ = true, .WRITE = true },
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        if (linux.errno(rc) != .SUCCESS) fatal("pool", error.OutOfMemory);
        const buffer = @as([*]const u8, @ptrFromInt(rc))[0..hash_buffer_size];
        while (true) {
            pool.jobs_lock.lock();
            while (pool.jobs.empty()) {
                const seq = pool.jobs_seq.load(.monotonic);
                pool.jobs_lock.unlock();
                futex_wait(&pool.jobs_seq, seq);
                pool.jobs_lock.lock();
            }
            const conn = pool.jobs.pop().?;
            pool.jobs_lock.unlock();

            conn.hash = fnv_rounds(buffer, conn.hash_rounds);

            pool.done_lock.lock();
            const was_empty = pool.done.empty();
            pool.done.push(conn);
            pool.done_lock.unlock();
            // Only the first result of a batch needs to wake the loop.
            if (was_empty) {
                const one: u64 = 1;
                _ = linux.write(pool.eventfd, @ptrCast(&one), @sizeOf(u64));
            }
        }
    }

    fn arm(pool: *Pool) void {
        pool.io.submit(*Pool, pool, on_eventfd, &pool.eventfd_completion, .{ .read = .{
            .fd = pool.eventfd,
            .buffer = mem.asBytes(&pool.eventfd_count),
            .offset = 0,
        } }, 0);
    }

    fn on_eventfd(pool: *Pool, _: *IO.Completion, result: IO.Result) void {
        _ = result catch |err| fatal("eventfd read", err);
        pool.done_lock.lock();
        var done = pool.done;
        pool.done = .{};
        pool.done_lock.unlock();
        while (done.pop()) |conn| conn.hash_done();
        pool.arm();
    }
};

fn fnv_rounds(buffer: []const u8, rounds: u32) u64 {
    var h: u64 = 14695981039346656037;
    for (0..rounds) |_| {
        for (buffer) |b| h = (h ^ b) *% 1099511628211;
    }
    return h;
}

// ---------------------------------------------------------------------------------------------
// HTTP bytes.

const not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n" ++
    "Content-Length: 0\r\n\r\n";

const bio: [900]u8 = @splat('a');
const user_parts = [_][]const u8{
    "{\"id\":",
    ",\"name\":\"user",
    "\",\"email\":\"user",
    "@example.com\",\"active\":true,\"roles\":[\"reader\",\"writer\"]," ++
        "\"balance\":1234.56,\"bio\":\"" ++ bio ++ "\"}",
};

/// json: the response for `id`, the template filled by byte copying only; returns its length.
fn write_user(out: *[small_size]u8, id: u32) usize {
    var digits_buffer: [20]u8 = undefined;
    const digits = format_decimal(&digits_buffer, id);
    const body_len = user_parts[0].len + user_parts[1].len + user_parts[2].len +
        user_parts[3].len + 3 * digits.len;
    var at = write_head(out, "application/json", body_len);
    inline for (user_parts, 0..) |part, i| {
        if (i > 0) {
            @memcpy(out[at..][0..digits.len], digits);
            at += digits.len;
        }
        @memcpy(out[at..][0..part.len], part);
        at += part.len;
    }
    return at;
}

/// Write the 200 response head into `out`; returns its length.
fn write_head(out: []u8, content_type: []const u8, body_len: usize) usize {
    var digits_buffer: [20]u8 = undefined;
    const digits = format_decimal(&digits_buffer, body_len);
    var at: usize = 0;
    const parts = [_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Type: ", content_type,
        "\r\nContent-Length: ",              digits,
        "\r\n\r\n",
    };
    for (parts) |part| {
        @memcpy(out[at..][0..part.len], part);
        at += part.len;
    }
    return at;
}

fn format_decimal(buffer: *[20]u8, value: u64) []const u8 {
    var v = value;
    var i: usize = buffer.len;
    while (true) {
        i -= 1;
        buffer[i] = @intCast('0' + v % 10);
        v /= 10;
        if (v == 0) return buffer[i..];
    }
}

/// Plain decimal digits, no sign or spaces, at most `max`.
fn parse_decimal(text: []const u8, max: u64) ?u64 {
    if (text.len == 0 or text.len > 20) return null;
    var value: u64 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        value = std.math.mul(u64, value, 10) catch return null;
        value = std.math.add(u64, value, c - '0') catch return null;
    }
    return if (value <= max) value else null;
}

fn suffix(path: []const u8, prefix: []const u8) ?[]const u8 {
    return if (mem.startsWith(u8, path, prefix)) path[prefix.len..] else null;
}

/// The trimmed value of the first header called `name` (lower case), if any.
fn header_value(headers: []const u8, comptime name: []const u8) ?[]const u8 {
    var lines = mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len > name.len and line[name.len] == ':' and
            std.ascii.eqlIgnoreCase(line[0..name.len], name))
        {
            return mem.trim(u8, line[name.len + 1 ..], " \t");
        }
    }
    return null;
}

// ---------------------------------------------------------------------------------------------
// Setup.

fn fatal(what: []const u8, err: anyerror) noreturn {
    const name = @errorName(err);
    for ([_][]const u8{ "server: ", what, ": ", name, "\n" }) |part| {
        _ = linux.write(2, part.ptr, part.len);
    }
    linux.exit_group(1);
}

fn usage(message: []const u8) noreturn {
    const help = "\nusage: server json|static|proxy|wal|cpu PORT\n";
    for ([_][]const u8{ "server: ", message, help }) |part| {
        _ = linux.write(2, part.ptr, part.len);
    }
    linux.exit_group(2);
}

fn check(rc: usize, what: []const u8) usize {
    const e = linux.errno(rc);
    if (e != .SUCCESS) fatal(what, switch (e) {
        .ADDRINUSE => error.AddressInUse,
        .NOENT => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        else => error.Unexpected,
    });
    return rc;
}

fn set_nodelay(fd: fd_t) void {
    const one: c_int = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&one), @sizeOf(c_int));
}

fn listen(port: u16) fd_t {
    const fd: fd_t = @intCast(check(
        linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0),
        "socket",
    ));
    const one: c_int = 1;
    _ = check(
        linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int)),
        "setsockopt",
    );
    const address: linux.sockaddr.in = .{ .port = mem.nativeToBig(u16, port), .addr = 0 };
    _ = check(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in)), "bind");
    _ = check(linux.listen(fd, listen_backlog), "listen");
    return fd;
}

/// `a.b.c.d:port` or `localhost:port`.
fn parse_backend(text: []const u8) ?linux.sockaddr.in {
    const colon = mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const host = text[0..colon];
    const port = parse_decimal(text[colon + 1 ..], std.math.maxInt(u16)) orelse return null;
    var octets: [4]u8 = .{ 127, 0, 0, 1 };
    if (!mem.eql(u8, host, "localhost")) {
        var parts = mem.splitScalar(u8, host, '.');
        for (&octets) |*octet| {
            octet.* = @intCast(parse_decimal(parts.next() orelse return null, 255) orelse
                return null);
        }
        if (parts.next() != null) return null;
    }
    return .{ .port = mem.nativeToBig(u16, @intCast(port)), .addr = @bitCast(octets) };
}

pub fn main(init: std.process.Init.Minimal) void {
    var args = init.args.iterate();
    _ = args.skip();
    const scenario_name = args.next() orelse usage("missing SCENARIO");
    const port_text = args.next() orelse usage("missing PORT");
    const scenario = std.meta.stringToEnum(Scenario, scenario_name) orelse
        usage("unknown SCENARIO");
    const port: u16 = @intCast(parse_decimal(port_text, std.math.maxInt(u16)) orelse
        usage("bad PORT"));

    var io = IO.init() catch |err| fatal("io_uring_setup", err);
    var server: Server = .{ .io = &io, .scenario = scenario, .listener = -1 };

    switch (scenario) {
        .json => {},
        .static => {
            const dir = init.environ.getPosix("FILES") orelse usage("static needs FILES=dir");
            server.files = @intCast(check(linux.openat(linux.AT.FDCWD, dir, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
            }, 0), "open FILES"));
        },
        .proxy => {
            const backend = init.environ.getPosix("BACKEND") orelse
                usage("proxy needs BACKEND=host:port");
            server.backend = parse_backend(backend) orelse usage("bad BACKEND");
        },
        .wal => {
            const path = init.environ.getPosix("LOG") orelse usage("wal needs LOG=path");
            server.wal.fd = @intCast(check(linux.openat(linux.AT.FDCWD, path, .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
                .CLOEXEC = true,
            }, 0o644), "open LOG"));
        },
        .cpu => {
            const pool = std.heap.page_allocator.create(Pool) catch
                fatal("pool", error.OutOfMemory);
            pool.* = .{
                .io = &io,
                .eventfd = @intCast(check(linux.eventfd(0, linux.EFD.CLOEXEC), "eventfd")),
            };
            pool.start() catch |err| fatal("pool", err);
            server.pool = pool;
        },
    }

    server.listener = listen(port);
    server.accept();
    const ready = "ready\n";
    _ = linux.write(1, ready, ready.len);

    while (true) {
        io.tick();
        server.on_tick();
    }
}

// ---------------------------------------------------------------------------------------------
// Tests of the byte handling (`zig test server.zig` runs them on any host).

test "json response is the template with the id in all three places" {
    var out: [small_size]u8 = undefined;
    var expected_buffer: [2048]u8 = undefined;
    const id = "4294967295";
    const body = try std.fmt.bufPrint(&expected_buffer, "{{\"id\":{s},\"name\":\"user{s}\"," ++
        "\"email\":\"user{s}@example.com\",\"active\":true,\"roles\":[\"reader\",\"writer\"]," ++
        "\"balance\":1234.56,\"bio\":\"{s}\"}}", .{ id, id, id, &bio });
    var head_buffer: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buffer, "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json\r\nContent-Length: {d}\r\n\r\n", .{body.len});
    const response = out[0..write_user(&out, 4294967295)];
    try std.testing.expectEqualStrings(head, response[0..head.len]);
    try std.testing.expectEqualStrings(body, response[head.len..]);
}

test "parse: split head, POST body, next request kept" {
    const conn = try std.testing.allocator.create(Connection);
    defer std.testing.allocator.destroy(conn);
    conn.scanned = 0;
    conn.recv_len = 0;
    const no_headers = "POST /log HTTP/1.1\r\n\r\n";
    @memcpy(conn.recv_buffer[0..no_headers.len], no_headers);
    conn.recv_len = no_headers.len;
    try std.testing.expect(conn.parse() == .invalid);

    conn.scanned = 0;
    const first = "POST /log HTTP/1.1\r\nHost: x\r\ncOnTeNt-LeNgTh:  3\r\n\r";
    @memcpy(conn.recv_buffer[0..first.len], first);
    conn.recv_len = first.len;
    try std.testing.expect(conn.parse() == .incomplete);
    const rest = "\nabcGET /user/1 HTTP/1.1\r\n\r\n";
    @memcpy(conn.recv_buffer[first.len..][0..rest.len], rest);
    conn.recv_len += rest.len;
    const request = conn.parse().request;
    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/log", request.path);
    const body = conn.recv_buffer[request.head_len..][0..request.body_len];
    try std.testing.expectEqualStrings("abc", body);
    try std.testing.expectEqualStrings(
        "GET /user/1 HTTP/1.1\r\n\r\n",
        conn.recv_buffer[request.head_len + request.body_len .. conn.recv_len],
    );
}

test "decimal parsing rejects what is not a plain u32" {
    try std.testing.expectEqual(@as(?u64, 4294967295), parse_decimal("4294967295", 4294967295));
    try std.testing.expectEqual(@as(?u64, null), parse_decimal("4294967296", 4294967295));
    try std.testing.expectEqual(@as(?u64, null), parse_decimal("", 10));
    try std.testing.expectEqual(@as(?u64, null), parse_decimal("+1", 10));
    try std.testing.expectEqual(@as(?u64, null), parse_decimal("99999999999999999999", 1 << 63));
}

test "hash of 200 rounds matches test.sh" {
    const buffer = try std.testing.allocator.alloc(u8, hash_buffer_size);
    defer std.testing.allocator.free(buffer);
    @memset(buffer, 0);
    try std.testing.expectEqual(@as(u64, 17515195554806768421), fnv_rounds(buffer, 200));
}
