//! The bench server (../SPEC.md) on rr's io: one loop, one Io. Clients
//! receive into the Io's chunks; each request is answered from the turn
//! it came in, or once what it waits on (a file, the backend, the log's
//! sync, work on the pool) is done. A client's events name it by its
//! index and generation in the key, so that one for a client gone does not
//! reach the next in its place.

use crate::base::io::{
    Conn, Data, Done, Error, Event, File, Io, Listener, Op, Open, Room, Work,
};
use crate::sys;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicU64, Ordering};

/// The table: a client holds its connection, a receive, sends, and as
/// many again for its backend connection and a file.
const SLOTS: usize = 32_768;
const CHUNKS: usize = 8192;
const CHUNK: usize = 4096;
/// A request's head and body at most, as SPEC says.
const HEAD_MAX: usize = 8 << 10;
const BODY_MAX: usize = 64 << 10;
/// A file at most, and one more byte to see its end.
const FILE_MAX: usize = 1 << 20;
/// The hash's buffer, and its constants (FNV-1a, 64 bits).
const HASHED: usize = 64 << 10;
const OFFSET: u64 = 14_695_981_039_346_656_037;
const PRIME: u64 = 1_099_511_628_211;

/// What an event is for: the bits above a client's index and generation.
const ACCEPT: u64 = 1 << 60;
const RECEIVE: u64 = 1 << 56;
const SEND: u64 = 2 << 56;
const FILE: u64 = 3 << 56;
const UPSTREAM: u64 = 4 << 56;
const UP_RECEIVE: u64 = 5 << 56;
const UP_SEND: u64 = 6 << 56;
const HASH: u64 = 7 << 56;
const LOG: u64 = 8 << 56;
const KIND: u64 = 0xff << 56;

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Json,
    Static,
    Proxy,
    Wal,
    Cpu,
}

/// A client: its connection, the bytes of a request not yet whole, its
/// backend connection, its file read, and what its hash work leaves.
struct Client {
    conn: Conn,
    generation: u32,
    pending: Vec<u8>,
    upstream: Option<Conn>,
    connecting: bool,
    /// The request the backend has, waiting for a connection.
    asked: Option<Vec<u8>>,
    answer: Vec<u8>,
    hashed: Arc<AtomicU64>,
    /// A request is in hand: the next waits in pending.
    busy: bool,
}

/// The work of /hash/n on the pool.
struct Hash {
    rounds: u64,
    result: Arc<AtomicU64>,
}

impl Work for Hash {
    fn run(&mut self) {
        let zeroes = [0u8; 1024];
        let mut h = OFFSET;
        for _ in 0..self.rounds {
            for _ in 0..HASHED / zeroes.len() {
                for &b in &zeroes {
                    h = (h ^ u64::from(b)).wrapping_mul(PRIME);
                }
            }
        }
        self.result.store(h, Ordering::Release);
    }
}

/// The log: its file while no write or sync has it, where the next write
/// goes, the bytes of the batch that waits and its clients, and those of
/// the batch the disk has.
struct Log {
    file: Option<File>,
    offset: u64,
    next: Vec<u8>,
    next_clients: Vec<u64>,
    writing: Vec<u64>,
    spare: Vec<u8>,
}

struct Server {
    io: Io,
    scenario: Scenario,
    clients: Vec<Option<Client>>,
    free: Vec<u32>,
    generations: Vec<u32>,
    /// Buffers back from sends, for the next.
    buffers: Vec<Vec<u8>>,
    files: Vec<u8>,
    backend: Option<SocketAddr>,
    log: Log,
}

/// The program's work: serve scenario on port until killed.
pub fn serve(scenario: &[u8], port: &[u8]) -> i32 {
    let Some(scenario) = scenario_of(scenario) else {
        sys::stderr(b"server: json, static, proxy, wal or cpu\n");
        return 2;
    };
    let Some(port) = decimal(port).and_then(|p| u16::try_from(p).ok()) else {
        sys::stderr(b"server: a port\n");
        return 2;
    };
    let Ok(io) = Io::new(SLOTS, CHUNKS, CHUNK) else {
        sys::stderr(b"server: no Io\n");
        return 1;
    };
    let mut server = Server {
        io,
        scenario,
        clients: Vec::new(),
        free: Vec::new(),
        generations: Vec::new(),
        buffers: Vec::new(),
        files: crate::env::var(c"FILES").unwrap_or_default(),
        backend: crate::env::var(c"BACKEND").and_then(|b| address(&b)),
        log: Log {
            file: None,
            offset: 0,
            next: Vec::new(),
            next_clients: Vec::new(),
            writing: Vec::new(),
            spare: Vec::new(),
        },
    };
    if scenario == Scenario::Wal && open_log(&mut server).is_err() {
        sys::stderr(b"server: no LOG\n");
        return 1;
    }
    let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let Ok(listener) = Listener::bind(any, 4096) else {
        sys::stderr(b"server: bind\n");
        return 1;
    };
    if server.io.accept(listener, ACCEPT).is_err() {
        return 1;
    }
    sys::stdout(b"ready\n");
    run(&mut server)
}

#[cfg_attr(rr, rr::poll)]
fn run(server: &mut Server) -> i32 {
    loop {
        if server.io.wait(None).is_err() {
            return 1;
        }
        while let Some(event) = server.io.next() {
            handle(server, event);
        }
        if server.scenario == Scenario::Wal {
            commit(server);
        }
    }
}

/// Opens the log at once, before the loop: its Event is the first.
fn open_log(server: &mut Server) -> Result<(), Error> {
    let path = crate::env::var(c"LOG").ok_or(Error::NotFound)?;
    if server.io.open(path, Open::Create, LOG).is_err() {
        return Err(Error::NoRoom);
    }
    loop {
        server.io.wait(None)?;
        if let Some(event) = server.io.next() {
            let Done::Opened { result, .. } = event.done else {
                return Err(Error::Other(0));
            };
            server.log.file = Some(result?);
            return Ok(());
        }
    }
}

fn handle(server: &mut Server, event: Event) {
    let key = event.key;
    if key == ACCEPT {
        accepted(server, event.done);
        return;
    }
    if key & KIND == LOG {
        logged(server, event.done);
        return;
    }
    match event.done {
        Done::Chunk(chunk) => {
            if let Some(client) = lookup(&mut server.clients, key) {
                if let Some(bytes) = server.io.bytes(&chunk) {
                    if client.pending.len().saturating_add(bytes.len()) <= HEAD_MAX + BODY_MAX {
                        client.pending.extend_from_slice(bytes);
                    }
                }
            }
            if let Err(chunk) = server.io.give_back(chunk) {
                drop(chunk);
            }
            requests(server, key);
        }
        Done::Stopped(result) => {
            if matches!(result, Err(Error::NoChunks)) {
                if let Some(client) = lookup(&mut server.clients, key) {
                    let op = server.io.receive(&client.conn, Room::Chunks, key);
                    forget(op.ok());
                    return;
                }
            }
            gone(server, key);
        }
        Done::Sent { buffer, result } => {
            put_buffer(server, buffer);
            if result.is_err() && key & KIND == SEND {
                drop_client(server, key);
            }
        }
        Done::Opened { result, .. } => match result {
            Ok(file) => {
                let buffer = buffer_of(server, FILE_MAX + 1);
                read_file(server, key, file, buffer, 0);
            }
            Err(_) => not_found(server, key),
        },
        Done::Read {
            file,
            buffer,
            result,
        } => match result {
            Ok(count) if count > 0 && buffer.len() < buffer.capacity() => {
                let at = buffer.len() as u64;
                read_file(server, key, file, buffer, at);
            }
            Ok(_) => {
                drop(file);
                file_read(server, key, buffer);
            }
            Err(_) => not_found(server, key),
        },
        Done::Connected(result) => upstream_made(server, key, result),
        Done::Received { buffer, result } => upstream_received(server, key, buffer, result),
        Done::Ran { .. } => hashed(server, key),
        Done::Accepted { .. }
        | Done::Elapsed(_)
        | Done::SentTo { .. }
        | Done::ReceivedFrom { .. }
        | Done::Written { .. }
        | Done::Synced { .. } => {}
    }
}

/// An Op the loop does not cancel: its Event comes all the same.
fn forget(op: Option<Op>) {
    drop(op);
}

fn accepted(server: &mut Server, done: Done) {
    let Done::Accepted { listener, result } = done else {
        return;
    };
    if let Err(listener) = server.io.accept(listener, ACCEPT) {
        drop(listener);
    }
    let Ok((conn, _peer)) = result else {
        return;
    };
    let index = match server.free.pop() {
        Some(index) => index,
        None => {
            if server.clients.len() >= SLOTS {
                server.io.close(conn);
                return;
            }
            server.clients.push(None);
            server.generations.push(0);
            u32::try_from(server.clients.len() - 1).unwrap_or(0)
        }
    };
    let generation = server
        .generations
        .get(index as usize)
        .copied()
        .unwrap_or(0);
    let key = client_key(index, generation);
    if server.io.receive(&conn, Room::Chunks, key | RECEIVE).is_err() {
        server.io.close(conn);
        server.free.push(index);
        return;
    }
    let client = Client {
        conn,
        generation,
        pending: Vec::with_capacity(512),
        upstream: None,
        connecting: false,
        asked: None,
        answer: Vec::new(),
        // rr: escape(shared): the client and its hash work on the pool.
        hashed: Arc::new(AtomicU64::new(0)),
        busy: false,
    };
    if let Some(at) = server.clients.get_mut(index as usize) {
        *at = Some(client);
    }
}

fn client_key(index: u32, generation: u32) -> u64 {
    (u64::from(generation & 0x00ff_ffff) << 32) | u64::from(index)
}

fn client_mut(server: &mut Server, key: u64) -> Option<&mut Client> {
    lookup(&mut server.clients, key)
}

/// The client a key names, while it is the one the key was made for.
fn lookup(clients: &mut [Option<Client>], key: u64) -> Option<&mut Client> {
    let index = usize::try_from(key & 0xffff_ffff).ok()?;
    let generation = u32::try_from((key >> 32) & 0x00ff_ffff).ok()?;
    let client = clients.get_mut(index)?.as_mut()?;
    (client.generation & 0x00ff_ffff == generation).then_some(client)
}

/// A client whose connection ended: closed, its place free.
fn gone(server: &mut Server, key: u64) {
    drop_client(server, key);
}

fn drop_client(server: &mut Server, key: u64) {
    if client_mut(server, key).is_none() {
        return;
    }
    let index = usize::try_from(key & 0xffff_ffff).unwrap_or(usize::MAX);
    let Some(client) = server.clients.get_mut(index).and_then(Option::take) else {
        return;
    };
    server.io.close(client.conn);
    if let Some(upstream) = client.upstream {
        server.io.close(upstream);
    }
    if let Some(generation) = server.generations.get_mut(index) {
        *generation = generation.wrapping_add(1);
    }
    server.free.push(u32::try_from(index).unwrap_or(0));
}

fn buffer_of(server: &mut Server, room: usize) -> Vec<u8> {
    match server.buffers.pop() {
        Some(mut buffer) => {
            buffer.clear();
            buffer.reserve(room);
            buffer
        }
        None => Vec::with_capacity(room.max(2048)),
    }
}

fn put_buffer(server: &mut Server, buffer: Vec<u8>) {
    if buffer.capacity() > 0 && buffer.capacity() <= 2 * FILE_MAX && server.buffers.len() < 4096 {
        server.buffers.push(buffer);
    }
}

/// The requests whole in a client's pending bytes, one at a time.
fn requests(server: &mut Server, key: u64) {
    let scenario = server.scenario;
    loop {
        let Some(client) = client_mut(server, key) else {
            return;
        };
        if client.busy {
            return;
        }
        let Some(head) = find(&client.pending, b"\r\n\r\n") else {
            if client.pending.len() > HEAD_MAX {
                drop_client(server, key);
            }
            return;
        };
        let head = head + 4;
        let body = content_length(client.pending.get(..head).unwrap_or_default());
        if body > BODY_MAX {
            drop_client(server, key);
            return;
        }
        let whole = head + body;
        if client.pending.len() < whole {
            return;
        }
        client.busy = true;
        let request = client.pending.get(..whole).unwrap_or_default();
        let (method, path) = request_line(request);
        let route = route(scenario, method, path);
        let id = path.and_then(|p| last_number(p)).unwrap_or(0);
        let name_at = path.map_or(0, |p| p.len());
        let file = path
            .and_then(|p| p.get(6..name_at))
            .map(Vec::from)
            .unwrap_or_default();
        let posted = client.pending.get(head..whole).map(Vec::from).unwrap_or_default();
        client.pending.drain(..whole);
        match route {
            Route::User => json(server, key, id),
            Route::File => static_file(server, key, &file),
            Route::Proxy => proxy(server, key, id),
            Route::Log => append(server, key, &posted),
            Route::Hash => hash(server, key, id),
            Route::Missing => respond(server, key, b"404 Not Found", b"text/plain", &[]),
        }
    }
}

#[derive(Clone, Copy)]
enum Route {
    User,
    File,
    Proxy,
    Log,
    Hash,
    Missing,
}

fn route(scenario: Scenario, method: &[u8], path: Option<&[u8]>) -> Route {
    let Some(path) = path else {
        return Route::Missing;
    };
    let get = method == b"GET";
    match scenario {
        Scenario::Json | Scenario::Cpu if get && path.starts_with(b"/user/") => Route::User,
        Scenario::Cpu if get && path.starts_with(b"/hash/") => Route::Hash,
        Scenario::Static if get && path.starts_with(b"/file/") => Route::File,
        Scenario::Proxy if get && path.starts_with(b"/proxy/") => Route::Proxy,
        Scenario::Wal if method == b"POST" && path == b"/log" => Route::Log,
        Scenario::Json | Scenario::Static | Scenario::Proxy | Scenario::Wal | Scenario::Cpu => {
            Route::Missing
        }
    }
}

/// A response of status, its type and body, in one send.
fn respond(server: &mut Server, key: u64, status: &[u8], kind: &[u8], body: &[u8]) {
    let mut out = buffer_of(server, 128 + body.len());
    head_into(&mut out, status, kind, body.len());
    out.extend_from_slice(body);
    send(server, key, Data::Bytes(out));
    done_request(server, key);
}

fn head_into(out: &mut Vec<u8>, status: &[u8], kind: &[u8], length: usize) {
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status);
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(kind);
    out.extend_from_slice(b"\r\nContent-Length: ");
    number_into(out, length as u64);
    out.extend_from_slice(b"\r\n\r\n");
}

fn send(server: &mut Server, key: u64, data: Data) {
    let Some(client) = lookup(&mut server.clients, key) else {
        return;
    };
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    match server.io.send(&client.conn, data, index_key | SEND) {
        Ok(op) => forget(Some(op)),
        Err(Data::Bytes(buffer)) => put_buffer(server, buffer),
        Err(Data::Chunk(chunk)) => {
            if let Err(chunk) = server.io.give_back(chunk) {
                drop(chunk);
            }
        }
        Err(Data::End) => {}
    }
}

/// The request is answered: the next one in pending, if whole, goes.
fn done_request(server: &mut Server, key: u64) {
    if let Some(client) = client_mut(server, key) {
        client.busy = false;
    }
}

fn json(server: &mut Server, key: u64, id: u64) {
    let mut body = buffer_of(server, 1200);
    json_into(&mut body, id);
    let mut out = buffer_of(server, 128 + body.len());
    head_into(&mut out, b"200 OK", b"application/json", body.len());
    out.extend_from_slice(&body);
    put_buffer(server, body);
    send(server, key, Data::Bytes(out));
    done_request(server, key);
}

/// SPEC's json template with the id in its three places.
fn json_into(out: &mut Vec<u8>, id: u64) {
    out.extend_from_slice(b"{\"id\":");
    number_into(out, id);
    out.extend_from_slice(b",\"name\":\"user");
    number_into(out, id);
    out.extend_from_slice(b"\",\"email\":\"user");
    number_into(out, id);
    out.extend_from_slice(
        b"@example.com\",\"active\":true,\"roles\":[\"reader\",\"writer\"],\"balance\":1234.56,\"bio\":\"",
    );
    out.resize(out.len() + 900, b'a');
    out.extend_from_slice(b"\"}");
}

fn static_file(server: &mut Server, key: u64, name: &[u8]) {
    if name.is_empty() || name.contains(&b'/') {
        respond(server, key, b"404 Not Found", b"text/plain", &[]);
        return;
    }
    let mut path = buffer_of(server, server.files.len() + name.len() + 1);
    path.extend_from_slice(&server.files);
    path.push(b'/');
    path.extend_from_slice(name);
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    if let Err(path) = server.io.open(path, Open::Read, index_key | FILE) {
        put_buffer(server, path);
        respond(server, key, b"404 Not Found", b"text/plain", &[]);
    }
}

fn read_file(server: &mut Server, key: u64, file: File, buffer: Vec<u8>, at: u64) {
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    if let Err((file, buffer)) = server.io.read_at(file, buffer, at, index_key | FILE) {
        drop(file);
        put_buffer(server, buffer);
        not_found(server, key);
    }
}

fn not_found(server: &mut Server, key: u64) {
    respond(server, key, b"404 Not Found", b"text/plain", &[]);
}

/// The file whole in buffer: its head, then the buffer itself, sent in
/// that order on the connection, with no copy.
fn file_read(server: &mut Server, key: u64, buffer: Vec<u8>) {
    let mut out = buffer_of(server, 128);
    head_into(&mut out, b"200 OK", b"application/octet-stream", buffer.len());
    send(server, key, Data::Bytes(out));
    send(server, key, Data::Bytes(buffer));
    done_request(server, key);
}

fn proxy(server: &mut Server, key: u64, id: u64) {
    let mut ask = buffer_of(server, 64);
    ask.extend_from_slice(b"GET /user/");
    number_into(&mut ask, id);
    ask.extend_from_slice(b" HTTP/1.1\r\nHost: b\r\n\r\n");
    let backend = server.backend;
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    let Some(client) = lookup(&mut server.clients, key) else {
        return;
    };
    client.answer.clear();
    if let Some(upstream) = &client.upstream {
        let receive = Room::Buffer(Vec::with_capacity(4096));
        forget(server.io.receive(upstream, receive, index_key | UP_RECEIVE).ok());
        forget(
            server
                .io
                .send(upstream, Data::Bytes(ask), index_key | UP_SEND)
                .ok(),
        );
        return;
    }
    client.asked = Some(ask);
    if client.connecting {
        return;
    }
    client.connecting = true;
    let Some(backend) = backend else {
        drop_client(server, key);
        return;
    };
    if server.io.connect(backend, index_key | UPSTREAM).is_err() {
        drop_client(server, key);
    }
}

fn upstream_made(server: &mut Server, key: u64, result: Result<Conn, Error>) {
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    let Ok(upstream) = result else {
        drop_client(server, key);
        return;
    };
    let Some(client) = lookup(&mut server.clients, key) else {
        server.io.close(upstream);
        return;
    };
    client.connecting = false;
    if let Some(ask) = client.asked.take() {
        let receive = Room::Buffer(Vec::with_capacity(4096));
        forget(server.io.receive(&upstream, receive, index_key | UP_RECEIVE).ok());
        forget(
            server
                .io
                .send(&upstream, Data::Bytes(ask), index_key | UP_SEND)
                .ok(),
        );
    }
    client.upstream = Some(upstream);
}

/// The backend's answer, as it comes: whole once its head and its
/// Content-Length of body are; then the client gets its body.
fn upstream_received(server: &mut Server, key: u64, buffer: Vec<u8>, result: Result<usize, Error>) {
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    if key & KIND != UP_RECEIVE || !result.is_ok_and(|n| n > 0) {
        drop_client(server, key);
        return;
    }
    let Some(client) = lookup(&mut server.clients, key) else {
        return;
    };
    client.answer.extend_from_slice(&buffer);
    let whole = find(&client.answer, b"\r\n\r\n").and_then(|at| {
        let head = at + 4;
        let length = content_length(client.answer.get(..head).unwrap_or_default());
        (client.answer.len() >= head + length).then_some((head, length))
    });
    let Some((head, length)) = whole else {
        let Some(upstream) = &client.upstream else {
            return;
        };
        let mut again = buffer;
        again.clear();
        forget(
            server
                .io
                .receive(upstream, Room::Buffer(again), index_key | UP_RECEIVE)
                .ok(),
        );
        return;
    };
    let mut out = buffer;
    out.clear();
    head_into(&mut out, b"200 OK", b"application/json", length);
    out.extend_from_slice(client.answer.get(head..head + length).unwrap_or_default());
    send(server, key, Data::Bytes(out));
    done_request(server, key);
    requests(server, key);
}

fn append(server: &mut Server, key: u64, body: &[u8]) {
    server.log.next.extend_from_slice(body);
    server.log.next_clients.push(key & 0x00ff_ffff_ffff_ffff);
}

/// The batch of this turn goes to the disk, once the last is on it.
fn commit(server: &mut Server) {
    if server.log.next.is_empty() || !server.log.writing.is_empty() {
        return;
    }
    let Some(file) = server.log.file.take() else {
        return;
    };
    let batch = core::mem::replace(&mut server.log.next, core::mem::take(&mut server.log.spare));
    core::mem::swap(&mut server.log.writing, &mut server.log.next_clients);
    let at = server.log.offset;
    server.log.offset += batch.len() as u64;
    if server.io.write_at(file, batch, at, LOG).is_err() {
        sys::die();
    }
}

fn logged(server: &mut Server, done: Done) {
    match done {
        Done::Written {
            file,
            buffer,
            result,
        } => {
            if result.is_err() {
                sys::die();
            }
            let mut spare = buffer;
            spare.clear();
            server.log.spare = spare;
            if server.io.sync(file, LOG).is_err() {
                sys::die();
            }
        }
        Done::Synced { file, result } => {
            if result.is_err() {
                sys::die();
            }
            server.log.file = Some(file);
            let mut writing = core::mem::take(&mut server.log.writing);
            for &key in &writing {
                respond(server, key, b"200 OK", b"text/plain", b"ok");
                requests(server, key);
            }
            writing.clear();
            server.log.writing = writing;
            commit(server);
        }
        Done::Accepted { .. }
        | Done::Connected(_)
        | Done::Received { .. }
        | Done::Sent { .. }
        | Done::Elapsed(_)
        | Done::SentTo { .. }
        | Done::ReceivedFrom { .. }
        | Done::Chunk(_)
        | Done::Stopped(_)
        | Done::Opened { .. }
        | Done::Read { .. }
        | Done::Ran { .. } => {}
    }
}

fn hash(server: &mut Server, key: u64, rounds: u64) {
    let index_key = key & 0x00ff_ffff_ffff_ffff;
    let Some(client) = client_mut(server, key) else {
        return;
    };
    let work = Hash {
        rounds,
        // rr: escape(copy): the work's holder of where it leaves its result.
        result: Arc::clone(&client.hashed),
    };
    if server.io.run(Box::new(work), index_key | HASH).is_err() {
        drop_client(server, key);
    }
}

fn hashed(server: &mut Server, key: u64) {
    let Some(client) = client_mut(server, key) else {
        return;
    };
    let result = client.hashed.load(Ordering::Acquire);
    let mut body = Vec::with_capacity(24);
    number_into(&mut body, result);
    respond(server, key, b"200 OK", b"text/plain", &body);
    requests(server, key);
}

fn scenario_of(name: &[u8]) -> Option<Scenario> {
    match name {
        b"json" => Some(Scenario::Json),
        b"static" => Some(Scenario::Static),
        b"proxy" => Some(Scenario::Proxy),
        b"wal" => Some(Scenario::Wal),
        b"cpu" => Some(Scenario::Cpu),
        _ => None,
    }
}

fn find(bytes: &[u8], what: &[u8]) -> Option<usize> {
    bytes.windows(what.len()).position(|w| w == what)
}

/// The method and path of a request's first line.
fn request_line(request: &[u8]) -> (&[u8], Option<&[u8]>) {
    let line = request
        .split(|&b| b == b'\r')
        .next()
        .unwrap_or_default();
    let mut parts = line.split(|&b| b == b' ');
    let method = parts.next().unwrap_or_default();
    (method, parts.next())
}

/// The Content-Length a head says, 0 when none.
fn content_length(head: &[u8]) -> usize {
    for line in head.split(|&b| b == b'\n') {
        let Some(name) = line.get(..15) else {
            continue;
        };
        if name.eq_ignore_ascii_case(b"content-length:") {
            let value = line.get(15..).unwrap_or_default();
            let digits: &[u8] = value.trim_ascii();
            return decimal(digits).and_then(|n| usize::try_from(n).ok()).unwrap_or(usize::MAX);
        }
    }
    0
}

/// The number a path ends with.
fn last_number(path: &[u8]) -> Option<u64> {
    let at = path.iter().rposition(|&b| b == b'/')?;
    decimal(path.get(at + 1..)?)
}

fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 19 {
        return None;
    }
    let mut n = 0u64;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u64::from(d - b'0');
    }
    Some(n)
}

fn number_into(out: &mut Vec<u8>, n: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut rest = n;
    loop {
        at -= 1;
        if let Some(d) = digits.get_mut(at) {
            *d = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        }
        rest /= 10;
        if rest == 0 || at == 0 {
            break;
        }
    }
    out.extend_from_slice(digits.get(at..).unwrap_or_default());
}

fn address(text: &[u8]) -> Option<SocketAddr> {
    core::str::from_utf8(text).ok()?.parse().ok()
}
