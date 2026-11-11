//! Bench server on tokio: one current-thread runtime, blocking work on
//! tokio's blocking pool. See ../SPEC.md.

use std::fs::File;
use std::future::poll_fn;
use std::hint::black_box;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::spawn_blocking;

const HEAD_MAX: usize = 8192;
const BODY_MAX: usize = 65536;
const FILE_MAX: usize = 1 << 20;
// Room in front of a file's bytes for its response head.
const GAP: usize = 128;
const HASH_BUF: usize = 65536;

const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
const JSON: &[u8] = b"application/json";
const OCTETS: &[u8] = b"application/octet-stream";
const TEXT: &[u8] = b"text/plain";

const HEAD1: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: ";
const HEAD2: &[u8] = b"\r\nContent-Length: ";
const HEAD3: &[u8] = b"\r\n\r\n";

const J1: &[u8] = b"{\"id\":";
const J2: &[u8] = b",\"name\":\"user";
const J3: &[u8] = b"\",\"email\":\"user";
const J4: &[u8] = b"@example.com\",\"active\":true,\"roles\":[\"reader\",\"writer\"],\"balance\":1234.56,\"bio\":\"";
const J5: &[u8] = b"\"}";
const BIO: usize = 900;

static ZEROES: [u8; HASH_BUF] = [0; HASH_BUF];

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Json,
    Static,
    Proxy,
    Wal,
    Cpu,
}

struct Config {
    scenario: Scenario,
    backend: Option<SocketAddr>,
    files: String,
    wal: Option<Arc<Wal>>,
}

// Group commit: appends accumulate in buf while the writer syncs the
// previous batch; every waiter of a batch is woken by its one sync.
struct WalState {
    buf: Vec<u8>,
    open: u64,
    durable: u64,
    open_waiters: Vec<Waker>,
    sealed_waiters: Vec<Waker>,
    writer: Option<Waker>,
}

struct Wal {
    st: Mutex<WalState>,
}

struct Request {
    head: usize,
    body: usize,
    method: (usize, usize),
    path: (usize, usize),
}

struct Upstream {
    s: TcpStream,
    buf: Vec<u8>,
    len: usize,
}

struct Conn {
    w: Vec<u8>,
    file: Vec<u8>,
    path: String,
    up: Option<Upstream>,
}

fn find_end(b: &[u8], from: usize) -> Option<usize> {
    let start = from.saturating_sub(3);
    b[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| start + i + 4)
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [c, rest @ ..] = b {
        if *c != b' ' && *c != b'\t' {
            break;
        }
        b = rest;
    }
    while let [rest @ .., c] = b {
        if *c != b' ' && *c != b'\t' {
            break;
        }
        b = rest;
    }
    b
}

fn parse_u64(b: &[u8], max: u64) -> Option<u64> {
    if b.is_empty() || b.len() > 20 {
        return None;
    }
    let mut v: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    if v > max {
        return None;
    }
    Some(v)
}

// Header lines after the first of a head ending in \r\n\r\n.
fn lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|&c| c == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .skip(1)
        .take_while(|l| !l.is_empty())
}

fn header<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    lines(head).find_map(|l| {
        let colon = l.iter().position(|&c| c == b':')?;
        if trim(&l[..colon]).eq_ignore_ascii_case(name) {
            Some(trim(&l[colon + 1..]))
        } else {
            None
        }
    })
}

// Ok(None): need more bytes; Err: malformed or too large.
fn parse(b: &[u8], scanned: usize) -> Result<Option<Request>, ()> {
    let head = match find_end(b, scanned) {
        Some(h) if h <= HEAD_MAX => h,
        Some(_) => return Err(()),
        None if b.len() >= HEAD_MAX => return Err(()),
        None => return Ok(None),
    };
    let line_end = b.iter().position(|&c| c == b'\r').unwrap_or(0);
    let line = &b[..line_end];
    let sp1 = line.iter().position(|&c| c == b' ').ok_or(())?;
    let sp2 = line[sp1 + 1..].iter().position(|&c| c == b' ').ok_or(())? + sp1 + 1;
    let body = match header(&b[..head], b"content-length") {
        Some(v) => parse_u64(v, BODY_MAX as u64).ok_or(())? as usize,
        None => 0,
    };
    Ok(Some(Request {
        head,
        body,
        method: (0, sp1),
        path: (sp1 + 1, sp2),
    }))
}

// Writes v in decimal at the end of d; returns the digits.
fn digits(mut v: u64, d: &mut [u8; 20]) -> &[u8] {
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &d[i..]
}

fn head_len(ctype: &[u8], n: &[u8]) -> usize {
    HEAD1.len() + ctype.len() + HEAD2.len() + n.len() + HEAD3.len()
}

// Fills dst, exactly head_len() long, with a 200 head.
fn head_into(dst: &mut [u8], ctype: &[u8], n: &[u8]) {
    let mut at = 0;
    for part in [HEAD1, ctype, HEAD2, n, HEAD3] {
        dst[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
}

fn put_head(w: &mut Vec<u8>, ctype: &[u8], n: usize) {
    let mut d = [0u8; 20];
    let n = digits(n as u64, &mut d);
    let at = w.len();
    w.resize(at + head_len(ctype, n), 0);
    head_into(&mut w[at..], ctype, n);
}

fn put_json(w: &mut Vec<u8>, id: u32) {
    let mut d = [0u8; 20];
    let id = digits(u64::from(id), &mut d);
    let len = J1.len() + J2.len() + J3.len() + J4.len() + BIO + J5.len() + 3 * id.len();
    put_head(w, JSON, len);
    w.extend_from_slice(J1);
    w.extend_from_slice(id);
    w.extend_from_slice(J2);
    w.extend_from_slice(id);
    w.extend_from_slice(J3);
    w.extend_from_slice(id);
    w.extend_from_slice(J4);
    w.resize(w.len() + BIO, b'a');
    w.extend_from_slice(J5);
}

fn put_text(w: &mut Vec<u8>, body: &[u8]) {
    put_head(w, TEXT, body.len());
    w.extend_from_slice(body);
}

fn hash(n: u32) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for _ in 0..n {
        for &b in black_box(&ZEROES[..]) {
            h = (h ^ u64::from(b)).wrapping_mul(1099511628211);
        }
    }
    h
}

// Reads the file into buf after GAP bytes and puts its head right
// before them; returns the response's range in buf.
fn read_file(path: &str, buf: &mut [u8]) -> io::Result<(usize, usize)> {
    let mut f = File::open(path)?;
    let mut n = 0;
    while n < FILE_MAX {
        match f.read(&mut buf[GAP + n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    drop(f);
    let mut d = [0u8; 20];
    let len = digits(n as u64, &mut d);
    let start = GAP - head_len(OCTETS, len);
    head_into(&mut buf[start..GAP], OCTETS, len);
    Ok((start, GAP + n))
}

impl Wal {
    async fn append(&self, body: &[u8]) {
        let mut id = 0;
        poll_fn(|cx| {
            let mut st = self.st.lock().unwrap();
            if id == 0 {
                st.buf.extend_from_slice(body);
                id = st.open;
                if let Some(w) = st.writer.take() {
                    w.wake();
                }
            } else if st.durable >= id {
                return Poll::Ready(());
            }
            let waiters = if id == st.open {
                &mut st.open_waiters
            } else {
                &mut st.sealed_waiters
            };
            waiters.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    async fn writer(self: Arc<Self>, mut file: File) {
        let mut off: u64 = 0;
        let mut spare = Vec::with_capacity(BODY_MAX);
        loop {
            let id = poll_fn(|cx| {
                let mut st = self.st.lock().unwrap();
                if st.buf.is_empty() {
                    st.writer = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                mem::swap(&mut st.buf, &mut spare);
                let st = &mut *st;
                mem::swap(&mut st.open_waiters, &mut st.sealed_waiters);
                st.open += 1;
                Poll::Ready(st.open - 1)
            })
            .await;
            let buf = mem::take(&mut spare);
            let at = off;
            let (f, mut buf, r) = spawn_blocking(move || {
                let r = file.write_all_at(&buf, at).and_then(|()| file.sync_data());
                (file, buf, r)
            })
            .await
            .unwrap();
            if let Err(e) = r {
                eprintln!("wal: {e}");
                std::process::exit(1);
            }
            file = f;
            off += buf.len() as u64;
            buf.clear();
            spare = buf;
            let mut st = self.st.lock().unwrap();
            st.durable = id;
            for w in st.sealed_waiters.drain(..) {
                w.wake();
            }
        }
    }
}

impl Upstream {
    // Forwards GET /user/<id>; leaves the reply in w.
    async fn fetch(&mut self, id: &[u8], w: &mut Vec<u8>) -> io::Result<()> {
        w.clear();
        w.extend_from_slice(b"GET /user/");
        w.extend_from_slice(id);
        w.extend_from_slice(b" HTTP/1.1\r\nHost: b\r\n\r\n");
        self.s.write_all(w).await?;
        let bad = || io::Error::from(io::ErrorKind::InvalidData);
        let mut scanned = 0;
        let head = loop {
            if let Some(h) = find_end(&self.buf[..self.len], scanned) {
                break h;
            }
            scanned = self.len;
            if self.len == self.buf.len() {
                return Err(bad());
            }
            self.read().await?;
        };
        let h = &self.buf[..head];
        let body = header(h, b"content-length")
            .and_then(|v| parse_u64(v, usize::MAX as u64))
            .ok_or_else(bad)? as usize;
        let total = head.checked_add(body).ok_or_else(bad)?;
        if total > self.buf.len() {
            self.buf.resize(total, 0);
        }
        while self.len < total {
            self.read().await?;
        }
        let h = &self.buf[..head];
        let ctype = header(h, b"content-type").unwrap_or(OCTETS);
        w.clear();
        put_head(w, ctype, body);
        w.extend_from_slice(&self.buf[head..total]);
        self.buf.copy_within(total..self.len, 0);
        self.len -= total;
        Ok(())
    }

    async fn read(&mut self) -> io::Result<()> {
        match self.s.read(&mut self.buf[self.len..]).await? {
            0 => Err(io::ErrorKind::UnexpectedEof.into()),
            n => {
                self.len += n;
                Ok(())
            }
        }
    }
}

fn route<'a>(method: &[u8], path: &'a [u8], want: &[u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if method != want {
        return None;
    }
    path.strip_prefix(prefix)
}

fn id_of(b: &[u8]) -> Option<u32> {
    parse_u64(b, u64::from(u32::MAX)).map(|v| v as u32)
}

impl Conn {
    // Answers one request; Ok(Some((a, b))) means the reply is
    // file[a..b], Ok(None) that it is w.
    async fn handle(
        &mut self,
        cfg: &Config,
        req: &[u8],
        r: &Request,
    ) -> io::Result<Option<(usize, usize)>> {
        let method = &req[r.method.0..r.method.1];
        let path = &req[r.path.0..r.path.1];
        let body = &req[r.head..r.head + r.body];
        self.w.clear();
        match cfg.scenario {
            Scenario::Json | Scenario::Cpu => {
                if let Some(id) = route(method, path, b"GET", b"/user/").and_then(id_of) {
                    put_json(&mut self.w, id);
                    return Ok(None);
                }
                if cfg.scenario == Scenario::Cpu {
                    if let Some(n) = route(method, path, b"GET", b"/hash/").and_then(id_of) {
                        let h = spawn_blocking(move || hash(n)).await.unwrap();
                        let mut d = [0u8; 20];
                        put_text(&mut self.w, digits(h, &mut d));
                        return Ok(None);
                    }
                }
            }
            Scenario::Static => {
                let name = route(method, path, b"GET", b"/file/")
                    .filter(|n| !n.is_empty() && n[0] != b'.' && !n.contains(&b'/'))
                    .and_then(|n| std::str::from_utf8(n).ok());
                if let Some(name) = name {
                    if self.file.is_empty() {
                        self.file = vec![0; GAP + FILE_MAX];
                    }
                    self.path.clear();
                    self.path.push_str(&cfg.files);
                    self.path.push('/');
                    self.path.push_str(name);
                    let path = mem::take(&mut self.path);
                    let mut buf = mem::take(&mut self.file);
                    let (path, buf, r) = spawn_blocking(move || {
                        let r = read_file(&path, &mut buf);
                        (path, buf, r)
                    })
                    .await
                    .unwrap();
                    self.path = path;
                    self.file = buf;
                    if let Ok(range) = r {
                        return Ok(Some(range));
                    }
                }
            }
            Scenario::Proxy => {
                if let Some(id) =
                    route(method, path, b"GET", b"/proxy/").filter(|b| id_of(b).is_some())
                {
                    if self.up.is_none() {
                        let s = TcpStream::connect(cfg.backend.unwrap()).await?;
                        s.set_nodelay(true)?;
                        self.up = Some(Upstream {
                            s,
                            buf: vec![0; HEAD_MAX + BODY_MAX],
                            len: 0,
                        });
                    }
                    let up = self.up.as_mut().unwrap();
                    up.fetch(id, &mut self.w).await?;
                    return Ok(None);
                }
            }
            Scenario::Wal => {
                if route(method, path, b"POST", b"/log").is_some_and(|rest| rest.is_empty()) {
                    cfg.wal.as_ref().unwrap().append(body).await;
                    put_text(&mut self.w, b"ok");
                    return Ok(None);
                }
            }
        }
        self.w.extend_from_slice(NOT_FOUND);
        Ok(None)
    }
}

async fn serve(mut s: TcpStream, cfg: Arc<Config>) {
    let mut c = Conn {
        w: Vec::with_capacity(4096),
        file: Vec::new(),
        path: String::new(),
        up: None,
    };
    let mut buf = vec![0u8; HEAD_MAX + BODY_MAX];
    let mut len = 0;
    let mut scanned = 0;
    let mut pending: Option<Request> = None;
    loop {
        if pending.is_none() {
            match parse(&buf[..len], scanned) {
                Ok(Some(r)) => pending = Some(r),
                Ok(None) => scanned = len,
                Err(()) => return,
            }
        }
        let ready = pending.as_ref().is_some_and(|r| len >= r.head + r.body);
        if !ready {
            match s.read(&mut buf[len..]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => len += n,
            }
            continue;
        }
        let r = pending.take().unwrap();
        let total = r.head + r.body;
        let out = match c.handle(&cfg, &buf[..total], &r).await {
            Ok(o) => o,
            Err(_) => return,
        };
        let reply = match out {
            Some((a, b)) => &c.file[a..b],
            None => &c.w[..],
        };
        if s.write_all(reply).await.is_err() {
            return;
        }
        buf.copy_within(total..len, 0);
        len -= total;
        scanned = 0;
    }
}

fn usage() -> ! {
    eprintln!("usage: server json|static|proxy|wal|cpu PORT");
    std::process::exit(2);
}

fn config(scenario: &str) -> io::Result<Config> {
    let scenario = match scenario {
        "json" => Scenario::Json,
        "static" => Scenario::Static,
        "proxy" => Scenario::Proxy,
        "wal" => Scenario::Wal,
        "cpu" => Scenario::Cpu,
        _ => usage(),
    };
    let env = |k: &str| std::env::var(k).map_err(|_| io::Error::other(format!("{k} not set")));
    let mut cfg = Config {
        scenario,
        backend: None,
        files: String::new(),
        wal: None,
    };
    match scenario {
        Scenario::Proxy => {
            let addr = env("BACKEND")?.to_socket_addrs()?.next();
            cfg.backend = Some(addr.ok_or_else(|| io::Error::other("BACKEND: no address"))?);
        }
        Scenario::Static => cfg.files = env("FILES")?,
        _ => {}
    }
    Ok(cfg)
}

async fn run(mut cfg: Config, port: u16) -> io::Result<()> {
    if cfg.scenario == Scenario::Wal {
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(std::env::var("LOG").map_err(|_| io::Error::other("LOG not set"))?)?;
        let wal = Arc::new(Wal {
            st: Mutex::new(WalState {
                buf: Vec::with_capacity(BODY_MAX),
                open: 1,
                durable: 0,
                open_waiters: Vec::new(),
                sealed_waiters: Vec::new(),
                writer: None,
            }),
        });
        tokio::spawn(wal.clone().writer(file));
        cfg.wal = Some(wal);
    }
    let cfg = Arc::new(cfg);
    let sock = TcpSocket::new_v4()?;
    sock.set_reuseaddr(true)?;
    sock.bind(SocketAddr::from(([0, 0, 0, 0], port)))?;
    let ln = sock.listen(4096)?;
    let mut out = io::stdout().lock();
    out.write_all(b"ready\n")?;
    out.flush()?;
    drop(out);
    loop {
        let (s, _) = match ln.accept().await {
            Ok(a) => a,
            Err(_) => continue,
        };
        let _ = s.set_nodelay(true);
        tokio::spawn(serve(s, cfg.clone()));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        usage();
    }
    let port: u16 = args[2].parse().unwrap_or_else(|_| usage());
    let r = config(&args[1]).and_then(|cfg| {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?
            .block_on(run(cfg, port))
    });
    if let Err(e) = r {
        eprintln!("server: {e}");
        std::process::exit(1);
    }
}
