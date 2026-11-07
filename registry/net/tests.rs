//! net's tests, and the wait Set's on real sockets: TCP over loopback,
//! as a server and its clients use it, on every way the system has to
//! wait (on Windows, socket notifications and WSAPoll both).

use super::{Error, Io, Listener, Stream, descriptors};
use crate::base::wait::{ERROR, EXPIRED, HUP, Instant, READ, Set, WRITE};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use test::Bencher;

fn sets() -> Vec<Set> {
    #[cfg(target_os = "windows")]
    return Vec::from([Set::new().unwrap(), Set::polled().unwrap()]);
    #[cfg(not(target_os = "windows"))]
    return Vec::from([Set::new().unwrap()]);
}

fn v4() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn v6() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
}

/// The events of one wait, as (key, ready), into events.
fn wait(set: &mut Set, until: Instant, events: &mut Vec<(u64, u8)>) {
    events.clear();
    for event in set.wait(Some(until)) {
        events.push((event.key, event.ready));
    }
}

/// Waits up to ten seconds for key with any of want; its readiness.
fn until(set: &mut Set, key: u64, want: u8) -> u8 {
    let end = Instant::now().after_ms(10_000);
    loop {
        for event in set.wait(Some(end)) {
            if event.key == key && event.ready & want != 0 {
                return event.ready;
            }
        }
        assert!(!end.reached_by(Instant::now()), "nothing for key {key}");
    }
}

/// Waits ms milliseconds, and checks that key was not reported with any
/// of these.
fn quiet(set: &mut Set, key: u64, these: u8, ms: u64) {
    let end = Instant::now().after_ms(ms);
    while !end.reached_by(Instant::now()) {
        for event in set.wait(Some(end)) {
            assert!(
                event.key != key || event.ready & these == 0,
                "key {key} reported {}",
                event.ready
            );
        }
    }
}

/// How often wait returns in ms milliseconds: a level-triggered wait the
/// system keeps waking spins.
fn wakeups(set: &mut Set, ms: u64) -> usize {
    let end = Instant::now().after_ms(ms);
    let mut count = 0;
    while !end.reached_by(Instant::now()) {
        set.wait(Some(end));
        count += 1;
    }
    count
}

/// The key a pair's listener is reported with.
const LISTENER: u64 = 1 << 40;

/// A connection through a listener on address: the client, made, and the
/// server's side, which the listener reports the client's address for.
/// Neither is in the Set.
fn pair(set: &mut Set, address: SocketAddr) -> (Stream, Stream) {
    let mut listener = Listener::bind(address, 16).unwrap();
    let mut client = Stream::connect(listener.local().unwrap()).unwrap();
    assert!(listener.watch(set, READ, LISTENER));
    assert!(client.watch(set, WRITE, LISTENER + 1));
    until(set, LISTENER + 1, WRITE | ERROR | HUP);
    assert!(client.connected().unwrap());
    let server = loop {
        if let Some((server, from)) = listener.accept().unwrap() {
            assert_eq!(Some(from), client.local());
            break server;
        }
        until(set, LISTENER, READ);
    };
    assert_eq!(client.peer(), listener.local());
    listener.close(set);
    assert!(client.watch(set, 0, LISTENER + 1));
    (client, server)
}

fn byte(seed: usize, at: usize) -> u8 {
    u8::try_from((seed * 31 + at * 7) % 251).unwrap()
}

/// What each client sends and gets back in echo_many.
const SIZE: usize = 32 * 1024;
const SERVER: u64 = 2 << 32;
const CLIENT: u64 = 3 << 32;
const INDEX: u64 = 0xFFFF_FFFF;

struct Client {
    stream: Option<Stream>,
    sent: usize,
    got: usize,
}

struct Peer {
    stream: Option<Stream>,
    key: u64,
    pending: Vec<u8>,
    ended: bool,
}

/// Hundreds of clients and their server in one loop: each client sends
/// 32 KiB in whatever pieces the system takes, the server sends back what
/// it reads as it can, and the client checks every byte; the server sees
/// each client's end and closes.
#[test]
fn echo_many() {
    let files = descriptors(4096);
    let count = usize::try_from(files.saturating_sub(64) / 2)
        .unwrap()
        .min(500);
    assert!(count >= 100, "only {files} descriptors");
    for mut set in sets() {
        echo(&mut set, count);
    }
}

fn echo(set: &mut Set, count: usize) {
    let mut listener = Listener::bind(v4(), 1024).unwrap();
    let address = listener.local().unwrap();
    assert!(listener.watch(set, READ, LISTENER));
    let mut clients: Vec<Client> = Vec::new();
    let mut peers: Vec<Peer> = Vec::new();
    let (mut finished, mut closed) = (0, 0);
    let mut buffer = [0u8; 16 * 1024];
    let mut events = Vec::new();
    let end = Instant::now().after_ms(60_000);
    while finished < count || closed < count {
        // 64 clients at most at a time: macOS caps a listen queue at 128.
        while clients.len() < count && clients.len() - finished < 64 {
            let mut stream = Stream::connect(address).unwrap();
            let key = CLIENT | u64::try_from(clients.len()).unwrap();
            assert!(stream.watch(set, READ | WRITE, key));
            clients.push(Client {
                stream: Some(stream),
                sent: 0,
                got: 0,
            });
        }
        assert!(
            !end.reached_by(Instant::now()),
            "{finished} of {count} done, {closed} closed"
        );
        wait(set, end, &mut events);
        for &(key, ready) in &events {
            let index = usize::try_from(key & INDEX).unwrap();
            match key & !INDEX {
                LISTENER => {
                    while let Some((mut stream, _)) = listener.accept().unwrap() {
                        let peer_key = SERVER | u64::try_from(peers.len()).unwrap();
                        assert!(stream.watch(set, READ, peer_key));
                        peers.push(Peer {
                            stream: Some(stream),
                            key: peer_key,
                            pending: Vec::new(),
                            ended: false,
                        });
                    }
                }
                SERVER => closed += serve(set, &mut peers[index], ready, &mut buffer),
                CLIENT => finished += talk(set, &mut clients[index], index, ready, &mut buffer),
                _ => panic!("key {key}"),
            }
        }
    }
    listener.close(set);
}

/// A client's turn: send what the system takes, check what came back; 1
/// when it got all of it back, and closed.
fn talk(set: &mut Set, client: &mut Client, seed: usize, ready: u8, buffer: &mut [u8]) -> usize {
    let Some(stream) = client.stream.as_mut() else {
        return 0;
    };
    assert_eq!(ready & ERROR, 0, "client {seed}: {:?}", stream.connected());
    while ready & WRITE != 0 && client.sent < SIZE {
        let piece = buffer.len().min(SIZE - client.sent);
        for (at, slot) in buffer[..piece].iter_mut().enumerate() {
            *slot = byte(seed, client.sent + at);
        }
        match stream.write(&buffer[..piece]).unwrap() {
            Io::Done(sent) => client.sent += sent,
            Io::Blocked => break,
        }
        if client.sent == SIZE {
            assert!(stream.watch(set, READ, CLIENT | u64::try_from(seed).unwrap()));
        }
    }
    if ready & (READ | HUP) == 0 {
        return 0;
    }
    loop {
        match stream.read(buffer).unwrap() {
            Io::Done(0) => panic!("client {seed}: the server ended at {}", client.got),
            Io::Done(got) => {
                for (at, &found) in buffer[..got].iter().enumerate() {
                    assert_eq!(found, byte(seed, client.got + at), "client {seed}");
                }
                client.got += got;
            }
            Io::Blocked => return 0,
        }
        if client.got == SIZE {
            client.stream.take().unwrap().close(set);
            return 1;
        }
    }
}

/// The server's turn for one client: read while there is room, send back
/// what it can, watch for what is left; 1 when the client ended and all
/// went back, and closed.
fn serve(set: &mut Set, peer: &mut Peer, ready: u8, buffer: &mut [u8]) -> usize {
    let key = peer.key;
    let Some(stream) = peer.stream.as_mut() else {
        return 0;
    };
    assert_eq!(ready & ERROR, 0, "server: {:?}", stream.connected());
    while ready & (READ | HUP) != 0 && !peer.ended && peer.pending.len() < 256 * 1024 {
        match stream.read(buffer).unwrap() {
            Io::Done(0) => peer.ended = true,
            Io::Done(got) => peer.pending.extend_from_slice(&buffer[..got]),
            Io::Blocked => break,
        }
    }
    while !peer.pending.is_empty() {
        match stream.write(&peer.pending).unwrap() {
            Io::Done(sent) => drop(peer.pending.drain(..sent)),
            Io::Blocked => break,
        }
    }
    if peer.ended && peer.pending.is_empty() {
        peer.stream.take().unwrap().close(set);
        return 1;
    }
    let read = if peer.ended { 0 } else { READ };
    let write = if peer.pending.is_empty() { 0 } else { WRITE };
    assert!(stream.watch(set, read | write, key));
    0
}

/// A writer fills what the system takes until it blocks; the reader then
/// drains it, and the writer is told when it may go on, to the last of 8
/// MiB, which arrive whole and in order.
#[test]
fn backpressure() {
    let mut chunk = Vec::new();
    chunk.resize(64 * 1024, 0u8);
    let mut events = Vec::new();
    for mut set in sets() {
        let (mut client, mut server) = pair(&mut set, v4());
        let (mut sent, mut got) = (0, 0);
        let mut blocked = false;
        while !blocked && sent < 1 << 30 {
            for (at, slot) in chunk.iter_mut().enumerate() {
                *slot = byte(1, sent + at);
            }
            match client.write(&chunk).unwrap() {
                Io::Done(count) => sent += count,
                Io::Blocked => blocked = true,
            }
        }
        assert!(blocked, "sent {sent} without blocking");
        let total = (8 << 20usize).max(sent + 1);
        assert!(client.watch(&mut set, WRITE, 1));
        assert!(server.watch(&mut set, READ, 2));
        let end = Instant::now().after_ms(30_000);
        while got < total {
            assert!(!end.reached_by(Instant::now()), "got {got} of {total}");
            wait(&mut set, end, &mut events);
            for &(key, ready) in &events {
                if key == 2 && ready & READ != 0 {
                    while let Io::Done(count) = server.read(&mut chunk).unwrap() {
                        assert!(count > 0, "ended at {got}");
                        for (at, &found) in chunk[..count].iter().enumerate() {
                            assert_eq!(found, byte(1, got + at));
                        }
                        got += count;
                    }
                }
                if key == 1 && ready & WRITE != 0 && sent < total {
                    let piece = chunk.len().min(total - sent);
                    for (at, slot) in chunk[..piece].iter_mut().enumerate() {
                        *slot = byte(1, sent + at);
                    }
                    if let Io::Done(count) = client.write(&chunk[..piece]).unwrap() {
                        sent += count;
                    }
                    if sent == total {
                        assert!(client.watch(&mut set, 0, 1));
                    }
                }
            }
        }
        client.close(&mut set);
        server.close(&mut set);
    }
}

/// Over IPv4 and IPv6: 4 MiB from the client, echoed by the server as it
/// comes, checked byte for byte; the client finishes, the server reads the
/// end and finishes too, and the client reads it.
#[test]
fn echo_both_families() {
    let mut buffer = [0u8; 16 * 1024];
    let mut events = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    for address in [v4(), v6()] {
        let mut set = Set::new().unwrap();
        let (mut client, mut server) = pair(&mut set, address);
        client.no_delay().unwrap();
        server.no_delay().unwrap();
        assert!(client.watch(&mut set, READ | WRITE, 1));
        assert!(server.watch(&mut set, READ, 2));
        let total = 4 << 20;
        let (mut sent, mut got) = (0, 0);
        pending.clear();
        let (mut client_ended, mut server_ended) = (false, false);
        let end = Instant::now().after_ms(30_000);
        while !(client_ended && server_ended) {
            assert!(!end.reached_by(Instant::now()), "sent {sent}, got {got}");
            wait(&mut set, end, &mut events);
            for &(key, ready) in &events {
                assert_eq!(ready & ERROR, 0);
                if key == 1 && ready & WRITE != 0 && sent < total {
                    let piece = buffer.len().min(total - sent);
                    for (at, slot) in buffer[..piece].iter_mut().enumerate() {
                        *slot = byte(2, sent + at);
                    }
                    if let Io::Done(count) = client.write(&buffer[..piece]).unwrap() {
                        sent += count;
                    }
                    if sent == total {
                        client.finish().unwrap();
                        assert!(client.watch(&mut set, READ, 1));
                    }
                }
                if key == 1 && ready & (READ | HUP) != 0 {
                    while let Io::Done(count) = client.read(&mut buffer).unwrap() {
                        if count == 0 {
                            assert_eq!(got, total);
                            client_ended = true;
                            assert!(client.watch(&mut set, 0, 1));
                            break;
                        }
                        for (at, &found) in buffer[..count].iter().enumerate() {
                            assert_eq!(found, byte(2, got + at));
                        }
                        got += count;
                    }
                }
                if key == 2 {
                    while !server_ended && pending.len() < 1 << 20 {
                        match server.read(&mut buffer).unwrap() {
                            Io::Done(0) => server_ended = true,
                            Io::Done(count) => pending.extend_from_slice(&buffer[..count]),
                            Io::Blocked => break,
                        }
                    }
                    while !pending.is_empty() {
                        match server.write(&pending).unwrap() {
                            Io::Done(count) => drop(pending.drain(..count)),
                            Io::Blocked => break,
                        }
                    }
                    let read = if server_ended { 0 } else { READ };
                    let write = if pending.is_empty() { 0 } else { WRITE };
                    if server_ended && pending.is_empty() {
                        server.finish().unwrap();
                    }
                    assert!(server.watch(&mut set, read | write, 2));
                }
            }
        }
        client.close(&mut set);
        server.close(&mut set);
    }
}

/// Nobody listens: the connection is refused, at once or once the Set
/// reports it; the case WSAPoll missed before Windows 10 2004.
#[test]
fn refused() {
    for mut set in sets() {
        let listener = Listener::bind(v4(), 1).unwrap();
        let address = listener.local().unwrap();
        listener.close(&mut set);
        match Stream::connect(address) {
            Err(error) => assert_eq!(error, Error::Refused),
            Ok(mut stream) => {
                assert!(stream.watch(&mut set, READ | WRITE, 1));
                until(&mut set, 1, ERROR | HUP);
                assert_eq!(stream.connected(), Err(Error::Refused));
                stream.close(&mut set);
            }
        }
    }
}

/// The peer's close reads as the end; its reset as an error; and writes
/// to a peer that is gone end in an error, not in SIGPIPE, which would
/// kill this process.
#[test]
fn hangup_reset_and_gone() {
    for mut set in sets() {
        let (mut closing, closer) = pair(&mut set, v4());
        assert!(closing.watch(&mut set, READ, 1));
        closer.close(&mut set);
        until(&mut set, 1, READ | HUP);
        assert_eq!(closing.read(&mut [0; 8]), Ok(Io::Done(0)));
        closing.close(&mut set);

        let (mut resetting, resetter) = pair(&mut set, v4());
        assert!(resetting.watch(&mut set, READ, 2));
        resetter.abort(&mut set);
        until(&mut set, 2, READ | HUP | ERROR);
        assert_eq!(resetting.read(&mut [0; 8]), Err(Error::Reset));
        resetting.close(&mut set);

        let (mut writer, gone) = pair(&mut set, v4());
        gone.close(&mut set);
        assert!(writer.watch(&mut set, WRITE, 3));
        let end = Instant::now().after_ms(10_000);
        let failed = loop {
            assert!(
                !end.reached_by(Instant::now()),
                "writes to a closed peer never failed"
            );
            match writer.write(&[1; 4096]) {
                Ok(_) => {
                    set.wait(Some(Instant::now().after_ms(5)));
                }
                Err(error) => break error,
            }
        };
        assert_eq!(failed, Error::Reset);
        writer.close(&mut set);
    }
}

/// Interest is what is reported: none, then writing alone, changed while
/// the system still watches for the old; then reading, until there is
/// nothing left to read; and the system is told, not only the Set: what
/// it masks does not wake it.
#[test]
fn interest() {
    for mut set in sets() {
        let (mut client, server) = pair(&mut set, v4());
        assert!(client.watch(&mut set, 0, 1));
        assert_eq!(server.write(b"x"), Ok(Io::Done(1)));
        quiet(&mut set, 1, READ | WRITE, 50);
        assert!(client.watch(&mut set, WRITE, 1));
        assert_eq!(until(&mut set, 1, WRITE) & READ, 0);
        assert!(client.watch(&mut set, READ, 1));
        until(&mut set, 1, READ);
        assert_eq!(client.read(&mut [0; 8]), Ok(Io::Done(1)));
        quiet(&mut set, 1, READ | WRITE, 50);
        assert!(
            wakeups(&mut set, 100) <= 3,
            "a narrowed interest woke the Set"
        );
        client.close(&mut set);
        server.close(&mut set);
    }
}

/// An entry with no interest is not watched, not even for the peer's
/// reset, which shows once it has one again; its deadline still counts.
#[test]
fn paused() {
    for mut set in sets() {
        let (mut client, server) = pair(&mut set, v4());
        assert!(client.watch(&mut set, 0, 1));
        server.abort(&mut set);
        quiet(&mut set, 1, u8::MAX, 50);
        let token = client.token().unwrap();
        set.deadline(token, Some(Instant::now().after_ms(10)));
        until(&mut set, 1, EXPIRED);
        assert!(client.watch(&mut set, READ, 1));
        assert_ne!(until(&mut set, 1, READ | HUP | ERROR), 0);
        assert!(client.watch(&mut set, 0, 1));
        quiet(&mut set, 1, u8::MAX, 50);
        assert!(
            wakeups(&mut set, 100) <= 3,
            "a socket with no interest woke the Set"
        );
        client.close(&mut set);
    }
}

/// A removed entry's token names nothing, even once a new socket takes
/// its place in the Set.
#[test]
fn stale_token() {
    for mut set in sets() {
        let (client, server) = pair(&mut set, v4());
        let old = set.add(client.raw(), READ, 1).unwrap();
        assert_eq!(server.write(b"x"), Ok(Io::Done(1)));
        until(&mut set, 1, READ);
        set.remove(old);
        drop(client);
        drop(server);
        let (new_client, new_server) = pair(&mut set, v4());
        let new = set.add(new_client.raw(), READ, 2).unwrap();
        assert!(!set.modify(old, READ | WRITE));
        set.deadline(old, Some(Instant::now()));
        set.remove(old);
        assert_eq!(new_server.write(b"y"), Ok(Io::Done(1)));
        until(&mut set, 2, READ);
        quiet(&mut set, 1, u8::MAX, 30);
        set.remove(new);
    }
}

/// A stream dropped without close: the system stops watching it; a new
/// socket that takes its number at once (on Linux and macOS the lowest
/// free; on Windows whatever handle comes) is watched for itself, and
/// removing the old entry after does not take the new one's watch away.
#[test]
fn dropped_without_close() {
    let mut others = Vec::new();
    for mut set in sets() {
        let (mut old, old_server) = pair(&mut set, v4());
        assert!(old.watch(&mut set, READ, 1));
        let old_token = old.token().unwrap();
        let number = old.raw();
        drop(old);
        // Listeners until one takes the old number: a few are lower.
        others.clear();
        let mut listener = Listener::bind(v4(), 4).unwrap();
        while cfg!(unix) && listener.raw() != number {
            assert!(others.len() < 8, "the number was not taken again");
            others.push(listener);
            listener = Listener::bind(v4(), 4).unwrap();
        }
        assert!(listener.watch(&mut set, READ, 2));
        set.remove(old_token);
        let client = Stream::connect(listener.local().unwrap()).unwrap();
        until(&mut set, 2, READ);
        quiet(&mut set, 1, u8::MAX, 30);
        listener.close(&mut set);
        drop(client);
        drop(old_server);
    }
}

/// An address another listens on is in use; once it closes, with a
/// connection it closed first in TIME_WAIT, the address listens again, as
/// a server that restarts needs.
#[test]
fn address_in_use_then_free() {
    let mut set = Set::new().unwrap();
    let mut first = Listener::bind(v4(), 4).unwrap();
    let address = first.local().unwrap();
    assert!(matches!(Listener::bind(address, 4), Err(Error::InUse)));
    let mut client = Stream::connect(address).unwrap();
    assert!(client.watch(&mut set, WRITE, 1));
    until(&mut set, 1, WRITE);
    assert!(first.watch(&mut set, READ, 2));
    until(&mut set, 2, READ);
    let (server, _) = first.accept().unwrap().unwrap();
    server.close(&mut set);
    assert!(client.watch(&mut set, READ, 1));
    until(&mut set, 1, READ | HUP);
    client.close(&mut set);
    first.close(&mut set);
    let again = Listener::bind(address, 4);
    assert!(again.is_ok(), "{:?}", again.err());
}

/// Two hundred clients through one listener, 64 connecting at a time (a
/// listen queue on macOS holds 128), each sending a line the server sends
/// back.
#[test]
fn many_clients() {
    assert!(descriptors(1024) >= 512);
    let mut set = Set::new().unwrap();
    let mut listener = Listener::bind(v4(), 256).unwrap();
    let address = listener.local().unwrap();
    assert!(listener.watch(&mut set, READ, LISTENER));
    let total: usize = 200;
    let mut clients = Vec::new();
    let mut servers: Vec<Stream> = Vec::new();
    let mut done = 0;
    let mut events = Vec::new();
    let end = Instant::now().after_ms(30_000);
    let line = b"one line, and back\n";
    while done < total {
        while clients.len() < total && clients.len() - done < 64 {
            let mut client = Stream::connect(address).unwrap();
            let key = u64::try_from(clients.len()).unwrap();
            assert!(client.watch(&mut set, WRITE, key));
            clients.push((client, false, false));
        }
        assert!(!end.reached_by(Instant::now()), "{done} of {total}");
        wait(&mut set, end, &mut events);
        for &(key, ready) in &events {
            if key == LISTENER {
                while let Some((mut server, _)) = listener.accept().unwrap() {
                    let index = u64::try_from(servers.len()).unwrap();
                    assert!(server.watch(&mut set, READ, SERVER | index));
                    servers.push(server);
                }
            } else if key & SERVER == SERVER {
                let server = &mut servers[usize::try_from(key & INDEX).unwrap()];
                let mut buffer = [0u8; 64];
                if let Ok(Io::Done(got)) = server.read(&mut buffer)
                    && got > 0
                {
                    assert_eq!(server.write(&buffer[..got]), Ok(Io::Done(got)));
                }
            } else {
                let (client, sent, finished) = &mut clients[usize::try_from(key).unwrap()];
                assert_eq!(ready & ERROR, 0);
                if !*sent && ready & WRITE != 0 {
                    assert!(client.connected().unwrap());
                    assert_eq!(client.write(line), Ok(Io::Done(line.len())));
                    *sent = true;
                    assert!(client.watch(&mut set, READ, key));
                } else if !*finished && ready & READ != 0 {
                    let mut buffer = [0u8; 64];
                    assert_eq!(client.read(&mut buffer), Ok(Io::Done(line.len())));
                    assert_eq!(&buffer[..line.len()], line);
                    *finished = true;
                    assert!(client.watch(&mut set, 0, key));
                    done += 1;
                } else {
                    // Reported before, or spurious.
                }
            }
        }
    }
    for (client, _, _) in clients {
        client.close(&mut set);
    }
    for server in servers {
        server.close(&mut set);
    }
    listener.close(&mut set);
}

/// A thousand connections, all idle but one, which gets a byte: a wait
/// and a read for each, as a server with many idle clients pays for each
/// request.
#[bench]
fn one_of_a_thousand(b: &mut Bencher) {
    assert!(descriptors(4096) >= 2100);
    let mut set = Set::new().unwrap();
    let mut pairs = Vec::new();
    for key in 0..1000u64 {
        let (client, mut server) = pair(&mut set, v4());
        assert!(server.watch(&mut set, READ, key));
        pairs.push((client, server));
    }
    let mut byte_read = [0u8; 1];
    {
        let (writer, reader) = &pairs[500];
        b.iter(|| {
            assert_eq!(writer.write(b"x"), Ok(Io::Done(1)));
            loop {
                if set.wait(None).iter().any(|event| event.key == 500) {
                    break;
                }
            }
            assert_eq!(reader.read(&mut byte_read), Ok(Io::Done(1)));
        });
    }
    for (client, server) in pairs {
        client.close(&mut set);
        server.close(&mut set);
    }
}

/// Probe on the branch: is a connecting socket reported writable by
/// socket notifications before it is connected?
#[cfg(target_os = "windows")]
#[test]
fn probe_a_notified_writable_is_connected() {
    let mut set = Set::new().unwrap();
    let mut listener = Listener::bind(v4(), 16).unwrap();
    let mut client = Stream::connect(listener.local().unwrap()).unwrap();
    assert!(listener.watch(&mut set, READ, LISTENER));
    assert!(client.watch(&mut set, WRITE, 7));
    until(&mut set, 7, WRITE | ERROR | HUP);
    assert!(client.peer().is_some());
}

/// Probe: once connected for sure, does peer say so on Windows?
#[cfg(target_os = "windows")]
#[test]
fn probe_b_peer_after_a_while() {
    let mut set = Set::new().unwrap();
    let mut listener = Listener::bind(v4(), 16).unwrap();
    let client = Stream::connect(listener.local().unwrap()).unwrap();
    assert!(listener.watch(&mut set, READ, LISTENER));
    until(&mut set, LISTENER, READ);
    set.wait(Some(Instant::now().after_ms(300)));
    assert!(client.peer().is_some());
}

/// Probe: is a connecting socket reported writable by WSAPoll before it
/// is connected?
#[cfg(target_os = "windows")]
#[test]
fn probe_c_polled_writable_is_connected() {
    let mut set = Set::polled().unwrap();
    let mut listener = Listener::bind(v4(), 16).unwrap();
    let mut client = Stream::connect(listener.local().unwrap()).unwrap();
    assert!(listener.watch(&mut set, READ, LISTENER));
    assert!(client.watch(&mut set, WRITE, 7));
    until(&mut set, 7, WRITE | ERROR | HUP);
    assert!(client.peer().is_some());
}

/// Probe: once connected, pending says no error on Windows.
#[cfg(target_os = "windows")]
#[test]
fn probe_d_pending_after_a_while() {
    let mut set = Set::new().unwrap();
    let mut listener = Listener::bind(v4(), 16).unwrap();
    let client = Stream::connect(listener.local().unwrap()).unwrap();
    assert!(listener.watch(&mut set, READ, LISTENER));
    until(&mut set, LISTENER, READ);
    set.wait(Some(Instant::now().after_ms(300)));
    assert!(client.connected().is_ok());
}
