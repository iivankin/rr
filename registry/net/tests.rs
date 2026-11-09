//! net's tests, and the Poll's on real sockets: TCP over loopback,
//! as a server and its clients use it, on every way the system has to
//! wait (on Windows, socket notifications and WSAPoll both).

use super::{Error, Io, Listener, Stream, descriptors, descriptors_before};
use crate::base::poll::{Instant, Interest, Poll, PollError, Ready};
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use test::Bencher;

fn polls() -> Vec<Poll> {
    #[cfg(target_os = "windows")]
    return Vec::from([Poll::new().unwrap(), Poll::polled().unwrap()]);
    #[cfg(not(target_os = "windows"))]
    return Vec::from([Poll::new().unwrap()]);
}

fn v4() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn v6() -> SocketAddr {
    SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
}

/// The events of one wait, as (key, ready), into events.
fn gather(poll: &mut Poll, until: Instant, events: &mut Vec<(u64, Ready)>) {
    events.clear();
    for event in poll.poll(Some(until)) {
        events.push((event.key, event.ready));
    }
}

/// Waits up to ten seconds for key with any of want; its readiness.
fn until(poll: &mut Poll, key: u64, want: Ready) -> Ready {
    let end = Instant::now().after_ms(10_000);
    loop {
        for event in poll.poll(Some(end)) {
            if event.key == key && event.ready.any(want) {
                return event.ready;
            }
        }
        assert!(!end.reached_by(Instant::now()), "nothing for key {key}");
    }
}

/// Waits ms milliseconds, and checks that key was not reported with any
/// of these.
fn quiet(poll: &mut Poll, key: u64, these: Ready, ms: u64) {
    let end = Instant::now().after_ms(ms);
    while !end.reached_by(Instant::now()) {
        for event in poll.poll(Some(end)) {
            assert!(
                event.key != key || !event.ready.any(these),
                "key {key} reported {:?}",
                event.ready
            );
        }
    }
}

/// How often wait returns in ms milliseconds: a level-triggered wait the
/// system keeps waking spins.
fn wakeups(poll: &mut Poll, ms: u64) -> usize {
    let end = Instant::now().after_ms(ms);
    let mut count = 0;
    while !end.reached_by(Instant::now()) {
        poll.poll(Some(end));
        count += 1;
    }
    count
}

/// The key a pair's listener is reported with.
const LISTENER: u64 = 1 << 40;

/// A connection through a listener on address: the client, made, and the
/// server's side, which the listener reports the client's address for.
/// Neither is in the Poll.
fn pair(poll: &mut Poll, address: SocketAddr) -> (Stream, Stream) {
    let mut listener = Listener::bind(address, 16).unwrap();
    let mut client = Stream::connect(listener.local().unwrap()).unwrap();
    listener.watch(poll, Interest::Read, LISTENER).unwrap();
    client.watch(poll, Interest::Write, LISTENER + 1).unwrap();
    until(poll, LISTENER + 1, Ready::WRITABLE.with(Ready::ERROR));
    assert!(client.connected().unwrap());
    let server = loop {
        if let Some((server, from)) = listener.accept().unwrap() {
            assert_eq!(Some(from), client.local());
            break server;
        }
        until(poll, LISTENER, Ready::READABLE);
    };
    assert_eq!(client.peer(), listener.local());
    listener.close(poll).unwrap();
    client.watch(poll, Interest::None, LISTENER + 1).unwrap();
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
    for mut poll in polls() {
        echo(&mut poll, count);
    }
}

/// The loop of a server and its clients, marked as a program marks its
/// own: rr follows each call from here and refuses one that blocks.
#[cfg_attr(rr, rr::poll)]
fn echo(poll: &mut Poll, count: usize) {
    let mut listener = Listener::bind(v4(), 1024).unwrap();
    let address = listener.local().unwrap();
    listener.watch(poll, Interest::Read, LISTENER).unwrap();
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
            stream.watch(poll, Interest::Both, key).unwrap();
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
        gather(poll, end, &mut events);
        for &(key, ready) in &events {
            let index = usize::try_from(key & INDEX).unwrap();
            match key & !INDEX {
                LISTENER => {
                    while let Some((mut stream, _)) = listener.accept().unwrap() {
                        let peer_key = SERVER | u64::try_from(peers.len()).unwrap();
                        stream.watch(poll, Interest::Read, peer_key).unwrap();
                        peers.push(Peer {
                            stream: Some(stream),
                            key: peer_key,
                            pending: Vec::new(),
                            ended: false,
                        });
                    }
                }
                SERVER => closed += serve(poll, &mut peers[index], ready, &mut buffer),
                CLIENT => finished += talk(poll, &mut clients[index], index, ready, &mut buffer),
                _ => panic!("key {key}"),
            }
        }
    }
    listener.close(poll).unwrap();
}

/// A client's turn: send what the system takes, check what came back; 1
/// when it got all of it back, and closed.
fn talk(
    poll: &mut Poll,
    client: &mut Client,
    seed: usize,
    ready: Ready,
    buffer: &mut [u8],
) -> usize {
    let Some(stream) = client.stream.as_mut() else {
        return 0;
    };
    assert!(!ready.error(), "client {seed}: {:?}", stream.connected());
    while ready.writable() && client.sent < SIZE {
        let piece = buffer.len().min(SIZE - client.sent);
        for (at, slot) in buffer[..piece].iter_mut().enumerate() {
            *slot = byte(seed, client.sent + at);
        }
        match stream.write(&buffer[..piece]).unwrap() {
            Io::Done(sent) => client.sent += sent,
            Io::Blocked => break,
        }
        if client.sent == SIZE {
            stream
                .watch(poll, Interest::Read, CLIENT | u64::try_from(seed).unwrap())
                .unwrap();
        }
    }
    if !ready.to_read() {
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
            client.stream.take().unwrap().close(poll).unwrap();
            return 1;
        }
    }
}

/// The server's turn for one client: read while there is room, send back
/// what it can, watch for what is left; 1 when the client ended and all
/// went back, and closed.
fn serve(poll: &mut Poll, peer: &mut Peer, ready: Ready, buffer: &mut [u8]) -> usize {
    let key = peer.key;
    let Some(stream) = peer.stream.as_mut() else {
        return 0;
    };
    assert!(!ready.error(), "server: {:?}", stream.connected());
    while ready.to_read() && !peer.ended && peer.pending.len() < 256 * 1024 {
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
        peer.stream.take().unwrap().close(poll).unwrap();
        return 1;
    }
    let (read, write) = (!peer.ended, !peer.pending.is_empty());
    stream.watch(poll, Interest::new(read, write), key).unwrap();
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
    for mut poll in polls() {
        let (mut client, mut server) = pair(&mut poll, v4());
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
        client.watch(&mut poll, Interest::Write, 1).unwrap();
        server.watch(&mut poll, Interest::Read, 2).unwrap();
        let end = Instant::now().after_ms(30_000);
        while got < total {
            assert!(!end.reached_by(Instant::now()), "got {got} of {total}");
            gather(&mut poll, end, &mut events);
            for &(key, ready) in &events {
                if key == 2 && ready.readable() {
                    while let Io::Done(count) = server.read(&mut chunk).unwrap() {
                        assert!(count > 0, "ended at {got}");
                        for (at, &found) in chunk[..count].iter().enumerate() {
                            assert_eq!(found, byte(1, got + at));
                        }
                        got += count;
                    }
                }
                if key == 1 && ready.writable() && sent < total {
                    let piece = chunk.len().min(total - sent);
                    for (at, slot) in chunk[..piece].iter_mut().enumerate() {
                        *slot = byte(1, sent + at);
                    }
                    if let Io::Done(count) = client.write(&chunk[..piece]).unwrap() {
                        sent += count;
                    }
                    if sent == total {
                        client.watch(&mut poll, Interest::None, 1).unwrap();
                    }
                }
            }
        }
        client.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
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
        let mut poll = Poll::new().unwrap();
        let (mut client, mut server) = pair(&mut poll, address);
        // On by default; Nagle's algorithm and back.
        client.no_delay(false).unwrap();
        client.no_delay(true).unwrap();
        client.watch(&mut poll, Interest::Both, 1).unwrap();
        server.watch(&mut poll, Interest::Read, 2).unwrap();
        let total = 4 << 20;
        let (mut sent, mut got) = (0, 0);
        pending.clear();
        let (mut client_ended, mut server_ended) = (false, false);
        let end = Instant::now().after_ms(30_000);
        while !(client_ended && server_ended) {
            assert!(!end.reached_by(Instant::now()), "sent {sent}, got {got}");
            gather(&mut poll, end, &mut events);
            for &(key, ready) in &events {
                assert!(!ready.error());
                if key == 1 && ready.writable() && sent < total {
                    let piece = buffer.len().min(total - sent);
                    for (at, slot) in buffer[..piece].iter_mut().enumerate() {
                        *slot = byte(2, sent + at);
                    }
                    if let Io::Done(count) = client.write(&buffer[..piece]).unwrap() {
                        sent += count;
                    }
                    if sent == total {
                        client.finish().unwrap();
                        client.watch(&mut poll, Interest::Read, 1).unwrap();
                    }
                }
                if key == 1 && ready.to_read() {
                    while let Io::Done(count) = client.read(&mut buffer).unwrap() {
                        if count == 0 {
                            assert_eq!(got, total);
                            client_ended = true;
                            client.watch(&mut poll, Interest::None, 1).unwrap();
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
                    let (read, write) = (!server_ended, !pending.is_empty());
                    if server_ended && pending.is_empty() {
                        server.finish().unwrap();
                    }
                    server
                        .watch(&mut poll, Interest::new(read, write), 2)
                        .unwrap();
                }
            }
        }
        client.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
    }
}

/// Nobody listens: the connection is refused, at once or once the Poll
/// reports it; the case WSAPoll missed before Windows 10 2004.
#[test]
fn refused() {
    for mut poll in polls() {
        let listener = Listener::bind(v4(), 1).unwrap();
        let address = listener.local().unwrap();
        listener.close(&mut poll).unwrap();
        match Stream::connect(address) {
            Err(error) => assert_eq!(error, Error::Refused),
            Ok(mut stream) => {
                stream.watch(&mut poll, Interest::Both, 1).unwrap();
                until(&mut poll, 1, Ready::ERROR.with(Ready::HANGUP));
                // The same error every time, and for reads and writes:
                // the system says it once.
                assert_eq!(stream.connected(), Err(Error::Refused));
                assert_eq!(stream.connected(), Err(Error::Refused));
                assert_eq!(stream.read(&mut [0; 8]), Err(Error::Refused));
                assert_eq!(stream.write(b"x"), Err(Error::Refused));
                stream.close(&mut poll).unwrap();
            }
        }
    }
}

/// The peer's close reads as the end; its reset as an error; and writes
/// to a peer that is gone end in an error, not in SIGPIPE, which would
/// kill this process.
#[test]
fn hangup_reset_and_gone() {
    for mut poll in polls() {
        let (mut closing, closer) = pair(&mut poll, v4());
        closing.watch(&mut poll, Interest::Read, 1).unwrap();
        closer.close(&mut poll).unwrap();
        until(&mut poll, 1, Ready::READABLE.with(Ready::HANGUP));
        assert_eq!(closing.read(&mut [0; 8]), Ok(Io::Done(0)));
        closing.close(&mut poll).unwrap();

        let (mut resetting, resetter) = pair(&mut poll, v4());
        resetting.watch(&mut poll, Interest::Read, 2).unwrap();
        resetter.abort(&mut poll).unwrap();
        until(
            &mut poll,
            2,
            Ready::READABLE.with(Ready::HANGUP).with(Ready::ERROR),
        );
        assert_eq!(resetting.read(&mut [0; 8]), Err(Error::Reset));
        resetting.close(&mut poll).unwrap();

        let (mut writer, gone) = pair(&mut poll, v4());
        gone.close(&mut poll).unwrap();
        writer.watch(&mut poll, Interest::Write, 3).unwrap();
        let end = Instant::now().after_ms(10_000);
        let failed = loop {
            assert!(
                !end.reached_by(Instant::now()),
                "writes to a closed peer never failed"
            );
            match writer.write(&[1; 4096]) {
                Ok(_) => {
                    poll.poll(Some(Instant::now().after_ms(5)));
                }
                Err(error) => break error,
            }
        };
        assert_eq!(failed, Error::Reset);
        writer.close(&mut poll).unwrap();
    }
}

/// Interest is what is reported: none, then writing alone, changed while
/// the system still watches for the old; then reading, until there is
/// nothing left to read; and the system is told, not only the Poll: what
/// it masks does not wake it.
#[test]
fn interest() {
    for mut poll in polls() {
        let (mut client, mut server) = pair(&mut poll, v4());
        client.watch(&mut poll, Interest::None, 1).unwrap();
        assert_eq!(server.write(b"x"), Ok(Io::Done(1)));
        quiet(&mut poll, 1, Ready::READABLE.with(Ready::WRITABLE), 50);
        client.watch(&mut poll, Interest::Write, 1).unwrap();
        assert!(!until(&mut poll, 1, Ready::WRITABLE).readable());
        client.watch(&mut poll, Interest::Read, 1).unwrap();
        until(&mut poll, 1, Ready::READABLE);
        assert_eq!(client.read(&mut [0; 8]), Ok(Io::Done(1)));
        quiet(&mut poll, 1, Ready::READABLE.with(Ready::WRITABLE), 50);
        assert!(
            wakeups(&mut poll, 100) <= 3,
            "a narrowed interest woke the Poll"
        );
        client.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
    }
}

/// An entry with no interest is not watched, not even for the peer's
/// reset, which shows once it has one again; its deadline still counts.
#[test]
fn paused() {
    for mut poll in polls() {
        let (mut client, server) = pair(&mut poll, v4());
        client.watch(&mut poll, Interest::None, 1).unwrap();
        server.abort(&mut poll).unwrap();
        quiet(&mut poll, 1, Ready::ANY, 50);
        let token = client.token().unwrap();
        poll.deadline(token, Some(Instant::now().after_ms(10)))
            .unwrap();
        assert_eq!(poll.remove(token), Err(PollError::Owned));
        until(&mut poll, 1, Ready::EXPIRED);
        client.watch(&mut poll, Interest::Read, 1).unwrap();
        until(
            &mut poll,
            1,
            Ready::READABLE.with(Ready::HANGUP).with(Ready::ERROR),
        );
        client.watch(&mut poll, Interest::None, 1).unwrap();
        quiet(&mut poll, 1, Ready::ANY, 50);
        assert!(
            wakeups(&mut poll, 100) <= 3,
            "a socket with no interest woke the Poll"
        );
        client.close(&mut poll).unwrap();
    }
}

/// A removed entry's token names nothing, even once a new socket takes
/// its place in the Poll. The server's side is added as it is, by its
/// socket: pair's client is in the Poll already, and a socket is in a Poll
/// once.
#[test]
fn stale_token() {
    for mut poll in polls() {
        let (mut client, server) = pair(&mut poll, v4());
        let old = poll.add(server.raw(), Interest::Read, 1).unwrap();
        assert_eq!(client.write(b"x"), Ok(Io::Done(1)));
        until(&mut poll, 1, Ready::READABLE);
        poll.remove(old).unwrap();
        client.close(&mut poll).unwrap();
        drop(server);
        let (mut new_client, new_server) = pair(&mut poll, v4());
        let new = poll.add(new_server.raw(), Interest::Read, 2).unwrap();
        assert_eq!(poll.modify(old, Interest::Both), Err(PollError::Gone));
        assert_eq!(
            poll.deadline(old, Some(Instant::now())),
            Err(PollError::Gone)
        );
        assert_eq!(poll.remove(old), Err(PollError::Gone));
        assert_eq!(new_client.write(b"y"), Ok(Io::Done(1)));
        until(&mut poll, 2, Ready::READABLE);
        quiet(&mut poll, 1, Ready::ANY, 30);
        poll.remove(new).unwrap();
        new_client.close(&mut poll).unwrap();
    }
}

/// A stream dropped without close: the system stops watching it; a new
/// socket that takes its number at once (on Linux and macOS the lowest
/// free; on Windows whatever handle comes) is watched for itself, and
/// removing the old entry after does not take the new one's watch away.
#[test]
fn dropped_without_close() {
    let mut others = Vec::new();
    for mut poll in polls() {
        let (mut old, old_server) = pair(&mut poll, v4());
        old.watch(&mut poll, Interest::Read, 1).unwrap();
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
        listener.watch(&mut poll, Interest::Read, 2).unwrap();
        // Gone where the listener took its number; elsewhere owned by
        // the stream that was dropped, and left until a socket does.
        let removed = poll.remove(old_token);
        assert!(matches!(removed, Err(PollError::Gone | PollError::Owned)));
        let client = Stream::connect(listener.local().unwrap()).unwrap();
        until(&mut poll, 2, Ready::READABLE);
        quiet(&mut poll, 1, Ready::ANY, 30);
        listener.close(&mut poll).unwrap();
        drop(client);
        drop(old_server);
    }
}

/// An address another listens on is in use; once it closes, with a
/// connection it closed first in TIME_WAIT, the address listens again, as
/// a server that restarts needs: on Windows with no option, which
/// SO_EXCLUSIVEADDRUSE would refuse while that connection lingers.
#[test]
fn address_in_use_then_free() {
    let mut poll = Poll::new().unwrap();
    let mut first = Listener::bind(v4(), 4).unwrap();
    let address = first.local().unwrap();
    assert!(matches!(Listener::bind(address, 4), Err(Error::InUse)));
    let mut client = Stream::connect(address).unwrap();
    client.watch(&mut poll, Interest::Write, 1).unwrap();
    until(&mut poll, 1, Ready::WRITABLE);
    first.watch(&mut poll, Interest::Read, 2).unwrap();
    until(&mut poll, 2, Ready::READABLE);
    let (server, _) = first.accept().unwrap().unwrap();
    server.close(&mut poll).unwrap();
    client.watch(&mut poll, Interest::Read, 1).unwrap();
    until(&mut poll, 1, Ready::READABLE.with(Ready::HANGUP));
    client.close(&mut poll).unwrap();
    first.close(&mut poll).unwrap();
    let again = Listener::bind(address, 4);
    assert!(again.is_ok(), "{:?}", again.err());
}

/// Two hundred clients through one listener, 64 connecting at a time (a
/// listen queue on macOS holds 128), each sending a line the server sends
/// back.
#[test]
fn many_clients() {
    assert!(descriptors(1024) >= 512);
    let mut poll = Poll::new().unwrap();
    let mut listener = Listener::bind(v4(), 256).unwrap();
    let address = listener.local().unwrap();
    listener.watch(&mut poll, Interest::Read, LISTENER).unwrap();
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
            client.watch(&mut poll, Interest::Write, key).unwrap();
            clients.push((client, false, false));
        }
        assert!(!end.reached_by(Instant::now()), "{done} of {total}");
        gather(&mut poll, end, &mut events);
        for &(key, ready) in &events {
            if key == LISTENER {
                while let Some((mut server, _)) = listener.accept().unwrap() {
                    let index = u64::try_from(servers.len()).unwrap();
                    server
                        .watch(&mut poll, Interest::Read, SERVER | index)
                        .unwrap();
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
                assert!(!ready.error());
                if !*sent && ready.writable() {
                    assert!(client.connected().unwrap());
                    assert_eq!(client.write(line), Ok(Io::Done(line.len())));
                    *sent = true;
                    client.watch(&mut poll, Interest::Read, key).unwrap();
                } else if !*finished && ready.readable() {
                    let mut buffer = [0u8; 64];
                    assert_eq!(client.read(&mut buffer), Ok(Io::Done(line.len())));
                    assert_eq!(&buffer[..line.len()], line);
                    *finished = true;
                    client.watch(&mut poll, Interest::None, key).unwrap();
                    done += 1;
                } else {
                    // Reported before, or spurious.
                }
            }
        }
    }
    for (client, _, _) in clients {
        client.close(&mut poll).unwrap();
    }
    for server in servers {
        server.close(&mut poll).unwrap();
    }
    listener.close(&mut poll).unwrap();
}

/// A thousand connections, all idle but one, which gets a byte: a wait
/// and a read for each, as a server with many idle clients pays for each
/// request.
#[bench]
fn one_of_a_thousand(b: &mut Bencher) {
    assert!(descriptors(4096) >= 2100);
    let mut poll = Poll::new().unwrap();
    let mut pairs = Vec::new();
    for key in 0..1000u64 {
        let (client, mut server) = pair(&mut poll, v4());
        server.watch(&mut poll, Interest::Read, key).unwrap();
        pairs.push((client, server));
    }
    let mut byte_read = [0u8; 1];
    {
        let (writer, reader) = &mut pairs[500];
        b.iter(|| {
            assert_eq!(writer.write(b"x"), Ok(Io::Done(1)));
            loop {
                if poll.poll(None).iter().any(|event| event.key == 500) {
                    break;
                }
            }
            assert_eq!(reader.read(&mut byte_read), Ok(Io::Done(1)));
        });
    }
    for (client, server) in pairs {
        client.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
    }
}

/// descriptors says what the system holds, not what was asked: macOS
/// cuts a limit to kern.maxfilesperproc, under its hard limit.
#[cfg(unix)]
#[test]
fn descriptors_as_held() {
    let raised = descriptors(1 << 40);
    assert!(raised >= 256);
    assert_eq!(descriptors(0), raised);
    if let Some(before) = descriptors_before() {
        assert!(before < raised, "{before} before, {raised} now");
    }
}

/// A socket removed from the Poll and added again at once, under a new
/// key: socket notifications hold a registration for a socket once.
#[test]
fn removed_and_added_again() {
    for mut poll in polls() {
        let (mut client, server) = pair(&mut poll, v4());
        let first = poll.add(server.raw(), Interest::Read, 1).unwrap();
        poll.remove(first).unwrap();
        let again = poll.add(server.raw(), Interest::Read, 2).unwrap();
        assert_eq!(client.write(b"x"), Ok(Io::Done(1)));
        until(&mut poll, 2, Ready::READABLE);
        poll.remove(again).unwrap();
        client.close(&mut poll).unwrap();
    }
}

/// The peer finished while the writer waits for room: the hangup, which
/// ends reading, is not reported to a Poll that waits for writing alone,
/// on any system, and wakes it no more than writing does but on WSAPoll,
/// which reports it whatever it is asked, and where it shows as writable.
#[test]
fn half_closed_writer() {
    let chunk = [7u8; 16 * 1024];
    for (at, mut poll) in polls().into_iter().enumerate() {
        let polled = cfg!(target_os = "windows") && at == 1;
        let (mut client, mut server) = pair(&mut poll, v4());
        let mut sent = 0usize;
        while let Io::Done(count) = client.write(&chunk).unwrap() {
            sent += count;
            assert!(sent < 1 << 30, "never blocked");
        }
        server.finish().unwrap();
        client.watch(&mut poll, Interest::Write, 1).unwrap();
        let end = Instant::now().after_ms(100);
        let mut idle = 0;
        while !end.reached_by(Instant::now()) {
            let mut writable = false;
            for event in poll.poll(Some(end)) {
                if event.key == 1 {
                    assert!(!event.ready.hangup(), "a writer told of a hangup");
                    writable |= event.ready.writable();
                }
            }
            if writable {
                // The system grew its buffer: writing goes on.
                while let Io::Done(_) = client.write(&chunk).unwrap() {}
            } else {
                idle += 1;
            }
        }
        assert!(
            polled || idle <= 3,
            "woken {idle} times with nothing to write"
        );
        client.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
    }
}

/// Sockets closed through the Poll while the system still has news of
/// them, a reset, and new ones made at once, which take their handles
/// on Windows: none of the old news is reported for the new.
#[test]
fn closed_handles_taken_again() {
    for mut poll in polls() {
        for round in 0..50u64 {
            let (mut client, mut server) = pair(&mut poll, v4());
            client
                .watch(&mut poll, Interest::Read, 2 * round + 1)
                .unwrap();
            server
                .watch(&mut poll, Interest::Read, 2 * round + 2)
                .unwrap();
            quiet(
                &mut poll,
                2 * round + 1,
                Ready::HANGUP.with(Ready::ERROR),
                10,
            );
            quiet(
                &mut poll,
                2 * round + 2,
                Ready::HANGUP.with(Ready::ERROR),
                10,
            );
            client.abort(&mut poll).unwrap();
            server.close(&mut poll).unwrap();
        }
    }
}

/// A client sends its request and finishes, as an HTTP/1.0 client or one
/// that streams an upload does, then waits to write and read while the
/// server answers: its own finish is no hangup, on any system (macOS's
/// write filter says nothing more may be sent, which epoll does not
/// report), and the answer comes whole, then the end.
#[test]
fn finished_writer() {
    let mut buffer = [0u8; 64];
    let mut answer = Vec::new();
    for mut poll in polls() {
        let (mut client, mut server) = pair(&mut poll, v4());
        assert_eq!(client.write(b"request"), Ok(Io::Done(7)));
        client.finish().unwrap();
        client.watch(&mut poll, Interest::Write, 1).unwrap();
        let end = Instant::now().after_ms(50);
        let mut writable = false;
        while !end.reached_by(Instant::now()) {
            for event in poll.poll(Some(end)) {
                if event.key == 1 {
                    assert!(!event.ready.hangup(), "its own finish a hangup");
                    assert!(!event.ready.error());
                    writable |= event.ready.writable();
                }
            }
        }
        // Linux and macOS say a socket that finished is writable: a write
        // fails at once, and does not block.
        assert!(writable || cfg!(target_os = "windows"));
        server.watch(&mut poll, Interest::Read, 2).unwrap();
        let mut got = 0;
        while got < 7 {
            until(&mut poll, 2, Ready::READABLE);
            if let Io::Done(count) = server.read(&mut buffer).unwrap() {
                got += count;
            }
        }
        assert_eq!(server.read(&mut buffer), Ok(Io::Done(0)));
        assert_eq!(server.write(b"answer"), Ok(Io::Done(6)));
        server.finish().unwrap();
        server.watch(&mut poll, Interest::None, 2).unwrap();
        client.watch(&mut poll, Interest::Both, 1).unwrap();
        answer.clear();
        loop {
            let ready = until(&mut poll, 1, Ready::READABLE.with(Ready::HANGUP));
            assert!(!ready.error());
            match client.read(&mut buffer).unwrap() {
                Io::Done(0) => break,
                Io::Done(count) => answer.extend_from_slice(&buffer[..count]),
                Io::Blocked => {}
            }
        }
        assert_eq!(answer, b"answer");
        client.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
    }
}

/// A socket added to a Poll twice, open: the second is refused, and the
/// first goes on as it was, with nothing of the second left to wake the
/// Poll; the same on every system but WSAPoll, which cannot tell it from
/// a new socket that took a closed one's handle, and where the second
/// takes the first's place (poll's entries.rs).
#[test]
fn added_twice() {
    for (at, mut poll) in polls().into_iter().enumerate() {
        let polled = cfg!(target_os = "windows") && at == 1;
        let (mut client, mut server) = pair(&mut poll, v4());
        let first = poll.add(server.raw(), Interest::Read, 1).unwrap();
        let again = poll.add(server.raw(), Interest::Both, 2);
        assert_eq!(again.is_ok(), polled);
        if !polled {
            assert_eq!(again.err(), Some(PollError::Twice));
        }
        let (kept, gone) = if polled { (2, 1) } else { (1, 2) };
        assert_eq!(client.write(b"x"), Ok(Io::Done(1)));
        until(&mut poll, kept, Ready::READABLE);
        assert_eq!(server.read(&mut [0; 8]), Ok(Io::Done(1)));
        if !polled {
            quiet(&mut poll, kept, Ready::READABLE, 50);
            assert!(
                wakeups(&mut poll, 100) <= 3,
                "the refused entry woke the Poll"
            );
        }
        quiet(&mut poll, gone, Ready::ANY, 30);
        poll.remove(again.unwrap_or(first)).unwrap();
        client.close(&mut poll).unwrap();
    }
}

/// A connection still being made reads and writes as NotConnected, on
/// every system, until connected says otherwise: to TEST-NET-1 (RFC
/// 5737), which nothing answers; where it has no route the system
/// refuses it at once, or connected's error is then every call's.
#[test]
fn not_connected_yet() {
    let address = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9));
    let Ok(mut stream) = Stream::connect(address) else {
        return;
    };
    // The attempt may fail at any moment, as Windows says at once that
    // the network is unreachable: until then each call is NotConnected,
    // and from then on each is that failure, the same every time. Not
    // connected at once: Windows names the peer while the connection is
    // still being made, which connected must not take for made.
    let mut failed = match stream.connected() {
        Ok(false) => None,
        Ok(true) => panic!("TEST-NET-1 answered"),
        Err(error) => Some(error),
    };
    let mut buf = [0; 8];
    for step in 0..6 {
        let result = match step % 3 {
            0 => stream.read(&mut buf).map(|_| ()),
            1 => stream.write(b"x").map(|_| ()),
            _ => stream.finish(),
        };
        match (failed, result) {
            (None, Err(Error::NotConnected)) => {}
            (None, Err(error)) => failed = Some(error),
            (Some(first), Err(error)) => assert_eq!(error, first),
            (_, Ok(())) => panic!("a stream not connected took a call"),
        }
    }
    if let Some(error) = failed {
        assert_eq!(stream.connected(), Err(error));
    }
}

/// A read into no room is refused: its Done(0) would be the peer's end.
#[test]
fn no_room() {
    let mut poll = Poll::new().unwrap();
    let (mut client, mut server) = pair(&mut poll, v4());
    assert_eq!(server.write(b"x"), Ok(Io::Done(1)));
    assert_eq!(client.read(&mut []), Err(Error::NoRoom));
    client.watch(&mut poll, Interest::Read, 1).unwrap();
    until(&mut poll, 1, Ready::READABLE);
    assert_eq!(client.read(&mut [0; 8]), Ok(Io::Done(1)));
    client.close(&mut poll).unwrap();
    server.close(&mut poll).unwrap();
}

/// A stream is its first Poll's: another refuses to watch it, and to close
/// it, which closes the socket all the same, once: the peer reads its
/// end, and the sockets made after, one of which may take its number,
/// stay open. Its token is lent for deadlines: neither Poll removes it.
#[test]
fn closed_once_in_its_own_set() {
    for mut poll in polls() {
        let mut other = Poll::new().unwrap();
        let (mut client, mut server) = pair(&mut poll, v4());
        let token = client.token().unwrap();
        assert_eq!(poll.remove(token), Err(PollError::Owned));
        assert_eq!(other.remove(token), Err(PollError::Foreign));
        assert_eq!(
            client.watch(&mut other, Interest::Read, 1),
            Err(PollError::Foreign)
        );
        assert_eq!(client.close(&mut other), Err(PollError::Foreign));
        server.watch(&mut poll, Interest::Read, 2).unwrap();
        until(&mut poll, 2, Ready::READABLE.with(Ready::HANGUP));
        assert_eq!(server.read(&mut [0; 8]), Ok(Io::Done(0)));
        let mut listener = Listener::bind(v4(), 4).unwrap();
        listener.watch(&mut poll, Interest::Read, 3).unwrap();
        let mut late = Stream::connect(listener.local().unwrap()).unwrap();
        until(&mut poll, 3, Ready::READABLE);
        let (mut accepted, _) = listener.accept().unwrap().unwrap();
        assert_eq!(accepted.write(b"y"), Ok(Io::Done(1)));
        late.watch(&mut poll, Interest::Read, 4).unwrap();
        until(&mut poll, 4, Ready::READABLE);
        assert_eq!(late.read(&mut [0; 8]), Ok(Io::Done(1)));
        late.close(&mut poll).unwrap();
        accepted.close(&mut poll).unwrap();
        server.close(&mut poll).unwrap();
        listener.close(&mut poll).unwrap();
    }
}

/// An accepted connection handed off: in no Poll, its peer as accept
/// gave it; adopted, it is watched like any stream, and talks. One never
/// adopted closes its socket when dropped: the peer reads its end.
#[test]
fn hands_off() {
    let mut poll = Poll::new().unwrap();
    let mut listener = Listener::bind(v4(), 4).unwrap();
    listener.watch(&mut poll, Interest::Read, 1).unwrap();
    let mut kept = Stream::connect(listener.local().unwrap()).unwrap();
    let mut dropped = Stream::connect(listener.local().unwrap()).unwrap();
    let mut handoffs = Vec::new();
    while handoffs.len() < 2 {
        until(&mut poll, 1, Ready::READABLE);
        while let Some(handoff) = listener.accept_handoff().unwrap() {
            handoffs.push(handoff);
        }
    }
    let late = handoffs.pop().unwrap();
    let first = handoffs.pop().unwrap();
    let (first, late) = if Some(first.peer()) == kept.local() {
        (first, late)
    } else {
        (late, first)
    };
    assert_eq!(Some(late.peer()), dropped.local());
    drop(late);
    dropped.watch(&mut poll, Interest::Read, 2).unwrap();
    until(&mut poll, 2, Ready::READABLE.with(Ready::HANGUP));
    assert!(matches!(
        dropped.read(&mut [0; 8]),
        Ok(Io::Done(0)) | Err(Error::Reset)
    ));
    let mut adopted = Stream::adopt(first);
    adopted.watch(&mut poll, Interest::Read, 3).unwrap();
    assert_eq!(kept.write(b"hi"), Ok(Io::Done(2)));
    until(&mut poll, 3, Ready::READABLE);
    let mut got = [0; 8];
    assert_eq!(adopted.read(&mut got), Ok(Io::Done(2)));
    assert_eq!(&got[..2], b"hi");
    adopted.close(&mut poll).unwrap();
    dropped.close(&mut poll).unwrap();
    kept.watch(&mut poll, Interest::Read, 4).unwrap();
    until(&mut poll, 4, Ready::READABLE.with(Ready::HANGUP));
    kept.close(&mut poll).unwrap();
    listener.close(&mut poll).unwrap();
}

/// Listeners that share an address: on Linux the kernel spreads the
/// connections among them (by a hash of each one's addresses: 64 to two
/// listeners all go to one once in 2^63); macOS and Windows refuse it.
#[test]
fn shares_an_address() {
    let first = Listener::bind_shared(v4(), 128);
    if cfg!(not(target_os = "linux")) {
        assert_eq!(first.err(), Some(Error::Unbalanced));
        return;
    }
    let mut poll = Poll::new().unwrap();
    let mut first = first.unwrap();
    let address = first.local().unwrap();
    let mut second = Listener::bind_shared(address, 128).unwrap();
    assert_eq!(Listener::bind(address, 4).err(), Some(Error::InUse));
    first.watch(&mut poll, Interest::Read, 1).unwrap();
    second.watch(&mut poll, Interest::Read, 2).unwrap();
    let mut clients = Vec::new();
    let mut accepted = [0usize; 2];
    let end = Instant::now().after_ms(10_000);
    while accepted[0] + accepted[1] < 64 {
        if clients.len() < 64 {
            clients.push(Stream::connect(address).unwrap());
        }
        assert!(!end.reached_by(Instant::now()), "accepted {accepted:?}");
        let soon = Instant::now().after_ms(10);
        for (at, listener) in [&first, &second].into_iter().enumerate() {
            while let Some((stream, _)) = listener.accept().unwrap() {
                drop(stream);
                accepted[at] += 1;
            }
        }
        poll.poll(Some(soon));
    }
    assert!(accepted[0] > 0 && accepted[1] > 0, "accepted {accepted:?}");
    first.close(&mut poll).unwrap();
    second.close(&mut poll).unwrap();
}
