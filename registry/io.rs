//! Completion I/O for a loop on each thread, after TigerBeetle's: an Io
//! takes operations (accept, connect, receive, send, a timeout), each with a
//! key the loop picks, runs them on io_uring (Linux 6.1 and later; nothing
//! else there) or kqueue (macOS), and hands each back once, done, as an
//! Event the loop takes by next; what an operation works on (a Listener, a
//! Stream, a buffer) is moved in and comes back in its Event, so nothing
//! the system still writes is in the loop's hands; a table of operations
//! fixed when the Io is made, which refuses one more by handing it back;
//! an Op that cancel takes; errors by kind, IPv4 and IPv6.
//!
//! A loop makes one Io, or has it made and moved to its thread before its
//! first wait (it stays there from then on), starts what it wants, and
//! waits:
//!
//! ```text
//! let mut io = Io::new(1024)?;
//! let listener = Listener::bind(address, 128)?;
//! let accepting = io.accept(listener, ACCEPT)?;     // Err hands it back
//! loop {
//!     io.wait(None)?;
//!     while let Some(event) = io.next() {
//!         match event.done {
//!             Done::Accepted { listener, result } => ...,
//!             Done::Received { stream, buffer, result } => ...,
//!             ...
//!         }
//!     }
//! }
//! ```
//!
//! Nothing calls back: wait sends the system what was started since the
//! last wait and sleeps until something is done (or its timeout passes),
//! and next takes what is done, in the order it was, one Event at a time,
//! its key the operation's. An Event owns what its operation was handed:
//! an accept hands back its Listener and the Stream it took, a receive its
//! Stream and its buffer with what was read after what it held, a send
//! both when all of the buffer is sent, or when it failed. A receive reads
//! into the room the buffer has beyond its length, up to its capacity: a
//! buffer without room is NoRoom at once, as its Ok(0) would read as the
//! peer's end. A send never stops part way: it is done when the system
//! took every byte.
//!
//! An operation is in the Io from its start to the next that hands back
//! its Event, and a slot of the table holds it all that time: a full table
//! refuses one more and hands back what it was given (Err), and the loop
//! takes Events, which frees their slots, before it starts more. One
//! Event at most waits for each slot, so the Io never holds more than its
//! table. Each Stream and Listener is in one operation at a time, as it is
//! moved in: two receives on one stream, whose order the system would not
//! keep, cannot be written.
//!
//! The Op a start returns names its operation until its Event is taken.
//! cancel ends it early: its Event comes with Canceled, and with what it
//! was handed. An operation the system finished before the cancel reached
//! it comes as finished. Dropping an Op cancels nothing: the operation
//! runs to its end, and its Event comes all the same. An Io dropped with
//! operations running cancels them and waits for the system to let go of
//! their buffers before it frees them.
//!
//! On Linux an Io is an io_uring of its own (one issuer, the thread of its
//! first wait, which enables it, and its work done when it waits:
//! IORING_SETUP_R_DISABLED, SINGLE_ISSUER and DEFER_TASKRUN, so Linux 6.1
//! or later; a wait on another thread after is refused, EEXIST), and there
//! is no other way: Io::new says why the system
//! gives none (Unavailable): no io_uring in the kernel or a seccomp filter
//! that says it has none, as gVisor's (Missing); io_uring_disabled = 2
//! (Disabled) or 1 for a process outside io_uring_group (Group); a filter
//! that denies it, as Docker's default profile does (Denied); a kernel
//! before 6.1 (Old). On macOS an Io is a kqueue: an operation is tried at
//! the next wait, and one the socket is not ready for waits in the kqueue
//! for it, once (EV_ONESHOT), as TigerBeetle's does; a timeout is a kqueue
//! timer.
//!
//! Every socket is non-blocking and not handed to child processes
//! (close-on-exec); small writes go at once (TCP_NODELAY), and a send to a
//! peer that is gone is an error, not SIGPIPE. A Listener's address may be
//! taken again while old connections linger (SO_REUSEADDR), and an IPv6
//! one takes IPv6 alone (IPV6_V6ONLY). A Stream is closed when it is
//! dropped. A Stream or Listener is the process's: it may go to another
//! thread's Io, as a loop on each core hands connections on.
//!
//! Errors come as the kinds a loop acts on: refused, reset, timed out,
//! unreachable, the address in use, canceled, no room, and the system's
//! code for the rest.

// rr: checked(0.5.2)
// rr: needs(thread)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests
// rr: choice(tests = no): none
// rr: option(os, many): Which systems does it build for?
// rr: choice(os = linux, default): Linux 6.1 and later, io_uring
// rr: choice(os = macos, default): macOS, kqueue
// rr: choice(os = windows, default): Windows

// rr: unless(os = linux)
#[cfg(target_os = "linux")]
compile_error!("rr add cut io without linux: add it again with linux in --option os");
// rr: end(os = linux)
// rr: unless(os = macos)
#[cfg(target_os = "macos")]
compile_error!("rr add cut io without macos: add it again with macos in --option os");
// rr: end(os = macos)
// rr: unless(os = windows)
#[cfg(windows)]
compile_error!("rr add cut io without windows: add it again with windows in --option os");
// rr: end(os = windows)

pub use crate::base::thread::Work;
pub use sys::{
    AF_INET, AF_INET6, Chunk, Done, Error, Event, Io, Listener, Op, SOCK_STREAM, Stream, Turn, Udp,
    Unavailable, Waker,
};

// rr: section(os = linux macos)
#[cfg(unix)]
pub use sys::{EINTR, EINVAL, errno};
// rr: end(os = linux macos)

// rr: section(os = windows)
/// Winsock, started once for the process, for what else asks it (resolve).
#[cfg(windows)]
pub use sys::startup;
// rr: end(os = windows)

mod sys {
    //! The system side of io: what the top of the file says it is, for each system.

    use crate::base::thread::{self, Job, Lock, Notify, Work as Blocking};
    use alloc::boxed::Box;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::cell::UnsafeCell;
    use core::mem;
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::time::Duration;
    use os::Raw;

    /// Why an operation failed, as a loop acts on it.
    #[derive(Clone, Copy)]
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug, PartialEq))]
    // rr: end(tests = yes)
    pub enum Error {
        /// Nobody listens there.
        Refused,
        /// The peer reset or aborted the connection, or is gone and a send
        /// found out.
        Reset,
        /// The connection timed out.
        TimedOut,
        /// No route to the host or its network, or either is down.
        Unreachable,
        /// The address is taken.
        InUse,
        /// cancel ended the operation.
        Canceled,
        /// A receive into a buffer without room, whose Ok(0) could not be
        /// told from the peer's end.
        NoRoom,
        /// Windows: a stream or listener another Io ran first; a socket
        /// stays in the completion port it was first in. Everywhere: a
        /// Chunk given to another Io than its own.
        Foreign,
        /// receive_many: no chunk was free for what came (or the Io has
        /// none): give chunks back and receive again.
        NoChunks,
        /// Listener::bind_shared where the system does not spread
        /// connections among listeners of one address: macOS gives them all
        /// to the one bound last, Windows shares none.
        Unbalanced,
        /// Io::new: the system has no way to run one.
        Unavailable(Unavailable),
        /// Anything else: the system's code (errno).
        Other(i32),
    }

    /// Why Linux gives no io_uring, which an Io is there.
    #[derive(Clone, Copy)]
    // rr: section(tests = yes)
    #[cfg_attr(test, derive(Debug, PartialEq))]
    // rr: end(tests = yes)
    pub enum Unavailable {
        /// The kernel has none (ENOSYS): built without it, or a seccomp
        /// filter, as gVisor's, says so.
        Missing,
        /// kernel.io_uring_disabled is 2: no process may make one.
        Disabled,
        /// kernel.io_uring_disabled is 1: only a process in the group
        /// kernel.io_uring_group names may make one.
        Group,
        /// Denied (EPERM) otherwise: a seccomp filter, as Docker's default
        /// profile is, or a security module.
        Denied,
        /// A kernel before 6.1, which refuses what an Io asks of it.
        Old,
    }

    /// A TCP connection, closed when it is dropped.
    pub struct Stream {
        fd: Fd,
    }

    impl Stream {
        /// Its own address.
        #[must_use]
        pub fn local(&self) -> Option<SocketAddr> {
            os::local(self.fd.raw)
        }

        /// Its peer's address.
        #[must_use]
        pub fn peer(&self) -> Option<SocketAddr> {
            os::peer(self.fd.raw)
        }

        /// Ends what it sends: the peer then reads its end; it still
        /// receives.
        pub fn finish(&self) -> Result<(), Error> {
            os::finish(self.fd.raw)
        }
    }

    /// A socket that listens for connections, closed when it is dropped.
    pub struct Listener {
        fd: Fd,
    }

    impl Listener {
        /// Listens on an address; port 0 takes one the system picks
        /// (local says which).
        pub fn bind(address: SocketAddr, backlog: u32) -> Result<Listener, Error> {
            Listener::bind_in(address, backlog, false)
        }

        /// Listens on an address beside other listeners of this user on it,
        /// one for each loop, and the kernel spreads the connections among
        /// them: Linux's SO_REUSEPORT (since 3.9). macOS gives them all to
        /// the listener bound last and Windows shares none, and both are
        /// refused (Unbalanced): accept on one thread there, and hand the
        /// streams to the others (queue).
        pub fn bind_shared(address: SocketAddr, backlog: u32) -> Result<Listener, Error> {
            if !os::BALANCED {
                return Err(Error::Unbalanced);
            }
            Listener::bind_in(address, backlog, true)
        }

        fn bind_in(address: SocketAddr, backlog: u32, shared: bool) -> Result<Listener, Error> {
            let fd = Fd::new(os::open(&address, Kind::Stream)?);
            os::prepare(fd.raw, address.is_ipv6())?;
            if shared {
                os::share(fd.raw)?;
            }
            let (bytes, length) = encode(&address);
            os::bind(fd.raw, bytes.get(..length).unwrap_or_default())?;
            os::listen(fd.raw, backlog)?;
            Ok(Listener { fd })
        }

        #[must_use]
        pub fn local(&self) -> Option<SocketAddr> {
            os::local(self.fd.raw)
        }
    }

    /// A UDP socket, closed when it is dropped.
    pub struct Udp {
        fd: Fd,
    }

    impl Udp {
        /// A socket on an address, which sends and receives datagrams; port
        /// 0 takes one the system picks (local says which). An IPv6 one
        /// takes IPv6 alone, and on Windows an ICMP refusal of what it sent
        /// does not fail its next receive (SIO_UDP_CONNRESET off).
        pub fn bind(address: SocketAddr) -> Result<Udp, Error> {
            let fd = Fd::new(os::open(&address, Kind::Datagram)?);
            os::datagram(fd.raw, address.is_ipv6())?;
            let (bytes, length) = encode(&address);
            os::bind(fd.raw, bytes.get(..length).unwrap_or_default())?;
            Ok(Udp { fd })
        }

        #[must_use]
        pub fn local(&self) -> Option<SocketAddr> {
            os::local(self.fd.raw)
        }
    }

    /// What a socket carries.
    #[derive(Clone, Copy)]
    enum Kind {
        Stream,
        Datagram,
    }

    /// A descriptor this owns, closed when it is dropped.
    struct Fd {
        raw: Raw,
        // rr: section(os = windows)
        /// Windows: the completion port it is in, once an Io ran it; it
        /// stays in that one.
        #[cfg(windows)]
        port: usize,
        // rr: end(os = windows)
    }

    impl Fd {
        // rr: section(os = linux macos)
        #[cfg(unix)]
        fn new(raw: Raw) -> Fd {
            Fd { raw }
        }
        // rr: end(os = linux macos)

        // rr: section(os = windows)
        #[cfg(windows)]
        fn new(raw: Raw) -> Fd {
            Fd { raw, port: 0 }
        }
        // rr: end(os = windows)
    }

    impl Drop for Fd {
        fn drop(&mut self) {
            os::close(self.raw);
        }
    }

    /// Names an operation until its Event is taken; cancel takes it.
    /// Dropped, it cancels nothing.
    #[must_use]
    pub struct Op {
        index: u32,
        generation: u32,
    }

    /// The slowest turn of a loop since slowest_turn last asked: how long
    /// it took, from a wait's return to the next wait, and the key of the
    /// last Event the loop took in it, the work of which, as like as not,
    /// took the time.
    pub struct Turn {
        pub took: Duration,
        pub key: u64,
    }

    /// An operation done, with the key it was started with.
    pub struct Event {
        pub key: u64,
        pub done: Done,
    }

    /// What an operation did, with what it was handed.
    pub enum Done {
        /// The listener, and the connection it took and its peer.
        Accepted {
            listener: Listener,
            result: Result<(Stream, SocketAddr), Error>,
        },
        /// The connection made.
        Connected(Result<Stream, Error>),
        /// The stream, and its buffer with so many bytes read after what it
        /// held; Ok(0) is the peer's end.
        Received {
            stream: Stream,
            buffer: Vec<u8>,
            result: Result<usize, Error>,
        },
        /// The stream and its buffer, all of which was sent, unless it failed.
        Sent {
            stream: Stream,
            buffer: Vec<u8>,
            result: Result<(), Error>,
        },
        /// The time passed, unless canceled.
        Elapsed(Result<(), Error>),
        /// The socket and its buffer, sent as one datagram, unless it failed.
        SentTo {
            udp: Udp,
            buffer: Vec<u8>,
            result: Result<(), Error>,
        },
        /// What came on a receive_many, in a chunk of the Io's: its bytes
        /// are bytes(&chunk), until it is given back (give_back, or
        /// send_chunk, which gives it back once sent). More come with the
        /// same key until Stopped.
        Chunk(Chunk),
        /// A receive_many is over: the stream, and Ok when the peer ended
        /// what it sends; Canceled, NoChunks or another error else. It comes
        /// after the stream's chunks, and after each send_chunk on it.
        Stopped {
            stream: Stream,
            result: Result<(), Error>,
        },
        /// A send_chunk is done, all of the chunk sent unless it failed; the
        /// chunk is the Io's again.
        SentChunk(Result<(), Error>),
        /// The work, back from thread's pool once it ran, or never run when
        /// canceled in line.
        Ran {
            work: Box<dyn Blocking + Send>,
            result: Result<(), Error>,
        },
        /// The socket, and its buffer with a datagram of so many bytes after
        /// what it held, and who sent it; one longer than the room is cut
        /// to it.
        ReceivedFrom {
            udp: Udp,
            buffer: Vec<u8>,
            result: Result<(usize, SocketAddr), Error>,
        },
    }

    /// What a slot's operation works on while it runs.
    enum Work {
        Idle,
        Accept(Listener),
        Connect(Stream),
        Receive(Stream, Vec<u8>),
        /// The stream, the buffer, and how much of it the system took.
        Send(Stream, Vec<u8>, usize),
        Timeout(Duration),
        SendTo(Udp, Vec<u8>),
        ReceiveFrom(Udp, Vec<u8>),
        /// Work on thread's pool, which tells the Io when it returned.
        Run(Job),
        /// A multishot receive into the Io's chunks; the stream stays until
        /// it is over and the sends on it are done.
        ReceiveMany(Stream),
        /// A chunk sent on a receive_many's stream: its descriptor, which the
        /// receive keeps open until this is done, the chunk, its length,
        /// and how much of it the system took.
        SendChunk {
            fd: Raw,
            id: u16,
            length: u32,
            sent: u32,
        },
        /// Done: what the next Event hands back.
        Finished(Done),
    }

    #[derive(PartialEq)]
    enum State {
        Free,
        /// Started, with the system.
        Running,
        /// Done, waiting in ready for next.
        Ready,
    }

    /// One operation of the table. A slot does not move while the Io lives
    /// (the table is a boxed slice), so the system may write its address
    /// and the time it reads while the operation runs.
    #[repr(C)]
    pub struct Slot {
        // rr: section(os = windows)
        /// Windows: the operation's OVERLAPPED, first, so that a completion
        /// names its slot.
        #[cfg(windows)]
        overlapped: [usize; 4],
        /// Windows: the socket AcceptEx accepts into, and where it writes
        /// both addresses, each a sockaddr_in6 and 16 bytes.
        #[cfg(windows)]
        accepting: Option<Raw>,
        #[cfg(windows)]
        accepted: [u8; 88],
        // rr: end(os = windows)
        // rr: section(os = linux)
        /// io_uring: a datagram's struct msghdr and its one struct iovec.
        #[cfg(target_os = "linux")]
        message: [u64; 7],
        #[cfg(target_os = "linux")]
        vector: [u64; 2],
        // rr: end(os = linux)
        generation: u32,
        state: State,
        /// cancel asked the system to end it.
        canceled: bool,
        /// kqueue: a connect begun, or the filter it waits on.
        begun: bool,
        armed: Option<i16>,
        /// receive_many: the send_chunks running on its stream, and how it
        /// ended, while they run; IOCP: the chunk its receive fills.
        sends: u32,
        ending: Option<Result<(), Error>>,
        chunk: Option<u16>,
        /// send_chunk: the receive_many whose stream it sends on, by slot
        /// and generation.
        owner: Option<(u32, u32)>,
        /// How long the operation may take (receive_within and its kin),
        /// whether that time passed, whether its timer is set (kqueue,
        /// IOCP), and when it ends on the monotonic clock (io_uring).
        limit: Option<Duration>,
        expired: bool,
        limited: bool,
        until: u64,
        key: u64,
        work: Work,
        /// A sockaddr, for connect to read and accept to fill, and its
        /// length, which accept updates.
        address: [u8; ADDRESS_BYTES],
        length: u32,
        /// io_uring: a timeout's struct __kernel_timespec.
        time: [i64; 2],
    }

    impl Slot {
        fn new() -> Slot {
            Slot {
                // rr: section(os = windows)
                #[cfg(windows)]
                overlapped: [0; 4],
                #[cfg(windows)]
                accepting: None,
                #[cfg(windows)]
                accepted: [0; 88],
                // rr: end(os = windows)
                // rr: section(os = linux)
                #[cfg(target_os = "linux")]
                message: [0; 7],
                #[cfg(target_os = "linux")]
                vector: [0; 2],
                // rr: end(os = linux)
                generation: 0,
                state: State::Free,
                canceled: false,
                begun: false,
                armed: None,
                sends: 0,
                ending: None,
                chunk: None,
                owner: None,
                limit: None,
                expired: false,
                limited: false,
                until: 0,
                key: 0,
                work: Work::Idle,
                address: [0; ADDRESS_BYTES],
                length: 0,
                time: [0; 2],
            }
        }

        /// The descriptor the operation works on, if any.
        fn fd(&self) -> Option<Raw> {
            match &self.work {
                Work::Accept(listener) => Some(listener.fd.raw),
                Work::Connect(stream) | Work::Receive(stream, _) | Work::Send(stream, _, _) => {
                    Some(stream.fd.raw)
                }
                Work::SendTo(udp, _) | Work::ReceiveFrom(udp, _) => Some(udp.fd.raw),
                Work::ReceiveMany(stream) => Some(stream.fd.raw),
                Work::SendChunk { fd, .. } => Some(*fd),
                Work::Idle | Work::Timeout(_) | Work::Run(_) | Work::Finished(_) => None,
            }
        }
    }

    /// The table: as many slots as the Io was made with, at most this many.
    const OPS_MAX: usize = 32_768;
    /// The most chunks an Io has: their ids are u16, and io_uring's ring of
    /// them holds at most this many.
    const CHUNKS_MAX: usize = 32_768;

    // rr: escape(shared): each Io's number, for its chunks, from any thread.
    static NEXT_IO: AtomicU32 = AtomicU32::new(1);

    /// What the system says of an operation: a count or a descriptor, or
    /// an errno.
    type Answer = Result<usize, i32>;

    /// The operation's user data: its slot and that slot's generation; the
    /// top bit for a cancel's own, whose answer says nothing, and the next
    /// for a Waker's.
    fn user_data(index: u32, generation: u32) -> u64 {
        (u64::from(generation & GENERATIONS) << 32) | u64::from(index)
    }

    const GENERATIONS: u32 = 0x1fff_ffff;
    const CANCEL: u64 = 1 << 63;
    /// The user data of what a Waker sets.
    const WAKE: u64 = 1 << 62;
    /// The user data of io_uring's linked timeout's own answer.
    const LIMIT: u64 = 1 << 61;

    fn parts(data: u64) -> Option<(usize, u32)> {
        if data & (CANCEL | WAKE | LIMIT) != 0 {
            return None;
        }
        let index = usize::try_from(data & 0xffff_ffff).ok()?;
        let generation = u32::try_from(data >> 32).ok()?;
        Some((index, generation))
    }

    /// The slot that user data names, while its operation runs.
    #[must_use]
    fn running(slots: &mut [Slot], data: u64) -> Option<(usize, &mut Slot)> {
        let (index, generation) = parts(data)?;
        let slot = slots.get_mut(index)?;
        (slot.state == State::Running && slot.generation & GENERATIONS == generation)
            .then_some((index, slot))
    }

    /// Ends a slot's operation as the system answered: true when it is to
    /// be tried again (a send with more to send, an accept whose connection
    /// was gone before it was taken), false when it is done, its Done in
    /// the slot.
    #[must_use]
    fn settle(slot: &mut Slot, answer: Answer) -> bool {
        let canceled = slot.canceled;
        // An operation its time ran out for was canceled by the system, or
        // by the Io once its timer fired: it timed out.
        let answer = match answer {
            Err(code)
                if slot.expired || (slot.limit.is_some() && !canceled && code == os::CANCELED) =>
            {
                Err(os::TIMED_OUT)
            }
            other => other,
        };
        let work = mem::replace(&mut slot.work, Work::Idle);
        let (work, again) = match (work, answer) {
            (Work::Accept(listener), Ok(fd)) => {
                let result = adopt(fd, &slot.address, slot.length);
                (Work::Finished(Done::Accepted { listener, result }), false)
            }
            (Work::Accept(listener), Err(code)) if os::passing(code) && !canceled => {
                (Work::Accept(listener), true)
            }
            (Work::Accept(listener), Err(code)) => {
                let result = Err(os::error(code));
                (Work::Finished(Done::Accepted { listener, result }), false)
            }
            (Work::Connect(stream), Ok(_)) => (Work::Finished(Done::Connected(Ok(stream))), false),
            (Work::Connect(_), Err(code)) => {
                (Work::Finished(Done::Connected(Err(os::error(code)))), false)
            }
            (Work::Receive(stream, mut buffer), Ok(count)) => {
                os::filled(&mut buffer, count);
                let done = Done::Received {
                    stream,
                    buffer,
                    result: Ok(count),
                };
                (Work::Finished(done), false)
            }
            (Work::Receive(stream, buffer), Err(code)) if os::again(code) && !canceled => {
                (Work::Receive(stream, buffer), true)
            }
            (Work::Receive(stream, buffer), Err(code)) => {
                let done = Done::Received {
                    stream,
                    buffer,
                    result: Err(os::error(code)),
                };
                (Work::Finished(done), false)
            }
            (Work::Send(stream, buffer, sent), Ok(count)) => {
                let sent = sent.saturating_add(count);
                if sent < buffer.len() && count > 0 && !canceled {
                    (Work::Send(stream, buffer, sent), true)
                } else {
                    let result = if sent < buffer.len() {
                        Err(if canceled {
                            Error::Canceled
                        } else {
                            Error::Reset
                        })
                    } else {
                        Ok(())
                    };
                    (
                        Work::Finished(Done::Sent {
                            stream,
                            buffer,
                            result,
                        }),
                        false,
                    )
                }
            }
            (Work::Send(stream, buffer, sent), Err(code)) if os::again(code) && !canceled => {
                (Work::Send(stream, buffer, sent), true)
            }
            (Work::Send(stream, buffer, _), Err(code)) => {
                let done = Done::Sent {
                    stream,
                    buffer,
                    result: Err(os::error(code)),
                };
                (Work::Finished(done), false)
            }
            (Work::Timeout(_), Ok(_)) => (Work::Finished(Done::Elapsed(Ok(()))), false),
            (Work::Timeout(_), Err(code)) => {
                (Work::Finished(Done::Elapsed(Err(os::error(code)))), false)
            }
            (Work::SendTo(udp, buffer), Err(code)) if os::again(code) && !canceled => {
                (Work::SendTo(udp, buffer), true)
            }
            (Work::SendTo(udp, buffer), answer) => {
                let result = answer.map(|_| ()).map_err(os::error);
                (
                    Work::Finished(Done::SentTo {
                        udp,
                        buffer,
                        result,
                    }),
                    false,
                )
            }
            (Work::ReceiveFrom(udp, mut buffer), Ok(count)) => {
                os::filled(&mut buffer, count);
                let filled = usize::try_from(slot.length).unwrap_or(0);
                let from = slot.address.get(..filled).and_then(decode);
                let result = from.map(|from| (count, from)).ok_or(Error::Other(0));
                (
                    Work::Finished(Done::ReceivedFrom {
                        udp,
                        buffer,
                        result,
                    }),
                    false,
                )
            }
            (Work::ReceiveFrom(udp, buffer), Err(code)) if os::again(code) && !canceled => {
                (Work::ReceiveFrom(udp, buffer), true)
            }
            (Work::ReceiveFrom(udp, buffer), Err(code)) => {
                let result = Err(os::error(code));
                (
                    Work::Finished(Done::ReceivedFrom {
                        udp,
                        buffer,
                        result,
                    }),
                    false,
                )
            }
            (
                Work::SendChunk {
                    fd,
                    id,
                    length,
                    sent,
                },
                Ok(count),
            ) => {
                let sent = sent.saturating_add(u32::try_from(count).unwrap_or(u32::MAX));
                if sent < length && count > 0 && !canceled {
                    let more = Work::SendChunk {
                        fd,
                        id,
                        length,
                        sent,
                    };
                    (more, true)
                } else {
                    let result = if sent < length {
                        Err(if canceled {
                            Error::Canceled
                        } else {
                            Error::Reset
                        })
                    } else {
                        Ok(())
                    };
                    (Work::Finished(Done::SentChunk(result)), false)
                }
            }
            (work @ Work::SendChunk { .. }, Err(code)) if os::again(code) && !canceled => {
                (work, true)
            }
            (Work::SendChunk { .. }, Err(code)) => {
                (Work::Finished(Done::SentChunk(Err(os::error(code)))), false)
            }
            (other @ (Work::Idle | Work::Run(_) | Work::ReceiveMany(_) | Work::Finished(_)), _) => {
                (other, false)
            }
        };
        slot.work = work;
        if !again {
            slot.state = State::Ready;
        }
        again
    }

    /// Ends a receive_many as the system said, its stream handed back
    /// (true), or once the send_chunks on it are done (false, ending kept).
    #[must_use]
    fn end_many(slot: &mut Slot, result: Result<(), Error>) -> bool {
        if slot.sends > 0 {
            slot.ending.get_or_insert(result);
            return false;
        }
        let Work::ReceiveMany(stream) = mem::replace(&mut slot.work, Work::Idle) else {
            return false;
        };
        slot.work = Work::Finished(Done::Stopped { stream, result });
        slot.state = State::Ready;
        true
    }

    /// A chunk of an Io's, which receive_many filled: the program's until it
    /// gives it back or sends it. It names its Io, which refuses another's.
    #[must_use = "a chunk is the Io's again only once given back or sent"]
    pub struct Chunk {
        io: u32,
        id: u16,
        length: u32,
    }

    /// The chunks of an Io, which receive_many fills: count of size bytes,
    /// in one block that never moves; the ids free (kqueue, IOCP; io_uring
    /// keeps them in its ring), and the chunks filled and not yet handed
    /// out, with their keys and lengths.
    pub struct Pool {
        bytes: Box<[u8]>,
        size: usize,
        count: usize,
        free: Vec<u16>,
        filled: VecDeque<(u64, u16, u32)>,
    }

    impl Pool {
        fn new(count: usize, size: usize) -> Pool {
            let mut bytes = Vec::new();
            bytes.resize(count.saturating_mul(size), 0u8);
            let mut free = Vec::with_capacity(count);
            for id in (0..count).rev() {
                free.push(u16::try_from(id).unwrap_or(0));
            }
            Pool {
                bytes: bytes.into_boxed_slice(),
                size,
                count,
                free,
                filled: VecDeque::with_capacity(count),
            }
        }

        /// The first byte of chunk id, for the system to write.
        fn at(&mut self, id: u16) -> *mut u8 {
            let start = usize::from(id)
                .saturating_mul(self.size)
                .min(self.bytes.len());
            self.bytes.as_mut_ptr().wrapping_add(start)
        }

        fn slice(&self, id: u16, length: u32) -> &[u8] {
            let start = usize::from(id).saturating_mul(self.size);
            let end = start
                .saturating_add(length as usize)
                .min(start.saturating_add(self.size));
            self.bytes.get(start..end).unwrap_or_default()
        }

        /// Hands out a filled chunk of key, at most one for each chunk.
        fn fill(&mut self, key: u64, id: u16, length: u32) {
            if self.filled.len() < self.count {
                self.filled.push_back((key, id, length));
            }
        }

        #[must_use]
        fn take(&mut self) -> Option<u16> {
            self.free.pop()
        }

        fn put(&mut self, id: u16) {
            if self.free.len() < self.count {
                self.free.push(id);
            }
        }
    }

    /// The connection an accept took, made as every stream here is, and
    /// its peer.
    fn adopt(fd: usize, address: &[u8], length: u32) -> Result<(Stream, SocketAddr), Error> {
        let stream = Stream {
            fd: Fd::new(os::raw(fd)),
        };
        os::adopt(stream.fd.raw)?;
        let filled = usize::try_from(length).unwrap_or(0);
        let peer = address
            .get(..filled)
            .and_then(decode)
            .ok_or(Error::Other(0))?;
        Ok((stream, peer))
    }

    pub struct Io {
        /// Which Io this is, as its chunks name it.
        id: u32,
        slots: Box<[Slot]>,
        /// The free slots, and those done, in the order they were.
        free: Vec<u32>,
        ready: VecDeque<u32>,
        /// A Waker was made: a wait with nothing running waits for it.
        wakeable: bool,
        /// The work of run that returned, by user data, which the pool's
        /// threads put there; and the list taken from it at a wait.
        finished: Arc<Finished>,
        taken: Vec<u64>,
        /// When the last wait returned, on the monotonic clock (0 before
        /// the first), the key of the last Event taken since, and the
        /// slowest turn: a turn is the program's work between two waits.
        turned: u64,
        last_key: u64,
        slowest: Option<Turn>,
        /// The system's side, on the heap, so that an Io is small to move
        /// to its thread.
        backend: Box<backend::Backend>,
    }

    /// What the pool's threads tell an Io: the user data of each run whose
    /// work returned, under a lock.
    struct Finished {
        lock: Lock,
        list: UnsafeCell<Vec<u64>>,
    }

    // rr: escape(unsafe): list is reached only under lock (Finished::push,
    // Finished::take).
    unsafe impl Sync for Finished {}

    impl Finished {
        fn push(&self, data: u64) {
            let _held = self.lock.lock();
            // rr: escape(unsafe): the lock is held: no one else touches the
            // list.
            let list = unsafe { &mut *self.list.get() };
            list.push(data);
        }

        /// Moves the list into into, which was empty, and the list's room
        /// with it.
        fn take(&self, into: &mut Vec<u64>) {
            let _held = self.lock.lock();
            // rr: escape(unsafe): the lock is held: no one else touches the
            // list.
            mem::swap(unsafe { &mut *self.list.get() }, into);
        }
    }

    /// A run's Notify: puts its user data in the Io's list and wakes it.
    struct Returned {
        finished: Arc<Finished>,
        wake: Arc<backend::Wake>,
        data: u64,
    }

    impl Notify for Returned {
        fn notify(&self) {
            self.finished.push(self.data);
            self.wake.wake();
        }
    }

    /// Wakes an Io's wait from another thread: wait returns, with what is
    /// done, as when its timeout passes. Wakes before a wait are one.
    pub struct Waker {
        wake: Arc<backend::Wake>,
    }

    impl Waker {
        pub fn wake(&self) {
            self.wake.wake();
        }
    }

    impl Io {
        /// An Io of so many operations at once (at least 1, at most
        /// 32768), on this thread.
        pub fn new(ops: usize) -> Result<Io, Error> {
            Io::with_chunks(ops, 0, 0)
        }

        /// An Io of so many operations, and chunks of size bytes for its
        /// receive_many (count at most 32768, a power of two on Linux,
        /// rounded up; none when 0).
        pub fn with_chunks(ops: usize, count: usize, size: usize) -> Result<Io, Error> {
            let ops = ops.clamp(1, OPS_MAX);
            let count = if count == 0 {
                0
            } else {
                count.clamp(1, CHUNKS_MAX).next_power_of_two()
            };
            let size = size.clamp(1, u32::MAX as usize);
            let pool = Pool::new(count, size);
            let backend = Box::new(backend::Backend::new(
                u32::try_from(ops).unwrap_or(1),
                pool,
            )?);
            let mut slots = Vec::with_capacity(ops);
            slots.resize_with(ops, Slot::new);
            let mut free = Vec::with_capacity(ops);
            for index in (0..ops).rev() {
                free.push(u32::try_from(index).unwrap_or(0));
            }
            Ok(Io {
                id: NEXT_IO.fetch_add(1, Ordering::Relaxed),
                slots: slots.into_boxed_slice(),
                free,
                ready: VecDeque::with_capacity(ops),
                wakeable: false,
                // rr: escape(shared): the Io and its runs' Notify hold it.
                finished: Arc::new(Finished {
                    lock: Lock::new(),
                    // rr: escape(shared): the list, under the lock.
                    list: UnsafeCell::new(Vec::with_capacity(ops)),
                }),
                taken: Vec::with_capacity(ops),
                turned: 0,
                last_key: 0,
                slowest: None,
                backend,
            })
        }

        /// Accepts the next connection on listener.
        pub fn accept(&mut self, listener: Listener, key: u64) -> Result<Op, Listener> {
            match self.free.pop() {
                Some(index) => Ok(self.start(index, key, Work::Accept(listener), None)),
                None => Err(listener),
            }
        }

        /// Connects to address.
        pub fn connect(&mut self, address: SocketAddr, key: u64) -> Result<Op, SocketAddr> {
            self.connect_in(address, key, None)
        }

        /// Connects to address, or gives up with TimedOut once after passed.
        pub fn connect_within(
            &mut self,
            address: SocketAddr,
            after: Duration,
            key: u64,
        ) -> Result<Op, SocketAddr> {
            self.connect_in(address, key, Some(after))
        }

        /// Receives as receive does, or gives up with TimedOut, buffer as it
        /// was, once after passed.
        pub fn receive_within(
            &mut self,
            stream: Stream,
            buffer: Vec<u8>,
            after: Duration,
            key: u64,
        ) -> Result<Op, (Stream, Vec<u8>)> {
            self.receive_in(stream, buffer, key, Some(after))
        }

        /// Sends as send does, or gives up with TimedOut once after passed
        /// since it started, however much was sent by then.
        pub fn send_within(
            &mut self,
            stream: Stream,
            buffer: Vec<u8>,
            after: Duration,
            key: u64,
        ) -> Result<Op, (Stream, Vec<u8>)> {
            self.send_in(stream, buffer, key, Some(after))
        }

        fn connect_in(
            &mut self,
            address: SocketAddr,
            key: u64,
            limit: Option<Duration>,
        ) -> Result<Op, SocketAddr> {
            let Some(index) = self.free.pop() else {
                return Err(address);
            };
            let fd = match os::open(&address, Kind::Stream) {
                Ok(fd) => fd,
                Err(error) => return Ok(self.finish(index, key, Done::Connected(Err(error)))),
            };
            let stream = Stream { fd: Fd::new(fd) };
            if let Err(error) = os::no_delay(stream.fd.raw) {
                return Ok(self.finish(index, key, Done::Connected(Err(error))));
            }
            if let Some(slot) = self.slots.get_mut(index as usize) {
                let (bytes, length) = encode(&address);
                slot.address = bytes;
                slot.length = u32::try_from(length).unwrap_or(0);
            }
            Ok(self.start(index, key, Work::Connect(stream), limit))
        }

        /// Receives into the room buffer has beyond its length.
        pub fn receive(
            &mut self,
            stream: Stream,
            buffer: Vec<u8>,
            key: u64,
        ) -> Result<Op, (Stream, Vec<u8>)> {
            self.receive_in(stream, buffer, key, None)
        }

        fn receive_in(
            &mut self,
            stream: Stream,
            buffer: Vec<u8>,
            key: u64,
            limit: Option<Duration>,
        ) -> Result<Op, (Stream, Vec<u8>)> {
            let Some(index) = self.free.pop() else {
                return Err((stream, buffer));
            };
            if buffer.len() == buffer.capacity() {
                let result = Err(Error::NoRoom);
                return Ok(self.finish(
                    index,
                    key,
                    Done::Received {
                        stream,
                        buffer,
                        result,
                    },
                ));
            }
            Ok(self.start(index, key, Work::Receive(stream, buffer), limit))
        }

        /// Sends all of buffer.
        pub fn send(
            &mut self,
            stream: Stream,
            buffer: Vec<u8>,
            key: u64,
        ) -> Result<Op, (Stream, Vec<u8>)> {
            self.send_in(stream, buffer, key, None)
        }

        fn send_in(
            &mut self,
            stream: Stream,
            buffer: Vec<u8>,
            key: u64,
            limit: Option<Duration>,
        ) -> Result<Op, (Stream, Vec<u8>)> {
            let Some(index) = self.free.pop() else {
                return Err((stream, buffer));
            };
            if buffer.is_empty() {
                let result = Ok(());
                return Ok(self.finish(
                    index,
                    key,
                    Done::Sent {
                        stream,
                        buffer,
                        result,
                    },
                ));
            }
            Ok(self.start(index, key, Work::Send(stream, buffer, 0), limit))
        }

        /// Receives what stream brings into the Io's chunks, as it comes,
        /// until the peer ends, an error, or cancel: an Event of Chunk with
        /// key for each part, then Stopped with the stream. On io_uring a
        /// multishot receive into a ring of the chunks the kernel picks
        /// from (IORING_RECV_MULTISHOT, IORING_REGISTER_PBUF_RING): no
        /// receive to start again for each part. Send on the stream meanwhile
        /// with send_chunk.
        pub fn receive_many(&mut self, stream: Stream, key: u64) -> Result<Op, Stream> {
            let Some(index) = self.free.pop() else {
                return Err(stream);
            };
            if self.backend.pool.count == 0 {
                let result = Err(Error::NoChunks);
                return Ok(self.finish(index, key, Done::Stopped { stream, result }));
            }
            Ok(self.start(index, key, Work::ReceiveMany(stream), None))
        }

        /// Sends chunk on the stream of receiving, a receive_many of this Io
        /// that runs, and gives it back once sent: its Event is SentChunk.
        /// Err hands the chunk back: a full table, receiving over, or a
        /// chunk of another Io.
        pub fn send_chunk(&mut self, receiving: &Op, chunk: Chunk, key: u64) -> Result<Op, Chunk> {
            if chunk.io != self.id {
                return Err(chunk);
            }
            let (index, generation) = (receiving.index, receiving.generation);
            let fd = match self.slots.get(index as usize) {
                Some(owner)
                    if owner.state == State::Running
                        && owner.generation == generation
                        && owner.ending.is_none() =>
                {
                    owner.fd()
                }
                _ => None,
            };
            let (Some(fd), Some(slot)) = (fd, self.free.pop()) else {
                return Err(chunk);
            };
            if let Some(owner) = self.slots.get_mut(index as usize) {
                owner.sends = owner.sends.saturating_add(1);
            }
            if let Some(sending) = self.slots.get_mut(slot as usize) {
                sending.chunk = Some(chunk.id);
                sending.owner = Some((index, generation));
            }
            let work = Work::SendChunk {
                fd,
                id: chunk.id,
                length: chunk.length,
                sent: 0,
            };
            Ok(self.start(slot, key, work, None))
        }

        /// The bytes of a chunk of this Io; None for another's.
        #[must_use]
        pub fn bytes(&self, chunk: &Chunk) -> Option<&[u8]> {
            (chunk.io == self.id).then(|| self.backend.pool.slice(chunk.id, chunk.length))
        }

        /// Gives a chunk back for receive_many to fill again; Err for
        /// another Io's, which is handed back.
        pub fn give_back(&mut self, chunk: Chunk) -> Result<(), Chunk> {
            if chunk.io != self.id {
                return Err(chunk);
            }
            self.backend.give_back(chunk.id);
            Ok(())
        }

        /// Sends buffer to address, as one datagram.
        pub fn send_to(
            &mut self,
            udp: Udp,
            buffer: Vec<u8>,
            address: SocketAddr,
            key: u64,
        ) -> Result<Op, (Udp, Vec<u8>)> {
            let Some(index) = self.free.pop() else {
                return Err((udp, buffer));
            };
            if let Some(slot) = self.slots.get_mut(index as usize) {
                let (bytes, length) = encode(&address);
                slot.address = bytes;
                slot.length = u32::try_from(length).unwrap_or(0);
            }
            Ok(self.start(index, key, Work::SendTo(udp, buffer), None))
        }

        /// Receives a datagram into the room buffer has beyond its length.
        pub fn receive_from(
            &mut self,
            udp: Udp,
            buffer: Vec<u8>,
            key: u64,
        ) -> Result<Op, (Udp, Vec<u8>)> {
            let Some(index) = self.free.pop() else {
                return Err((udp, buffer));
            };
            if buffer.len() == buffer.capacity() {
                let result = Err(Error::NoRoom);
                return Ok(self.finish(
                    index,
                    key,
                    Done::ReceivedFrom {
                        udp,
                        buffer,
                        result,
                    },
                ));
            }
            Ok(self.start(index, key, Work::ReceiveFrom(udp, buffer), None))
        }

        /// Runs work that blocks on thread's pool, as tokio's spawn_blocking
        /// does: its Event hands it back once it returned. cancel keeps it
        /// from starting while it waits in line, never once a thread took it.
        pub fn run(
            &mut self,
            work: Box<dyn Blocking + Send>,
            key: u64,
        ) -> Result<Op, Box<dyn Blocking + Send>> {
            let Some(index) = self.free.pop() else {
                return Err(work);
            };
            let generation = self
                .slots
                .get(index as usize)
                .map_or(0, |slot| slot.generation);
            // rr: escape(shared): the pool's thread tells the Io through it.
            let returned = Arc::new(Returned {
                // rr: escape(copy): the run's holder of the list.
                finished: Arc::clone(&self.finished),
                wake: self.backend.waker(),
                data: user_data(index, generation),
            });
            match thread::spawn(work, returned) {
                Ok(job) => {
                    if let Some(slot) = self.slots.get_mut(index as usize) {
                        slot.key = key;
                        slot.work = Work::Run(job);
                        slot.state = State::Running;
                    }
                    Ok(Op { index, generation })
                }
                Err(work) => {
                    // rr: escape(bound): the slot taken back, as it was.
                    self.free.push(index);
                    Err(work)
                }
            }
        }

        /// Done when so much time has passed, on the system's monotonic clock.
        pub fn timeout(&mut self, after: Duration, key: u64) -> Result<Op, Duration> {
            match self.free.pop() {
                Some(index) => Ok(self.start(index, key, Work::Timeout(after), None)),
                None => Err(after),
            }
        }

        /// Ends op early: true when it was running; false when it is done
        /// already (its Event waits, or was taken).
        #[must_use]
        pub fn cancel(&mut self, op: &Op) -> bool {
            let (index, generation) = (op.index, op.generation);
            let Some(slot) = self.slots.get_mut(index as usize) else {
                return false;
            };
            if slot.state != State::Running || slot.generation != generation || slot.canceled {
                return false;
            }
            if let Work::Run(_) = slot.work {
                return self.unrun(index);
            }
            slot.canceled = true;
            let data = user_data(index, generation);
            if self.backend.cancel(data, slot) {
                // rr: escape(bound): a slot is in ready once, and there are
                // as many as its capacity.
                self.ready.push_back(index);
            }
            true
        }

        /// What wakes this Io's wait from another thread.
        pub fn waker(&mut self) -> Waker {
            self.wakeable = true;
            Waker {
                wake: self.backend.waker(),
            }
        }

        /// Sends the system what was started and waits until something is
        /// done, a Waker wakes it or timeout passes (None: no limit; none
        /// when nothing runs and no Waker was made). How many Events wait
        /// for next.
        pub fn wait(&mut self, timeout: Option<Duration>) -> Result<usize, Error> {
            self.turn();
            let running = self.slots.len() - self.free.len() - self.ready.len();
            let timeout = if (running == 0 && !self.wakeable) || !self.ready.is_empty() {
                Some(Duration::ZERO)
            } else {
                timeout
            };
            self.backend
                .wait(&mut self.slots, &mut self.ready, timeout)?;
            self.returned();
            self.turned = backend::Backend::now();
            Ok(self.ready.len())
        }

        /// The turn that ends with this wait, kept when it is the slowest.
        fn turn(&mut self) {
            if self.turned == 0 {
                return;
            }
            let took = Duration::from_nanos(backend::Backend::now().saturating_sub(self.turned));
            if self
                .slowest
                .as_ref()
                .is_none_or(|slowest| took > slowest.took)
            {
                self.slowest = Some(Turn {
                    took,
                    key: self.last_key,
                });
            }
        }

        /// The slowest turn of the loop since this was last asked, which it
        /// forgets: a turn longer than the program allows (a few
        /// milliseconds) is work for run, as the other connections of the
        /// loop wait while it runs. A test asserts it; a server logs it.
        #[must_use]
        pub fn slowest_turn(&mut self) -> Option<Turn> {
            self.slowest.take()
        }

        /// The next operation done, which frees its slot.
        #[must_use]
        pub fn next(&mut self) -> Option<Event> {
            if let Some((key, id, length)) = self.backend.pool.filled.pop_front() {
                self.last_key = key;
                let chunk = Chunk {
                    io: self.id,
                    id,
                    length,
                };
                return Some(Event {
                    key,
                    done: Done::Chunk(chunk),
                });
            }
            let index = self.ready.pop_front()?;
            let slot = self.slots.get_mut(index as usize)?;
            let Work::Finished(done) = mem::replace(&mut slot.work, Work::Idle) else {
                return None;
            };
            let (given, owner) = (slot.chunk.take(), slot.owner.take());
            slot.state = State::Free;
            slot.generation = slot.generation.wrapping_add(1) & GENERATIONS;
            slot.canceled = false;
            slot.begun = false;
            slot.armed = None;
            slot.limit = None;
            slot.expired = false;
            slot.limited = false;
            slot.until = 0;
            slot.sends = 0;
            slot.ending = None;
            let key = slot.key;
            // rr: escape(bound): a slot is free or taken, and there are as
            // many as its capacity.
            self.free.push(index);
            if let (Some(id), Some(_)) = (given, owner) {
                self.backend.give_back(id);
            }
            if let Some((owner, generation)) = owner {
                self.sent_on(owner, generation);
            }
            self.last_key = key;
            Some(Event { key, done })
        }

        /// A send_chunk on owner's stream is done: the receive_many that
        /// ended while it ran ends now, with the last.
        fn sent_on(&mut self, owner: u32, generation: u32) {
            let Some(slot) = self.slots.get_mut(owner as usize) else {
                return;
            };
            if slot.generation != generation || slot.state != State::Running {
                return;
            }
            slot.sends = slot.sends.saturating_sub(1);
            if slot.sends > 0 {
                return;
            }
            let Some(result) = slot.ending.take() else {
                return;
            };
            if end_many(slot, result) {
                // rr: escape(bound): a slot is in ready once, and there are
                // as many as its capacity.
                self.ready.push_back(owner);
            }
        }

        fn start(&mut self, index: u32, key: u64, work: Work, limit: Option<Duration>) -> Op {
            let Some(slot) = self.slots.get_mut(index as usize) else {
                return Op {
                    index,
                    generation: 0,
                };
            };
            slot.key = key;
            slot.work = work;
            slot.state = State::Running;
            slot.limit = limit;
            if let Work::Accept(_) | Work::ReceiveFrom(..) = slot.work {
                slot.length = u32::try_from(ADDRESS_BYTES).unwrap_or(0);
            }
            let generation = slot.generation;
            self.backend.submit(user_data(index, generation), slot);
            Op { index, generation }
        }

        /// Takes a run's work out of the pool's line, never run: whether it
        /// was still there.
        #[must_use]
        fn unrun(&mut self, index: u32) -> bool {
            let Some(slot) = self.slots.get_mut(index as usize) else {
                return false;
            };
            let Work::Run(job) = mem::replace(&mut slot.work, Work::Idle) else {
                return false;
            };
            match job.cancel() {
                Ok(work) => {
                    let result = Err(Error::Canceled);
                    slot.work = Work::Finished(Done::Ran { work, result });
                    slot.state = State::Ready;
                    // rr: escape(bound): a slot is in ready once, and there
                    // are as many as its capacity.
                    self.ready.push_back(index);
                    true
                }
                Err(job) => {
                    slot.work = Work::Run(job);
                    false
                }
            }
        }

        /// The runs whose work returned, done.
        fn returned(&mut self) {
            self.finished.take(&mut self.taken);
            for data in self.taken.drain(..) {
                let Some((index, slot)) = running(&mut self.slots, data) else {
                    continue;
                };
                let Work::Run(job) = mem::replace(&mut slot.work, Work::Idle) else {
                    continue;
                };
                match job.take() {
                    Ok(work) => {
                        let result = Ok(());
                        slot.work = Work::Finished(Done::Ran { work, result });
                    }
                    Err(job) => {
                        slot.work = Work::Run(job);
                        continue;
                    }
                }
                slot.state = State::Ready;
                // rr: escape(bound): a slot is in ready once, and there are
                // as many as its capacity.
                self.ready.push_back(u32::try_from(index).unwrap_or(0));
            }
        }

        /// An operation done before it is started, as a receive into no
        /// room is.
        fn finish(&mut self, index: u32, key: u64, done: Done) -> Op {
            let generation = match self.slots.get_mut(index as usize) {
                Some(slot) => {
                    slot.key = key;
                    slot.work = Work::Finished(done);
                    slot.state = State::Ready;
                    slot.generation
                }
                None => 0,
            };
            // rr: escape(bound): a slot is in ready once, and there are as
            // many as its capacity.
            self.ready.push_back(index);
            Op { index, generation }
        }
    }

    impl Drop for Io {
        fn drop(&mut self) {
            self.backend.close(&mut self.slots);
        }
    }

    /// The families and the stream type as the system numbers them, for
    /// resolve.
    pub use os::{AF_INET, AF_INET6, SOCK_STREAM};

    // rr: section(os = linux macos)
    /// The calling thread's errno, EINTR and EINVAL, for resolve and trust.
    #[cfg(unix)]
    pub use os::c::errno;
    #[cfg(unix)]
    pub use os::{EINTR, EINVAL};
    // rr: end(os = linux macos)

    // rr: section(os = windows)
    #[cfg(windows)]
    pub use os::startup;
    // rr: end(os = windows)

    // rr: section(tests = yes)
    /// Now on the monotonic clock, in nanoseconds, for the tests.
    #[cfg(test)]
    pub fn now() -> u64 {
        backend::Backend::now()
    }
    // rr: end(tests = yes)

    /// The bytes of a sockaddr_in6, the larger of the two.
    const ADDRESS_BYTES: usize = 28;

    /// A sockaddr for address, and its length: the port and the flow label
    /// in the network's order, the scope in the host's, little on every
    /// target.
    fn encode(address: &SocketAddr) -> ([u8; ADDRESS_BYTES], usize) {
        let mut bytes = [0u8; ADDRESS_BYTES];
        let (family, length) = match address {
            SocketAddr::V4(_) => (os::AF_INET, 16),
            SocketAddr::V6(_) => (os::AF_INET6, ADDRESS_BYTES),
        };
        put(&mut bytes, 0, &os::family(family, length));
        put(&mut bytes, 2, &address.port().to_be_bytes());
        match address {
            SocketAddr::V4(v4) => put(&mut bytes, 4, &v4.ip().octets()),
            SocketAddr::V6(v6) => {
                put(&mut bytes, 4, &v6.flowinfo().to_be_bytes());
                put(&mut bytes, 8, &v6.ip().octets());
                put(&mut bytes, 24, &v6.scope_id().to_le_bytes());
            }
        }
        (bytes, length)
    }

    fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
        if let Some(place) = bytes.get_mut(at..at + value.len()) {
            place.copy_from_slice(value);
        }
    }

    /// The address in a sockaddr the system filled.
    fn decode(bytes: &[u8]) -> Option<SocketAddr> {
        let family = os::family_of(bytes)?;
        let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
        if family == os::AF_INET {
            let ip: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            return Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)));
        }
        if family != os::AF_INET6 {
            return None;
        }
        let flow = u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?);
        let ip: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
        let scope = u32::from_le_bytes(bytes.get(24..28)?.try_into().ok()?);
        Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(ip),
            port,
            flow,
            scope,
        )))
    }

    // rr: section(os = linux macos)
    /// Linux and macOS: the C library's sockets.
    #[cfg(unix)]
    mod os {
        use super::{Error, Kind};
        use alloc::vec::Vec;
        use core::ffi::c_int;
        use core::net::SocketAddr;

        pub type Raw = c_int;

        /// The system's calls.
        pub mod c {
            use core::ffi::{c_int, c_void};

            #[link(name = "c")]
            // rr: escape(unsafe): each signature is the C library's, from its
            // headers.
            unsafe extern "C" {
                #[must_use]
                pub fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
                #[must_use]
                pub fn bind(fd: c_int, address: *const u8, length: u32) -> c_int;
                #[must_use]
                pub fn listen(fd: c_int, backlog: c_int) -> c_int;
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn accept(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
                // rr: end(os = macos)
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn connect(fd: c_int, address: *const u8, length: u32) -> c_int;
                // rr: end(os = macos)
                #[must_use]
                pub fn getsockname(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
                #[must_use]
                pub fn getpeername(fd: c_int, address: *mut u8, length: *mut u32) -> c_int;
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn getsockopt(
                    fd: c_int,
                    level: c_int,
                    name: c_int,
                    value: *mut c_void,
                    length: *mut u32,
                ) -> c_int;
                // rr: end(os = macos)
                #[must_use]
                pub fn setsockopt(
                    fd: c_int,
                    level: c_int,
                    name: c_int,
                    value: *const c_void,
                    length: u32,
                ) -> c_int;
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn send(fd: c_int, buffer: *const c_void, length: usize, flags: c_int)
                -> isize;
                // rr: end(os = macos)
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
                // rr: end(os = macos)
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn sendto(
                    fd: c_int,
                    buffer: *const c_void,
                    length: usize,
                    flags: c_int,
                    address: *const u8,
                    address_length: u32,
                ) -> isize;
                // rr: end(os = macos)
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn recvfrom(
                    fd: c_int,
                    buffer: *mut c_void,
                    length: usize,
                    flags: c_int,
                    address: *mut u8,
                    address_length: *mut u32,
                ) -> isize;
                // rr: end(os = macos)
                #[must_use]
                pub fn shutdown(fd: c_int, how: c_int) -> c_int;
                #[must_use]
                pub fn close(fd: c_int) -> c_int;
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                pub fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
                // rr: end(os = macos)
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                #[must_use]
                fn __error() -> *mut c_int;
                // rr: end(os = macos)
                // rr: section(os = linux)
                #[cfg(target_os = "linux")]
                #[must_use]
                fn __errno_location() -> *mut c_int;
                // rr: end(os = linux)
            }

            /// The calling thread's errno.
            #[must_use]
            pub fn errno() -> c_int {
                // rr: section(os = macos)
                #[cfg(target_os = "macos")]
                // rr: escape(unsafe): the C library's thread-local errno.
                let place = unsafe { __error() };
                // rr: end(os = macos)
                // rr: section(os = linux)
                #[cfg(target_os = "linux")]
                // rr: escape(unsafe): the C library's thread-local errno.
                let place = unsafe { __errno_location() };
                // rr: end(os = linux)
                // rr: escape(unsafe): the C library returns a valid pointer.
                unsafe { *place }
            }
        }

        // sys/socket.h's, netinet/in.h's, netinet/tcp.h's and errno.h's:
        // Linux's from asm-generic, as x86_64 and aarch64 have them, macOS's
        // from its SDK.
        pub const AF_INET: u16 = 2;
        pub const SOCK_STREAM: c_int = 1;
        const SOCK_DGRAM: c_int = 2;
        const IPPROTO_TCP: c_int = 6;
        const IPPROTO_IPV6: c_int = 41;
        const TCP_NODELAY: c_int = 1;
        const SHUT_WR: c_int = 1;
        const EPIPE: c_int = 32;
        pub const EINTR: c_int = 4;
        pub const EINVAL: c_int = 22;
        // rr: section(os = linux)
        #[cfg(target_os = "linux")]
        pub use numbers::*;
        // rr: end(os = linux)
        // rr: section(os = linux)
        #[cfg(target_os = "linux")]
        mod numbers {
            use core::ffi::c_int;
            pub const AF_INET6: u16 = 10;
            pub const SOL_SOCKET: c_int = 1;
            pub const SO_REUSEADDR: c_int = 2;
            pub const SO_REUSEPORT: c_int = 15;
            pub const IPV6_V6ONLY: c_int = 26;
            pub const SOCK_NONBLOCK: c_int = 0x800;
            pub const SOCK_CLOEXEC: c_int = 0x8_0000;
            pub const MSG_NOSIGNAL: u32 = 0x4000;
            pub const EPERM: c_int = 1;
            pub const EAGAIN: c_int = 11;
            pub const EBUSY: c_int = 16;
            pub const ENOSYS: c_int = 38;
            pub const ETIME: c_int = 62;
            pub const ETIMEDOUT: c_int = 110;
            pub const ECANCELED: c_int = 125;
            /// What a canceled operation answers, and what one that ran out
            /// of time is told.
            pub const CANCELED: c_int = ECANCELED;
            pub const TIMED_OUT: c_int = ETIMEDOUT;
            pub const ECONNREFUSED: c_int = 111;
            pub const ECONNRESET: c_int = 104;
            pub const ECONNABORTED: c_int = 103;
            pub const EHOSTUNREACH: c_int = 113;
            pub const ENETUNREACH: c_int = 101;
            pub const EADDRINUSE: c_int = 98;
            pub const ENETDOWN: c_int = 100;
            pub const ENETRESET: c_int = 102;
            pub const EPROTO: c_int = 71;
            pub const ENOPROTOOPT: c_int = 92;
            pub const EHOSTDOWN: c_int = 112;
            pub const ENONET: c_int = 64;
            pub const EOPNOTSUPP: c_int = 95;
        }
        // rr: end(os = linux)
        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        pub use numbers::*;
        // rr: end(os = macos)
        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        mod numbers {
            use core::ffi::c_int;
            pub const AF_INET6: u16 = 30;
            pub const SOL_SOCKET: c_int = 0xffff;
            pub const SO_ERROR: c_int = 0x1007;
            pub const SO_REUSEADDR: c_int = 0x4;
            pub const SO_NOSIGPIPE: c_int = 0x1022;
            pub const IPV6_V6ONLY: c_int = 27;
            pub const F_GETFL: c_int = 3;
            pub const F_SETFL: c_int = 4;
            pub const F_SETFD: c_int = 2;
            pub const FD_CLOEXEC: c_int = 1;
            pub const O_NONBLOCK: c_int = 0x4;
            pub const EAGAIN: c_int = 35;
            pub const EINPROGRESS: c_int = 36;
            pub const ETIMEDOUT: c_int = 60;
            pub const ECANCELED: c_int = 89;
            pub const CANCELED: c_int = ECANCELED;
            pub const TIMED_OUT: c_int = ETIMEDOUT;
            pub const ECONNREFUSED: c_int = 61;
            pub const ECONNRESET: c_int = 54;
            pub const ECONNABORTED: c_int = 53;
            pub const EHOSTUNREACH: c_int = 65;
            pub const ENETUNREACH: c_int = 51;
            pub const EADDRINUSE: c_int = 48;
            pub const ENETDOWN: c_int = 50;
            pub const ENETRESET: c_int = 52;
            pub const EHOSTDOWN: c_int = 64;
        }
        // rr: end(os = macos)

        pub fn error(code: c_int) -> Error {
            match code {
                ECONNREFUSED => Error::Refused,
                ECONNRESET | EPIPE | ECONNABORTED | ENETRESET => Error::Reset,
                ETIMEDOUT => Error::TimedOut,
                EHOSTUNREACH | ENETUNREACH | EHOSTDOWN | ENETDOWN => Error::Unreachable,
                EADDRINUSE => Error::InUse,
                ECANCELED => Error::Canceled,
                other => Error::Other(other),
            }
        }

        /// What a receive or a send answers that is to be tried again.
        pub fn again(code: c_int) -> bool {
            matches!(code, EAGAIN | EINTR)
        }

        // rr: section(os = linux)
        /// What a failed accept says of the connection it took, not of the
        /// listener: none waits, or the one that did is gone. Linux passes
        /// on the new connection's network errors too, which accept(2) says
        /// to take as EAGAIN.
        #[cfg(target_os = "linux")]
        pub fn passing(code: c_int) -> bool {
            matches!(
                code,
                EAGAIN
                    | EINTR
                    | ECONNABORTED
                    | ENETDOWN
                    | EPROTO
                    | ENOPROTOOPT
                    | EHOSTDOWN
                    | ENONET
                    | EHOSTUNREACH
                    | EOPNOTSUPP
                    | ENETUNREACH
            )
        }
        // rr: end(os = linux)

        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        pub fn passing(code: c_int) -> bool {
            matches!(code, EAGAIN | EINTR | ECONNABORTED)
        }
        // rr: end(os = macos)

        /// The call's error, when it returned -1.
        pub fn check(done: c_int) -> Result<(), Error> {
            if done < 0 {
                Err(error(c::errno()))
            } else {
                Ok(())
            }
        }

        /// A descriptor the system answered with, as a count.
        pub fn raw(fd: usize) -> c_int {
            c_int::try_from(fd).unwrap_or(-1)
        }

        // rr: section(os = macos)
        /// The family's bytes at the start of a sockaddr of length bytes.
        #[cfg(target_os = "macos")]
        pub fn family(family: u16, length: usize) -> [u8; 2] {
            [
                u8::try_from(length).unwrap_or(0),
                u8::try_from(family).unwrap_or(0),
            ]
        }
        // rr: end(os = macos)

        // rr: section(os = linux)
        #[cfg(target_os = "linux")]
        pub fn family(family: u16, _length: usize) -> [u8; 2] {
            family.to_le_bytes()
        }
        // rr: end(os = linux)

        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        pub fn family_of(bytes: &[u8]) -> Option<u16> {
            bytes.get(1).copied().map(u16::from)
        }
        // rr: end(os = macos)

        // rr: section(os = linux)
        #[cfg(target_os = "linux")]
        pub fn family_of(bytes: &[u8]) -> Option<u16> {
            Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
        }
        // rr: end(os = linux)

        fn socket_kind(kind: Kind) -> c_int {
            match kind {
                Kind::Stream => SOCK_STREAM,
                Kind::Datagram => SOCK_DGRAM,
            }
        }

        fn domain(address: &SocketAddr) -> c_int {
            c_int::from(if address.is_ipv4() { AF_INET } else { AF_INET6 })
        }

        pub fn length(bytes: &[u8]) -> u32 {
            u32::try_from(bytes.len()).unwrap_or(0)
        }

        // rr: section(os = linux)
        /// A new socket for address's family: non-blocking, closed on exec,
        /// in one call.
        #[cfg(target_os = "linux")]
        pub fn open(address: &SocketAddr, kind: Kind) -> Result<c_int, Error> {
            let kind = socket_kind(kind) | SOCK_NONBLOCK | SOCK_CLOEXEC;
            // rr: escape(unsafe): socket takes plain numbers.
            let fd = unsafe { c::socket(domain(address), kind, 0) };
            check(fd)?;
            Ok(fd)
        }
        // rr: end(os = linux)

        // rr: section(os = macos)
        /// A new socket for address's family, made non-blocking, closed on
        /// exec and without SIGPIPE, as macOS has no flags for it at once.
        #[cfg(target_os = "macos")]
        pub fn open(address: &SocketAddr, kind: Kind) -> Result<c_int, Error> {
            // rr: escape(unsafe): socket takes plain numbers.
            let fd = unsafe { c::socket(domain(address), socket_kind(kind), 0) };
            check(fd)?;
            prepare_new(fd).inspect_err(|_| close(fd))?;
            Ok(fd)
        }
        // rr: end(os = macos)

        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        fn prepare_new(fd: c_int) -> Result<(), Error> {
            // rr: escape(unsafe): fd is open.
            let flags = unsafe { c::fcntl(fd, F_GETFL) };
            check(flags)?;
            // rr: escape(unsafe): fd is open.
            check(unsafe { c::fcntl(fd, F_SETFL, flags | O_NONBLOCK) })?;
            // rr: escape(unsafe): fd is open.
            check(unsafe { c::fcntl(fd, F_SETFD, FD_CLOEXEC) })?;
            option(fd, SOL_SOCKET, SO_NOSIGPIPE, 1)
        }
        // rr: end(os = macos)

        // rr: section(os = macos)
        /// A connection accept took, made as every stream here is.
        #[cfg(target_os = "macos")]
        pub fn adopt(fd: c_int) -> Result<(), Error> {
            prepare_new(fd)?;
            no_delay(fd)
        }
        // rr: end(os = macos)

        // rr: section(os = linux)
        /// A connection io_uring accepted, non-blocking and closed on exec.
        #[cfg(target_os = "linux")]
        pub fn adopt(fd: c_int) -> Result<(), Error> {
            no_delay(fd)
        }
        // rr: end(os = linux)

        fn option(fd: c_int, level: c_int, name: c_int, value: c_int) -> Result<(), Error> {
            // An int in the host's order, little on every target.
            let bytes = value.to_le_bytes();
            // rr: escape(unsafe): bytes holds an int, as each option here
            // takes.
            let done =
                unsafe { c::setsockopt(fd, level, name, bytes.as_ptr().cast(), length(&bytes)) };
            check(done)
        }

        /// A listener's options: its address taken again while connections
        /// to it linger in TIME_WAIT; IPv6 alone on an IPv6 socket.
        pub fn prepare(fd: c_int, v6: bool) -> Result<(), Error> {
            option(fd, SOL_SOCKET, SO_REUSEADDR, 1)?;
            datagram(fd, v6)
        }

        /// A datagram socket's options: IPv6 alone on an IPv6 socket.
        pub fn datagram(fd: c_int, v6: bool) -> Result<(), Error> {
            if v6 {
                option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1)?;
            }
            Ok(())
        }

        pub fn no_delay(fd: c_int) -> Result<(), Error> {
            option(fd, IPPROTO_TCP, TCP_NODELAY, 1)
        }

        // rr: section(os = linux)
        /// Whether the kernel spreads connections among listeners that share
        /// an address: Linux's SO_REUSEPORT does; macOS's gives them to the
        /// one bound last.
        #[cfg(target_os = "linux")]
        pub const BALANCED: bool = true;
        // rr: end(os = linux)
        // rr: section(os = macos)
        #[cfg(target_os = "macos")]
        pub const BALANCED: bool = false;
        // rr: end(os = macos)

        // rr: section(os = linux)
        /// Lets other listeners of this user bind the address beside it.
        #[cfg(target_os = "linux")]
        pub fn share(fd: c_int) -> Result<(), Error> {
            option(fd, SOL_SOCKET, SO_REUSEPORT, 1)
        }
        // rr: end(os = linux)

        // rr: section(os = macos)
        /// Never reached: BALANCED refuses first.
        #[cfg(target_os = "macos")]
        pub fn share(_fd: c_int) -> Result<(), Error> {
            Err(Error::Unbalanced)
        }
        // rr: end(os = macos)

        pub fn bind(fd: c_int, address: &[u8]) -> Result<(), Error> {
            // rr: escape(unsafe): address is a sockaddr of its length.
            check(unsafe { c::bind(fd, address.as_ptr(), length(address)) })
        }

        pub fn listen(fd: c_int, backlog: u32) -> Result<(), Error> {
            let backlog = c_int::try_from(backlog).unwrap_or(c_int::MAX);
            // rr: escape(unsafe): fd is bound.
            check(unsafe { c::listen(fd, backlog) })
        }

        pub fn finish(fd: c_int) -> Result<(), Error> {
            // rr: escape(unsafe): shutdown takes plain numbers.
            check(unsafe { c::shutdown(fd, SHUT_WR) })
        }

        #[must_use]
        pub fn local(fd: c_int) -> Option<SocketAddr> {
            let mut address = [0u8; super::ADDRESS_BYTES];
            let mut size = length(&address);
            // rr: escape(unsafe): address holds size bytes.
            let done = unsafe { c::getsockname(fd, address.as_mut_ptr(), &raw mut size) };
            (done == 0).then_some(())?;
            super::decode(address.get(..usize::try_from(size).ok()?)?)
        }

        #[must_use]
        pub fn peer(fd: c_int) -> Option<SocketAddr> {
            let mut address = [0u8; super::ADDRESS_BYTES];
            let mut size = length(&address);
            // rr: escape(unsafe): address holds size bytes.
            let done = unsafe { c::getpeername(fd, address.as_mut_ptr(), &raw mut size) };
            (done == 0).then_some(())?;
            super::decode(address.get(..usize::try_from(size).ok()?)?)
        }

        /// The length of buffer after so many bytes the system wrote into
        /// its room.
        pub fn filled(buffer: &mut Vec<u8>, count: usize) {
            let length = buffer.len().saturating_add(count).min(buffer.capacity());
            // rr: escape(unsafe): the system wrote count bytes after the
            // length, within the capacity it was given.
            unsafe { buffer.set_len(length) }
        }

        pub fn close(fd: c_int) {
            // rr: escape(unsafe): fd is its owner's, closed once, by its drop.
            unsafe {
                // rr: escape(discard): close releases the descriptor whatever
                // it
                // answers; no one is left to tell.
                let _: c_int = c::close(fd);
            }
        }
    }
    // rr: end(os = linux macos)

    // rr: section(os = windows)
    /// Windows: Winsock.
    #[cfg(windows)]
    mod os {
        use super::{Error, Kind};
        use alloc::vec::Vec;
        use core::net::SocketAddr;
        use core::ptr::null;
        use core::sync::atomic::{AtomicBool, Ordering};

        pub type Raw = usize;

        /// The system's calls.
        pub mod c {
            use core::ffi::c_void;

            /// struct WSABUF.
            #[repr(C)]
            pub struct WsaBuf {
                pub len: u32,
                pub buf: *mut u8,
            }

            #[link(name = "ws2_32", kind = "raw-dylib")]
            // rr: escape(unsafe): each signature is ws2_32's, from its
            // documentation.
            unsafe extern "system" {
                #[must_use]
                pub fn WSAStartup(version: u16, data: *mut u8) -> i32;
                #[must_use]
                pub fn WSASocketW(
                    family: i32,
                    kind: i32,
                    protocol: i32,
                    info: *const c_void,
                    group: u32,
                    flags: u32,
                ) -> usize;
                #[must_use]
                pub fn bind(socket: usize, address: *const u8, length: i32) -> i32;
                #[must_use]
                pub fn listen(socket: usize, backlog: i32) -> i32;
                #[must_use]
                pub fn getsockname(socket: usize, address: *mut u8, length: *mut i32) -> i32;
                #[must_use]
                pub fn getpeername(socket: usize, address: *mut u8, length: *mut i32) -> i32;
                #[must_use]
                pub fn setsockopt(
                    socket: usize,
                    level: i32,
                    name: i32,
                    value: *const u8,
                    length: i32,
                ) -> i32;
                #[must_use]
                pub fn shutdown(socket: usize, how: i32) -> i32;
                #[must_use]
                pub fn closesocket(socket: usize) -> i32;
                #[must_use]
                pub fn WSAGetLastError() -> i32;
                #[must_use]
                pub fn WSAIoctl(
                    socket: usize,
                    code: u32,
                    input: *const c_void,
                    input_length: u32,
                    output: *mut c_void,
                    output_length: u32,
                    returned: *mut u32,
                    overlapped: *mut c_void,
                    routine: *const c_void,
                ) -> i32;
                #[must_use]
                pub fn WSARecv(
                    socket: usize,
                    buffers: *const WsaBuf,
                    count: u32,
                    received: *mut u32,
                    flags: *mut u32,
                    overlapped: *mut c_void,
                    routine: *const c_void,
                ) -> i32;
                #[must_use]
                pub fn WSASend(
                    socket: usize,
                    buffers: *const WsaBuf,
                    count: u32,
                    sent: *mut u32,
                    flags: u32,
                    overlapped: *mut c_void,
                    routine: *const c_void,
                ) -> i32;
                #[must_use]
                pub fn WSARecvFrom(
                    socket: usize,
                    buffers: *const WsaBuf,
                    count: u32,
                    received: *mut u32,
                    flags: *mut u32,
                    from: *mut u8,
                    from_length: *mut i32,
                    overlapped: *mut c_void,
                    routine: *const c_void,
                ) -> i32;
                #[must_use]
                pub fn WSASendTo(
                    socket: usize,
                    buffers: *const WsaBuf,
                    count: u32,
                    sent: *mut u32,
                    flags: u32,
                    to: *const u8,
                    to_length: i32,
                    overlapped: *mut c_void,
                    routine: *const c_void,
                ) -> i32;
                #[must_use]
                pub fn WSAGetOverlappedResult(
                    socket: usize,
                    overlapped: *mut c_void,
                    transferred: *mut u32,
                    wait: i32,
                    flags: *mut u32,
                ) -> i32;
            }
        }

        // ws2def.h's, ws2ipdef.h's, winsock2.h's, winerror.h's and their
        // WSAE* codes.
        pub const AF_INET: u16 = 2;
        pub const AF_INET6: u16 = 23;
        pub const SOCK_STREAM: i32 = 1;
        const SOCK_DGRAM: i32 = 2;
        const IPPROTO_TCP: i32 = 6;
        const IPPROTO_UDP: i32 = 17;
        /// mstcpip.h: _WSAIOW(IOC_VENDOR, 12).
        const SIO_UDP_CONNRESET: u32 = 0x9800_000C;
        const IPPROTO_IPV6: i32 = 41;
        const IPV6_V6ONLY: i32 = 27;
        const TCP_NODELAY: i32 = 1;
        const SD_SEND: i32 = 1;
        pub const SOL_SOCKET: i32 = 0xffff;
        const WSA_FLAG_OVERLAPPED: u32 = 0x01;
        const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
        const INVALID_SOCKET: usize = !0;
        pub const WSA_IO_PENDING: i32 = 997;
        /// ERROR_OPERATION_ABORTED, which WSA_OPERATION_ABORTED is too.
        pub const ABORTED: i32 = 995;
        pub const CANCELED: i32 = ABORTED;
        pub const TIMED_OUT: i32 = WSAETIMEDOUT;
        /// No system's code: a socket in another Io's completion port.
        pub const FOREIGN: i32 = -1;

        const WSAEINTR: i32 = 10004;
        const WSAEACCES: i32 = 10013;
        const WSAEWOULDBLOCK: i32 = 10035;
        const WSAEADDRINUSE: i32 = 10048;
        const WSAENETDOWN: i32 = 10050;
        const WSAENETUNREACH: i32 = 10051;
        const WSAENETRESET: i32 = 10052;
        const WSAECONNABORTED: i32 = 10053;
        const WSAECONNRESET: i32 = 10054;
        const WSAESHUTDOWN: i32 = 10058;
        const WSAETIMEDOUT: i32 = 10060;
        const WSAECONNREFUSED: i32 = 10061;
        const WSAEHOSTDOWN: i32 = 10064;
        const WSAEHOSTUNREACH: i32 = 10065;

        #[must_use]
        pub fn last() -> i32 {
            // rr: escape(unsafe): the thread's last Winsock error.
            unsafe { c::WSAGetLastError() }
        }

        pub fn error(code: i32) -> Error {
            match code {
                WSAECONNREFUSED => Error::Refused,
                WSAECONNRESET | WSAECONNABORTED | WSAESHUTDOWN | WSAENETRESET => Error::Reset,
                WSAETIMEDOUT => Error::TimedOut,
                WSAEHOSTUNREACH | WSAENETUNREACH | WSAEHOSTDOWN | WSAENETDOWN => Error::Unreachable,
                WSAEADDRINUSE => Error::InUse,
                ABORTED => Error::Canceled,
                FOREIGN => Error::Foreign,
                other => Error::Other(other),
            }
        }

        pub fn again(code: i32) -> bool {
            matches!(code, WSAEWOULDBLOCK | WSAEINTR)
        }

        /// What a failed accept says of the connection it took: one reset
        /// before it was taken.
        pub fn passing(code: i32) -> bool {
            matches!(code, WSAEWOULDBLOCK | WSAEINTR | WSAECONNRESET)
        }

        fn check(done: i32) -> Result<(), Error> {
            if done == 0 {
                Ok(())
            } else {
                Err(error(last()))
            }
        }

        pub fn raw(socket: usize) -> usize {
            socket
        }

        /// The family, two bytes in the host's order, little on Windows.
        pub fn family(family: u16, _length: usize) -> [u8; 2] {
            family.to_le_bytes()
        }

        pub fn family_of(bytes: &[u8]) -> Option<u16> {
            Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
        }

        pub fn length(bytes: &[u8]) -> i32 {
            i32::try_from(bytes.len()).unwrap_or(0)
        }

        // rr: escape(shared): Winsock is started once for the process; a
        // race only starts it twice, which it counts.
        static STARTED: AtomicBool = AtomicBool::new(false);

        pub fn startup() {
            if STARTED.load(Ordering::Acquire) {
                return;
            }
            let mut data = [0u8; 512];
            // rr: escape(unsafe): WSADATA is 408 bytes at most; data holds 512.
            if unsafe { c::WSAStartup(0x0202, data.as_mut_ptr()) } == 0 {
                STARTED.store(true, Ordering::Release);
            }
        }

        /// A new socket of family for overlapped I/O, which no child
        /// process inherits; Err the system's code.
        pub fn socket(family: u16, kind: Kind) -> Result<usize, i32> {
            startup();
            let flags = WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT;
            let (kind, protocol) = match kind {
                Kind::Stream => (SOCK_STREAM, IPPROTO_TCP),
                Kind::Datagram => (SOCK_DGRAM, IPPROTO_UDP),
            };
            // rr: escape(unsafe): WSASocketW takes plain numbers.
            let socket =
                unsafe { c::WSASocketW(i32::from(family), kind, protocol, null(), 0, flags) };
            if socket == INVALID_SOCKET {
                return Err(last());
            }
            Ok(socket)
        }

        pub fn open(address: &SocketAddr, kind: Kind) -> Result<usize, Error> {
            socket(if address.is_ipv4() { AF_INET } else { AF_INET6 }, kind).map_err(error)
        }

        pub fn option(socket: usize, level: i32, name: i32, value: &[u8]) -> Result<(), Error> {
            // rr: escape(unsafe): value holds what the option takes.
            check(unsafe { c::setsockopt(socket, level, name, value.as_ptr(), length(value)) })
        }

        /// A listener's options: IPv6 alone on an IPv6 socket, and nothing
        /// for its address, as in Go, libuv and Rust's std: Windows takes
        /// an address again while connections to it linger without
        /// SO_REUSEADDR, which would let another take it while it listens.
        pub fn prepare(socket: usize, v6: bool) -> Result<(), Error> {
            if v6 {
                option(socket, IPPROTO_IPV6, IPV6_V6ONLY, &1i32.to_le_bytes())?;
            }
            Ok(())
        }

        /// A datagram socket's options: IPv6 alone on an IPv6 socket, and
        /// no WSAECONNRESET on a receive for an ICMP refusal of what it
        /// sent before, as Go and libuv turn it off.
        pub fn datagram(socket: usize, v6: bool) -> Result<(), Error> {
            prepare(socket, v6)?;
            let off = 0u32.to_le_bytes();
            let mut returned = 0u32;
            // rr: escape(unsafe): off is the BOOL the control takes.
            let done = unsafe {
                c::WSAIoctl(
                    socket,
                    SIO_UDP_CONNRESET,
                    off.as_ptr().cast(),
                    4,
                    core::ptr::null_mut(),
                    0,
                    &raw mut returned,
                    core::ptr::null_mut(),
                    null(),
                )
            };
            check(done)
        }

        /// Windows has no option that spreads connections among listeners
        /// of one address.
        pub const BALANCED: bool = false;

        /// Never reached: BALANCED refuses first.
        pub fn share(_socket: usize) -> Result<(), Error> {
            Err(Error::Unbalanced)
        }

        pub fn no_delay(socket: usize) -> Result<(), Error> {
            option(socket, IPPROTO_TCP, TCP_NODELAY, &1i32.to_le_bytes())
        }

        pub fn adopt(socket: usize) -> Result<(), Error> {
            no_delay(socket)
        }

        /// Binds; an address another user's socket holds, or one the system
        /// keeps for itself, is refused as access denied, which is the
        /// address in use.
        pub fn bind(socket: usize, address: &[u8]) -> Result<(), Error> {
            bind_code(socket, address).map_err(|code| match code {
                WSAEACCES => Error::InUse,
                code => error(code),
            })
        }

        /// Binds; Err the system's code.
        pub fn bind_code(socket: usize, address: &[u8]) -> Result<(), i32> {
            // rr: escape(unsafe): address is a sockaddr of its length.
            if unsafe { c::bind(socket, address.as_ptr(), length(address)) } == 0 {
                Ok(())
            } else {
                Err(last())
            }
        }

        pub fn listen(socket: usize, backlog: u32) -> Result<(), Error> {
            let backlog = i32::try_from(backlog).unwrap_or(i32::MAX);
            // rr: escape(unsafe): the socket is bound.
            check(unsafe { c::listen(socket, backlog) })
        }

        pub fn finish(socket: usize) -> Result<(), Error> {
            // rr: escape(unsafe): shutdown takes plain numbers.
            check(unsafe { c::shutdown(socket, SD_SEND) })
        }

        #[must_use]
        pub fn local(socket: usize) -> Option<SocketAddr> {
            let mut address = [0u8; super::ADDRESS_BYTES];
            let mut size = length(&address);
            // rr: escape(unsafe): address holds size bytes.
            let done = unsafe { c::getsockname(socket, address.as_mut_ptr(), &raw mut size) };
            (done == 0).then_some(())?;
            super::decode(address.get(..usize::try_from(size).ok()?)?)
        }

        #[must_use]
        pub fn peer(socket: usize) -> Option<SocketAddr> {
            let mut address = [0u8; super::ADDRESS_BYTES];
            let mut size = length(&address);
            // rr: escape(unsafe): address holds size bytes.
            let done = unsafe { c::getpeername(socket, address.as_mut_ptr(), &raw mut size) };
            (done == 0).then_some(())?;
            super::decode(address.get(..usize::try_from(size).ok()?)?)
        }

        /// The length of buffer after so many bytes the system wrote into
        /// its room.
        pub fn filled(buffer: &mut Vec<u8>, count: usize) {
            let length = buffer.len().saturating_add(count).min(buffer.capacity());
            // rr: escape(unsafe): the system wrote count bytes after the
            // length, within the capacity it was given.
            unsafe { buffer.set_len(length) }
        }

        pub fn close(socket: usize) {
            // rr: escape(unsafe): the socket is its owner's, closed once, by
            // its drop.
            unsafe {
                // rr: escape(discard): closesocket releases the socket
                // whatever it answers; no one is left to tell.
                let _: i32 = c::closesocket(socket);
            }
        }
    }
    // rr: end(os = windows)

    // rr: section(os = linux)
    /// Linux: an io_uring.
    #[cfg(target_os = "linux")]
    mod backend {
        use super::os::c::errno;
        use super::os::{
            EAGAIN, EBUSY, EINVAL, ENOSYS, EPERM, ETIME, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_NONBLOCK,
            error,
        };
        use super::{
            CANCEL, Error, LIMIT, Pool, Slot, State, Unavailable, WAKE, Work, end_many, running,
            settle,
        };
        use alloc::boxed::Box;
        use alloc::collections::VecDeque;
        use alloc::sync::Arc;
        use core::ffi::{c_char, c_int, c_long, c_void};
        use core::ptr::null_mut;
        use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};
        use core::time::Duration;

        #[link(name = "c")]
        // rr: escape(unsafe): each signature is the C library's, from its
        // headers.
        unsafe extern "C" {
            #[must_use]
            fn syscall(number: c_long, ...) -> c_long;
            #[must_use]
            fn mmap(
                address: *mut c_void,
                length: usize,
                protection: c_int,
                flags: c_int,
                fd: c_int,
                offset: i64,
            ) -> *mut c_void;
            #[must_use]
            fn munmap(address: *mut c_void, length: usize) -> c_int;
            #[must_use]
            fn open(path: *const c_char, flags: c_int, ...) -> c_int;
            #[must_use]
            fn read(fd: c_int, buffer: *mut c_void, length: usize) -> isize;
            #[must_use]
            fn write(fd: c_int, buffer: *const c_void, length: usize) -> isize;
            #[must_use]
            fn eventfd(initial: u32, flags: c_int) -> c_int;
            #[must_use]
            fn clock_gettime(clock: c_int, time: *mut [i64; 2]) -> c_int;
            #[must_use]
            fn close(fd: c_int) -> c_int;
        }

        // The system calls, the same on x86_64 and aarch64 (asm-generic's
        // numbers since 5.1), and liburing's io_uring.h.
        const SYS_SETUP: c_long = 425;
        const SYS_ENTER: c_long = 426;
        const SYS_REGISTER: c_long = 427;
        const REGISTER_ENABLE_RINGS: c_long = 12;
        const SETUP_R_DISABLED: u32 = 1 << 6;
        const SETUP_CQSIZE: u32 = 1 << 3;
        const SETUP_CLAMP: u32 = 1 << 4;
        const SETUP_SUBMIT_ALL: u32 = 1 << 7;
        const SETUP_SINGLE_ISSUER: u32 = 1 << 12;
        const SETUP_DEFER_TASKRUN: u32 = 1 << 13;
        const FEAT_SINGLE_MMAP: u32 = 1 << 0;
        const FEAT_NODROP: u32 = 1 << 1;
        const FEAT_EXT_ARG: u32 = 1 << 8;
        const ENTER_GETEVENTS: u32 = 1 << 0;
        const ENTER_EXT_ARG: u32 = 1 << 3;
        const OFF_SQ_RING: i64 = 0;
        const OFF_SQES: i64 = 0x1000_0000;
        const OP_TIMEOUT: u8 = 11;
        const OP_ACCEPT: u8 = 13;
        const OP_ASYNC_CANCEL: u8 = 14;
        const OP_CONNECT: u8 = 16;
        const OP_READ: u8 = 22;
        const OP_SENDMSG: u8 = 9;
        const OP_RECVMSG: u8 = 10;
        const OP_LINK_TIMEOUT: u8 = 15;
        const OP_SEND: u8 = 26;
        const IOSQE_IO_LINK: u8 = 1 << 2;
        const IOSQE_BUFFER_SELECT: u8 = 1 << 5;
        /// IORING_RECV_MULTISHOT, in ioprio.
        const RECV_MULTISHOT: u16 = 1 << 1;
        const CQE_F_BUFFER: u32 = 1 << 0;
        const CQE_F_MORE: u32 = 1 << 1;
        const CQE_BUFFER_SHIFT: u32 = 16;
        const REGISTER_PBUF_RING: c_long = 22;
        /// errno.h's: the ring of chunks was empty.
        const ENOBUFS: c_int = 105;
        /// sys/mman.h's, for the ring of chunks.
        const MAP_PRIVATE_ANONYMOUS: c_int = 0x02 | 0x20;
        /// time.h's.
        const CLOCK_MONOTONIC: c_int = 1;
        const OP_RECV: u8 = 27;
        // sys/mman.h's and fcntl.h's.
        const PROT_READ_WRITE: c_int = 0x3;
        const MAP_SHARED_POPULATE: c_int = 0x01 | 0x8000;
        const O_RDONLY_CLOEXEC: c_int = 0x8_0000;
        const EFD_CLOEXEC: c_int = 0x8_0000;
        /// The most one receive or send asks of the system at once: len is
        /// a __u32.
        const CHUNK: usize = 1 << 30;

        /// struct io_uring_sqe: 64 bytes, the unions as the fields used.
        #[repr(C)]
        struct Sqe {
            opcode: u8,
            flags: u8,
            ioprio: u16,
            fd: i32,
            off: u64,
            addr: u64,
            len: u32,
            op_flags: u32,
            user_data: u64,
            buf_index: u16,
            personality: u16,
            file_index: u32,
            addr3: u64,
            pad: u64,
        }

        /// struct io_uring_cqe without the 32-byte form.
        #[repr(C)]
        struct Cqe {
            user_data: u64,
            res: i32,
            flags: u32,
        }

        /// struct io_uring_params: 40 bytes, then the offsets of the two
        /// rings, 40 bytes each.
        #[repr(C)]
        struct Params {
            sq_entries: u32,
            cq_entries: u32,
            flags: u32,
            sq_thread_cpu: u32,
            sq_thread_idle: u32,
            features: u32,
            wq_fd: u32,
            resv: [u32; 3],
            /// head, tail, ring_mask, ring_entries, flags, dropped, array,
            /// resv1, then user_addr as two words.
            sq_off: [u32; 10],
            /// head, tail, ring_mask, ring_entries, overflow, cqes, flags,
            /// resv1, then user_addr as two words.
            cq_off: [u32; 10],
        }

        /// struct io_uring_getevents_arg.
        #[repr(C)]
        struct Getevents {
            sigmask: u64,
            sigmask_sz: u32,
            min_wait_usec: u32,
            ts: u64,
        }

        const _: () = assert!(size_of::<Sqe>() == 64);
        const _: () = assert!(size_of::<Cqe>() == 16);
        const _: () = assert!(size_of::<Params>() == 120);
        const _: () = assert!(size_of::<Getevents>() == 24);

        pub struct Backend {
            fd: c_int,
            /// The rings' memory, mapped once (IORING_FEAT_SINGLE_MMAP), and
            /// the entries'.
            ring: *mut c_void,
            ring_size: usize,
            sqes: *mut Sqe,
            sqes_size: usize,
            sq_head: *const AtomicU32,
            sq_tail: *const AtomicU32,
            sq_mask: u32,
            sq_entries: u32,
            cq_head: *const AtomicU32,
            cq_tail: *const AtomicU32,
            cq_mask: u32,
            cqes: *const Cqe,
            /// The submission tail not yet given to the kernel.
            tail: u32,
            /// Whether the ring was enabled, by its first enter, for the
            /// thread that made that.
            enabled: bool,
            /// What Wakers set, which the ring reads while the Io lives, into
            /// count; whether that read is with the kernel, and whether the
            /// Io is closing, when it is not read again.
            wake: Arc<Wake>,
            count: Box<[u8; 8]>,
            listening: bool,
            closing: bool,
            /// The chunks, and the ring of them the kernel picks from when a
            /// multishot receive takes one: struct io_uring_buf entries of 16
            /// bytes, its tail in the first one's last two, and how many it
            /// was given.
            pub pool: Pool,
            chunk_ring: *mut c_void,
            chunk_tail: u16,
        }

        /// struct io_uring_buf_reg.
        #[repr(C)]
        struct BufReg {
            ring_addr: u64,
            ring_entries: u32,
            bgid: u16,
            flags: u16,
            min_left: u32,
            resv: [u32; 5],
        }

        const _: () = assert!(size_of::<BufReg>() == 40);

        // rr: escape(unsafe): the ring is the process's memory, which no
        // thread owns; an Io is moved whole, never shared, and the kernel
        // refuses (EEXIST) one moved after its first wait to another thread.
        unsafe impl Send for Backend {}

        /// An eventfd, blocking, so that the ring's read of it waits for a
        /// write (a read of a non-blocking one is EAGAIN at once).
        pub struct Wake {
            fd: c_int,
        }

        impl Wake {
            pub fn wake(&self) {
                // A u64 in the host's order, little on x86_64 and aarch64.
                let one = 1u64.to_le_bytes();
                // rr: escape(unsafe): one is 8 bytes; a counter at its most is
                // set already.
                unsafe {
                    // rr: escape(discard): one is 8 bytes; a counter at its
                    // most is set already.
                    let _: isize = write(self.fd, one.as_ptr().cast(), 8);
                }
            }
        }

        impl Drop for Wake {
            fn drop(&mut self) {
                close_ring(self.fd);
            }
        }

        /// Now on the monotonic clock, in nanoseconds.
        #[must_use]
        fn monotonic_ns() -> u64 {
            let mut time = [0i64; 2];
            // rr: escape(unsafe): time is a struct timespec, two longs.
            if unsafe { clock_gettime(CLOCK_MONOTONIC, &raw mut time) } != 0 {
                return 0;
            }
            let [seconds, nanoseconds] = time;
            u64::try_from(seconds)
                .unwrap_or(0)
                .saturating_mul(1_000_000_000)
                .saturating_add(u64::try_from(nanoseconds).unwrap_or(0))
        }

        /// A pointer as the kernel takes it, a __u64: it reads and writes
        /// there, so the address is exposed.
        fn pointer(at: *const u8) -> u64 {
            u64::try_from(at.expose_provenance()).unwrap_or(0)
        }

        /// A head or a tail at offset in the ring's memory, which the
        /// kernel lays out aligned.
        fn word(ring: *mut c_void, offset: u32) -> *const AtomicU32 {
            ring.wrapping_byte_add(offset as usize).cast()
        }

        /// Why setup refused, by errno and io_uring_disabled.
        fn unavailable(code: c_int) -> Error {
            let why = match code {
                ENOSYS => Unavailable::Missing,
                EINVAL => Unavailable::Old,
                EPERM => match disabled() {
                    Some(b'2') => Unavailable::Disabled,
                    Some(b'1') => Unavailable::Group,
                    _ => Unavailable::Denied,
                },
                other => return error(other),
            };
            Error::Unavailable(why)
        }

        /// The first byte of /proc/sys/kernel/io_uring_disabled (Linux
        /// 6.6 and later).
        #[must_use]
        fn disabled() -> Option<u8> {
            let path = c"/proc/sys/kernel/io_uring_disabled";
            // rr: escape(unsafe): the path is NUL-terminated.
            let fd = unsafe { open(path.as_ptr(), O_RDONLY_CLOEXEC) };
            if fd < 0 {
                return None;
            }
            let mut byte = [0u8; 1];
            // rr: escape(unsafe): byte holds one byte; fd is open.
            let read = unsafe { read(fd, byte.as_mut_ptr().cast(), 1) };
            // rr: escape(unsafe): fd is this function's.
            unsafe {
                // rr: escape(discard): a descriptor only read; nothing to
                // tell.
                let _: c_int = close(fd);
            }
            (read == 1).then_some(byte[0])
        }

        impl Backend {
            pub fn new(ops: u32, pool: Pool) -> Result<Backend, Error> {
                let mut params = Params {
                    sq_entries: 0,
                    // Room for each operation's answer, its linked
                    // timeout's and its cancel's.
                    cq_entries: ops.saturating_mul(4),
                    // Disabled until its first wait, whose thread is then its
                    // one issuer: an Io may be made on one thread and run
                    // on another.
                    flags: SETUP_CQSIZE
                        | SETUP_CLAMP
                        | SETUP_SUBMIT_ALL
                        | SETUP_R_DISABLED
                        | SETUP_SINGLE_ISSUER
                        | SETUP_DEFER_TASKRUN,
                    sq_thread_cpu: 0,
                    sq_thread_idle: 0,
                    features: 0,
                    wq_fd: 0,
                    resv: [0; 3],
                    sq_off: [0; 10],
                    cq_off: [0; 10],
                };
                // rr: escape(unsafe): params is a struct io_uring_params
                // the call fills.
                let fd = unsafe { syscall(SYS_SETUP, c_long::from(ops), &raw mut params) };
                if fd < 0 {
                    return Err(unavailable(errno()));
                }
                let fd = c_int::try_from(fd).unwrap_or(-1);
                let needed = FEAT_SINGLE_MMAP | FEAT_NODROP | FEAT_EXT_ARG;
                if params.features & needed != needed {
                    close_ring(fd);
                    return Err(Error::Unavailable(Unavailable::Old));
                }
                // rr: escape(unsafe): eventfd takes plain numbers.
                let event = unsafe { eventfd(0, EFD_CLOEXEC) };
                if event < 0 {
                    let code = errno();
                    close_ring(fd);
                    return Err(error(code));
                }
                // rr: escape(shared): the Io and each Waker hold the eventfd.
                let wake = Arc::new(Wake { fd: event });
                let mut backend =
                    Backend::map(fd, &params, wake, pool).inspect_err(|_| close_ring(fd))?;
                backend.arm();
                backend.chunks()?;
                Ok(backend)
            }

            pub fn waker(&self) -> Arc<Wake> {
                // rr: escape(copy): a Waker holds the eventfd too.
                Arc::clone(&self.wake)
            }

            /// Reads what Wakers set, once more.
            fn arm(&mut self) {
                let fd = self.wake.fd;
                let addr = pointer(self.count.as_mut_ptr());
                self.push(Sqe {
                    opcode: OP_READ,
                    flags: 0,
                    ioprio: 0,
                    fd,
                    off: 0,
                    addr,
                    len: 8,
                    op_flags: 0,
                    user_data: WAKE,
                    buf_index: 0,
                    personality: 0,
                    file_index: 0,
                    addr3: 0,
                    pad: 0,
                });
                self.listening = true;
            }

            fn map(fd: c_int, p: &Params, wake: Arc<Wake>, pool: Pool) -> Result<Backend, Error> {
                let sq_size = p.sq_off[6] as usize + p.sq_entries as usize * 4;
                let cq_size = p.cq_off[5] as usize + p.cq_entries as usize * size_of::<Cqe>();
                let ring_size = sq_size.max(cq_size);
                let ring = mapped(fd, ring_size, OFF_SQ_RING)?;
                let sqes_size = p.sq_entries as usize * size_of::<Sqe>();
                let sqes = match mapped(fd, sqes_size, OFF_SQES) {
                    Ok(sqes) => sqes.cast::<Sqe>(),
                    Err(e) => {
                        unmap(ring, ring_size);
                        return Err(e);
                    }
                };
                let array = ring.wrapping_byte_add(p.sq_off[6] as usize).cast::<u32>();
                for i in 0..p.sq_entries {
                    let entry = array.wrapping_add(i as usize);
                    // rr: escape(unsafe): the array has sq_entries entries,
                    // each the index of its own entry, as liburing sets it.
                    unsafe { entry.write(i) }
                }
                Ok(Backend {
                    fd,
                    ring,
                    ring_size,
                    sqes,
                    sqes_size,
                    sq_head: word(ring, p.sq_off[0]),
                    sq_tail: word(ring, p.sq_off[1]),
                    sq_mask: p.sq_entries.wrapping_sub(1),
                    sq_entries: p.sq_entries,
                    cq_head: word(ring, p.cq_off[0]),
                    cq_tail: word(ring, p.cq_off[1]),
                    cq_mask: p.cq_entries.wrapping_sub(1),
                    cqes: ring.wrapping_byte_add(p.cq_off[5] as usize).cast(),
                    tail: 0,
                    enabled: false,
                    wake,
                    count: Box::new([0; 8]),
                    listening: false,
                    closing: false,
                    pool,
                    chunk_ring: null_mut(),
                    chunk_tail: 0,
                })
            }

            /// Now on the monotonic clock, in nanoseconds.
            #[must_use]
            pub fn now() -> u64 {
                monotonic_ns()
            }

            /// Registers the ring of chunks, group 0, and gives it every chunk.
            fn chunks(&mut self) -> Result<(), Error> {
                if self.pool.count == 0 {
                    return Ok(());
                }
                let bytes = self.pool.count.saturating_mul(16);
                // rr: escape(unsafe): a mapping of the program's own, page
                // aligned as the kernel asks of the ring.
                let at = unsafe {
                    mmap(
                        null_mut(),
                        bytes,
                        PROT_READ_WRITE,
                        MAP_PRIVATE_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                // rr: escape(sentinel): mmap's MAP_FAILED, (void *) -1.
                if at.addr() == usize::MAX {
                    return Err(error(errno()));
                }
                self.chunk_ring = at;
                let reg = BufReg {
                    ring_addr: pointer(self.chunk_ring.cast()),
                    ring_entries: u32::try_from(self.pool.count).unwrap_or(0),
                    bgid: 0,
                    flags: 0,
                    min_left: 0,
                    resv: [0; 5],
                };
                // rr: escape(unsafe): reg is a struct io_uring_buf_reg of one
                // ring the program keeps mapped while the ring lives.
                let done = unsafe {
                    syscall(
                        SYS_REGISTER,
                        c_long::from(self.fd),
                        REGISTER_PBUF_RING,
                        &raw const reg,
                        c_long::from(1u8),
                    )
                };
                if done < 0 {
                    return Err(error(errno()));
                }
                for id in 0..self.pool.count {
                    self.give_back(u16::try_from(id).unwrap_or(0));
                }
                Ok(())
            }

            /// Puts chunk id back in the ring, for the kernel to fill again.
            pub fn give_back(&mut self, id: u16) {
                if self.chunk_ring.is_null() {
                    return;
                }
                let mask = self.pool.count.saturating_sub(1);
                let entry = self
                    .chunk_ring
                    .wrapping_byte_add((usize::from(self.chunk_tail) & mask) * 16)
                    .cast::<u8>();
                let addr = pointer(self.pool.at(id)).to_le_bytes();
                let size = u32::try_from(self.pool.size)
                    .unwrap_or(u32::MAX)
                    .to_le_bytes();
                let bid = id.to_le_bytes();
                let mut bytes = [0u8; 14];
                bytes[..8].copy_from_slice(&addr);
                bytes[8..12].copy_from_slice(&size);
                bytes[12..].copy_from_slice(&bid);
                // rr: escape(unsafe): the entry is within the ring mapped,
                // one the kernel gave back; its last two bytes are left, as
                // the first entry's hold the tail.
                unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), entry, 14) }
                self.chunk_tail = self.chunk_tail.wrapping_add(1);
                let tail = self.chunk_ring.wrapping_byte_add(14).cast::<AtomicU16>();
                // rr: escape(unsafe): the tail is the program's to move, the
                // kernel's to read.
                unsafe { (*tail).store(self.chunk_tail, Ordering::Release) }
            }

            fn sq_head(&self) -> u32 {
                // rr: escape(unsafe): the kernel's head, in the
                // mapped ring, which it moves.
                unsafe { (*self.sq_head).load(Ordering::Acquire) }
            }

            /// Hands the kernel what the submission ring holds when it has
            /// no room for count more.
            fn room(&mut self, count: u32) {
                if self.tail.wrapping_sub(self.sq_head()).saturating_add(count) > self.sq_entries {
                    // rr: escape(discard): a refusal comes back as each
                    // entry's answer.
                    let _: Result<(), Error> = self.enter(0, None);
                }
            }

            /// Puts an entry in the submission ring, first handing the
            /// kernel what is there when it is full.
            fn push(&mut self, sqe: Sqe) {
                if self.tail.wrapping_sub(self.sq_head()) >= self.sq_entries {
                    // rr: escape(discard): a refusal comes back as each
                    // entry's answer.
                    let _: Result<(), Error> = self.enter(0, None);
                }
                let index = (self.tail & self.sq_mask) as usize;
                let entry = self.sqes.wrapping_add(index);
                // rr: escape(unsafe): index is within the sq_entries entries
                // mapped, which the kernel has consumed.
                unsafe { entry.write(sqe) }
                self.tail = self.tail.wrapping_add(1);
            }

            /// Hands the kernel the entries pushed, and waits for at least
            /// so many answers, or timeout; the first enables the ring for
            /// this thread, its one issuer from then on.
            fn enter(&mut self, wanted: u32, timeout: Option<Duration>) -> Result<(), Error> {
                if !self.enabled {
                    // rr: escape(unsafe): the call takes the ring and no
                    // argument.
                    let done = unsafe {
                        syscall(
                            SYS_REGISTER,
                            c_long::from(self.fd),
                            REGISTER_ENABLE_RINGS,
                            null_mut::<c_void>(),
                            c_long::from(0u8),
                        )
                    };
                    if done < 0 {
                        return Err(error(errno()));
                    }
                    self.enabled = true;
                }
                // rr: escape(unsafe): the tail is the program's
                // to move, the kernel's to read.
                unsafe { (*self.sq_tail).store(self.tail, Ordering::Release) }
                let pending = self.tail.wrapping_sub(self.sq_head());
                let time = timeout.map(|t| {
                    [
                        i64::try_from(t.as_secs()).unwrap_or(i64::MAX),
                        i64::from(t.subsec_nanos()),
                    ]
                });
                let arg = Getevents {
                    sigmask: 0,
                    sigmask_sz: 8,
                    min_wait_usec: 0,
                    ts: time.as_ref().map_or(0, |t| pointer(t.as_ptr().cast())),
                };
                let flags = ENTER_GETEVENTS | ENTER_EXT_ARG;
                // rr: escape(unsafe): arg is a struct io_uring_getevents_arg
                // of its size, and the time it points to lives through the
                // call.
                let done = unsafe {
                    syscall(
                        SYS_ENTER,
                        c_long::from(self.fd),
                        c_long::from(pending),
                        c_long::from(wanted),
                        c_long::from(flags),
                        &raw const arg,
                        size_of::<Getevents>(),
                    )
                };
                if done >= 0 {
                    return Ok(());
                }
                match errno() {
                    // The time passed, a signal came, or the answers wait
                    // to be taken: none is an error.
                    ETIME | super::os::EINTR | EAGAIN | EBUSY => Ok(()),
                    code => Err(error(code)),
                }
            }

            /// Puts the slot's operation in the submission ring.
            pub fn submit(&mut self, data: u64, slot: &mut Slot) {
                let mut sqe = Sqe {
                    opcode: 0,
                    flags: 0,
                    ioprio: 0,
                    fd: slot.fd().unwrap_or(-1),
                    off: 0,
                    addr: 0,
                    len: 0,
                    op_flags: 0,
                    user_data: data,
                    buf_index: 0,
                    personality: 0,
                    file_index: 0,
                    addr3: 0,
                    pad: 0,
                };
                match &mut slot.work {
                    Work::Accept(_) => {
                        sqe.opcode = OP_ACCEPT;
                        sqe.addr = pointer(slot.address.as_mut_ptr());
                        sqe.off = pointer((&raw mut slot.length).cast());
                        sqe.op_flags = (SOCK_NONBLOCK | SOCK_CLOEXEC).cast_unsigned();
                    }
                    Work::Connect(_) => {
                        sqe.opcode = OP_CONNECT;
                        sqe.addr = pointer(slot.address.as_ptr());
                        sqe.off = u64::from(slot.length);
                    }
                    Work::Receive(_, buffer) => {
                        sqe.opcode = OP_RECV;
                        let room = buffer.spare_capacity_mut();
                        sqe.addr = pointer(room.as_mut_ptr().cast());
                        sqe.len = u32::try_from(room.len().min(CHUNK)).unwrap_or(0);
                    }
                    Work::Send(_, buffer, sent) => {
                        sqe.opcode = OP_SEND;
                        let rest = buffer.get(*sent..).unwrap_or_default();
                        sqe.addr = pointer(rest.as_ptr());
                        sqe.len = u32::try_from(rest.len().min(CHUNK)).unwrap_or(0);
                        sqe.op_flags = MSG_NOSIGNAL;
                    }
                    Work::Timeout(after) => {
                        sqe.opcode = OP_TIMEOUT;
                        slot.time = [
                            i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
                            i64::from(after.subsec_nanos()),
                        ];
                        sqe.addr = pointer(slot.time.as_ptr().cast());
                        sqe.len = 1;
                    }
                    Work::SendTo(_, buffer) => {
                        sqe.opcode = OP_SENDMSG;
                        slot.vector = [pointer(buffer.as_ptr()), buffer.len() as u64];
                        slot.message = [
                            pointer(slot.address.as_ptr()),
                            u64::from(slot.length),
                            pointer(slot.vector.as_ptr().cast()),
                            1,
                            0,
                            0,
                            0,
                        ];
                        sqe.addr = pointer(slot.message.as_ptr().cast());
                        sqe.len = 1;
                        sqe.op_flags = MSG_NOSIGNAL;
                    }
                    Work::ReceiveFrom(_, buffer) => {
                        sqe.opcode = OP_RECVMSG;
                        let room = buffer.spare_capacity_mut();
                        slot.vector = [pointer(room.as_mut_ptr().cast()), room.len() as u64];
                        // msg_namelen, then its padding, in the second word.
                        slot.message = [
                            pointer(slot.address.as_mut_ptr()),
                            u64::from(slot.length),
                            pointer(slot.vector.as_ptr().cast()),
                            1,
                            0,
                            0,
                            0,
                        ];
                        sqe.addr = pointer(slot.message.as_ptr().cast());
                        sqe.len = 1;
                    }
                    Work::ReceiveMany(_) => {
                        sqe.opcode = OP_RECV;
                        sqe.ioprio = RECV_MULTISHOT;
                        sqe.flags = IOSQE_BUFFER_SELECT;
                        sqe.buf_index = 0;
                    }
                    Work::SendChunk {
                        id, length, sent, ..
                    } => {
                        sqe.opcode = OP_SEND;
                        let at = self.pool.at(*id).wrapping_add(*sent as usize);
                        sqe.addr = pointer(at);
                        sqe.len = length.saturating_sub(*sent);
                        sqe.op_flags = MSG_NOSIGNAL;
                    }
                    Work::Idle | Work::Run(_) | Work::Finished(_) => return,
                }
                let Some(limit) = slot.limit else {
                    self.push(sqe);
                    return;
                };
                // A linked timeout: the time left of the operation's, which a
                // send started again does not start over.
                let now = monotonic_ns();
                if slot.until == 0 {
                    slot.until =
                        now.saturating_add(u64::try_from(limit.as_nanos()).unwrap_or(u64::MAX));
                }
                let left = slot.until.saturating_sub(now);
                slot.time = [
                    i64::try_from(left / 1_000_000_000).unwrap_or(i64::MAX),
                    i64::try_from(left % 1_000_000_000).unwrap_or(0),
                ];
                // Both in one submission, or the link is broken.
                self.room(2);
                sqe.flags |= IOSQE_IO_LINK;
                self.push(sqe);
                self.push(Sqe {
                    opcode: OP_LINK_TIMEOUT,
                    flags: 0,
                    ioprio: 0,
                    fd: -1,
                    off: 0,
                    addr: pointer(slot.time.as_ptr().cast()),
                    len: 1,
                    op_flags: 0,
                    user_data: LIMIT,
                    buf_index: 0,
                    personality: 0,
                    file_index: 0,
                    addr3: 0,
                    pad: 0,
                });
            }

            /// Asks the kernel to end the operation; its answer comes as
            /// any other's.
            #[must_use]
            pub fn cancel(&mut self, data: u64, _slot: &mut Slot) -> bool {
                self.cancel_data(data);
                false
            }

            fn cancel_data(&mut self, data: u64) {
                self.push(Sqe {
                    opcode: OP_ASYNC_CANCEL,
                    flags: 0,
                    ioprio: 0,
                    fd: -1,
                    off: 0,
                    addr: data,
                    len: 0,
                    op_flags: 0,
                    user_data: CANCEL,
                    buf_index: 0,
                    personality: 0,
                    file_index: 0,
                    addr3: 0,
                    pad: 0,
                });
            }

            pub fn wait(
                &mut self,
                slots: &mut [Slot],
                ready: &mut VecDeque<u32>,
                timeout: Option<Duration>,
            ) -> Result<(), Error> {
                let wanted = u32::from(timeout != Some(Duration::ZERO));
                self.enter(wanted, timeout)?;
                self.reap(slots, ready);
                Ok(())
            }

            /// Takes every answer the completion ring holds.
            fn reap(&mut self, slots: &mut [Slot], ready: &mut VecDeque<u32>) {
                // rr: escape(unsafe): the head is the program's to
                // move.
                let mut head = unsafe { (*self.cq_head).load(Ordering::Relaxed) };
                // rr: escape(unsafe): the tail is the kernel's.
                let tail = unsafe { (*self.cq_tail).load(Ordering::Acquire) };
                for _ in 0..tail.wrapping_sub(head) {
                    let entry = self.cqes.wrapping_add((head & self.cq_mask) as usize);
                    // rr: escape(unsafe): the entry is within those mapped,
                    // which the kernel wrote before it moved the tail.
                    let Cqe {
                        user_data: data,
                        res,
                        flags,
                    } = unsafe { entry.read() };
                    head = head.wrapping_add(1);
                    if data == WAKE {
                        self.listening = false;
                        if !self.closing {
                            self.arm();
                        }
                        continue;
                    }
                    let Some((index, slot)) = running(slots, data) else {
                        continue;
                    };
                    if let Work::ReceiveMany(_) = slot.work {
                        self.many(slot, index, ready, data, res, flags);
                        continue;
                    }
                    if let Work::ReceiveFrom(..) = slot.work {
                        // The msg_namelen recvmsg wrote, the low half of the
                        // second word on a little-endian target.
                        slot.length = u32::try_from(slot.message[1] & 0xffff_ffff).unwrap_or(0);
                    }
                    let answer = match (res, &slot.work) {
                        (res, Work::Timeout(_)) if res == -ETIME => Ok(0),
                        (res, _) if res >= 0 => Ok(res.cast_unsigned() as usize),
                        (res, _) => Err(res.saturating_neg()),
                    };
                    if settle(slot, answer) {
                        self.submit(data, slot);
                    } else {
                        ready.push_back(u32::try_from(index).unwrap_or(0));
                    }
                }
                // rr: escape(unsafe): the head is the program's to
                // move, the kernel's to read.
                unsafe { (*self.cq_head).store(head, Ordering::Release) }
            }

            /// A multishot receive's answer: a chunk it filled, and, without
            /// IORING_CQE_F_MORE, its end, or its start again when the kernel
            /// stopped it with more to come.
            fn many(
                &mut self,
                slot: &mut Slot,
                index: usize,
                ready: &mut VecDeque<u32>,
                data: u64,
                res: i32,
                flags: u32,
            ) {
                if res > 0 && flags & CQE_F_BUFFER != 0 {
                    let id = u16::try_from(flags >> CQE_BUFFER_SHIFT).unwrap_or(0);
                    self.pool.fill(slot.key, id, res.cast_unsigned());
                }
                if flags & CQE_F_MORE != 0 {
                    return;
                }
                if res > 0 && !slot.canceled {
                    self.submit(data, slot);
                    return;
                }
                let result = match res {
                    0.. => Ok(()),
                    _ if res == -ENOBUFS => Err(Error::NoChunks),
                    _ => Err(error(res.saturating_neg())),
                };
                if end_many(slot, result) {
                    ready.push_back(u32::try_from(index).unwrap_or(0));
                }
            }

            /// Cancels every operation and waits until the kernel answered
            /// each, so that none writes a buffer freed after: nothing is
            /// settled or started again, as the Io is going.
            pub fn close(&mut self, slots: &mut [Slot]) {
                self.closing = true;
                if self.listening {
                    self.cancel_data(WAKE);
                }
                for (index, slot) in slots.iter_mut().enumerate() {
                    if slot.state == State::Running {
                        let data =
                            super::user_data(u32::try_from(index).unwrap_or(0), slot.generation);
                        self.cancel_data(data);
                    }
                }
                // Each turn takes answers, or waits a second for one: a
                // canceled operation answers at once.
                let turns = slots.len().saturating_mul(2).saturating_add(8);
                let mut turn = 0;
                while turn < turns
                    && (self.listening || slots.iter().any(|s| s.state == State::Running))
                {
                    turn += 1;
                    if self.enter(1, Some(Duration::from_secs(1))).is_err() {
                        return;
                    }
                    // rr: escape(unsafe): the head is the program's to
                    // move.
                    let mut head = unsafe { (*self.cq_head).load(Ordering::Relaxed) };
                    // rr: escape(unsafe): the tail is the kernel's.
                    let tail = unsafe { (*self.cq_tail).load(Ordering::Acquire) };
                    for _ in 0..tail.wrapping_sub(head) {
                        let entry = self.cqes.wrapping_add((head & self.cq_mask) as usize);
                        // rr: escape(unsafe): the entry is within those mapped,
                        // which the kernel wrote before it moved the tail.
                        let Cqe {
                            user_data: data,
                            flags,
                            ..
                        } = unsafe { entry.read() };
                        head = head.wrapping_add(1);
                        if data == WAKE {
                            self.listening = false;
                        } else if let Some((_, slot)) = running(slots, data) {
                            // A multishot receive holds its chunks until its
                            // last answer, which says no more.
                            if flags & CQE_F_MORE == 0 {
                                slot.state = State::Ready;
                            }
                        } else {
                            // A cancel's own answer, or one already taken.
                        }
                    }
                    // rr: escape(unsafe): the head is the program's to move,
                    // the kernel's to read.
                    unsafe { (*self.cq_head).store(head, Ordering::Release) }
                }
            }
        }

        fn mapped(fd: c_int, size: usize, offset: i64) -> Result<*mut c_void, Error> {
            // rr: escape(unsafe): the kernel maps its own memory of the ring.
            let at = unsafe {
                mmap(
                    null_mut(),
                    size,
                    PROT_READ_WRITE,
                    MAP_SHARED_POPULATE,
                    fd,
                    offset,
                )
            };
            // rr: escape(sentinel): mmap's MAP_FAILED, (void *) -1.
            if at.addr() == usize::MAX {
                return Err(error(errno()));
            }
            Ok(at)
        }

        fn unmap(at: *mut c_void, size: usize) {
            // rr: escape(unsafe): at is a mapping of size bytes, unmapped once.
            unsafe {
                // rr: escape(discard): an unmapping refused leaves memory
                // the process ends with.
                let _: c_int = munmap(at, size);
            }
        }

        fn close_ring(fd: c_int) {
            // rr: escape(unsafe): fd is the ring's, closed once.
            unsafe {
                // rr: escape(discard): close releases the descriptor whatever
                // it answers.
                let _: c_int = close(fd);
            }
        }

        impl Drop for Backend {
            fn drop(&mut self) {
                unmap(self.sqes.cast(), self.sqes_size);
                unmap(self.ring, self.ring_size);
                close_ring(self.fd);
                if !self.chunk_ring.is_null() {
                    unmap(self.chunk_ring, self.pool.count.saturating_mul(16));
                }
            }
        }
    }
    // rr: end(os = linux)

    // rr: section(os = macos)
    /// macOS: a kqueue, and each operation tried when the socket is ready.
    #[cfg(target_os = "macos")]
    mod backend {
        use super::os::c::{self, errno};
        use super::os::{EAGAIN, EINPROGRESS, F_SETFD, FD_CLOEXEC, SO_ERROR, SOL_SOCKET, error};
        use super::{Answer, Error, Pool, Slot, WAKE, Work, end_many, running, settle};
        use alloc::collections::VecDeque;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use core::ffi::{c_int, c_void};
        use core::ptr::{null, null_mut, without_provenance_mut};
        use core::time::Duration;

        /// struct kevent, which sys/event.h declares under #pragma pack(4):
        /// 32 bytes, aligned to 4.
        #[repr(C, packed(4))]
        struct Kevent {
            ident: usize,
            filter: i16,
            flags: u16,
            fflags: u32,
            data: isize,
            udata: *mut c_void,
        }

        /// struct timespec: a time_t and a long.
        #[repr(C)]
        struct Timespec {
            seconds: i64,
            nanoseconds: i64,
        }

        #[link(name = "c")]
        // rr: escape(unsafe): each signature is the C library's, from its
        // headers.
        unsafe extern "C" {
            #[must_use]
            fn kqueue() -> c_int;
            /// clockid_t is an enum, an int.
            #[must_use]
            fn clock_gettime_nsec_np(clock: c_int) -> u64;
            #[must_use]
            fn kevent(
                kq: c_int,
                changes: *const Kevent,
                change_count: c_int,
                events: *mut Kevent,
                event_count: c_int,
                timeout: *const Timespec,
            ) -> c_int;
        }

        // sys/event.h's filters, flags and notes.
        const EVFILT_READ: i16 = -1;
        const EVFILT_WRITE: i16 = -2;
        const EVFILT_TIMER: i16 = -7;
        const EVFILT_USER: i16 = -10;
        /// sys/socket.h's.
        const MSG_PEEK: c_int = 0x2;
        const EV_ADD: u16 = 0x1;
        const EV_CLEAR: u16 = 0x20;
        const NOTE_TRIGGER: u32 = 0x0100_0000;
        const EV_DELETE: u16 = 0x2;
        const EV_ONESHOT: u16 = 0x10;
        const EV_ERROR: u16 = 0x4000;
        const NOTE_NSECONDS: u32 = 0x4;
        /// The longest kevent waits at once: it refuses a timeout of 2^31
        /// seconds or more (EINVAL), and Go cuts it to 10^6 seconds.
        const SECONDS_MAX: u64 = 1_000_000;
        /// The events one wait takes; the rest, still ready, the next.
        const BATCH: usize = 256;
        /// The most one operation is tried in a turn before the others
        /// have theirs, as libuv writes a stream at most 32 times.
        const TRIES: usize = 32;

        fn change(ident: usize, filter: i16, flags: u16, data: u64) -> Kevent {
            Kevent {
                ident,
                filter,
                flags,
                fflags: 0,
                data: 0,
                udata: without_provenance_mut(usize::try_from(data).unwrap_or(0)),
            }
        }

        /// The kqueue, which the Io and each Waker hold: a Waker triggers
        /// its user filter.
        pub struct Wake {
            kq: c_int,
        }

        impl Wake {
            pub fn wake(&self) {
                let mut trigger = change(0, EVFILT_USER, 0, WAKE);
                trigger.fflags = NOTE_TRIGGER;
                // rr: escape(unsafe): one change, no events asked for; the
                // filter is added with the kqueue, so a trigger is refused only
                // for a kqueue gone, which nothing waits on.
                unsafe {
                    // rr: escape(discard): one change, no events asked for; the
                    // filter is added with the kqueue, so a trigger is refused
                    // only for a kqueue gone, which nothing waits on.
                    let _: c_int = kevent(self.kq, &raw const trigger, 1, null_mut(), 0, null());
                }
            }
        }

        impl Drop for Wake {
            fn drop(&mut self) {
                super::os::close(self.kq);
            }
        }

        // rr: escape(unsafe): a kqueue is the process's, which any thread
        // may wait on; changes and events are scratch whose udata are user
        // data, not pointers. An Io is moved whole, never shared.
        unsafe impl Send for Backend {}

        pub struct Backend {
            queue: Arc<Wake>,
            kq: c_int,
            /// The operations to try at the next wait, by user data, which
            /// takes them into trying first.
            pending: VecDeque<u64>,
            trying: VecDeque<u64>,
            /// The filters to add at the next wait.
            changes: Vec<Kevent>,
            /// What a wait takes from the kqueue: BATCH entries.
            events: Vec<Kevent>,
            /// The chunks receive_many reads into.
            pub pool: Pool,
        }

        impl Backend {
            pub fn new(ops: u32, pool: Pool) -> Result<Backend, Error> {
                // rr: escape(unsafe): kqueue takes nothing.
                let kq = unsafe { kqueue() };
                if kq < 0 {
                    return Err(error(errno()));
                }
                // rr: escape(shared): the Io and each Waker hold the kqueue.
                let queue = Arc::new(Wake { kq });
                // rr: escape(unsafe): kq is open; fork drops a kqueue, exec
                // does not.
                if unsafe { c::fcntl(kq, F_SETFD, FD_CLOEXEC) } != 0 {
                    return Err(error(errno()));
                }
                let user = change(0, EVFILT_USER, EV_ADD | EV_CLEAR, WAKE);
                // rr: escape(unsafe): one change, no events asked for.
                if unsafe { kevent(kq, &raw const user, 1, null_mut(), 0, null()) } != 0 {
                    return Err(error(errno()));
                }
                let ops = ops as usize;
                let mut events = Vec::with_capacity(BATCH);
                events.resize_with(BATCH, || change(0, 0, 0, 0));
                Ok(Backend {
                    queue,
                    kq,
                    pending: VecDeque::with_capacity(ops),
                    trying: VecDeque::with_capacity(ops),
                    changes: Vec::with_capacity(ops),
                    events,
                    pool,
                })
            }

            pub fn waker(&self) -> Arc<Wake> {
                // rr: escape(copy): a Waker holds the kqueue too.
                Arc::clone(&self.queue)
            }

            pub fn submit(&mut self, data: u64, slot: &mut Slot) {
                if let Work::Timeout(after) = slot.work {
                    let mut timer =
                        change(slot_ident(data), EVFILT_TIMER, EV_ADD | EV_ONESHOT, data);
                    timer.fflags = NOTE_NSECONDS;
                    timer.data = isize::try_from(after.as_nanos()).unwrap_or(isize::MAX);
                    slot.armed = Some(EVFILT_TIMER);
                    // rr: escape(bound): one change for each running
                    // operation at most, and there are as many as the table.
                    self.changes.push(timer);
                    return;
                }
                if let Some(limit) = slot.limit {
                    // Its own timer, in EVFILT_TIMER's namespace by its slot,
                    // as a timeout's.
                    let mut timer =
                        change(slot_ident(data), EVFILT_TIMER, EV_ADD | EV_ONESHOT, data);
                    timer.fflags = NOTE_NSECONDS;
                    timer.data = isize::try_from(limit.as_nanos()).unwrap_or(isize::MAX);
                    slot.limited = true;
                    // rr: escape(bound): one timer for each running operation
                    // at most.
                    self.changes.push(timer);
                }
                // rr: escape(bound): each running operation is pending once
                // at most.
                self.pending.push_back(data);
            }

            pub fn give_back(&mut self, id: u16) {
                self.pool.put(id);
            }

            /// Now on the monotonic clock (CLOCK_UPTIME_RAW, time.h), in
            /// nanoseconds.
            #[must_use]
            pub fn now() -> u64 {
                // rr: escape(unsafe): the call takes a clock's number.
                unsafe { clock_gettime_nsec_np(8) }
            }

            /// Reads what a receive_many's socket has into free chunks, at
            /// most TRIES of them a turn, as other operations are tried; its
            /// filter stays (not EV_ONESHOT) until it is over.
            fn drain_many(
                &mut self,
                slot: &mut Slot,
                index: usize,
                ready: &mut VecDeque<u32>,
                data: u64,
            ) {
                let fd = slot.fd().unwrap_or(-1);
                for _ in 0..TRIES {
                    let Some(id) = self.pool.take() else {
                        // No chunk: over only once something came, as io_uring
                        // says ENOBUFS then; the peer's end without data is the
                        // end.
                        let mut byte = [0u8; 1];
                        // rr: escape(unsafe): byte holds the one byte peeked.
                        let got = unsafe { c::recv(fd, byte.as_mut_ptr().cast(), 1, MSG_PEEK) };
                        match got {
                            1.. => self.end(slot, index, ready, data, Err(Error::NoChunks)),
                            0 => self.end(slot, index, ready, data, Ok(())),
                            _ => break,
                        }
                        return;
                    };
                    let (at, size) = (self.pool.at(id), self.pool.size);
                    // rr: escape(unsafe): the chunk holds size bytes, and is
                    // nobody else's while it is out of the pool.
                    let got = unsafe { c::recv(fd, at.cast(), size, 0) };
                    if let Ok(count) = u32::try_from(got) {
                        if count == 0 {
                            self.pool.put(id);
                            self.end(slot, index, ready, data, Ok(()));
                            return;
                        }
                        self.pool.fill(slot.key, id, count);
                        continue;
                    }
                    let code = errno();
                    self.pool.put(id);
                    if !super::os::again(code) {
                        self.end(slot, index, ready, data, Err(error(code)));
                        return;
                    }
                    break;
                }
                if slot.armed.is_none() {
                    slot.armed = Some(EVFILT_READ);
                    // rr: escape(bound): one change for each running operation
                    // at most.
                    self.changes
                        .push(change(ident(fd), EVFILT_READ, EV_ADD, data));
                }
            }

            /// Ends a receive_many: its filter goes, and it is over now or
            /// once the sends on its stream are done.
            fn end(
                &mut self,
                slot: &mut Slot,
                index: usize,
                ready: &mut VecDeque<u32>,
                data: u64,
                result: Result<(), Error>,
            ) {
                if let (Some(armed), Some(fd)) = (slot.armed.take(), slot.fd()) {
                    self.delete(ident(fd), armed, data);
                    self.changes.retain(|c| c.udata.addr() as u64 != data);
                }
                if end_many(slot, result) {
                    push_ready(ready, index);
                }
            }

            /// Deletes what the kqueue waits on for an operation, at once.
            fn delete(&self, ident: usize, filter: i16, data: u64) {
                let delete = change(ident, filter, EV_DELETE, data);
                // rr: escape(unsafe): one change, no events asked for.
                unsafe {
                    // rr: escape(discard): a filter gone already is what was
                    // wanted.
                    let _: c_int = kevent(self.kq, &raw const delete, 1, null_mut(), 0, null());
                }
            }

            /// Deletes an operation's own timer, once it is done another way.
            fn unlimit(&mut self, slot: &mut Slot, data: u64) {
                if slot.limited {
                    slot.limited = false;
                    self.delete(slot_ident(data), EVFILT_TIMER, data);
                    self.changes
                        .retain(|c| c.udata.addr() as u64 != data || c.filter != EVFILT_TIMER);
                }
            }

            /// Ends the operation at once: what the kqueue waits on for it
            /// is deleted; one pending is passed over.
            #[must_use]
            pub fn cancel(&mut self, data: u64, slot: &mut Slot) -> bool {
                if let Work::ReceiveMany(_) = slot.work {
                    if let (Some(armed), Some(fd)) = (slot.armed.take(), slot.fd()) {
                        self.delete(ident(fd), armed, data);
                        self.changes.retain(|c| c.udata.addr() as u64 != data);
                    }
                    return end_many(slot, Err(Error::Canceled));
                }
                if let Some(filter) = slot.armed.take() {
                    let ident = if filter == EVFILT_TIMER {
                        slot_ident(data)
                    } else {
                        ident(slot.fd().unwrap_or(-1))
                    };
                    self.delete(ident, filter, data);
                    // A change not yet made goes with the operation.
                    self.changes.retain(|c| c.udata.addr() as u64 != data);
                }
                self.unlimit(slot, data);
                // rr: escape(discard): a canceled operation is never tried
                // again.
                let _: bool = settle(slot, Err(super::os::ECANCELED));
                true
            }

            pub fn wait(
                &mut self,
                slots: &mut [Slot],
                ready: &mut VecDeque<u32>,
                timeout: Option<Duration>,
            ) -> Result<(), Error> {
                // What is tried and still pending waits for the next wait.
                core::mem::swap(&mut self.pending, &mut self.trying);
                while let Some(data) = self.trying.pop_front() {
                    self.attempt(slots, ready, data);
                }
                let timeout = if ready.is_empty() {
                    timeout
                } else {
                    Some(Duration::ZERO)
                };
                let time = timeout.map(|t| Timespec {
                    seconds: i64::try_from(t.as_secs().min(SECONDS_MAX)).unwrap_or(0),
                    nanoseconds: i64::from(t.subsec_nanos()),
                });
                let count = c_int::try_from(self.changes.len()).unwrap_or(0);
                // rr: escape(unsafe): changes holds count entries and events
                // BATCH; an error of a change comes as an event, as there is
                // room for each.
                let got = unsafe {
                    kevent(
                        self.kq,
                        self.changes.as_ptr(),
                        count,
                        self.events.as_mut_ptr(),
                        c_int::try_from(BATCH.max(self.changes.len())).unwrap_or(0),
                        time.as_ref().map_or(null(), core::ptr::from_ref),
                    )
                };
                self.changes.clear();
                let Ok(got) = usize::try_from(got) else {
                    return match errno() {
                        super::os::EINTR => Ok(()),
                        code => Err(error(code)),
                    };
                };
                for i in 0..got.min(self.events.len()) {
                    let (data, flags, filter, code) = match self.events.get(i) {
                        Some(e) => (e.udata.addr() as u64, e.flags, e.filter, e.data),
                        None => break,
                    };
                    let Some((index, slot)) = running(slots, data) else {
                        continue;
                    };
                    if let Work::ReceiveMany(_) = slot.work {
                        if flags & EV_ERROR != 0 {
                            slot.armed = None;
                            let result = Err(error(i32::try_from(code).unwrap_or(0)));
                            self.end(slot, index, ready, data, result);
                        } else {
                            self.drain_many(slot, index, ready, data);
                        }
                        continue;
                    }
                    if filter == EVFILT_TIMER && !matches!(slot.work, Work::Timeout(_)) {
                        // The operation's time ran out: what it waits on goes,
                        // and it ends as timed out.
                        slot.limited = false;
                        slot.expired = true;
                        if let (Some(armed), Some(fd)) = (slot.armed.take(), slot.fd()) {
                            self.delete(ident(fd), armed, data);
                        }
                        self.changes.retain(|c| c.udata.addr() as u64 != data);
                        finish(slot, index, ready, Err(super::os::ECANCELED));
                        continue;
                    }
                    slot.armed = None;
                    if flags & EV_ERROR != 0 {
                        self.unlimit(slot, data);
                        let answer = Err(i32::try_from(code).unwrap_or(0));
                        finish(slot, index, ready, answer);
                        continue;
                    }
                    if filter == EVFILT_TIMER {
                        finish(slot, index, ready, Ok(0));
                        continue;
                    }
                    self.attempt(slots, ready, data);
                }
                Ok(())
            }

            /// Tries the operation now; one the socket is not ready for
            /// waits in the kqueue.
            fn attempt(&mut self, slots: &mut [Slot], ready: &mut VecDeque<u32>, data: u64) {
                let Some((index, slot)) = running(slots, data) else {
                    return;
                };
                if let Work::ReceiveMany(_) = slot.work {
                    self.drain_many(slot, index, ready, data);
                    return;
                }
                for _ in 0..TRIES {
                    let answer = perform(slot, &mut self.pool);
                    if let Err(EAGAIN) = answer {
                        let filter = match slot.work {
                            Work::Accept(_)
                            | Work::Receive(..)
                            | Work::ReceiveFrom(..)
                            | Work::ReceiveMany(_) => EVFILT_READ,
                            Work::Idle
                            | Work::Connect(_)
                            | Work::Send(..)
                            | Work::SendChunk { .. }
                            | Work::SendTo(..)
                            | Work::Timeout(_)
                            | Work::Run(_)
                            | Work::Finished(_) => EVFILT_WRITE,
                        };
                        let ident = ident(slot.fd().unwrap_or(-1));
                        slot.armed = Some(filter);
                        // rr: escape(bound): one change for each running
                        // operation at most.
                        self.changes
                            .push(change(ident, filter, EV_ADD | EV_ONESHOT, data));
                        return;
                    }
                    if !settle(slot, answer) {
                        self.unlimit(slot, data);
                        push_ready(ready, index);
                        return;
                    }
                }
                // rr: escape(bound): each running operation is pending once
                // at most.
                self.pending.push_back(data);
            }

            /// Nothing the kernel holds is the program's memory: what is
            /// left to try goes.
            pub fn close(&mut self, _slots: &mut [Slot]) {
                self.pending.clear();
                self.changes.clear();
            }
        }

        fn finish(slot: &mut Slot, index: usize, ready: &mut VecDeque<u32>, answer: Answer) {
            if !settle(slot, answer) {
                push_ready(ready, index);
            }
        }

        fn push_ready(ready: &mut VecDeque<u32>, index: usize) {
            ready.push_back(u32::try_from(index).unwrap_or(0));
        }

        fn ident(fd: c_int) -> usize {
            usize::try_from(fd).unwrap_or(0)
        }

        /// A timer's identifier: its slot, in EVFILT_TIMER's own namespace.
        fn slot_ident(data: u64) -> usize {
            usize::try_from(data & 0xffff_ffff).unwrap_or(0)
        }

        /// The operation's system call, as it stands: EAGAIN when the
        /// socket is not ready.
        fn perform(slot: &mut Slot, pool: &mut Pool) -> Answer {
            let fd = slot.fd().unwrap_or(-1);
            match &mut slot.work {
                Work::Accept(_) => {
                    slot.length = super::os::length(&slot.address);
                    // rr: escape(unsafe): address holds length bytes.
                    let got =
                        unsafe { c::accept(fd, slot.address.as_mut_ptr(), &raw mut slot.length) };
                    answer(isize::try_from(got).unwrap_or(-1))
                }
                Work::Connect(_) if !slot.begun => {
                    slot.begun = true;
                    let length = slot.length;
                    // rr: escape(unsafe): address holds a sockaddr of length
                    // bytes.
                    if unsafe { c::connect(fd, slot.address.as_ptr(), length) } == 0 {
                        return Ok(0);
                    }
                    match errno() {
                        EINPROGRESS | super::os::EINTR => Err(EAGAIN),
                        code => Err(code),
                    }
                }
                Work::Connect(_) => pending(fd),
                Work::Receive(_, buffer) => {
                    let room = buffer.spare_capacity_mut();
                    // rr: escape(unsafe): room is the buffer's spare
                    // capacity, which recv writes into.
                    let got = unsafe { c::recv(fd, room.as_mut_ptr().cast(), room.len(), 0) };
                    answer(got)
                }
                Work::Send(_, buffer, sent) => {
                    let rest = buffer.get(*sent..).unwrap_or_default();
                    // rr: escape(unsafe): rest holds its length.
                    let got = unsafe { c::send(fd, rest.as_ptr().cast(), rest.len(), 0) };
                    answer(got)
                }
                Work::SendTo(_, buffer) => {
                    // rr: escape(unsafe): buffer holds its length; address a
                    // sockaddr of length bytes.
                    let got = unsafe {
                        c::sendto(
                            fd,
                            buffer.as_ptr().cast(),
                            buffer.len(),
                            0,
                            slot.address.as_ptr(),
                            slot.length,
                        )
                    };
                    answer(got)
                }
                Work::ReceiveFrom(_, buffer) => {
                    slot.length = super::os::length(&slot.address);
                    let room = buffer.spare_capacity_mut();
                    // rr: escape(unsafe): room is the buffer's spare
                    // capacity; address holds length bytes.
                    let got = unsafe {
                        c::recvfrom(
                            fd,
                            room.as_mut_ptr().cast(),
                            room.len(),
                            0,
                            slot.address.as_mut_ptr(),
                            &raw mut slot.length,
                        )
                    };
                    answer(got)
                }
                Work::SendChunk {
                    id, length, sent, ..
                } => {
                    let at = pool.at(*id).wrapping_add(*sent as usize);
                    let rest = length.saturating_sub(*sent) as usize;
                    // rr: escape(unsafe): the chunk holds length bytes, the
                    // program's while it is out of the pool.
                    let got = unsafe { c::send(fd, at.cast(), rest, 0) };
                    answer(got)
                }
                Work::Idle
                | Work::Timeout(_)
                | Work::Run(_)
                | Work::ReceiveMany(_)
                | Work::Finished(_) => Ok(0),
            }
        }

        /// A count the call returned, or its errno.
        fn answer(got: isize) -> Answer {
            if got < 0 {
                Err(errno())
            } else {
                Ok(got.unsigned_abs())
            }
        }

        /// How a connection begun went: SO_ERROR, which reading clears.
        fn pending(fd: c_int) -> Answer {
            let mut code = [0u8; 4];
            let mut size = super::os::length(&code);
            // rr: escape(unsafe): code holds size bytes.
            let done = unsafe {
                c::getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    code.as_mut_ptr().cast(),
                    &raw mut size,
                )
            };
            if done < 0 {
                return Err(errno());
            }
            // An int in the host's order, little on every target.
            match c_int::from_le_bytes(code) {
                0 => Ok(0),
                code => Err(code),
            }
        }
    }
    // rr: end(os = macos)

    // rr: section(os = windows)
    /// Windows: an I/O completion port, with AcceptEx, ConnectEx, WSARecv
    /// and WSASend, as TigerBeetle's and libuv's; timeouts are the Io's own.
    #[cfg(windows)]
    mod backend {
        use super::os::c::{self, WsaBuf};
        use super::os::{ABORTED, FOREIGN, SOL_SOCKET, WSA_IO_PENDING, last, socket};
        use super::{
            Answer, Error, Pool, Raw, Slot, State, Work, end_many, running, settle, user_data,
        };
        use crate::base::thread::INFINITE;
        use alloc::collections::VecDeque;
        use alloc::sync::Arc;
        use alloc::vec::Vec;
        use core::ffi::c_void;
        use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        use core::ptr::{null, null_mut, without_provenance_mut};
        use core::time::Duration;

        /// struct OVERLAPPED_ENTRY: 32 bytes on 64-bit Windows.
        #[repr(C)]
        struct Entry {
            key: usize,
            overlapped: *mut c_void,
            internal: usize,
            transferred: u32,
        }

        const _: () = assert!(size_of::<Entry>() == 32);

        /// mswsock.h's AcceptEx and ConnectEx, which WSAIoctl hands out.
        type AcceptEx = unsafe extern "system" fn(
            listener: usize,
            accept: usize,
            output: *mut c_void,
            data: u32,
            local: u32,
            remote: u32,
            received: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        type ConnectEx = unsafe extern "system" fn(
            socket: usize,
            name: *const u8,
            length: i32,
            send: *const c_void,
            send_length: u32,
            sent: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;

        #[link(name = "kernel32", kind = "raw-dylib")]
        // rr: escape(unsafe): each signature is kernel32's, from its
        // documentation.
        unsafe extern "system" {
            #[must_use]
            fn CreateIoCompletionPort(
                file: *mut c_void,
                existing: *mut c_void,
                key: usize,
                threads: u32,
            ) -> *mut c_void;
            #[must_use]
            fn GetQueuedCompletionStatusEx(
                port: *mut c_void,
                entries: *mut Entry,
                count: u32,
                removed: *mut u32,
                milliseconds: u32,
                alertable: i32,
            ) -> i32;
            #[must_use]
            fn PostQueuedCompletionStatus(
                port: *mut c_void,
                transferred: u32,
                key: usize,
                overlapped: *mut c_void,
            ) -> i32;
            #[must_use]
            fn CancelIoEx(file: *mut c_void, overlapped: *mut c_void) -> i32;
            #[must_use]
            fn CloseHandle(handle: *mut c_void) -> i32;
            #[must_use]
            fn QueryPerformanceCounter(count: *mut i64) -> i32;
            #[must_use]
            fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
            #[must_use]
            fn GetLastError() -> u32;
        }

        // winsock2.h's, mswsock.h's and winbase.h's.
        const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
        const SO_UPDATE_ACCEPT_CONTEXT: i32 = 0x700B;
        const SO_UPDATE_CONNECT_CONTEXT: i32 = 0x7010;
        const WAIT_TIMEOUT: u32 = 258;
        /// winerror.h: a datagram longer than the buffer given for it.
        const WSAEMSGSIZE: i32 = 10040;
        /// WSAID_ACCEPTEX and WSAID_CONNECTEX, as GUIDs lie in memory.
        const ACCEPTEX: [u8; 16] = guid(
            0xb536_7df1,
            0xcbac,
            0x11cf,
            [0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92],
        );
        const CONNECTEX: [u8; 16] = guid(
            0x25a2_07b9,
            0xddf3,
            0x4660,
            [0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e],
        );
        /// Each address AcceptEx writes: a sockaddr_in6 and 16 bytes.
        const ACCEPTED: u32 = 44;
        /// The completions one wait takes; the rest, the next.
        const BATCH: usize = 256;

        const fn guid(first: u32, second: u16, third: u16, rest: [u8; 8]) -> [u8; 16] {
            let [a, b, c, d] = first.to_le_bytes();
            let [e, f] = second.to_le_bytes();
            let [g, h] = third.to_le_bytes();
            let [i, j, k, l, m, n, o, p] = rest;
            [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]
        }

        fn handle(socket: usize) -> *mut c_void {
            without_provenance_mut(socket)
        }

        /// The completion port, which the Io and each Waker hold: a Waker
        /// posts a completion of no operation to it.
        pub struct Wake {
            port: usize,
        }

        impl Wake {
            fn port(&self) -> *mut c_void {
                handle(self.port)
            }

            pub fn wake(&self) {
                // rr: escape(unsafe): a post without an OVERLAPPED, which a
                // wait passes over; a port that refuses one is gone.
                unsafe {
                    // rr: escape(discard): a post without an OVERLAPPED, which
                    // a wait passes over; a port that refuses one is gone.
                    let _: i32 = PostQueuedCompletionStatus(self.port(), 0, 0, null_mut());
                }
            }
        }

        impl Drop for Wake {
            fn drop(&mut self) {
                // rr: escape(unsafe): the port is this value's own; close
                // releases it whatever it answers.
                unsafe {
                    // rr: escape(discard): the port is this value's own; close
                    // releases it whatever it answers.
                    let _: i32 = CloseHandle(self.port());
                }
            }
        }

        // rr: escape(unsafe): a completion port is the process's, which any
        // thread may wait on; entries are scratch whose pointers name the
        // Io's slots. An Io is moved whole, never shared.
        unsafe impl Send for Backend {}

        pub struct Backend {
            queue: Arc<Wake>,
            accept_ex: AcceptEx,
            connect_ex: ConnectEx,
            entries: Vec<Entry>,
            /// Operations the system refused at once, which post nothing:
            /// their answers, at the next wait, which takes them into
            /// retried first.
            refused: VecDeque<(u64, i32)>,
            retried: VecDeque<(u64, i32)>,
            /// The running timeouts by deadline, soonest first.
            timers: Vec<(u64, u64)>,
            /// The chunks receive_many reads into, one WSARecv at a time.
            pub pool: Pool,
        }

        /// The extension function that guid names, from a socket of the
        /// provider: the output is a pointer the call writes.
        fn extension(socket: usize, guid: &[u8; 16], out: *mut c_void) -> Result<(), Error> {
            let mut returned = 0u32;
            // rr: escape(unsafe): guid is 16 bytes; out holds a pointer.
            let done = unsafe {
                c::WSAIoctl(
                    socket,
                    SIO_GET_EXTENSION_FUNCTION_POINTER,
                    guid.as_ptr().cast(),
                    16,
                    out,
                    u32::try_from(size_of::<usize>()).unwrap_or(8),
                    &raw mut returned,
                    null_mut(),
                    null(),
                )
            };
            if done == 0 {
                Ok(())
            } else {
                Err(super::os::error(last()))
            }
        }

        impl Backend {
            pub fn new(ops: u32, pool: Pool) -> Result<Backend, Error> {
                let probe = super::Fd::new(
                    socket(super::os::AF_INET, super::Kind::Stream).map_err(super::os::error)?,
                );
                let mut accept_ex: Option<AcceptEx> = None;
                let mut connect_ex: Option<ConnectEx> = None;
                extension(probe.raw, &ACCEPTEX, (&raw mut accept_ex).cast())?;
                extension(probe.raw, &CONNECTEX, (&raw mut connect_ex).cast())?;
                let (Some(accept_ex), Some(connect_ex)) = (accept_ex, connect_ex) else {
                    return Err(Error::Other(0));
                };
                // rr: escape(unsafe): a new port takes no file.
                let port = unsafe { CreateIoCompletionPort(handle(usize::MAX), null_mut(), 0, 1) };
                if port.is_null() {
                    // rr: escape(unsafe): the thread's last error.
                    let code = unsafe { GetLastError() };
                    return Err(Error::Other(i32::try_from(code).unwrap_or(0)));
                }
                let mut entries = Vec::with_capacity(BATCH);
                entries.resize_with(BATCH, || Entry {
                    key: 0,
                    overlapped: null_mut(),
                    internal: 0,
                    transferred: 0,
                });
                let ops = ops as usize;
                Ok(Backend {
                    // rr: escape(shared): the Io and each Waker hold the port.
                    queue: Arc::new(Wake { port: port.addr() }),
                    accept_ex,
                    connect_ex,
                    entries,
                    refused: VecDeque::with_capacity(ops),
                    retried: VecDeque::with_capacity(ops),
                    timers: Vec::with_capacity(ops),
                    pool,
                })
            }

            pub fn give_back(&mut self, id: u16) {
                self.pool.put(id);
            }

            pub fn waker(&self) -> Arc<Wake> {
                // rr: escape(copy): a Waker holds the port too.
                Arc::clone(&self.queue)
            }

            /// Now on the monotonic clock, in nanoseconds.
            #[must_use]
            pub fn now() -> u64 {
                let (mut count, mut frequency) = (0i64, 0i64);
                // rr: escape(unsafe): count is a local LARGE_INTEGER.
                unsafe {
                    // rr: escape(discard): the call cannot fail from Windows
                    // XP on.
                    let _: i32 = QueryPerformanceCounter(&raw mut count);
                }
                // rr: escape(unsafe): frequency is a local LARGE_INTEGER.
                unsafe {
                    // rr: escape(discard): nor this one.
                    let _: i32 = QueryPerformanceFrequency(&raw mut frequency);
                }
                let ticks = u128::from(u64::try_from(count).unwrap_or(0));
                let hertz = u128::from(u64::try_from(frequency).unwrap_or(1).max(1));
                let nanos = (ticks * 1_000_000_000).checked_div(hertz).unwrap_or(0);
                u64::try_from(nanos).unwrap_or(u64::MAX)
            }

            /// Puts the socket in this port, once: one in another's is
            /// refused.
            fn associate(&self, fd: &mut super::Fd) -> Result<(), i32> {
                let port = self.queue.port;
                if fd.port == port {
                    return Ok(());
                }
                if fd.port != 0 {
                    return Err(FOREIGN);
                }
                // rr: escape(unsafe): the socket is open; a SOCKET is a
                // handle.
                let done =
                    unsafe { CreateIoCompletionPort(handle(fd.raw), self.queue.port(), 0, 0) };
                if done.is_null() {
                    return Err(FOREIGN);
                }
                fd.port = port;
                Ok(())
            }

            pub fn submit(&mut self, data: u64, slot: &mut Slot) {
                slot.overlapped = [0; 4];
                if let Work::Timeout(after) = slot.work {
                    let nanos = u64::try_from(after.as_nanos()).unwrap_or(u64::MAX);
                    let deadline = Backend::now().saturating_add(nanos);
                    let at = self.timers.partition_point(|&(d, _)| d <= deadline);
                    // rr: escape(bound): one entry for each running timeout,
                    // and there are as many as the table.
                    self.timers.insert(at, (deadline, data));
                    return;
                }
                if slot.limit.is_some() && !slot.limited {
                    let limit = slot
                        .limit
                        .map_or(0, |l| u64::try_from(l.as_nanos()).unwrap_or(u64::MAX));
                    let deadline = Backend::now().saturating_add(limit);
                    let at = self.timers.partition_point(|&(d, _)| d <= deadline);
                    // rr: escape(bound): one entry for each running operation
                    // at most.
                    self.timers.insert(at, (deadline, data));
                    slot.limited = true;
                }
                if let Err(code) = self.start(slot) {
                    // rr: escape(bound): one entry for each running
                    // operation at most.
                    self.refused.push_back((data, code));
                }
            }

            /// Starts a socket's operation: Err when the system refused it
            /// and will post nothing.
            fn start(&mut self, slot: &mut Slot) -> Result<(), i32> {
                let overlapped = slot.overlapped.as_mut_ptr().cast::<c_void>();
                let done = match &mut slot.work {
                    Work::Accept(listener) => {
                        self.associate(&mut listener.fd)?;
                        let family =
                            super::os::local(listener.fd.raw).map_or(super::os::AF_INET, |a| {
                                if a.is_ipv4() {
                                    super::os::AF_INET
                                } else {
                                    super::os::AF_INET6
                                }
                            });
                        let accepting = socket(family, super::Kind::Stream)?;
                        slot.accepting = Some(accepting);
                        let mut received = 0u32;
                        // rr: escape(unsafe): accepted holds both addresses;
                        // the OVERLAPPED is the slot's, which does not move.
                        let accepted = unsafe {
                            (self.accept_ex)(
                                listener.fd.raw,
                                accepting,
                                slot.accepted.as_mut_ptr().cast(),
                                0,
                                ACCEPTED,
                                ACCEPTED,
                                &raw mut received,
                                overlapped,
                            )
                        };
                        if accepted != 0 { 0 } else { -1 }
                    }
                    Work::Connect(stream) => {
                        self.associate(&mut stream.fd)?;
                        let any = if super::os::family_of(&slot.address) == Some(super::os::AF_INET)
                        {
                            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
                        } else {
                            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
                        };
                        let (bytes, length) = super::encode(&any);
                        super::os::bind_code(
                            stream.fd.raw,
                            bytes.get(..length).unwrap_or_default(),
                        )?;
                        let named = i32::try_from(slot.length).unwrap_or(0);
                        // rr: escape(unsafe): address holds a sockaddr of
                        // length bytes; the OVERLAPPED is the slot's.
                        let connected = unsafe {
                            (self.connect_ex)(
                                stream.fd.raw,
                                slot.address.as_ptr(),
                                named,
                                null(),
                                0,
                                null_mut(),
                                overlapped,
                            )
                        };
                        if connected != 0 { 0 } else { -1 }
                    }
                    Work::Receive(stream, buffer) => {
                        self.associate(&mut stream.fd)?;
                        let room = buffer.spare_capacity_mut();
                        let parts = WsaBuf {
                            len: u32::try_from(room.len()).unwrap_or(u32::MAX),
                            buf: room.as_mut_ptr().cast(),
                        };
                        let mut flags = 0u32;
                        // rr: escape(unsafe): the WSABUF names the buffer's
                        // room, which the slot holds until the answer.
                        unsafe {
                            c::WSARecv(
                                stream.fd.raw,
                                &raw const parts,
                                1,
                                null_mut(),
                                &raw mut flags,
                                overlapped,
                                null(),
                            )
                        }
                    }
                    Work::Send(stream, buffer, sent) => {
                        self.associate(&mut stream.fd)?;
                        let rest = buffer.get_mut(*sent..).unwrap_or_default();
                        let parts = WsaBuf {
                            len: u32::try_from(rest.len()).unwrap_or(u32::MAX),
                            buf: rest.as_mut_ptr(),
                        };
                        // rr: escape(unsafe): the WSABUF names the rest of
                        // the buffer, which the slot holds until the answer.
                        unsafe {
                            c::WSASend(
                                stream.fd.raw,
                                &raw const parts,
                                1,
                                null_mut(),
                                0,
                                overlapped,
                                null(),
                            )
                        }
                    }
                    Work::SendTo(udp, buffer) => {
                        self.associate(&mut udp.fd)?;
                        let parts = WsaBuf {
                            len: u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                            buf: buffer.as_mut_ptr(),
                        };
                        let to = i32::try_from(slot.length).unwrap_or(0);
                        // rr: escape(unsafe): the WSABUF names the buffer and
                        // address a sockaddr of to bytes, both the slot's
                        // until the answer.
                        unsafe {
                            c::WSASendTo(
                                udp.fd.raw,
                                &raw const parts,
                                1,
                                null_mut(),
                                0,
                                slot.address.as_ptr(),
                                to,
                                overlapped,
                                null(),
                            )
                        }
                    }
                    Work::ReceiveFrom(udp, buffer) => {
                        self.associate(&mut udp.fd)?;
                        let room = buffer.spare_capacity_mut();
                        let parts = WsaBuf {
                            len: u32::try_from(room.len()).unwrap_or(u32::MAX),
                            buf: room.as_mut_ptr().cast(),
                        };
                        let mut flags = 0u32;
                        // rr: escape(unsafe): the WSABUF names the buffer's
                        // room, and the address and its length (an int, as
                        // length is) are the slot's until the answer.
                        unsafe {
                            c::WSARecvFrom(
                                udp.fd.raw,
                                &raw const parts,
                                1,
                                null_mut(),
                                &raw mut flags,
                                slot.address.as_mut_ptr(),
                                (&raw mut slot.length).cast(),
                                overlapped,
                                null(),
                            )
                        }
                    }
                    Work::ReceiveMany(stream) => {
                        self.associate(&mut stream.fd)?;
                        // No chunk free: a receive of no bytes, which answers
                        // once something came.
                        let id = self.pool.take();
                        slot.chunk = id;
                        let parts = match id {
                            Some(id) => WsaBuf {
                                len: u32::try_from(self.pool.size).unwrap_or(u32::MAX),
                                buf: self.pool.at(id),
                            },
                            None => WsaBuf {
                                len: 0,
                                buf: null_mut(),
                            },
                        };
                        let mut flags = 0u32;
                        // rr: escape(unsafe): the WSABUF names a chunk out of
                        // the pool, the operation's until its answer.
                        unsafe {
                            c::WSARecv(
                                stream.fd.raw,
                                &raw const parts,
                                1,
                                null_mut(),
                                &raw mut flags,
                                overlapped,
                                null(),
                            )
                        }
                    }
                    Work::SendChunk {
                        fd,
                        id,
                        length,
                        sent,
                    } => {
                        let parts = WsaBuf {
                            len: length.saturating_sub(*sent),
                            buf: self.pool.at(*id).wrapping_add(*sent as usize),
                        };
                        // rr: escape(unsafe): the WSABUF names the rest of a
                        // chunk out of the pool, the operation's until its
                        // answer.
                        unsafe {
                            c::WSASend(*fd, &raw const parts, 1, null_mut(), 0, overlapped, null())
                        }
                    }
                    Work::Idle | Work::Timeout(_) | Work::Run(_) | Work::Finished(_) => {
                        return Ok(());
                    }
                };
                if done == 0 {
                    return Ok(());
                }
                match last() {
                    WSA_IO_PENDING => Ok(()),
                    code => Err(code),
                }
            }

            /// A timeout ends at once; a socket's operation when the port
            /// says so, aborted.
            #[must_use]
            pub fn cancel(&mut self, data: u64, slot: &mut Slot) -> bool {
                if let Work::Timeout(_) = slot.work {
                    self.timers.retain(|&(_, d)| d != data);
                    // rr: escape(discard): a timeout is never tried again.
                    let _: bool = settle(slot, Err(ABORTED));
                    return true;
                }
                if slot.limited {
                    slot.limited = false;
                    self.timers.retain(|&(_, d)| d != data);
                }
                abort(slot);
                false
            }

            pub fn wait(
                &mut self,
                slots: &mut [Slot],
                ready: &mut VecDeque<u32>,
                timeout: Option<Duration>,
            ) -> Result<(), Error> {
                // What is refused again waits for the next wait.
                core::mem::swap(&mut self.refused, &mut self.retried);
                while let Some((data, code)) = self.retried.pop_front() {
                    self.answer(slots, ready, data, Err(code));
                }
                let now = Backend::now();
                let mut wait = timeout.map(|t| u64::try_from(t.as_nanos()).unwrap_or(u64::MAX));
                if let Some(&(deadline, _)) = self.timers.first() {
                    let until = deadline.saturating_sub(now);
                    wait = Some(wait.map_or(until, |w| w.min(until)));
                }
                if !ready.is_empty() {
                    wait = Some(0);
                }
                let milliseconds = wait.map_or(INFINITE, |ns| {
                    u32::try_from(ns.div_ceil(1_000_000))
                        .unwrap_or(INFINITE - 1)
                        .min(INFINITE - 1)
                });
                let removed = self.dequeue(milliseconds)?;
                let base = slots.as_ptr().addr();
                for i in 0..removed {
                    let Some(entry) = self.entries.get(i) else {
                        break;
                    };
                    let Some(index) = slot_of(base, entry.overlapped) else {
                        continue;
                    };
                    let (status, transferred) = (entry.internal, entry.transferred);
                    let Some(slot) = slots.get_mut(index) else {
                        continue;
                    };
                    if slot.state != State::Running {
                        continue;
                    }
                    let data = user_data(u32::try_from(index).unwrap_or(0), slot.generation);
                    let answer = complete(slot, status, transferred);
                    self.answer(slots, ready, data, answer);
                }
                self.expire(slots, ready);
                Ok(())
            }

            /// Takes what the port has, waiting so many milliseconds for it:
            /// how many entries it filled.
            fn dequeue(&mut self, milliseconds: u32) -> Result<usize, Error> {
                let mut removed = 0u32;
                let count = u32::try_from(self.entries.len()).unwrap_or(0);
                // rr: escape(unsafe): entries holds count entries.
                let got = unsafe {
                    GetQueuedCompletionStatusEx(
                        self.queue.port(),
                        self.entries.as_mut_ptr(),
                        count,
                        &raw mut removed,
                        milliseconds,
                        0,
                    )
                };
                if got != 0 {
                    return Ok((removed as usize).min(self.entries.len()));
                }
                // rr: escape(unsafe): the thread's last error.
                match unsafe { GetLastError() } {
                    WAIT_TIMEOUT => Ok(0),
                    code => Err(Error::Other(i32::try_from(code).unwrap_or(0))),
                }
            }

            /// Settles an operation as the system answered it, and starts it
            /// again or hands it to ready.
            fn answer(
                &mut self,
                slots: &mut [Slot],
                ready: &mut VecDeque<u32>,
                data: u64,
                answer: Answer,
            ) {
                let Some((index, slot)) = running(slots, data) else {
                    return;
                };
                if let Work::ReceiveMany(_) = slot.work {
                    self.many(slot, index, ready, data, answer);
                    return;
                }
                if settle(slot, answer) {
                    self.submit(data, slot);
                    return;
                }
                if slot.limited {
                    slot.limited = false;
                    self.timers.retain(|&(_, d)| d != data);
                }
                ready.push_back(u32::try_from(index).unwrap_or(0));
            }

            /// A receive_many's answer: its chunk filled and the next started,
            /// or its end, the chunk given back.
            fn many(
                &mut self,
                slot: &mut Slot,
                index: usize,
                ready: &mut VecDeque<u32>,
                data: u64,
                answer: Answer,
            ) {
                let id = slot.chunk.take();
                let result = match (answer, id) {
                    // The receive of no bytes: something came; a chunk now
                    // free takes it, or it was more than there was room for.
                    (Ok(_), None) if self.pool.free.is_empty() => Err(Error::NoChunks),
                    (Ok(_), None) if !slot.canceled => {
                        self.submit(data, slot);
                        return;
                    }
                    (Ok(count), Some(id)) if count > 0 => {
                        self.pool
                            .fill(slot.key, id, u32::try_from(count).unwrap_or(u32::MAX));
                        if !slot.canceled {
                            self.submit(data, slot);
                            return;
                        }
                        Err(Error::Canceled)
                    }
                    (Ok(_), _) => Ok(()),
                    (Err(code), _) => Err(super::os::error(code)),
                };
                if let Some(id) = slot.chunk.take().or(id) {
                    self.pool.put(id);
                }
                if end_many(slot, result) {
                    ready.push_back(u32::try_from(index).unwrap_or(0));
                }
            }

            /// Ends the timeouts whose deadlines passed, soonest first.
            fn expire(&mut self, slots: &mut [Slot], ready: &mut VecDeque<u32>) {
                let now = Backend::now();
                let passed = self.timers.partition_point(|&(d, _)| d <= now);
                for (_, data) in self.timers.drain(..passed) {
                    let Some((index, slot)) = running(slots, data) else {
                        continue;
                    };
                    if let Work::Timeout(_) = slot.work {
                        if !settle(slot, Ok(0)) {
                            ready.push_back(u32::try_from(index).unwrap_or(0));
                        }
                        continue;
                    }
                    // An operation's time ran out: the port answers it
                    // aborted, which settle takes as timed out.
                    slot.limited = false;
                    slot.expired = true;
                    abort(slot);
                }
            }

            /// Cancels every operation and waits until the port answered
            /// each, so that none writes a buffer freed after: nothing is
            /// settled or started again, as the Io is going.
            pub fn close(&mut self, slots: &mut [Slot]) {
                self.timers.clear();
                for slot in slots.iter_mut() {
                    if slot.state != State::Running {
                        continue;
                    }
                    let Some(fd) = slot.fd() else {
                        slot.state = State::Ready;
                        continue;
                    };
                    let overlapped = slot.overlapped.as_mut_ptr().cast::<c_void>();
                    // rr: escape(unsafe): the OVERLAPPED is the operation's;
                    // one done already answers as it would.
                    unsafe {
                        // rr: escape(discard): the OVERLAPPED is the
                        // operation's; one done already answers as it would.
                        let _: i32 = CancelIoEx(handle(fd), overlapped);
                    }
                }
                // Each turn takes answers, or waits a second for one: an
                // aborted operation answers at once.
                let turns = slots.len().saturating_mul(2).saturating_add(8);
                let mut turn = 0;
                while turn < turns && slots.iter().any(|s| s.state == State::Running) {
                    turn += 1;
                    let Ok(removed) = self.dequeue(1000) else {
                        return;
                    };
                    let base = slots.as_ptr().addr();
                    for i in 0..removed {
                        let Some(entry) = self.entries.get(i) else {
                            break;
                        };
                        let Some(slot) =
                            slot_of(base, entry.overlapped).and_then(|index| slots.get_mut(index))
                        else {
                            continue;
                        };
                        slot.state = State::Ready;
                        if let Some(accepting) = slot.accepting.take() {
                            super::os::close(accepting);
                        }
                    }
                }
            }
        }

        /// Asks the port to end a socket's operation, which then answers
        /// aborted; one done already is not found, and answers as it would.
        fn abort(slot: &mut Slot) {
            let Some(fd) = slot.fd() else {
                return;
            };
            let overlapped = slot.overlapped.as_mut_ptr().cast::<c_void>();
            // rr: escape(unsafe): the OVERLAPPED is the operation's.
            unsafe {
                // rr: escape(discard): an operation done already is not found,
                // and its answer comes as it would.
                let _: i32 = CancelIoEx(handle(fd), overlapped);
            }
        }

        /// The slot whose OVERLAPPED, its first field, is at overlapped, for
        /// slots at base; None for one not in them, as a Waker's post is.
        fn slot_of(base: usize, overlapped: *mut c_void) -> Option<usize> {
            let offset = overlapped.addr().checked_sub(base)?;
            let size = size_of::<Slot>();
            (offset.checked_rem(size)? == 0).then_some(())?;
            offset.checked_div(size)
        }

        /// What a completion says of its operation; an accept's socket made
        /// a connection's, a connect's made usable.
        fn complete(slot: &mut Slot, status: usize, transferred: u32) -> Answer {
            let accepting = slot.accepting.take();
            let fd = slot.fd().unwrap_or(0);
            if status != 0 {
                if let Some(accepting) = accepting {
                    super::os::close(accepting);
                }
                let overlapped = slot.overlapped.as_mut_ptr().cast::<c_void>();
                let (mut count, mut flags) = (0u32, 0u32);
                // rr: escape(unsafe): the OVERLAPPED is the operation's, done.
                let done = unsafe {
                    c::WSAGetOverlappedResult(fd, overlapped, &raw mut count, 0, &raw mut flags)
                };
                if done != 0 {
                    return Err(ABORTED);
                }
                // A datagram longer than the room fills it and says so; it is
                // cut to the room, as Linux and macOS cut it.
                return match (last(), &slot.work) {
                    (WSAEMSGSIZE, Work::ReceiveFrom(..)) => Ok(count as usize),
                    (code, _) => Err(code),
                };
            }
            match &slot.work {
                Work::Accept(_) => {
                    let Some(accepting) = accepting else {
                        return Err(ABORTED);
                    };
                    let listener: Raw = fd;
                    let context = super::os::option(
                        accepting,
                        SOL_SOCKET,
                        SO_UPDATE_ACCEPT_CONTEXT,
                        &listener.to_le_bytes(),
                    );
                    let mut size = super::os::length(&slot.address);
                    // rr: escape(unsafe): address holds size bytes.
                    let named = unsafe {
                        c::getpeername(accepting, slot.address.as_mut_ptr(), &raw mut size)
                    };
                    if context.is_err() || named != 0 {
                        let code = last();
                        super::os::close(accepting);
                        return Err(code);
                    }
                    slot.length = u32::try_from(size).unwrap_or(0);
                    Ok(accepting)
                }
                Work::Connect(_) => {
                    // The socket itself as the option's value, as Go's
                    // net/fd_windows.go gives it.
                    let own: Raw = fd;
                    match super::os::option(
                        fd,
                        SOL_SOCKET,
                        SO_UPDATE_CONNECT_CONTEXT,
                        &own.to_le_bytes(),
                    ) {
                        Ok(()) => Ok(0),
                        Err(_) => Err(last()),
                    }
                }
                Work::Idle
                | Work::Receive(..)
                | Work::Send(..)
                | Work::SendTo(..)
                | Work::ReceiveFrom(..)
                | Work::ReceiveMany(_)
                | Work::SendChunk { .. }
                | Work::Timeout(_)
                | Work::Run(_)
                | Work::Finished(_) => Ok(transferred as usize),
            }
        }
    }
    // rr: end(os = windows)
}

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    //! io's tests on real sockets: TCP over loopback, a server and its
    //! clients in one Io, as a loop runs them.

    use super::{Done, Error, Event, Io, Listener, Stream, Udp, Unavailable, Work};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use core::sync::atomic::{AtomicU64, Ordering};
    use core::time::Duration;
    use test::Bencher;

    const ACCEPT: u64 = 1;
    const CONNECT: u64 = 2;
    const SERVER: u64 = 3;
    const CLIENT: u64 = 4;
    const TURN: Duration = Duration::from_millis(10);

    fn io(ops: usize) -> Io {
        match Io::new(ops) {
            Ok(io) => io,
            Err(Error::Unavailable(why)) => panic!("no io_uring: {why:?}"),
            Err(e) => panic!("Io::new: {e:?}"),
        }
    }

    fn v4() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    fn v6() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
    }

    /// The next event, within five seconds.
    fn next(io: &mut Io) -> Event {
        for _ in 0..500 {
            if let Some(event) = io.next() {
                return event;
            }
            io.wait(Some(TURN)).unwrap();
        }
        panic!("no event in five seconds");
    }

    /// A connection to a listener on address: the server's end, the
    /// client's, and the listener.
    fn pair(io: &mut Io, address: SocketAddr) -> (Stream, Stream, Listener) {
        let bound = Listener::bind(address, 16).unwrap();
        let at = bound.local().unwrap();
        assert!(io.accept(bound, ACCEPT).is_ok());
        assert!(io.connect(at, CONNECT).is_ok());
        let (mut server, mut client, mut listening) = (None, None, None);
        for _ in 0..2 {
            let event = next(io);
            if let Done::Accepted { listener, result } = event.done {
                let (stream, peer) = result.unwrap();
                assert_eq!(peer.ip(), at.ip());
                server = Some(stream);
                listening = Some(listener);
            } else if let Done::Connected(result) = event.done {
                client = Some(result.unwrap());
            } else {
                panic!("not a connection");
            }
        }
        (server.unwrap(), client.unwrap(), listening.unwrap())
    }

    fn send(io: &mut Io, stream: Stream, bytes: &[u8], key: u64) {
        let mut buffer = Vec::with_capacity(bytes.len());
        // rr: escape(copy): the send owns its buffer.
        buffer.extend_from_slice(bytes);
        assert!(io.send(stream, buffer, key).is_ok());
    }

    fn receive(io: &mut Io, stream: Stream, room: usize, key: u64) {
        assert!(io.receive(stream, Vec::with_capacity(room), key).is_ok());
    }

    fn sent(event: Event) -> Stream {
        let Done::Sent { stream, result, .. } = event.done else {
            panic!("not a send");
        };
        result.unwrap();
        stream
    }

    fn received(event: Event) -> (Stream, Vec<u8>) {
        let Done::Received {
            stream,
            buffer,
            result,
        } = event.done
        else {
            panic!("not a receive");
        };
        assert_eq!(result.unwrap(), buffer.len());
        (stream, buffer)
    }

    #[test]
    fn echo_both_families() {
        for address in [v4(), v6()] {
            let mut io = io(8);
            let (server, client, _listener) = pair(&mut io, address);
            send(&mut io, client, b"hello", CLIENT);
            receive(&mut io, server, 64, SERVER);
            let (mut back, mut served) = (None, None);
            for _ in 0..2 {
                let event = next(&mut io);
                if event.key == CLIENT {
                    back = Some(sent(event));
                } else {
                    let (stream, buffer) = received(event);
                    assert_eq!(buffer, b"hello");
                    served = Some(stream);
                }
            }
            send(&mut io, served.unwrap(), b"back", SERVER);
            receive(&mut io, back.unwrap(), 64, CLIENT);
            for _ in 0..2 {
                let event = next(&mut io);
                if event.key == CLIENT {
                    assert_eq!(received(event).1, b"back");
                }
            }
        }
    }

    #[test]
    fn appends_after_what_it_holds() {
        let mut io = io(8);
        let (server, client, _listener) = pair(&mut io, v4());
        send(&mut io, client, b"two", CLIENT);
        let _client = sent(next(&mut io));
        let mut buffer = Vec::with_capacity(16);
        buffer.extend_from_slice(b"one ");
        assert!(io.receive(server, buffer, SERVER).is_ok());
        let Done::Received {
            buffer: got,
            result,
            ..
        } = next(&mut io).done
        else {
            panic!("not a receive");
        };
        assert_eq!(result, Ok(3));
        assert_eq!(got, b"one two");
    }

    #[test]
    fn timeouts_in_order() {
        let mut io = io(8);
        for ms in [30u64, 10, 20] {
            assert!(io.timeout(Duration::from_millis(ms), ms).is_ok());
        }
        for ms in [10, 20, 30] {
            assert_eq!(next(&mut io).key, ms);
        }
    }

    #[test]
    fn cancel() {
        let mut io = io(8);
        let (server, _client, _listener) = pair(&mut io, v4());
        let mut held = Vec::with_capacity(16);
        held.push(7);
        let Ok(receiving) = io.receive(server, held, SERVER) else {
            panic!("full");
        };
        let Ok(timer) = io.timeout(Duration::from_secs(60), CLIENT) else {
            panic!("full");
        };
        assert_eq!(io.wait(Some(Duration::ZERO)), Ok(0));
        assert!(io.cancel(&receiving));
        assert!(io.cancel(&timer));
        assert!(!io.cancel(&timer));
        let mut seen = 0;
        for _ in 0..2 {
            let event = next(&mut io);
            if let Done::Received { buffer, result, .. } = event.done {
                assert_eq!(result, Err(Error::Canceled));
                assert_eq!(buffer, [7]);
                seen |= 1;
            } else if let Done::Elapsed(result) = event.done {
                assert_eq!(result, Err(Error::Canceled));
                seen |= 2;
            } else {
                panic!("another operation");
            }
        }
        assert_eq!(seen, 3);
    }

    /// A receive within a time gives up with TimedOut once it passed, its
    /// buffer as it was; one the peer answers in time receives; a send
    /// within a time sends.
    #[test]
    fn within() {
        let mut io = io(8);
        let (server, client, _listener) = pair(&mut io, v4());
        let mut held = Vec::with_capacity(16);
        held.push(7);
        let quick = Duration::from_millis(30);
        assert!(io.receive_within(server, held, quick, SERVER).is_ok());
        let Done::Received {
            stream: quiet,
            buffer,
            result,
        } = next(&mut io).done
        else {
            panic!("not a receive");
        };
        assert_eq!(result, Err(Error::TimedOut));
        assert_eq!(buffer, [7]);
        let long = Duration::from_secs(10);
        assert!(
            io.receive_within(quiet, Vec::with_capacity(16), long, SERVER)
                .is_ok()
        );
        let mut bytes = Vec::with_capacity(4);
        bytes.extend_from_slice(b"late");
        assert!(io.send_within(client, bytes, long, CLIENT).is_ok());
        for _ in 0..2 {
            let event = next(&mut io);
            if event.key == CLIENT {
                let _client = sent(event);
            } else {
                assert_eq!(received(event).1, b"late");
            }
        }
        // The time of one done in time does not end another in its slot.
        assert!(io.timeout(Duration::from_millis(60), 9).is_ok());
        assert_eq!(next(&mut io).key, 9);
    }

    #[test]
    fn cancel_after_done() {
        let mut io = io(8);
        let Ok(timer) = io.timeout(Duration::ZERO, 1) else {
            panic!("full");
        };
        let event = next(&mut io);
        assert!(matches!(event.done, Done::Elapsed(Ok(()))));
        assert!(!io.cancel(&timer));
    }

    #[test]
    fn full_table_hands_back() {
        let mut io = io(2);
        assert!(io.timeout(Duration::from_secs(60), 1).is_ok());
        assert!(io.timeout(Duration::from_secs(60), 2).is_ok());
        let three = Duration::from_secs(3);
        assert_eq!(io.timeout(three, 3).err(), Some(three));
        let listener = Listener::bind(v4(), 1).unwrap();
        let at = listener.local();
        let Err(back) = io.accept(listener, 4) else {
            panic!("room in a full table");
        };
        assert_eq!(back.local(), at);
    }

    #[test]
    fn no_room() {
        let mut io = io(8);
        let (server, _client, _listener) = pair(&mut io, v4());
        assert!(io.receive(server, Vec::new(), SERVER).is_ok());
        let Done::Received { result, .. } = next(&mut io).done else {
            panic!("not a receive");
        };
        assert_eq!(result, Err(Error::NoRoom));
    }

    #[test]
    fn refused() {
        let mut io = io(8);
        let listener = Listener::bind(v4(), 1).unwrap();
        let at = listener.local().unwrap();
        drop(listener);
        assert!(io.connect(at, CONNECT).is_ok());
        let Done::Connected(result) = next(&mut io).done else {
            panic!("not a connect");
        };
        assert_eq!(result.err(), Some(Error::Refused));
    }

    #[test]
    fn peer_end() {
        let mut io = io(8);
        let (server, client, _listener) = pair(&mut io, v4());
        drop(client);
        receive(&mut io, server, 16, SERVER);
        assert!(received(next(&mut io)).1.is_empty());
    }

    #[test]
    fn finish_ends_what_it_sends() {
        let mut io = io(8);
        let (server, client, _listener) = pair(&mut io, v4());
        client.finish().unwrap();
        receive(&mut io, server, 16, SERVER);
        assert!(received(next(&mut io)).1.is_empty());
    }

    /// A send larger than what the system buffers ends when the peer has
    /// read it all: none of it is lost or sent twice.
    #[test]
    fn large_send() {
        let mut io = io(8);
        let (server, client, _listener) = pair(&mut io, v4());
        let size = 8 << 20;
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        assert!(io.send(client, buffer, CLIENT).is_ok());
        receive(&mut io, server, 64 << 10, SERVER);
        let mut got = 0usize;
        let mut done = false;
        while !done || got < size {
            let event = next(&mut io);
            if event.key == CLIENT {
                let _client = sent(event);
                done = true;
                continue;
            }
            let (stream, part) = received(event);
            assert!(!part.is_empty());
            for (i, &b) in part.iter().enumerate() {
                assert_eq!(usize::from(b), (got + i) % 251);
            }
            got += part.len();
            if got < size {
                receive(&mut io, stream, 64 << 10, SERVER);
            }
        }
        assert_eq!(got, size);
    }

    #[test]
    fn many_connections() {
        let count = 64;
        let mut io = io(2 * count + 2);
        let bound = Listener::bind(v4(), 128).unwrap();
        let at = bound.local().unwrap();
        assert!(io.accept(bound, ACCEPT).is_ok());
        for _ in 0..count {
            assert!(io.connect(at, CONNECT).is_ok());
        }
        let (mut accepted, mut connected) = (Vec::new(), Vec::new());
        while accepted.len() < count || connected.len() < count {
            let event = next(&mut io);
            if let Done::Accepted { listener, result } = event.done {
                accepted.push(result.unwrap().0);
                if accepted.len() < count {
                    assert!(io.accept(listener, ACCEPT).is_ok());
                }
            } else if let Done::Connected(result) = event.done {
                connected.push(result.unwrap());
            } else {
                panic!("not a connection");
            }
        }
        for stream in connected {
            send(&mut io, stream, b"x", CLIENT);
        }
        for stream in accepted {
            receive(&mut io, stream, 4, SERVER);
        }
        let mut bytes = 0;
        for _ in 0..2 * count {
            let event = next(&mut io);
            if event.key == SERVER {
                bytes += received(event).1.len();
            }
        }
        assert_eq!(bytes, count);
    }

    /// An Io dropped while the system holds its buffers waits for it to
    /// let go of them.
    #[test]
    fn dropped_running() {
        let mut io = io(8);
        let (server, client, listener) = pair(&mut io, v4());
        receive(&mut io, server, 1 << 16, SERVER);
        receive(&mut io, client, 1 << 16, CLIENT);
        assert!(io.accept(listener, ACCEPT).is_ok());
        assert!(io.timeout(Duration::from_secs(60), 9).is_ok());
        assert_eq!(io.wait(Some(Duration::ZERO)), Ok(0));
        drop(io);
    }

    #[test]
    fn datagrams_both_families() {
        for address in [v4(), v6()] {
            let mut io = io(8);
            let one = Udp::bind(address).unwrap();
            let two = Udp::bind(address).unwrap();
            let (from, to) = (one.local().unwrap(), two.local().unwrap());
            let mut bytes = Vec::with_capacity(8);
            bytes.extend_from_slice(b"ping");
            assert!(io.send_to(one, bytes, to, CLIENT).is_ok());
            assert!(io.receive_from(two, Vec::with_capacity(64), SERVER).is_ok());
            for _ in 0..2 {
                let event = next(&mut io);
                if let Done::SentTo { result, .. } = event.done {
                    result.unwrap();
                } else if let Done::ReceivedFrom { buffer, result, .. } = event.done {
                    let (count, sender) = result.unwrap();
                    assert_eq!((count, &buffer[..]), (4, &b"ping"[..]));
                    assert_eq!(sender, from);
                } else {
                    panic!("not a datagram");
                }
            }
        }
    }

    /// A datagram longer than the room is cut to it; the next is whole.
    #[test]
    fn datagram_cut_to_the_room() {
        let mut io = io(8);
        let one = Udp::bind(v4()).unwrap();
        let two = Udp::bind(v4()).unwrap();
        let to = two.local().unwrap();
        let mut long = Vec::with_capacity(16);
        long.extend_from_slice(b"0123456789");
        assert!(io.send_to(one, long, to, CLIENT).is_ok());
        let Done::SentTo { udp, result, .. } = next(&mut io).done else {
            panic!("not a send");
        };
        result.unwrap();
        assert!(io.receive_from(two, Vec::with_capacity(4), SERVER).is_ok());
        let Done::ReceivedFrom { buffer, .. } = next(&mut io).done else {
            panic!("not a receive");
        };
        assert_eq!(buffer, b"0123");
        drop(udp);
    }

    /// Work that blocks runs on thread's pool, and comes back as an Event
    /// with what it found; one canceled in line never runs.
    #[test]
    fn runs_work_that_blocks() {
        let mut io = io(8);
        // rr: escape(shared): what the work found, which the test reads.
        let found = Arc::new(AtomicU64::new(0));
        let sum = Sum {
            up_to: 1000,
            // rr: escape(copy): the work's holder of what it finds.
            found: Arc::clone(&found),
        };
        assert!(io.run(Box::new(sum), 5).is_ok());
        let event = next(&mut io);
        assert_eq!(event.key, 5);
        let Done::Ran { result, .. } = event.done else {
            panic!("not a run");
        };
        assert_eq!(result, Ok(()));
        assert_eq!(found.load(Ordering::Acquire), 500_500);
    }

    struct Sum {
        up_to: u64,
        found: Arc<AtomicU64>,
    }

    impl Work for Sum {
        fn run(&mut self) {
            self.found.store((1..=self.up_to).sum(), Ordering::Release);
        }
    }

    /// What a peer sends comes in chunks of the Io's, as it comes, which
    /// send_chunk sends back; the peer's end stops the receive, after the
    /// send, with the stream.
    #[test]
    fn chunks_echo() {
        let mut io = Io::with_chunks(8, 8, 64).unwrap();
        let (server, client, _listener) = pair(&mut io, v4());
        let Ok(receiving) = io.receive_many(server, SERVER) else {
            panic!("full");
        };
        send(&mut io, client, b"hello", CLIENT);
        let mut back = None;
        let mut sent = false;
        while !sent || back.is_none() {
            let event = next(&mut io);
            if let Done::Chunk(chunk) = event.done {
                assert_eq!(io.bytes(&chunk), Some(&b"hello"[..]));
                assert!(io.send_chunk(&receiving, chunk, 7).is_ok());
            } else if let Done::SentChunk(result) = event.done {
                assert_eq!(event.key, 7);
                result.unwrap();
                sent = true;
            } else if let Done::Sent { stream, .. } = event.done {
                back = Some(stream);
            } else {
                panic!("another operation");
            }
        }
        receive(&mut io, back.unwrap(), 16, CLIENT);
        let (peer, buffer) = received(next(&mut io));
        assert_eq!(buffer, b"hello");
        drop(peer);
        let Done::Stopped { result, .. } = next(&mut io).done else {
            panic!("not the end");
        };
        assert_eq!(result, Ok(()));
    }

    /// Chunks smaller than what came take it in turn, in order, each given
    /// back; with none free for what still comes, the receive stops, as
    /// io_uring's ENOBUFS does.
    #[test]
    fn chunks_in_turn_and_none_free() {
        let mut io = Io::with_chunks(8, 4, 4).unwrap();
        let (server, client, _listener) = pair(&mut io, v4());
        assert!(io.receive_many(server, SERVER).is_ok());
        send(&mut io, client, b"0123456789", CLIENT);
        let mut got = Vec::new();
        let mut sender = None;
        while got.len() < 10 || sender.is_none() {
            let event = next(&mut io);
            if let Done::Chunk(chunk) = event.done {
                got.extend_from_slice(io.bytes(&chunk).unwrap());
                assert!(io.give_back(chunk).is_ok());
            } else if let Done::Sent { stream, .. } = event.done {
                sender = Some(stream);
            } else {
                panic!("another operation");
            }
        }
        assert_eq!(got, b"0123456789");
        send(&mut io, sender.unwrap(), b"ab", CLIENT);
        let mut held = Vec::new();
        loop {
            let event = next(&mut io);
            if let Done::Chunk(chunk) = event.done {
                held.push(chunk);
            } else if let Done::Sent { stream, .. } = event.done {
                send(&mut io, stream, b"cdefghijklmnop", CLIENT);
            } else if let Done::Stopped { result, .. } = event.done {
                assert_eq!(result, Err(Error::NoChunks));
                break;
            } else {
                panic!("another operation");
            }
        }
        for chunk in held {
            assert!(io.give_back(chunk).is_ok());
        }
    }

    /// An Io without chunks stops a receive_many at once; a chunk of
    /// another Io is refused.
    #[test]
    fn chunks_refused() {
        let mut io = io(8);
        let (server, _client, _listener) = pair(&mut io, v4());
        assert!(io.receive_many(server, SERVER).is_ok());
        let Done::Stopped { result, .. } = next(&mut io).done else {
            panic!("not the end");
        };
        assert_eq!(result, Err(Error::NoChunks));
    }

    /// Listeners that share an address, where the kernel spreads the
    /// connections among them (Linux); refused where it does not.
    #[test]
    fn shares_an_address() {
        let first = Listener::bind_shared(v4(), 16);
        if cfg!(not(target_os = "linux")) {
            assert_eq!(first.err().map(|_| ()), Some(()));
            assert!(matches!(
                Listener::bind_shared(v4(), 16),
                Err(Error::Unbalanced)
            ));
            return;
        }
        let first = first.unwrap();
        let at = first.local().unwrap();
        let second = Listener::bind_shared(at, 16).unwrap();
        assert_eq!(second.local(), Some(at));
        assert!(matches!(Listener::bind(at, 16), Err(Error::InUse)));
    }

    /// The slowest turn says how long the program worked between two
    /// waits, and the key of the Event it worked on.
    #[test]
    fn slowest_turn() {
        let mut io = io(8);
        assert!(io.timeout(Duration::ZERO, 3).is_ok());
        let event = next(&mut io);
        assert_eq!(event.key, 3);
        // Work of the program's own, a turn of 20 ms or more.
        let start = super::sys::now();
        while super::sys::now().saturating_sub(start) < 20_000_000 {}
        assert_eq!(io.wait(Some(Duration::ZERO)), Ok(0));
        let turn = io.slowest_turn().unwrap();
        assert!(turn.took >= Duration::from_millis(20), "{:?}", turn.took);
        assert_eq!(turn.key, 3);
        assert!(io.slowest_turn().is_none());
    }

    /// A wake ends a wait with nothing running, and wakes before it are
    /// one: the next wait sleeps its timeout.
    #[test]
    fn woken() {
        let mut io = io(8);
        let waker = io.waker();
        waker.wake();
        waker.wake();
        assert_eq!(io.wait(None), Ok(0));
        assert_eq!(io.wait(Some(Duration::from_millis(20))), Ok(0));
        let other = io.waker();
        other.wake();
        assert!(io.timeout(Duration::from_secs(60), 1).is_ok());
        assert_eq!(io.wait(None), Ok(0));
    }

    /// What Io::new says where Linux gives no io_uring, as a loop shows it.
    #[test]
    fn unavailable_says_why() {
        let error = Error::Unavailable(Unavailable::Denied);
        assert_ne!(error, Error::Unavailable(Unavailable::Missing));
    }

    /// One byte to one server of a hundred, each with a receive waiting,
    /// and its receive started again: what a loop of many idle connections
    /// pays for the one that speaks (net's one_of_a_thousand, with fewer,
    /// as macOS gives a process 256 descriptors).
    #[bench]
    fn one_of_a_hundred(b: &mut Bencher) {
        const PAIRS: u64 = 100;
        let mut io = io(2 * 100 + 8);
        let mut clients = Vec::new();
        let mut listeners = Vec::new();
        for key in 0..PAIRS {
            let (server, client, listener) = pair(&mut io, v4());
            assert!(io.receive(server, Vec::with_capacity(16), key).is_ok());
            clients.push(Some(client));
            listeners.push(listener);
        }
        let mut turn = 0u64;
        let mut out = Some(Vec::with_capacity(16));
        b.iter(|| {
            let key = turn % PAIRS;
            turn += 1;
            let index = usize::try_from(key).unwrap();
            let mut bytes = out.take().unwrap();
            bytes.clear();
            bytes.push(1);
            let client = clients[index].take().unwrap();
            assert!(io.send(client, bytes, CLIENT + PAIRS).is_ok());
            for _ in 0..2 {
                let event = next(&mut io);
                if let Done::Sent { stream, buffer, .. } = event.done {
                    clients[index] = Some(stream);
                    out = Some(buffer);
                } else if let Done::Received {
                    stream, mut buffer, ..
                } = event.done
                {
                    buffer.clear();
                    assert!(io.receive(stream, buffer, event.key).is_ok());
                } else {
                    panic!("another operation");
                }
            }
        });
        drop(listeners);
    }

    /// One byte there and back over loopback, as a loop of one connection
    /// sees it.
    #[bench]
    fn round_trip(b: &mut Bencher) {
        let mut io = io(8);
        let (server, client, _listener) = pair(&mut io, v4());
        let (mut server, mut client) = (Some(server), Some(client));
        let (mut out, mut room) = (Some(Vec::with_capacity(64)), Some(Vec::with_capacity(64)));
        b.iter(|| {
            let mut bytes = out.take().unwrap();
            bytes.clear();
            bytes.push(1);
            assert!(io.send(client.take().unwrap(), bytes, CLIENT).is_ok());
            let mut into = room.take().unwrap();
            into.clear();
            assert!(io.receive(server.take().unwrap(), into, SERVER).is_ok());
            for _ in 0..2 {
                let event = next(&mut io);
                if let Done::Sent { stream, buffer, .. } = event.done {
                    client = Some(stream);
                    out = Some(buffer);
                } else if let Done::Received { stream, buffer, .. } = event.done {
                    server = Some(stream);
                    room = Some(buffer);
                } else {
                    panic!("another operation");
                }
            }
        });
    }
}
// rr: end(tests = yes)
