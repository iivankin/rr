//! A TLS 1.3 client (RFC 8446) without I/O: the caller moves bytes
//! between the socket and the client, which serves a blocking loop, a
//! poll loop or a thread alike.
//!
//! The profile: TLS_AES_128_GCM_SHA256, an X25519 key share, server
//! signatures ECDSA P-256 and P-384 and RSA-PSS with SHA-256 or SHA-384,
//! SNI and ALPN. A HelloRetryRequest with a cookie is answered; one that
//! asks for another group fails, since X25519 is the only group offered.
//! No resumption, no 0-RTT and no client certificate: tickets are
//! ignored, and a CertificateRequest is answered with an empty
//! Certificate, as RFC 8446 4.4.2 says a client without one must; the
//! server then decides. A KeyUpdate is honoured and answered when asked,
//! and the client updates its own keys every 2^24 records it seals.
//!
//! Bytes come in any split, down to one at a time, into a receive
//! buffer of one record, where an application record is opened in place
//! and read from; the next record is taken only once it is consumed.
//! Records go out sealed in place in a pending buffer the caller drains.
//!
//! The server's chain is verified by x509 against a store, or by the
//! caller (Verify::Caller), such as the operating system's verifier,
//! which may fetch certificates over the network and so runs off the
//! loop. The handshake then waits at the server's Certificate: input
//! takes nothing, chain lends the certificates, and verified resumes.
//! The caller's verifier matches the host; the client checks
//! CertificateVerify with the leaf's key. A blocking loop:
//!
//! ```text
//! let mut tls = Client::new(host, &[b"http/1.1"], Verify::Caller, now, &random)?;
//! loop {
//!     while !tls.pending().is_empty() { let n = socket.write(tls.pending())?; tls.sent(n); }
//!     if tls.awaiting() {
//!         let mut chain = [&[][..]; x509::CHAIN_MAX];
//!         let n = tls.chain(&mut chain).unwrap_or(0);
//!         let trusted = system_verify(&chain[..n], host);   // may block
//!         tls.verified(trusted);
//!         continue;
//!     }
//!     if tls.connected() && !request.is_empty() { request = &request[tls.write(request)?..]; continue; }
//!     let n = socket.read(&mut buf)?;
//!     let mut at = 0;
//!     while (at < n || !tls.read().is_empty()) && !tls.awaiting() {
//!         at += tls.input(&buf[at..n])?;
//!         use_data(tls.read());
//!         tls.consume(tls.read().len());
//!     }
//!     keep buf[at..n] for after the verdict
//! }
//! ```
//!
//! A poll loop: watch the socket for writing while pending holds bytes.
//! When the client awaits, copy the chain to the verifier's thread and
//! stop reading the socket (input would take nothing); keep unread
//! bytes. When the thread's answer comes, call verified, then go on with
//! the kept bytes and the socket as before.

use crate::base::aesgcm::{self, AesGcm};
use crate::base::sha256::{self, Sha256};
use crate::base::x509;
use crate::base::x25519;
use alloc::string::String;
use alloc::vec::Vec;

/// The most plaintext of one record.
pub const RECORD_MAX: usize = 1 << 14;
/// The most handshake message body this takes, reassembled across records.
pub const MESSAGE_MAX: usize = 64 * 1024;
/// Records one call to input processes at most; the rest waits for the
/// next call.
pub const RECORDS_PER_INPUT: usize = 32;
/// The most bytes write leaves pending: one full record. write takes
/// nothing more until pending is sent.
pub const PENDING_MAX: usize = SEALED_MAX;
/// The most a HelloRetryRequest's cookie may hold here; real ones are a
/// few hundred bytes.
pub const COOKIE_MAX: usize = 4096;
/// The most bytes of the ALPN list, each protocol with its length byte.
pub const ALPN_MAX: usize = 1024;

const HEADER: usize = 5;
const TAG: usize = aesgcm::TAG_LEN;
/// A protected record: the plaintext, its type byte and up to 255 of
/// padding, and the tag (RFC 8446 5.2).
const CIPHERTEXT_MAX: usize = RECORD_MAX + 256;
/// A full record as this client seals it, without padding.
const SEALED_MAX: usize = HEADER + RECORD_MAX + 1 + TAG;
/// Records under one key before the client updates its own: RFC 8446
/// 5.5 allows AES-GCM 2^24.5 full records.
const KEY_RECORDS_MAX: u64 = 1 << 24;
const HASH: usize = sha256::DIGEST_BYTES;
/// A KeyUpdate and an alert, sealed.
const KEY_UPDATE_SEALED: usize = HEADER + 4 + 1 + 1 + TAG;
const ALERT_SEALED: usize = HEADER + 2 + 1 + TAG;
/// The longest ClientHello: header and fixed fields, SNI of 253 bytes,
/// groups, signatures, versions, the key share, the whole ALPN list and
/// the largest cookie, as hello writes them.
const HELLO_MAX: usize = 4 + 43 + (9 + 253) + 8 + 18 + 7 + 42 + (6 + ALPN_MAX) + (6 + COOKIE_MAX);
/// What the handshake may leave pending when the caller sends none of
/// it: both ClientHellos, the empty Certificate with the longest context,
/// Finished, and an alert.
const HANDSHAKE_PENDING_MAX: usize = 2 * (HEADER + HELLO_MAX)
    + (HEADER + 4 + 1 + 255 + 3 + 1 + TAG)
    + (HEADER + 4 + HASH + 1 + TAG)
    + ALERT_SEALED;
/// What pending holds at most once connected. write adds a record only
/// while pending stays within PENDING_MAX, with the client's own
/// KeyUpdate before it. An answer to the server's KeyUpdate goes after
/// it, and another only once that one is sent, when what is pending came
/// through write again or nothing is. Last, close_notify or an alert.
const CONNECTED_PENDING_MAX: usize = PENDING_MAX + 2 * KEY_UPDATE_SEALED + ALERT_SEALED;
/// The pending buffer, which no record goes past.
const TX_MAX: usize = if HANDSHAKE_PENDING_MAX > CONNECTED_PENDING_MAX {
    HANDSHAKE_PENDING_MAX
} else {
    CONNECTED_PENDING_MAX
};

// Record content types.
const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION: u8 = 23;

// Handshake message types.
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;
const KEY_UPDATE: u8 = 24;
const MESSAGE_HASH: u8 = 254;

// Extensions.
const SERVER_NAME: u16 = 0;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const PRE_SHARED_KEY: u16 = 41;
const EARLY_DATA: u16 = 42;
const SUPPORTED_VERSIONS: u16 = 43;
const COOKIE: u16 = 44;
const PSK_MODES: u16 = 45;
const KEY_SHARE: u16 = 51;

const TLS13: u16 = 0x0304;
const AES_128_GCM_SHA256: u16 = 0x1301;
const X25519: u16 = 0x001d;

/// ServerHello's random when it is a HelloRetryRequest: SHA-256 of
/// "HelloRetryRequest" (RFC 8446 4.1.3).
const HELLO_RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// What CertificateVerify's signature covers before the transcript hash.
const VERIFY_CONTEXT: &[u8; 34] = b"TLS 1.3, server CertificateVerify\0";

/// Why the connection failed, or a call was refused. A failure sticks:
/// each later input and write returns it, and pending holds the alert
/// that tells the server, when there is one.
#[derive(Clone, Copy)]
#[cfg_attr(any(test, fuzzing), derive(Debug, PartialEq))]
pub enum Error {
    /// The host is neither a DNS name nor an IP literal.
    Host,
    /// An ALPN protocol is empty or over 255 bytes, or the list is over
    /// ALPN_MAX.
    Alpn,
    /// A record or message does not parse (decode_error).
    Decode,
    /// A record or message where the protocol does not allow it
    /// (unexpected_message).
    Unexpected,
    /// A value outside what was offered or allowed (illegal_parameter).
    Parameter,
    /// An extension the server may not send here (unsupported_extension).
    Extension,
    /// The server does not speak TLS 1.3 (protocol_version).
    Version,
    /// A HelloRetryRequest for a key share group other than X25519,
    /// which is all this offers (illegal_parameter).
    Group,
    /// A record over its limit, before or after decryption
    /// (record_overflow).
    Overflow,
    /// A handshake message over MESSAGE_MAX, or a cookie over COOKIE_MAX
    /// (decode_error).
    TooLarge,
    /// A record that does not authenticate (bad_record_mac).
    Forged,
    /// A certificate of the chain is outside its validity
    /// (certificate_expired).
    Expired,
    /// The leaf does not name the host (bad_certificate).
    Name,
    /// No path leads to a trusted anchor (unknown_ca).
    Untrusted,
    /// The chain is refused for another reason (bad_certificate).
    Certificate,
    /// CertificateVerify does not verify (decrypt_error).
    Signature,
    /// The server's Finished does not verify (decrypt_error).
    Finished,
    /// The server sent this alert. close_notify (0) during the handshake
    /// is one too.
    Alert(u8),
    /// write before the handshake is complete.
    NotConnected,
    /// write after close.
    Closed,
}

impl Error {
    /// The alert that tells the server, or None for an error that is
    /// the server's alert or the caller's mistake.
    fn alert(self) -> Option<u8> {
        match self {
            Error::Unexpected => Some(10),
            Error::Forged => Some(20),
            Error::Overflow => Some(22),
            Error::Name | Error::Certificate => Some(42),
            Error::Expired => Some(45),
            Error::Parameter | Error::Group => Some(47),
            Error::Untrusted => Some(48),
            Error::Decode | Error::TooLarge => Some(50),
            Error::Signature | Error::Finished => Some(51),
            Error::Version => Some(70),
            Error::Extension => Some(110),
            Error::Host | Error::Alpn | Error::Alert(_) | Error::NotConnected | Error::Closed => {
                None
            }
        }
    }
}

impl From<aesgcm::Error> for Error {
    fn from(error: aesgcm::Error) -> Error {
        match error {
            aesgcm::Error::Forged => Error::Forged,
            aesgcm::Error::TooLong => Error::Overflow,
        }
    }
}

impl From<x509::Error> for Error {
    fn from(error: x509::Error) -> Error {
        match error {
            x509::Error::Expired => Error::Expired,
            x509::Error::Host => Error::Name,
            x509::Error::Untrusted | x509::Error::Distrusted => Error::Untrusted,
            x509::Error::Malformed
            | x509::Error::Unsupported
            | x509::Error::Critical
            | x509::Error::Duplicate
            | x509::Error::Usage
            | x509::Error::NotCa
            | x509::Error::PathLength
            | x509::Error::Constrained
            | x509::Error::Signature
            | x509::Error::TooMany => Error::Certificate,
        }
    }
}

/// Where the handshake is: the message expected next.
#[derive(Clone, Copy)]
enum State {
    /// ServerHello, or a HelloRetryRequest.
    Hello,
    /// ServerHello after a HelloRetryRequest.
    Retried,
    Extensions,
    /// Certificate, or a CertificateRequest before it.
    Certificate,
    /// The caller verifies the Certificate at the front of hs.
    Awaiting,
    /// The caller trusts the Certificate at the front of hs.
    Trusted,
    Verify,
    Finished,
    Connected,
    /// The server sent close_notify after the handshake: what comes
    /// after it is ignored.
    Closed,
}

/// One direction's record protection: the traffic secret, for
/// KeyUpdate, its key and IV, and the next record's sequence number.
struct Keys {
    secret: [u8; HASH],
    aead: AesGcm,
    iv: [u8; aesgcm::NONCE_LEN],
    seq: u64,
}

impl Keys {
    fn new(secret: &[u8; HASH]) -> Keys {
        let mut key = [0; aesgcm::KEY_LEN];
        let mut iv = [0; aesgcm::NONCE_LEN];
        expand(secret, b"key", &[], &mut key);
        expand(secret, b"iv", &[], &mut iv);
        Keys {
            secret: *secret,
            aead: AesGcm::new(&key),
            iv,
            seq: 0,
        }
    }

    /// The keys after a KeyUpdate (RFC 8446 7.2).
    fn next(&self) -> Keys {
        let mut secret = [0; HASH];
        expand(&self.secret, b"traffic upd", &[], &mut secret);
        Keys::new(&secret)
    }

    /// The next record's nonce: the sequence number XORed into the IV's
    /// last eight bytes (RFC 8446 5.3).
    fn nonce(&mut self) -> Result<[u8; aesgcm::NONCE_LEN], Error> {
        let mut nonce = self.iv;
        for (byte, number) in nonce.iter_mut().skip(4).zip(self.seq.to_be_bytes()) {
            *byte ^= number;
        }
        // 2^64 records would take a peer longer than a connection lasts.
        self.seq = self.seq.checked_add(1).ok_or(Error::Unexpected)?;
        Ok(nonce)
    }
}

/// Fields of a handshake message, front to back.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let (head, tail) = self.rest.split_at_checked(count).ok_or(Error::Decode)?;
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        self.take(1)?.first().copied().ok_or(Error::Decode)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let pair = self.take(2)?.first_chunk::<2>().ok_or(Error::Decode)?;
        Ok(u16::from_be_bytes(*pair))
    }

    /// A vector after its length of width bytes, big-endian.
    fn vector(&mut self, width: usize) -> Result<&'a [u8], Error> {
        let length = self
            .take(width)?
            .iter()
            .fold(0, |length, byte| (length << 8) | usize::from(*byte));
        self.take(length)
    }

    /// Nothing may follow the fields read.
    fn end(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode)
        }
    }
}

/// Who verifies the server's certificate chain.
pub enum Verify<'a> {
    /// x509 against these anchors, for the host at the time given.
    Store(&'a x509::Store),
    /// The caller, such as the operating system's verifier on a thread:
    /// the handshake waits at the server's Certificate until verified.
    /// The caller matches the host too; the client only takes the leaf's
    /// key, which checks CertificateVerify.
    Caller,
}

/// A TLS 1.3 connection's client side. A store it verifies the server's
/// chain against outlives it.
pub struct Client<'a> {
    verify: Verify<'a>,
    now: i64,
    host: String,
    /// Whether host is an IP literal, which SNI does not carry.
    literal: bool,
    /// ALPN's ProtocolNameList as sent, without its length.
    offer: Vec<u8>,
    /// The protocol the server chose, where it is in offer.
    chosen: Option<(usize, usize)>,
    random: [u8; 32],
    secret: [u8; x25519::KEY_BYTES],
    public: [u8; x25519::KEY_BYTES],
    state: State,
    transcript: Sha256,
    /// The key that checks the server's Finished.
    server_finished: [u8; HASH],
    /// The master secret, which the application keys come from.
    master: [u8; HASH],
    /// The leaf's DER, whose key checks CertificateVerify, the message
    /// after its own, once that message's buffer has moved on.
    // rr: escape(bound): x509 refuses a certificate over
    // CERTIFICATE_BYTES_MAX, and this is cleared before it takes one.
    leaf: Vec<u8>,
    /// A CertificateRequest's context, echoed in the empty Certificate.
    context: Option<Vec<u8>>,
    input_keys: Option<Keys>,
    output_keys: Option<Keys>,
    /// One record as it comes; an application record is opened here.
    rx: Vec<u8>,
    /// The unread plaintext of the record in rx; app_end is 0 when there
    /// is none.
    app_at: usize,
    app_end: usize,
    /// A handshake message that spans records, and what follows it.
    hs: Vec<u8>,
    /// Records to send, from tx_at on.
    tx: Vec<u8>,
    tx_at: usize,
    /// Where a KeyUpdate this sent ends in tx: one not yet sent answers
    /// the server's later requests too.
    reply_end: usize,
    /// close_notify or a fatal alert is queued: nothing goes after it.
    close_sent: bool,
    failed: Option<Error>,
}

impl<'a> Client<'a> {
    /// A client for host (a DNS name, or an IP literal, which SNI does
    /// not carry), offering the ALPN protocols given, if any, and
    /// verifying the server's chain as verify says, at now (Unix seconds).
    /// random is 64 bytes of the system's randomness: the ClientHello's
    /// random, then the X25519 secret. The ClientHello is pending.
    pub fn new(
        host: &str,
        alpn: &[&[u8]],
        verify: Verify<'a>,
        now: i64,
        random: &[u8; 64],
    ) -> Result<Client<'a>, Error> {
        let host = host.strip_suffix('.').unwrap_or(host);
        let literal = ip_literal(host);
        if !literal && !dns_name(host) {
            return Err(Error::Host);
        }
        let mut offer = Vec::new();
        for name in alpn {
            let Ok(length) = u8::try_from(name.len()) else {
                return Err(Error::Alpn);
            };
            if length == 0 || offer.len() + 1 + name.len() > ALPN_MAX {
                return Err(Error::Alpn);
            }
            offer.push(length);
            offer.extend_from_slice(name);
        }
        let (head, tail) = random.split_at(32);
        let mut client_random = [0; 32];
        client_random.copy_from_slice(head);
        let mut secret = [0; x25519::KEY_BYTES];
        secret.copy_from_slice(tail);
        let mut client = Client {
            verify,
            now,
            // rr: escape(copy): the connection outlives the caller's name;
            // x509 matches it and the second ClientHello carries it again.
            host: String::from(host),
            literal,
            offer,
            chosen: None,
            random: client_random,
            public: x25519::public_key(&secret),
            secret,
            state: State::Hello,
            transcript: Sha256::new(),
            server_finished: [0; HASH],
            master: [0; HASH],
            leaf: Vec::new(),
            context: None,
            input_keys: None,
            output_keys: None,
            rx: Vec::with_capacity(HEADER + CIPHERTEXT_MAX),
            app_at: 0,
            app_end: 0,
            hs: Vec::new(),
            tx: Vec::with_capacity(TX_MAX),
            tx_at: 0,
            reply_end: 0,
            close_sent: false,
            failed: None,
        };
        let hello = client.hello(&[]);
        // The first ClientHello's record says TLS 1.0, as most clients'
        // do, for middleboxes that look (RFC 8446 5.1).
        client.handshake_message(&hello, 1)?;
        Ok(client)
    }

    /// Takes bytes from the socket, in any split, and returns how many
    /// it took. It stops early when a record's plaintext waits to be
    /// read, and after RECORDS_PER_INPUT records: what it did not take
    /// goes in again, after read and consume, and after verified while
    /// the client awaits a verdict. Bytes after the server's close_notify
    /// are taken and ignored.
    #[cfg_attr(rr, rr::hot)]
    pub fn input(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        match self.take(bytes) {
            Ok(taken) => Ok(taken),
            Err(error) => {
                // rr: escape(cold): a connection fails once.
                self.fail(error);
                Err(error)
            }
        }
    }

    /// Bytes to write to the socket.
    pub fn pending(&self) -> &[u8] {
        self.tx.get(self.tx_at..).unwrap_or_default()
    }

    /// Marks n bytes of pending as written.
    pub fn sent(&mut self, n: usize) {
        self.tx_at = self.tx_at.saturating_add(n).min(self.tx.len());
        self.drained();
    }

    /// Seals application data into records of up to RECORD_MAX bytes and
    /// returns how much it took: less than all when pending would pass
    /// PENDING_MAX, and none until pending is sent.
    #[cfg_attr(rr, rr::hot)]
    pub fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.close_sent {
            return Err(Error::Closed);
        }
        if !self.connected() {
            return Err(Error::NotConnected);
        }
        match self.encrypt(data) {
            Ok(taken) => Ok(taken),
            Err(error) => {
                // rr: escape(cold): a connection fails once.
                self.fail(error);
                Err(error)
            }
        }
    }

    /// Decrypted application data, in the receive buffer.
    pub fn read(&self) -> &[u8] {
        self.rx.get(self.app_at..self.app_end).unwrap_or_default()
    }

    /// Marks n bytes of read as used; once all are, input takes the next
    /// record.
    pub fn consume(&mut self, n: usize) {
        if self.app_end == 0 {
            return;
        }
        self.app_at = self.app_at.saturating_add(n).min(self.app_end);
        if self.app_at == self.app_end {
            self.app_at = 0;
            self.app_end = 0;
            self.rx.clear();
        }
    }

    /// Whether the handshake is complete and the connection has not
    /// failed.
    pub fn connected(&self) -> bool {
        matches!(self.state, State::Connected | State::Closed) && self.failed.is_none()
    }

    /// Whether the server sent close_notify: nothing more will be read.
    /// Writing may go on until close.
    pub fn closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// Queues close_notify; nothing is written after it.
    pub fn close(&mut self) {
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        if let Err(error) = self.records(ALERT, &[1, 0], 3) {
            self.fail(error);
        }
    }

    /// The protocol the server chose by ALPN.
    pub fn alpn(&self) -> Option<&[u8]> {
        let (at, length) = self.chosen?;
        self.offer.get(at..at + length)
    }

    /// Whether the handshake waits for verified: Verify::Caller, and the
    /// server's Certificate is in.
    pub fn awaiting(&self) -> bool {
        matches!(self.state, State::Awaiting)
    }

    /// The server's certificates, leaf first, into out while the client
    /// awaits a verdict; how many. They are borrowed from the handshake
    /// buffer, not copied. None when there is no chain to verify, or out
    /// is shorter than it: x509::CHAIN_MAX slots hold any this takes.
    pub fn chain<'c>(&'c self, out: &mut [&'c [u8]]) -> Option<usize> {
        if !self.awaiting() {
            return None;
        }
        let &[_, a, b, c] = self.hs.first_chunk::<4>()?;
        let length = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
        certificates(self.hs.get(4..4 + length)?, out).ok()
    }

    /// The caller's verdict on chain. False fails the connection with
    /// Untrusted, whose alert is unknown_ca: the chain did not lead to an
    /// anchor the caller trusts (RFC 8446 6.2). True goes on with the
    /// messages already in, CertificateVerify first, which the client
    /// checks with the leaf's key. A call while nothing is awaited does
    /// nothing.
    pub fn verified(&mut self, trusted: bool) {
        if !self.awaiting() {
            return;
        }
        if !trusted {
            self.fail(Error::Untrusted);
            return;
        }
        self.state = State::Trusted;
        let buffer = core::mem::take(&mut self.hs);
        if let Err(error) = self.proceed(buffer) {
            self.fail(error);
        }
    }

    /// Ends the connection on error: the alert for it, if any, is queued
    /// unless close_notify went before it, and everything else stops.
    fn fail(&mut self, error: Error) {
        self.failed = Some(error);
        self.app_at = 0;
        self.app_end = 0;
        self.rx.clear();
        self.hs.clear();
        if let Some(code) = error.alert()
            && !self.close_sent
        {
            // rr: escape(discard): the connection is over whether the
            // alert is queued or not.
            let _: Result<(), Error> = self.records(ALERT, &[2, code], 3);
        }
        self.close_sent = true;
    }

    fn take(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let mut taken = 0;
        for _ in 0..RECORDS_PER_INPUT {
            if matches!(self.state, State::Closed) {
                return Ok(bytes.len());
            }
            if self.app_end != 0 || matches!(self.state, State::Awaiting) {
                break;
            }
            taken += self.fill(bytes.get(taken..).unwrap_or_default(), HEADER);
            let want = self.wanted()?;
            taken += self.fill(bytes.get(taken..).unwrap_or_default(), want);
            if self.rx.len() < want {
                break;
            }
            self.record()?;
        }
        Ok(taken)
    }

    /// Takes from rest up to want bytes of the record; the count taken.
    fn fill(&mut self, rest: &[u8], want: usize) -> usize {
        let count = want.saturating_sub(self.rx.len()).min(rest.len());
        if let Some(part) = rest.get(..count) {
            // rr: escape(copy): a record is opened in place, so it comes
            // whole into the receive buffer: the one copy of its bytes.
            self.rx.extend_from_slice(part);
        }
        count
    }

    /// The bytes of the record in rx: its header's, then the whole
    /// record's once the header is in and its type and length allowed.
    fn wanted(&self) -> Result<usize, Error> {
        let Some(&[kind, _, _, high, low]) = self.rx.first_chunk::<HEADER>() else {
            return Ok(HEADER);
        };
        // legacy_record_version is ignored, as RFC 8446 5.1 says.
        let length = usize::from(u16::from_be_bytes([high, low]));
        let limit = match kind {
            APPLICATION => CIPHERTEXT_MAX,
            CHANGE_CIPHER_SPEC | ALERT | HANDSHAKE => RECORD_MAX,
            _ => return Err(Error::Unexpected),
        };
        if length > limit {
            return Err(Error::Overflow);
        }
        Ok(HEADER + length)
    }

    /// Processes the whole record in rx, which then starts over unless
    /// it holds plaintext to read.
    fn record(&mut self) -> Result<(), Error> {
        match self.rx.first().copied() {
            Some(APPLICATION) => self.protected()?,
            Some(CHANGE_CIPHER_SPEC) => self.change_cipher_spec()?,
            Some(kind @ (ALERT | HANDSHAKE)) => {
                // rr: escape(cold): plaintext records come before the
                // server's keys only.
                self.plaintext(kind)?;
            }
            _ => return Err(Error::Unexpected),
        }
        if self.app_end == 0 {
            self.rx.clear();
        }
        Ok(())
    }

    /// Opens the protected record in rx in place (RFC 8446 5.2).
    fn protected(&mut self) -> Result<(), Error> {
        let Some(keys) = &mut self.input_keys else {
            return Err(Error::Unexpected);
        };
        let (header, body) = self.rx.split_at_mut_checked(HEADER).ok_or(Error::Decode)?;
        let at = body.len().checked_sub(TAG).ok_or(Error::Forged)?;
        let (data, tag) = body.split_at_mut_checked(at).ok_or(Error::Forged)?;
        let tag = tag.first_chunk::<TAG>().ok_or(Error::Forged)?;
        let nonce = keys.nonce()?;
        keys.aead.open(&nonce, header, data, tag)?;
        // The content type is the last byte that is not padding.
        let end = data
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or(Error::Unexpected)?;
        if end > RECORD_MAX {
            return Err(Error::Overflow);
        }
        let kind = data.get(end).copied();
        let (start, stop) = (HEADER, HEADER + end);
        match kind {
            Some(APPLICATION) => {
                if !matches!(self.state, State::Connected) || !self.hs.is_empty() {
                    return Err(Error::Unexpected);
                }
                if end > 0 {
                    self.app_at = start;
                    self.app_end = stop;
                }
            }
            // rr: escape(cold): handshake messages after the handshake are
            // a ticket or a key update now and then.
            Some(HANDSHAKE) => self.handshake(start, stop)?,
            Some(ALERT) => self.alert(start, stop)?,
            _ => return Err(Error::Unexpected),
        }
        Ok(())
    }

    /// The middlebox compatibility record, dropped before the server's
    /// Finished (RFC 8446 5).
    fn change_cipher_spec(&self) -> Result<(), Error> {
        let late = matches!(self.state, State::Connected | State::Closed);
        if late || !self.hs.is_empty() || self.rx.get(HEADER..) != Some(&[1][..]) {
            return Err(Error::Unexpected);
        }
        Ok(())
    }

    /// An alert or handshake record in the clear, before ServerHello.
    fn plaintext(&mut self, kind: u8) -> Result<(), Error> {
        if self.input_keys.is_some() {
            return Err(Error::Unexpected);
        }
        let end = self.rx.len();
        if kind == ALERT {
            return self.alert(HEADER, end);
        }
        self.handshake(HEADER, end)
    }

    /// The alert at rx[start..stop].
    fn alert(&mut self, start: usize, stop: usize) -> Result<(), Error> {
        if !self.hs.is_empty() {
            return Err(Error::Unexpected);
        }
        let Some(&[_, description]) = self.rx.get(start..stop) else {
            return Err(Error::Decode);
        };
        match description {
            // close_notify ends what the server sends.
            0 if matches!(self.state, State::Connected) => self.state = State::Closed,
            // user_canceled is followed by close_notify (RFC 8446 6.1).
            90 => {}
            // Every other alert is an error, whatever its level (6.2).
            _ => return Err(Error::Alert(description)),
        }
        Ok(())
    }

    /// The handshake bytes at rx[start..stop], after any part message
    /// that came before them.
    fn handshake(&mut self, start: usize, stop: usize) -> Result<(), Error> {
        // A handshake record is never empty (RFC 8446 5.1).
        if start == stop {
            return Err(Error::Unexpected);
        }
        let mut buffer = core::mem::take(&mut self.hs);
        if let Some(part) = self.rx.get(start..stop) {
            buffer.extend_from_slice(part);
        }
        self.proceed(buffer)
    }

    /// Processes the messages in buffer, which then holds what is left:
    /// a part message, or a Certificate the caller verifies and the
    /// messages after it.
    fn proceed(&mut self, mut buffer: Vec<u8>) -> Result<(), Error> {
        let used = self.messages(&buffer)?;
        buffer.drain(..used);
        // After the handshake a message is rare: its buffer goes with it.
        if buffer.is_empty() && matches!(self.state, State::Connected) {
            buffer = Vec::new();
        }
        self.hs = buffer;
        Ok(())
    }

    /// Processes the whole messages at the front of buffer; how many
    /// bytes they took.
    fn messages(&mut self, buffer: &[u8]) -> Result<usize, Error> {
        let mut at = 0;
        while let Some(&[kind, a, b, c]) = buffer.get(at..).and_then(<[u8]>::first_chunk::<4>) {
            let length = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
            if length > MESSAGE_MAX {
                return Err(Error::TooLarge);
            }
            let end = at + 4 + length;
            let Some(message) = buffer.get(at..end) else {
                break;
            };
            let keys_change = self.message(kind, message)?;
            if matches!(self.state, State::Awaiting) {
                // The Certificate stays for chain, and for the verdict.
                break;
            }
            at = end;
            // A message before a change of keys ends its record (5.1).
            if keys_change && at != buffer.len() {
                return Err(Error::Unexpected);
            }
        }
        Ok(at)
    }

    /// One handshake message, its header included; whether the keys
    /// change after it.
    fn message(&mut self, kind: u8, message: &[u8]) -> Result<bool, Error> {
        let body = message.get(4..).unwrap_or_default();
        match (self.state, kind) {
            (State::Hello | State::Retried, SERVER_HELLO) => self.server_hello(message, body),
            (State::Extensions, ENCRYPTED_EXTENSIONS) => self.extensions(message, body),
            (State::Certificate, CERTIFICATE_REQUEST) if self.context.is_none() => {
                self.request(message, body)
            }
            (State::Certificate | State::Trusted, CERTIFICATE) => self.certificate(message, body),
            (State::Verify, CERTIFICATE_VERIFY) => self.verify(message, body),
            (State::Finished, FINISHED) => self.finished(message, body),
            // No resumption: a ticket is of no use.
            (State::Connected, NEW_SESSION_TICKET) => Ok(false),
            (State::Connected, KEY_UPDATE) => self.key_update(body),
            _ => Err(Error::Unexpected),
        }
    }

    fn server_hello(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut fields = Reader { rest: body };
        let version = fields.u16()?;
        let random = fields.take(32)?;
        let session = fields.vector(1)?;
        let suite = fields.u16()?;
        let compression = fields.u8()?;
        let mut extensions = Reader {
            rest: fields.vector(2)?,
        };
        fields.end()?;
        let retry = random == HELLO_RETRY;
        let mut selected = None;
        let mut share = None;
        let mut cookie = None;
        let mut stray = false;
        while !extensions.rest.is_empty() {
            let kind = extensions.u16()?;
            let mut data = Reader {
                rest: extensions.vector(2)?,
            };
            let again = match kind {
                SUPPORTED_VERSIONS => selected.replace(data.u16()?).is_some(),
                // A HelloRetryRequest names a group; a ServerHello adds
                // its key.
                KEY_SHARE if retry => share.replace((data.u16()?, &[][..])).is_some(),
                KEY_SHARE => share.replace((data.u16()?, data.vector(2)?)).is_some(),
                COOKIE if retry => cookie.replace(data.vector(2)?).is_some(),
                _ => {
                    stray = true;
                    data.rest = &[];
                    false
                }
            };
            if again {
                return Err(Error::Decode);
            }
            data.end()?;
        }
        // A server below TLS 1.3 sends neither, nor a known version.
        if version != 0x0303 || selected != Some(TLS13) {
            return Err(Error::Version);
        }
        if stray {
            return Err(Error::Extension);
        }
        if !session.is_empty() || suite != AES_128_GCM_SHA256 || compression != 0 {
            return Err(Error::Parameter);
        }
        if retry {
            return self.retry(message, share, cookie);
        }
        let Some((X25519, key)) = share else {
            return Err(Error::Parameter);
        };
        let peer = key.first_chunk::<32>().ok_or(Error::Parameter)?;
        if key.len() != 32 {
            return Err(Error::Parameter);
        }
        let shared = x25519::shared(&self.secret, peer).ok_or(Error::Parameter)?;
        self.secret = [0; x25519::KEY_BYTES];
        self.transcript.update(message);
        let secrets = handshake_secrets(&shared, &self.hash());
        let mut finished = [0; HASH];
        expand(&secrets.server, b"finished", &[], &mut finished);
        self.server_finished = finished;
        self.master = secrets.master;
        self.input_keys = Some(Keys::new(&secrets.server));
        self.output_keys = Some(Keys::new(&secrets.client));
        self.state = State::Extensions;
        Ok(true)
    }

    /// A HelloRetryRequest: the second ClientHello adds the cookie
    /// (RFC 8446 4.1.4). Its key share would be X25519's again, so a
    /// retry that names a group changes nothing that could help.
    fn retry(
        &mut self,
        message: &[u8],
        share: Option<(u16, &[u8])>,
        cookie: Option<&[u8]>,
    ) -> Result<bool, Error> {
        if matches!(self.state, State::Retried) {
            return Err(Error::Unexpected);
        }
        match share {
            Some((X25519, _)) => return Err(Error::Parameter),
            Some(_) => return Err(Error::Group),
            None => {}
        }
        let Some(cookie) = cookie else {
            return Err(Error::Parameter);
        };
        if cookie.is_empty() {
            return Err(Error::Decode);
        }
        if cookie.len() > COOKIE_MAX {
            return Err(Error::TooLarge);
        }
        // The first ClientHello stands in the transcript as its hash.
        let first = self.hash();
        self.transcript = Sha256::new();
        self.transcript.update(&[MESSAGE_HASH, 0, 0, 32]);
        self.transcript.update(&first);
        self.transcript.update(message);
        self.state = State::Retried;
        let hello = self.hello(cookie);
        self.handshake_message(&hello, 3)?;
        Ok(true)
    }

    fn extensions(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut fields = Reader { rest: body };
        let mut list = Reader {
            rest: fields.vector(2)?,
        };
        fields.end()?;
        while !list.rest.is_empty() {
            let kind = list.u16()?;
            let data = list.vector(2)?;
            match kind {
                // The server used the name; nothing comes with it.
                SERVER_NAME if self.literal => return Err(Error::Extension),
                SERVER_NAME if !data.is_empty() => return Err(Error::Decode),
                ALPN => self.choose(data)?,
                SIGNATURE_ALGORITHMS | PRE_SHARED_KEY | EARLY_DATA | SUPPORTED_VERSIONS
                | COOKIE | PSK_MODES | KEY_SHARE => return Err(Error::Extension),
                // Others, such as supported_groups, are information, as Go
                // and OpenSSL take them.
                _ => {}
            }
        }
        self.transcript.update(message);
        self.state = State::Certificate;
        Ok(false)
    }

    /// The server's ALPN choice: one protocol of those offered.
    fn choose(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.offer.is_empty() {
            return Err(Error::Extension);
        }
        if self.chosen.is_some() {
            return Err(Error::Decode);
        }
        let mut fields = Reader { rest: data };
        let mut list = Reader {
            rest: fields.vector(2)?,
        };
        fields.end()?;
        let name = list.vector(1)?;
        list.end()?;
        if name.is_empty() {
            return Err(Error::Decode);
        }
        let mut offered = Reader { rest: &self.offer };
        let mut at = 0;
        while let Ok(protocol) = offered.vector(1) {
            if protocol == name {
                self.chosen = Some((at + 1, name.len()));
                return Ok(());
            }
            at += 1 + protocol.len();
        }
        Err(Error::Parameter)
    }

    fn request(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut fields = Reader { rest: body };
        let context = fields.vector(1)?;
        fields.vector(2)?;
        fields.end()?;
        // rr: escape(copy): the empty Certificate echoes the context after
        // this message's buffer has moved on.
        self.context = Some(context.to_vec());
        self.transcript.update(message);
        Ok(false)
    }

    fn certificate(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut slots: [&[u8]; x509::CHAIN_MAX] = [&[]; x509::CHAIN_MAX];
        let count = certificates(body, &mut slots)?;
        let chain = slots.get(..count).unwrap_or_default();
        let leaf = match (&self.verify, self.state) {
            (Verify::Store(store), _) => x509::verify(chain, store, &self.host, self.now)?.der,
            (Verify::Caller, State::Trusted) => {
                let leaf = chain.first().copied().unwrap_or_default();
                // The key must be one CertificateVerify can be checked with.
                x509::parse(leaf)?;
                leaf
            }
            (Verify::Caller, _) => {
                self.state = State::Awaiting;
                return Ok(false);
            }
        };
        self.leaf.clear();
        self.leaf.extend_from_slice(leaf);
        // The name is matched; nothing sends it again.
        self.host = String::new();
        self.transcript.update(message);
        self.state = State::Verify;
        Ok(false)
    }

    fn verify(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut fields = Reader { rest: body };
        let scheme = fields.u16()?;
        let signature = fields.vector(2)?;
        fields.end()?;
        if !matches!(scheme, 0x0403 | 0x0503 | 0x0804 | 0x0805) {
            return Err(Error::Parameter);
        }
        // RFC 8446 4.4.3: 64 spaces, the context string and the hash.
        let mut content = [0x20; 64 + VERIFY_CONTEXT.len() + HASH];
        let hash = self.hash();
        for (byte, value) in content
            .iter_mut()
            .skip(64)
            .zip(VERIFY_CONTEXT.iter().chain(&hash))
        {
            *byte = *value;
        }
        let certificate = x509::parse(&self.leaf)?;
        let leaf = x509::Leaf {
            der: certificate.der,
            key: certificate.key,
        };
        if !leaf.verify_tls13(scheme, &content, signature) {
            return Err(Error::Signature);
        }
        self.leaf = Vec::new();
        self.transcript.update(message);
        self.state = State::Finished;
        Ok(false)
    }

    /// The server's Finished; the client's flight and the application
    /// keys follow it.
    fn finished(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        if body.len() != HASH {
            return Err(Error::Decode);
        }
        if !same(body, &mac(&self.server_finished, &self.hash())) {
            return Err(Error::Finished);
        }
        self.transcript.update(message);
        let hash = self.hash();
        let client = derive(&self.master, b"c ap traffic", &hash);
        let server = derive(&self.master, b"s ap traffic", &hash);
        self.input_keys = Some(Keys::new(&server));
        if let Some(context) = self.context.take() {
            // An empty Certificate: the context, and no certificates.
            let mut empty = Vec::with_capacity(8 + context.len());
            empty.extend_from_slice(&message_header(CERTIFICATE, context.len() + 4));
            // The context came in a vector of one length byte.
            empty.push(u8::try_from(context.len()).unwrap_or(u8::MAX));
            empty.extend_from_slice(&context);
            empty.extend_from_slice(&[0, 0, 0]);
            self.handshake_message(&empty, 3)?;
        }
        let Some(keys) = &self.output_keys else {
            return Err(Error::Unexpected);
        };
        let mut key = [0; HASH];
        expand(&keys.secret, b"finished", &[], &mut key);
        let mut ours = [0; 4 + HASH];
        for (byte, value) in ours.iter_mut().zip(
            message_header(FINISHED, HASH)
                .iter()
                .chain(&mac(&key, &self.hash())),
        ) {
            *byte = *value;
        }
        self.handshake_message(&ours, 3)?;
        self.output_keys = Some(Keys::new(&client));
        // Of the ALPN offer, only the choice is kept, for alpn.
        if let Some((at, length)) = self.chosen {
            self.offer.drain(..at);
            self.offer.truncate(length);
            self.chosen = Some((0, length));
        } else {
            self.offer.clear();
        }
        self.offer.shrink_to_fit();
        self.master = [0; HASH];
        self.server_finished = [0; HASH];
        self.state = State::Connected;
        Ok(true)
    }

    fn key_update(&mut self, body: &[u8]) -> Result<bool, Error> {
        let &[request] = body else {
            return Err(Error::Decode);
        };
        if request > 1 {
            return Err(Error::Parameter);
        }
        let next = self.input_keys.as_ref().ok_or(Error::Unexpected)?.next();
        self.input_keys = Some(next);
        // Our KeyUpdate still pending answers this request too; after
        // close_notify nothing may be sent.
        if request == 1 && !self.close_sent && self.reply_end <= self.tx_at {
            self.update()?;
            self.reply_end = self.tx.len();
        }
        Ok(true)
    }

    /// Sends a KeyUpdate that asks for none back, then seals under the
    /// next keys.
    fn update(&mut self) -> Result<(), Error> {
        self.records(HANDSHAKE, &[KEY_UPDATE, 0, 0, 1, 0], 3)?;
        let next = self.output_keys.as_ref().ok_or(Error::Unexpected)?.next();
        self.output_keys = Some(next);
        Ok(())
    }

    fn encrypt(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mut taken = 0;
        for piece in data.chunks(RECORD_MAX) {
            self.drained();
            if self.tx.len() + HEADER + piece.len() + 1 + TAG > PENDING_MAX {
                break;
            }
            if self
                .output_keys
                .as_ref()
                .is_some_and(|keys| keys.seq >= KEY_RECORDS_MAX)
            {
                // rr: escape(cold): once in 2^24 records.
                self.update()?;
            }
            let Some(keys) = &mut self.output_keys else {
                return Err(Error::NotConnected);
            };
            seal(keys, &mut self.tx, APPLICATION, piece)?;
            taken += piece.len();
        }
        Ok(taken)
    }

    /// Once pending is all sent, tx starts over at its front.
    fn drained(&mut self) {
        if self.tx_at == self.tx.len() {
            self.tx.clear();
            self.tx_at = 0;
            self.reply_end = 0;
        }
    }

    /// A handshake message into the transcript and out in records.
    fn handshake_message(&mut self, message: &[u8], minor: u8) -> Result<(), Error> {
        self.transcript.update(message);
        self.records(HANDSHAKE, message, minor)
    }

    /// data in records of kind, sealed once the client has keys; minor
    /// is the plaintext header's version, 3.minor.
    fn records(&mut self, kind: u8, data: &[u8], minor: u8) -> Result<(), Error> {
        self.drained();
        for piece in data.chunks(RECORD_MAX) {
            match &mut self.output_keys {
                Some(keys) => seal(keys, &mut self.tx, kind, piece)?,
                None => {
                    let [high, low] = u16::try_from(piece.len()).unwrap_or(u16::MAX).to_be_bytes();
                    self.tx.extend_from_slice(&[kind, 3, minor, high, low]);
                    self.tx.extend_from_slice(piece);
                }
            }
        }
        Ok(())
    }

    /// The transcript's hash so far.
    fn hash(&self) -> [u8; HASH] {
        // rr: escape(copy): the transcript goes on past this hash.
        self.transcript.clone().finish()
    }

    /// A ClientHello with the cookie, if any (RFC 8446 4.1.2). The
    /// limits on host, ALPN and cookie keep every length in its field.
    fn hello(&self, cookie: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(256 + self.host.len() + self.offer.len() + cookie.len());
        m.extend_from_slice(&[CLIENT_HELLO, 0, 0, 0, 3, 3]);
        m.extend_from_slice(&self.random);
        // No session ID: no middlebox compatibility mode. One suite and
        // no compression.
        m.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        let extensions = m.len();
        m.extend_from_slice(&[0, 0]);
        if !self.literal {
            let host = self.host.as_bytes();
            put(&mut m, &[0, 0], host.len() + 5);
            put(&mut m, &[], host.len() + 3);
            put(&mut m, &[0], host.len());
            m.extend_from_slice(host);
        }
        // supported_groups: X25519.
        m.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 0x1d]);
        // signature_algorithms: what CertificateVerify may use, then
        // PKCS #1, which only certificates may (RFC 8446 4.2.3).
        m.extend_from_slice(&[0, 13, 0, 14, 0, 12, 4, 3, 5, 3, 8, 4, 8, 5, 4, 1, 5, 1]);
        // supported_versions: TLS 1.3.
        m.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
        // key_share: X25519's.
        m.extend_from_slice(&[0, 51, 0, 38, 0, 36, 0, 0x1d, 0, 32]);
        m.extend_from_slice(&self.public);
        if !self.offer.is_empty() {
            put(&mut m, &[0, 16], self.offer.len() + 2);
            put(&mut m, &[], self.offer.len());
            m.extend_from_slice(&self.offer);
        }
        if !cookie.is_empty() {
            put(&mut m, &[0, 44], cookie.len() + 2);
            put(&mut m, &[], cookie.len());
            m.extend_from_slice(cookie);
        }
        let length = u16::try_from(m.len() - extensions - 2).unwrap_or(u16::MAX);
        if let Some(slot) = m.get_mut(extensions..extensions + 2) {
            slot.copy_from_slice(&length.to_be_bytes());
        }
        let header = message_header(CLIENT_HELLO, m.len() - 4);
        if let Some(slot) = m.get_mut(..4) {
            slot.copy_from_slice(&header);
        }
        m
    }
}

/// The certificates of a Certificate message's body into out, leaf
/// first; how many. More than out holds is refused, and so is none
/// (RFC 8446 4.4.2.4).
fn certificates<'m>(body: &'m [u8], out: &mut [&'m [u8]]) -> Result<usize, Error> {
    let mut fields = Reader { rest: body };
    if !fields.vector(1)?.is_empty() {
        return Err(Error::Parameter);
    }
    let mut list = Reader {
        rest: fields.vector(3)?,
    };
    fields.end()?;
    let mut count = 0;
    while !list.rest.is_empty() {
        let der = list.vector(3)?;
        list.vector(2)?;
        let slot = out.get_mut(count).ok_or(Error::Certificate)?;
        if der.is_empty() {
            return Err(Error::Decode);
        }
        *slot = der;
        count += 1;
    }
    if count == 0 {
        return Err(Error::Decode);
    }
    Ok(count)
}

/// Appends prefix, then length as two bytes.
fn put(m: &mut Vec<u8>, prefix: &[u8], length: usize) {
    m.extend_from_slice(prefix);
    m.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
}

/// A handshake message's header: its type and 24-bit length.
fn message_header(kind: u8, length: usize) -> [u8; 4] {
    let [_, a, b, c] = u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes();
    [kind, a, b, c]
}

/// Seals data as one record of kind at the end of tx (RFC 8446 5.2):
/// the header, the data, its type and the tag, sealed in place.
fn seal(keys: &mut Keys, tx: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<(), Error> {
    let Ok(length) = u16::try_from(data.len() + 1 + TAG) else {
        return Err(Error::Overflow);
    };
    if tx.len() + HEADER + usize::from(length) > TX_MAX {
        return Err(Error::Overflow);
    }
    let start = tx.len();
    let [high, low] = length.to_be_bytes();
    tx.extend_from_slice(&[APPLICATION, 3, 3, high, low]);
    // rr: escape(copy): the record is sealed in place in the pending
    // buffer, and the caller's data is borrowed.
    tx.extend_from_slice(data);
    tx.push(kind);
    let nonce = keys.nonce()?;
    let (head, body) = tx
        .split_at_mut_checked(start + HEADER)
        .ok_or(Error::Overflow)?;
    let header = head.get(start..).unwrap_or_default();
    let tag = keys.aead.seal(&nonce, header, body)?;
    tx.extend_from_slice(&tag);
    Ok(())
}

/// The secrets ServerHello's key share leads to (RFC 8446 7.1).
struct Secrets {
    client: [u8; HASH],
    server: [u8; HASH],
    master: [u8; HASH],
}

/// The handshake traffic secrets and the master secret, from the X25519
/// shared secret and the hash of ClientHello..ServerHello. Without a
/// PSK the early secret is HKDF-Extract of zeros.
fn handshake_secrets(shared: &[u8; 32], hash: &[u8; HASH]) -> Secrets {
    let empty = sha256::digest(&[]);
    let early = sha256::hkdf_extract(&[0; HASH], &[0; HASH]);
    let handshake = sha256::hkdf_extract(&derive(&early, b"derived", &empty), shared);
    Secrets {
        client: derive(&handshake, b"c hs traffic", hash),
        server: derive(&handshake, b"s hs traffic", hash),
        master: sha256::hkdf_extract(&derive(&handshake, b"derived", &empty), &[0; HASH]),
    }
}

/// Derive-Secret: HKDF-Expand-Label of a transcript hash.
fn derive(secret: &[u8; HASH], label: &[u8], hash: &[u8; HASH]) -> [u8; HASH] {
    let mut out = [0; HASH];
    expand(secret, label, hash, &mut out);
    out
}

/// HKDF-Expand-Label (RFC 8446 7.1). The labels are this file's, at most
/// 12 bytes, and a context is a hash at most: info fits 64 bytes.
fn expand(secret: &[u8; HASH], label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = [0; 64];
    let lengths = [out.len(), 6 + label.len(), context.len()]
        .map(|length| u8::try_from(length).unwrap_or(u8::MAX));
    let [size, labelled, hashed] = lengths;
    let mut at = 0;
    for part in [
        &[0, size, labelled][..],
        b"tls13 ",
        label,
        &[hashed],
        context,
    ] {
        if let Some(slot) = info.get_mut(at..at + part.len()) {
            slot.copy_from_slice(part);
        }
        at += part.len();
    }
    let info = info.get(..at).unwrap_or_default();
    if !sha256::hkdf_expand(secret, info, out) {
        // rr: escape(panic): out is at most 32 bytes, far under HKDF's
        // limit of 8160.
        unreachable!();
    }
}

/// HMAC-SHA256 of data under key, which HKDF-Extract is with key as
/// the salt: a Finished's verify_data (RFC 8446 4.4.4).
fn mac(key: &[u8; HASH], data: &[u8; HASH]) -> [u8; HASH] {
    sha256::hkdf_extract(key, data)
}

/// Whether a equals b, in time that does not depend on where they
/// differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    let differ = a.iter().zip(b).fold(0, |differ, (x, y)| differ | (x ^ y));
    a.len() == b.len() && differ == 0
}

/// Whether host is an IP address, IPv6 also in brackets.
fn ip_literal(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'));
    match bare {
        Some(inner) => inner.parse::<core::net::Ipv6Addr>().is_ok(),
        None => host.parse::<core::net::IpAddr>().is_ok(),
    }
}

/// Whether host can go in SNI as a DNS name: labels of letters, digits,
/// hyphens and underscores, as x509 matches them.
fn dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

#[cfg(test)]
mod tests;

/// Any bytes as the server's after a fixed ClientHello, fed in pieces
/// whose size the first byte picks: the client answers without a panic,
/// and a failure sticks.
#[cfg(fuzzing)]
pub fn fuzz_server(input: &[u8]) {
    let Some((&seed, rest)) = input.split_first() else {
        return;
    };
    let mut store = x509::Store::new();
    assert!(store.add_der(&x509::test_certificate("test.root").unwrap()));
    let mut client = Client::new(
        "api.example.test",
        &[b"h2"],
        Verify::Store(&store),
        x509::TEST_NOW,
        &[0x5c; 64],
    );
    fuzz_feed(client.as_mut().unwrap(), rest, usize::from(seed % 64) + 1);
}

/// Any bytes as the server's handshake messages after a real
/// ServerHello, sealed into records under its handshake keys: the
/// parsers behind the encryption, which mutation of the records alone
/// does not reach. The first byte picks the records' size, and in its
/// low bit the caller as verifier, who trusts any chain.
#[cfg(fuzzing)]
pub fn fuzz_flight(input: &[u8]) {
    let Some((&seed, rest)) = input.split_first() else {
        return;
    };
    let mut store = x509::Store::new();
    assert!(store.add_der(&x509::test_certificate("test.root").unwrap()));
    let verify = if seed & 1 == 1 {
        Verify::Caller
    } else {
        Verify::Store(&store)
    };
    let mut client = Client::new(
        "api.example.test",
        &[b"h2"],
        verify,
        x509::TEST_NOW,
        &[0x5c; 64],
    )
    .unwrap();
    client.sent(client.pending().len());
    let mut hello = Vec::from([HANDSHAKE, 3, 3, 0, 90, SERVER_HELLO, 0, 0, 86, 3, 3]);
    hello.extend_from_slice(&[0x7e; 32]);
    hello.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 46, 0, 43, 0, 2, 3, 4]);
    hello.extend_from_slice(&[0, 51, 0, 36, 0, 0x1d, 0, 32]);
    hello.extend_from_slice(&x25519::public_key(&[0x3a; 32]));
    assert_eq!(client.input(&hello), Ok(hello.len()));
    // The client's keys for reading are the server's for writing.
    let mut keys = Keys::new(&client.input_keys.as_ref().unwrap().secret);
    let mut bytes = Vec::new();
    for piece in rest.chunks(usize::from(seed >> 1) * 32 + 1) {
        if seal(&mut keys, &mut bytes, HANDSHAKE, piece).is_err() {
            break;
        }
    }
    fuzz_feed(&mut client, &bytes, bytes.len().max(1));
}

/// Feeds input to the client in pieces of piece bytes, reading and
/// sending what it gives and trusting any chain it awaits a verdict on;
/// a failure sticks.
#[cfg(fuzzing)]
fn fuzz_feed(client: &mut Client<'_>, input: &[u8], piece: usize) {
    for mut part in input.chunks(piece) {
        while !part.is_empty() {
            match client.input(part) {
                Ok(taken) => {
                    part = part.get(taken..).unwrap_or_default();
                    let count = client.read().len();
                    let waited = client.awaiting();
                    if waited {
                        let mut chain: [&[u8]; x509::CHAIN_MAX] = [&[]; x509::CHAIN_MAX];
                        assert!(client.chain(&mut chain).is_some_and(|n| n > 0));
                        client.verified(true);
                    }
                    assert!(taken > 0 || count > 0 || waited);
                    assert!(count <= RECORD_MAX);
                    client.consume(count);
                    client.sent(client.pending().len());
                }
                Err(error) => {
                    assert!(client.input(&[APPLICATION]) == Err(error));
                    assert!(!client.connected());
                    assert!(client.write(b"x") == Err(error));
                    return;
                }
            }
        }
    }
}
