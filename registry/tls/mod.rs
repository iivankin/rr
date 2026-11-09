//! A TLS 1.3 client (RFC 9846) without I/O: the caller moves bytes
//! between the socket and the client, which serves a blocking loop, a
//! poll loop or a thread alike.
//!
//! The profile: TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384, in
//! that order, as Go and BoringSSL offer them where the CPU has AES
//! instructions; key shares for X25519MLKEM768,
//! post-quantum, and X25519 on one X25519 key, as Go and browsers send
//! them, and P-256, which RFC 9846 9.1 requires, for a server that asks
//! in a HelloRetryRequest; server signatures ECDSA P-256, P-384 and
//! P-521 and RSA-PSS with SHA-256, SHA-384 or SHA-512; SNI and ALPN; middlebox compatibility
//! (a random session ID and one change_cipher_spec, RFC 9846 E.4). A
//! HelloRetryRequest with a cookie, a group or both is answered. Records
//! that carry nothing, 32 in a row, end the connection. No resumption, no 0-RTT and no client certificate: tickets are
//! ignored, and a CertificateRequest is answered with an empty
//! Certificate, as RFC 9846 4.5.1 says a client without one must; the
//! server then decides. A KeyUpdate is honoured and answered when asked,
//! and the client updates its own keys every 2^24 records it seals.
//!
//! Bytes come in any split, down to one at a time, into a receive
//! buffer of one record, where an application record is opened in place
//! and read from; the next record is taken only once it is consumed.
//! Records go out sealed in place in a pending buffer the caller drains.
//! input and write say how many bytes they took (Taken, which must be
//! used): the rest goes in again. sent of more than pending holds,
//! input while plaintext waits unread or a verdict is awaited, and a
//! verdict with none awaited are refused with errors of their own, so
//! that a loop that forgets a step fails rather than spin; when the
//! socket ends, eof says whether close_notify came first (RFC 9846 6.1).
//! Secrets are wiped where they go: the key shares' once used, each
//! traffic and handshake secret when it is replaced or dropped (the AES
//! key schedules and ML-KEM's key are aesgcm's and mlkem's to wipe).
//! The client draws its randomness from random itself: the ClientHello's
//! random and session ID, and each key share's seed. Records are sealed
//! and opened by aesgcm's SealingKey and OpeningKey, which number their
//! own nonces.
//!
//! The server's chain is verified by x509 against a store, or by the
//! caller (Verify::Caller), such as the operating system's verifier,
//! which may fetch certificates over the network and so runs off the
//! loop. The handshake then waits at the server's Certificate: input
//! refuses with Awaiting, chain lends the certificates, and verified
//! resumes with the verifier's x509::Approval, which only x509::verify
//! and trust's check make, for that leaf and host: the client compares
//! it with its own leaf and host, and fails on another's (internal_error).
//! refused ends the handshake (unknown_ca). The client checks
//! CertificateVerify with the approved leaf's key. A blocking loop, as
//! tests.rs's program runs it:
//!
//! ```text
//! let mut tls = Client::new(host, &[b"http/1.1"], Verify::Caller, now, Random::system())?;
//! let (mut at, mut end) = (0, 0);
//! loop {
//!     while !tls.pending().is_empty() {
//!         let n = socket.write(tls.pending())?;
//!         tls.sent(n)?;
//!     }
//!     if tls.awaiting() {
//!         let mut chain = [&[][..]; x509::CHAIN_MAX];
//!         let n = tls.chain(&mut chain).unwrap_or(0);
//!         match trust.verify_blocking(&chain[..n], host, now) {
//!             Ok(approval) => tls.verified(approval)?,
//!             Err(_) => tls.refused(),       // input then says Untrusted
//!         }
//!         continue;
//!     }
//!     if tls.connected() && !request.is_empty() {
//!         let taken = tls.write(request)?.count();
//!         request = &request[taken..];
//!         continue;
//!     }
//!     if at == end {
//!         (at, end) = (0, socket.read(&mut buf)?);
//!         if end == 0 {
//!             tls.eof()?;                    // Truncated without close_notify
//!             break;
//!         }
//!     }
//!     at += tls.input(&buf[at..end])?.count();
//!     use_data(tls.read());
//!     tls.consume(tls.read().len());
//! }
//! ```
//!
//! On an error, send what pending still holds (the alert) before the
//! socket closes. A poll loop: watch the socket for writing while
//! pending holds bytes. When the client awaits, start trust's check on
//! the chain (Trust::check, which never blocks) and stop reading the
//! socket; keep unread bytes. When the check's poll answers, call
//! verified with its approval or refused, then go on with the kept
//! bytes and the socket as before. Never call verify_blocking on the
//! loop's thread.

use crate::base::aesgcm::{self, OpeningKey, SealingKey};
use crate::base::ecdh;
use crate::base::mlkem;
use crate::base::random;
use crate::base::sha256::{self, Sha256};
use crate::base::sha384::{self, Sha384};
use crate::base::x509;
use crate::base::x25519;
use alloc::boxed::Box;
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
/// Records in a row that carry nothing, before the client gives up on
/// the server: empty application data, change_cipher_spec, user_canceled,
/// KeyUpdate and NewSessionTicket, as BoringSSL bounds them.
const IDLE_MAX: u8 = 32;

const HEADER: usize = 5;
const TAG: usize = aesgcm::TAG_LEN;
/// A protected record: the plaintext, its type byte and up to 255 of
/// padding, and the tag (RFC 9846 5.2).
const CIPHERTEXT_MAX: usize = RECORD_MAX + 256;
/// A full record as this client seals it, without padding.
const SEALED_MAX: usize = HEADER + RECORD_MAX + 1 + TAG;
/// Records under one key before the client updates its own: RFC 9846
/// 5.5 allows AES-GCM 2^24.5 full records.
const KEY_RECORDS_MAX: u64 = 1 << 24;
/// The longest hash of a suite: SHA-384's.
const HASH_MAX: usize = sha384::SHA384_BYTES;
/// Key changes in pending at once, each a Mark: the handshake keys after
/// the ClientHello, the application keys after Finished, one KeyUpdate
/// that answers the server and one of the client's own.
const MARKS_MAX: usize = 4;
/// A KeyUpdate and an alert, sealed.
const KEY_UPDATE_SEALED: usize = HEADER + 4 + 1 + 1 + TAG;
const ALERT_SEALED: usize = HEADER + 2 + 1 + TAG;
/// The first ClientHello's key shares: X25519MLKEM768's and X25519's.
const SHARES_BYTES: usize = 6 + (4 + HYBRID_SHARE) + (4 + x25519::KEY_BYTES);
/// The longest ClientHello: header and fixed fields with two suites and
/// the session ID,
/// SNI of 253 bytes, groups, signatures, versions, the key shares, the
/// whole ALPN list and the largest cookie, as hello writes them.
const HELLO_MAX: usize =
    4 + 45 + 32 + (9 + 253) + 12 + 24 + 7 + SHARES_BYTES + (6 + ALPN_MAX) + (6 + COOKIE_MAX);
/// The middlebox compatibility record: change_cipher_spec.
const CCS_RECORD: [u8; 6] = [CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1];
/// What the handshake may leave pending when the caller sends none of
/// it: both ClientHellos, change_cipher_spec, the empty Certificate,
/// Finished, and an alert.
const HANDSHAKE_PENDING_MAX: usize = 2 * (HEADER + HELLO_MAX)
    + CCS_RECORD.len()
    + (HEADER + 4 + 1 + 3 + 1 + TAG)
    + (HEADER + 4 + HASH_MAX + 1 + TAG)
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
const SUPPORTED_GROUPS: u16 = 10;
const SIGNATURE_ALGORITHMS: u16 = 13;
const ALPN: u16 = 16;
const SUPPORTED_VERSIONS: u16 = 43;
const COOKIE: u16 = 44;
const KEY_SHARE: u16 = 51;

const TLS13: u16 = 0x0304;
const AES_128_GCM_SHA256: u16 = 0x1301;
const AES_256_GCM_SHA384: u16 = 0x1302;
// Named groups.
const SECP256R1: u16 = 0x0017;
const X25519: u16 = 0x001d;
const X25519MLKEM768: u16 = 0x11ec;
/// X25519MLKEM768's shares: ML-KEM-768's encapsulation key or ciphertext,
/// then X25519's key (draft-ietf-tls-ecdhe-mlkem 3).
const HYBRID_SHARE: usize = mlkem::ENCAPSULATION_KEY_BYTES + x25519::KEY_BYTES;
const HYBRID_REPLY: usize = mlkem::CIPHERTEXT_BYTES + x25519::KEY_BYTES;

/// ServerHello's random when it is a HelloRetryRequest: SHA-256 of
/// "HelloRetryRequest" (RFC 9846 4.2.3).
const HELLO_RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The last 8 bytes of ServerHello.random from a TLS 1.3 server that
/// negotiates TLS 1.2, or below it (RFC 9846 4.2.3).
const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
const DOWNGRADE_TLS11: [u8; 8] = *b"DOWNGRD\x00";

/// What CertificateVerify's signature covers before the transcript hash.
const VERIFY_CONTEXT: &[u8; 34] = b"TLS 1.3, server CertificateVerify\0";

/// Why the connection failed, or a call was refused. A failure sticks:
/// each later input, write and eof returns it, and pending holds only
/// the rest of a record the caller began to send and the alert that
/// tells the server, when there is one: records queued but not begun
/// are dropped. The caller's mistakes (NotConnected, Closed, Awaiting,
/// Unconsumed, Sent, NotAwaiting) are refused calls instead: the
/// connection goes on, and the call did nothing.
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
    /// A required extension is not there: a CertificateRequest without
    /// signature_algorithms (missing_extension).
    Missing,
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
    /// A certificate the store holds revoked, with no path around it
    /// (certificate_revoked).
    Revoked,
    /// The chain is refused for another reason (bad_certificate).
    Certificate,
    /// CertificateVerify does not verify (decrypt_error).
    Signature,
    /// The server's Finished does not verify (decrypt_error).
    Finished,
    /// A limit of the client's own: a sequence number or the pending
    /// buffer would overflow (internal_error).
    Internal,
    /// The server sent this alert. close_notify (0) during the handshake
    /// is one too.
    Alert(u8),
    /// The caller's approval is of another leaf or host than this
    /// connection's (internal_error: the server is not at fault).
    Approval,
    /// The transport ended before the server's close_notify (eof): what
    /// came may have been cut short (RFC 9846 6.1).
    Truncated,
    /// write before the handshake is complete.
    NotConnected,
    /// write after close.
    Closed,
    /// input while the handshake awaits the caller's verdict: call
    /// verified or refused first.
    Awaiting,
    /// input while read holds plaintext: consume it first.
    Unconsumed,
    /// sent counted more bytes than pending holds.
    Sent,
    /// verified while no verdict is awaited.
    NotAwaiting,
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
            Error::Parameter => Some(47),
            Error::Missing => Some(109),
            Error::Untrusted => Some(48),
            Error::Revoked => Some(44),
            Error::Decode | Error::TooLarge => Some(50),
            Error::Signature | Error::Finished => Some(51),
            Error::Version => Some(70),
            Error::Internal | Error::Approval => Some(80),
            Error::Extension => Some(110),
            Error::Host
            | Error::Alpn
            | Error::Alert(_)
            | Error::Truncated
            | Error::NotConnected
            | Error::Closed
            | Error::Awaiting
            | Error::Unconsumed
            | Error::Sent
            | Error::NotAwaiting => None,
        }
    }
}

impl From<aesgcm::Error> for Error {
    fn from(error: aesgcm::Error) -> Error {
        match error {
            aesgcm::Error::Forged => Error::Forged,
            aesgcm::Error::TooLong => Error::Overflow,
            // 2^64 - 1 records would take a peer longer than a connection
            // lasts; the client ends it rather than wrap (RFC 9846 5.3).
            aesgcm::Error::Exhausted => Error::Internal,
        }
    }
}

impl From<x509::Error> for Error {
    fn from(error: x509::Error) -> Error {
        match error {
            x509::Error::Expired => Error::Expired,
            x509::Error::Host => Error::Name,
            x509::Error::Untrusted | x509::Error::Distrusted => Error::Untrusted,
            x509::Error::Revoked => Error::Revoked,
            x509::Error::Approval => Error::Approval,
            x509::Error::Malformed
            | x509::Error::Unsupported
            | x509::Error::Critical
            | x509::Error::Duplicate
            | x509::Error::Usage
            | x509::Error::NotCa
            | x509::Error::PathLength
            | x509::Error::Constrained
            | x509::Error::Signature
            | x509::Error::TooMany
            | x509::Error::Order => Error::Certificate,
        }
    }
}

/// How many bytes input or write took: what is past them was not taken
/// and goes in again. A count left unread is a warning, as dropping it
/// would lose data.
#[must_use = "the bytes past the count were not taken: pass them again"]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Taken(usize);

impl Taken {
    /// The bytes taken, from the front.
    pub fn count(self) -> usize {
        self.0
    }
}

/// Middlebox compatibility's change_cipher_spec.
#[derive(Clone, Copy)]
enum Ccs {
    Due,
    Sent,
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
    /// close came before the handshake was complete: the client's
    /// Finished never goes, so it never connects, and what comes is
    /// ignored.
    Abandoned,
}

/// A secret or a transcript hash, of the suite's hash: SHA-256 for
/// TLS_AES_128_GCM_SHA256, SHA-384 for TLS_AES_256_GCM_SHA384. A secret
/// keeps its hash through the key schedule. It is not Copy, so that a
/// secret moves rather than leaves copies, and each is wiped when it
/// goes.
enum Digest {
    Sha256([u8; sha256::DIGEST_BYTES]),
    Sha384([u8; sha384::SHA384_BYTES]),
}

impl Digest {
    fn bytes(&self) -> &[u8] {
        match self {
            Digest::Sha256(bytes) => bytes,
            Digest::Sha384(bytes) => bytes,
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Digest::Sha256(bytes) => bytes,
            Digest::Sha384(bytes) => bytes,
        }
    }

    /// Zeros as long as the hash.
    fn zero(&self) -> Digest {
        match self {
            Digest::Sha256(_) => Digest::Sha256([0; sha256::DIGEST_BYTES]),
            Digest::Sha384(_) => Digest::Sha384([0; sha384::SHA384_BYTES]),
        }
    }

    /// The hash of data, by the same hash.
    fn of(&self, data: &[u8]) -> Digest {
        match self {
            Digest::Sha256(_) => Digest::Sha256(sha256::digest(data)),
            Digest::Sha384(_) => Digest::Sha384(sha384::digest384(data)),
        }
    }

    /// HKDF-Extract of input with this as the salt.
    fn extract(&self, input: &[u8]) -> Digest {
        match self {
            Digest::Sha256(salt) => Digest::Sha256(*sha256::hkdf_extract(salt, input).bytes()),
            Digest::Sha384(salt) => Digest::Sha384(*sha384::hkdf_extract(salt, input).bytes()),
        }
    }
}

impl Drop for Digest {
    fn drop(&mut self) {
        random::wipe(self.bytes_mut());
    }
}

/// The client's direction's record protection: the traffic secret, for
/// KeyUpdate, and the key and IV, which number the records it seals.
/// The secret's hash names the suite: AES-128-GCM after SHA-256's,
/// AES-256-GCM after SHA-384's.
struct Keys {
    secret: Digest,
    key: SealingKey,
}

/// The server's direction's: the same, opening its records.
struct Opening {
    secret: Digest,
    key: OpeningKey,
}

impl Keys {
    /// The keys of secret, which they keep.
    fn new(secret: Digest) -> Keys {
        let mut iv = [0; aesgcm::NONCE_LEN];
        expand(&secret, b"iv", &[], &mut iv);
        let key = match secret {
            Digest::Sha256(_) => {
                let mut key = [0; aesgcm::KEY_LEN];
                expand(&secret, b"key", &[], &mut key);
                let sealing = SealingKey::new(&key, &iv);
                random::wipe(&mut key);
                sealing
            }
            Digest::Sha384(_) => {
                let mut key = [0; aesgcm::KEY256_LEN];
                expand(&secret, b"key", &[], &mut key);
                let sealing = SealingKey::new256(&key, &iv);
                random::wipe(&mut key);
                sealing
            }
        };
        Keys { secret, key }
    }

    /// The keys after a KeyUpdate (RFC 9846 7.2).
    fn next(&self) -> Keys {
        Keys::new(derive(&self.secret, b"traffic upd", &[]))
    }
}

impl Opening {
    /// The keys of secret, which they keep.
    fn new(secret: Digest) -> Opening {
        let mut iv = [0; aesgcm::NONCE_LEN];
        expand(&secret, b"iv", &[], &mut iv);
        let key = match secret {
            Digest::Sha256(_) => {
                let mut key = [0; aesgcm::KEY_LEN];
                expand(&secret, b"key", &[], &mut key);
                let opening = OpeningKey::new(&key, &iv);
                random::wipe(&mut key);
                opening
            }
            Digest::Sha384(_) => {
                let mut key = [0; aesgcm::KEY256_LEN];
                expand(&secret, b"key", &[], &mut key);
                let opening = OpeningKey::new256(&key, &iv);
                random::wipe(&mut key);
                opening
            }
        };
        Opening { secret, key }
    }

    /// The keys after a KeyUpdate (RFC 9846 7.2).
    fn next(&self) -> Opening {
        Opening::new(derive(&self.secret, b"traffic upd", &[]))
    }
}

/// The transcript (RFC 9846 4.1): by both hashes until ServerHello, or a
/// HelloRetryRequest, names the suite, then by its hash alone. SHA-384's
/// state is boxed, so that a client of TLS_AES_128_GCM_SHA256 stays small
/// once it drops it.
enum Transcript {
    Both(Sha256, Box<Sha384>),
    Sha256(Sha256),
    Sha384(Box<Sha384>),
}

impl Transcript {
    fn new() -> Transcript {
        Transcript::Both(Sha256::new(), Box::new(Sha384::new()))
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Transcript::Both(a, b) => {
                a.update(data);
                b.update(data);
            }
            Transcript::Sha256(a) => a.update(data),
            Transcript::Sha384(b) => b.update(data),
        }
    }

    /// The hash so far; SHA-256's while both run, which no caller asks for.
    fn hash(&self) -> Digest {
        match self {
            // rr: escape(copy): the transcript goes on past this hash.
            Transcript::Both(a, _) | Transcript::Sha256(a) => Digest::Sha256(a.clone().finish()),
            // fork copies: the transcript goes on past this hash.
            Transcript::Sha384(b) => Digest::Sha384(b.fork().finish()),
        }
    }

    /// Keeps the hash of the suite the server chose: one the client did
    /// not offer, or after a HelloRetryRequest another than it named, is
    /// illegal_parameter (RFC 9846 4.2.3, 4.2.4).
    fn select(&mut self, suite: u16) -> Result<(), Error> {
        match (&*self, suite) {
            (Transcript::Sha256(_), AES_128_GCM_SHA256)
            | (Transcript::Sha384(_), AES_256_GCM_SHA384) => return Ok(()),
            (Transcript::Both(..), AES_128_GCM_SHA256 | AES_256_GCM_SHA384) => {}
            _ => return Err(Error::Parameter),
        }
        let both = core::mem::replace(self, Transcript::Sha256(Sha256::new()));
        if let Transcript::Both(a, b) = both {
            *self = if suite == AES_256_GCM_SHA384 {
                Transcript::Sha384(b)
            } else {
                Transcript::Sha256(a)
            };
        }
        Ok(())
    }

    /// A new transcript by the same hash, which a HelloRetryRequest starts
    /// with the first ClientHello's hash.
    fn restart(&mut self) {
        match self {
            Transcript::Both(a, b) => {
                *a = Sha256::new();
                **b = Sha384::new();
            }
            Transcript::Sha256(a) => *a = Sha256::new(),
            Transcript::Sha384(b) => **b = Sha384::new(),
        }
    }
}

/// Where the output keys changed in pending: the record at at is the
/// first under the next keys, and the ones before end under secret
/// (none: in the clear) at sequence number seq. A failure takes the
/// keys back to the first record not yet begun, which it drops. A slot
/// let go is set to UNMARKED, which wipes its secret.
struct Mark {
    at: usize,
    secret: Option<Digest>,
    seq: u64,
}

/// A slot of marks that holds no change.
const UNMARKED: Mark = Mark {
    at: 0,
    secret: None,
    seq: 0,
};

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

/// Who verifies the server's chain.
pub enum Verify<'a> {
    /// x509 against these anchors, for the host at the time given.
    Store(&'a x509::Store),
    /// The caller, such as the operating system's verifier on a thread
    /// (trust::Check): the handshake waits at the server's Certificate
    /// until verified takes the x509::Approval of its leaf for the
    /// client's host, or refused ends it. The client takes the leaf's key
    /// from it, which checks CertificateVerify.
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
    /// legacy_session_id: random, for middlebox compatibility (RFC 9846
    /// E.4), and echoed by the server; none without it, as RFC 8448's
    /// client.
    session: Option<[u8; 32]>,
    /// The X25519 secret, until ServerHello, and its public key.
    secret: Option<x25519::Secret>,
    public: [u8; x25519::KEY_BYTES],
    /// ML-KEM-768's half of the X25519MLKEM768 share, until ServerHello.
    kem: Option<Box<mlkem::DecapsulationKey>>,
    /// A P-256 secret, for a server that asks for that group, until
    /// ServerHello, and its public key once one did.
    p256: Option<ecdh::Secret>,
    p256_public: Option<[u8; ecdh::PUBLIC_BYTES]>,
    /// The group a HelloRetryRequest asked for: the second ClientHello
    /// shares a key for it alone, and ServerHello must choose it.
    group: Option<u16>,
    /// The change_cipher_spec of middlebox compatibility: sent once,
    /// before the second ClientHello or the client's encrypted flight.
    ccs: Ccs,
    /// Records in a row that carried nothing.
    idle: u8,
    state: State,
    transcript: Transcript,
    /// The key that checks the server's Finished.
    server_finished: Digest,
    /// The master secret, which the application keys come from.
    master: Digest,
    /// The approval of the leaf, from x509 or the caller, until
    /// CertificateVerify is checked with its key.
    approval: Option<x509::Approval>,
    /// The leaf's DER, whose key checks CertificateVerify, the message
    /// after its own, once that message's buffer has moved on.
    // rr: escape(bound): x509 refuses a certificate over
    // CERTIFICATE_BYTES_MAX, and this is cleared before it takes one.
    leaf: Vec<u8>,
    /// The server asked for a certificate: the client answers with an
    /// empty Certificate.
    requested: bool,
    input_keys: Option<Opening>,
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
    /// The output keys' changes in tx after tx_at, oldest first.
    marks: [Mark; MARKS_MAX],
    marked: usize,
    /// close_notify or a fatal alert is queued: nothing goes after it.
    close_sent: bool,
    failed: Option<Error>,
}

/// The randomness a client draws: the ClientHello's random and
/// legacy_session_id, and the seeds of the X25519, ML-KEM-768 and P-256
/// keys. Only the system's (system) or, in a test or a fuzz target, a
/// fixed one: never bytes a caller made up. A program takes it where it
/// takes the time, so that a simulation can stand in for both.
pub struct Random {
    client: [u8; 32],
    session: [u8; 32],
    x25519: random::Seed32,
    mlkem: random::Seed64,
    p256: random::Seed64,
}

impl Random {
    /// The system's, from the random component.
    pub fn system() -> Random {
        let (mut client, mut session) = ([0; 32], [0; 32]);
        random::fill(&mut client);
        random::fill(&mut session);
        Random {
            client,
            session,
            x25519: random::seed32(),
            mlkem: random::seed64(),
            p256: random::seed64(),
        }
    }

    /// The same every time, so that a test or a fuzz target replays: the
    /// bytes 0x5c, an X25519 secret of x25519.
    #[cfg(any(test, fuzzing))]
    pub fn fixed(x25519: [u8; x25519::KEY_BYTES]) -> Random {
        Random {
            client: [0x5c; 32],
            session: [0x5c; 32],
            x25519: random::Seed32::for_tests(x25519),
            mlkem: random::Seed64::for_tests([0x5c; 64]),
            p256: random::Seed64::for_tests([0x5c; 64]),
        }
    }
}

impl<'a> Client<'a> {
    /// A client for host (a DNS name, or an IP literal, which SNI does
    /// not carry), offering the ALPN protocols given, if any, and
    /// verifying the server's chain as verify says, at now (Unix seconds).
    /// The ClientHello is pending: it offers X25519MLKEM768 and X25519,
    /// sharing a key for both, and P-256 for a server that asks for it in
    /// a retry; its random, session ID and keys come from random.
    pub fn new(
        host: &str,
        alpn: &[&[u8]],
        verify: Verify<'a>,
        now: i64,
        random: Random,
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
        let Random {
            client: client_random,
            session,
            x25519,
            mlkem,
            p256,
        } = random;
        let secret = x25519::Secret::new(x25519);
        // rr: escape(move): once a connection, as it starts; boxed, so
        // that the client stays small after the handshake drops it.
        let kem = Box::new(mlkem::DecapsulationKey::generate(mlkem));
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
            session: Some(session),
            public: *secret.public_key().bytes(),
            secret: Some(secret),
            kem: Some(kem),
            p256: Some(ecdh::Secret::new(p256)),
            p256_public: None,
            group: None,
            ccs: Ccs::Due,
            idle: 0,
            state: State::Hello,
            transcript: Transcript::new(),
            server_finished: Digest::Sha256([0; sha256::DIGEST_BYTES]),
            master: Digest::Sha256([0; sha256::DIGEST_BYTES]),
            approval: None,
            leaf: Vec::new(),
            requested: false,
            input_keys: None,
            output_keys: None,
            rx: Vec::with_capacity(HEADER + CIPHERTEXT_MAX),
            app_at: 0,
            app_end: 0,
            hs: Vec::new(),
            tx: Vec::with_capacity(TX_MAX),
            tx_at: 0,
            reply_end: 0,
            marks: [UNMARKED; MARKS_MAX],
            marked: 0,
            close_sent: false,
            failed: None,
        };
        let hello = client.hello(&[]);
        // The first ClientHello's record says TLS 1.0, as most clients'
        // do, for middleboxes that look (RFC 9846 5.1).
        client.handshake_message(&hello, 1)?;
        Ok(client)
    }

    /// Takes bytes from the socket, in any split, and returns how many
    /// it took. It stops early when a record's plaintext waits to be
    /// read, after RECORDS_PER_INPUT records, and at the server's
    /// Certificate when the caller verifies it: what it did not take goes
    /// in again, after read and consume, or after verified. While read
    /// holds plaintext it refuses with Unconsumed, and while a verdict is
    /// awaited with Awaiting: a loop that forgets either fails loudly
    /// rather than spin. Bytes after the server's close_notify are taken
    /// and ignored. When the socket ends, call eof.
    #[cfg_attr(rr, rr::hot)]
    pub fn input(&mut self, bytes: &[u8]) -> Result<Taken, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.app_end != 0 {
            return Err(Error::Unconsumed);
        }
        if matches!(self.state, State::Awaiting) {
            return Err(Error::Awaiting);
        }
        match self.take(bytes) {
            Ok(taken) => Ok(Taken(taken)),
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

    /// Marks n bytes of pending as written; more than pending holds is
    /// refused with Sent, and marks nothing.
    pub fn sent(&mut self, n: usize) -> Result<(), Error> {
        if n > self.pending().len() {
            return Err(Error::Sent);
        }
        self.tx_at += n;
        // A key change whose first record has begun is past taking back.
        let begun = self
            .marks
            .iter()
            .take(self.marked)
            .take_while(|mark| mark.at <= self.tx_at)
            .count();
        let live = self.marks.get_mut(..self.marked).unwrap_or_default();
        live.rotate_left(begun);
        for slot in live.iter_mut().skip(self.marked - begun) {
            *slot = UNMARKED;
        }
        self.marked -= begun;
        self.drained();
        Ok(())
    }

    /// Seals application data into records of up to RECORD_MAX bytes and
    /// returns how much it took: less than all when pending would pass
    /// PENDING_MAX, and none until pending is sent. The rest goes in
    /// again once pending is sent.
    #[cfg_attr(rr, rr::hot)]
    pub fn write(&mut self, data: &[u8]) -> Result<Taken, Error> {
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
            Ok(taken) => Ok(Taken(taken)),
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

    /// The socket ended (a read of nothing): fine once the server's
    /// close_notify came, or after close ended the handshake. Otherwise
    /// what came may have been cut short (RFC 9846 6.1): the connection
    /// fails with Truncated, and what was read must not be taken as
    /// whole.
    pub fn eof(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if matches!(self.state, State::Closed | State::Abandoned) {
            return Ok(());
        }
        self.fail(Error::Truncated);
        Err(Error::Truncated)
    }

    /// Queues close_notify; nothing is written after it. Before the
    /// handshake is complete it ends the handshake: the client's Finished
    /// is never sent, so the client never connects, and input takes and
    /// ignores what the server sends.
    pub fn close(&mut self) {
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        if !matches!(self.state, State::Connected | State::Closed) {
            self.state = State::Abandoned;
            self.hs = Vec::new();
            self.leaf = Vec::new();
            self.approval = None;
        }
        if let Err(error) = self.records(ALERT, &[1, 0], 3) {
            self.fail(error);
        }
    }

    /// The protocol the server chose by ALPN.
    pub fn alpn(&self) -> Option<&[u8]> {
        let (at, length) = self.chosen?;
        self.offer.get(at..at + length)
    }

    /// Whether the handshake waits for verified or refused:
    /// Verify::Caller, and the server's Certificate is in. Not once the
    /// connection failed, as refused fails it: input then says why.
    pub fn awaiting(&self) -> bool {
        matches!(self.state, State::Awaiting) && self.failed.is_none()
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

    /// The caller's yes to chain: approval, which x509::verify or
    /// trust's check gave for chain's leaf and the client's host. The
    /// handshake goes on with the messages already in, CertificateVerify
    /// first, which the client checks with the leaf's key; their error,
    /// if any, is returned and sticks. An approval of another leaf or
    /// host fails the connection with Approval, whose alert is
    /// internal_error. NotAwaiting while nothing is awaited.
    pub fn verified(&mut self, approval: x509::Approval) -> Result<(), Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if !self.awaiting() {
            return Err(Error::NotAwaiting);
        }
        let mut slots = [&[][..]; x509::CHAIN_MAX];
        let matches = self.chain(&mut slots).is_some()
            && slots
                .first()
                .is_some_and(|leaf| approval.approves(leaf, &self.host));
        if !matches {
            self.fail(Error::Approval);
            return Err(Error::Approval);
        }
        self.approval = Some(approval);
        self.state = State::Trusted;
        let buffer = core::mem::take(&mut self.hs);
        if let Err(error) = self.proceed(buffer) {
            self.fail(error);
            return Err(error);
        }
        Ok(())
    }

    /// The caller's no: its verifier refused the chain, or failed to
    /// answer. The connection fails with Untrusted, whose alert is
    /// unknown_ca: the chain did not lead to an anchor the caller trusts
    /// (RFC 9846 6.2). Once the connection failed it does nothing.
    pub fn refused(&mut self) {
        if self.failed.is_none() {
            self.fail(Error::Untrusted);
        }
    }

    /// Ends the connection on error: nothing more goes out (RFC 9846 6,
    /// 6.2) but the rest of a record the caller began to send, which a
    /// torn record would garble, and the alert for the error, if any,
    /// unless close_notify began before it. Everything else stops.
    fn fail(&mut self, error: Error) {
        self.failed = Some(error);
        self.approval = None;
        self.app_at = 0;
        self.app_end = 0;
        self.rx.clear();
        self.hs.clear();
        let kept = self.begun();
        // close_notify is the last record: it began if nothing after the
        // kept ones is left.
        let closed = self.close_sent && kept == self.tx.len();
        self.rewind(kept);
        if let Some(code) = error.alert()
            && !closed
        {
            // rr: escape(discard): the connection is over whether the
            // alert is queued or not.
            let _: Result<(), Error> = self.records(ALERT, &[2, code], 3);
        }
        self.close_sent = true;
    }

    /// Where the first record of tx not yet begun starts: the end of the
    /// record tx_at is in, or tx_at between records.
    fn begun(&self) -> usize {
        let mut at = 0;
        while at < self.tx_at {
            let Some(&[_, _, _, high, low]) =
                self.tx.get(at..).and_then(<[u8]>::first_chunk::<HEADER>)
            else {
                return self.tx.len();
            };
            at += HEADER + usize::from(u16::from_be_bytes([high, low]));
        }
        at.min(self.tx.len())
    }

    /// Drops the records of tx from kept on, and takes the output keys
    /// back to those the first of them was sealed under, at its sequence
    /// number: what goes next follows the records the server gets.
    fn rewind(&mut self, kept: usize) {
        if kept >= self.tx.len() {
            return;
        }
        // The first change after kept: the keys before it sealed the
        // first record dropped.
        let first = self
            .marks
            .iter()
            .take(self.marked)
            .position(|mark| mark.at > kept);
        let (sealed, mut seq, end) = match first.and_then(|index| self.marks.get(index)) {
            Some(mark) => (mark.secret.is_some(), mark.seq, mark.at),
            None => (
                self.output_keys.is_some(),
                self.output_keys
                    .as_ref()
                    .map_or(0, |keys| keys.key.sequence()),
                self.tx.len(),
            ),
        };
        // The sealed records dropped under those keys: each took a number.
        let mut at = kept;
        while at < end {
            let Some(&[kind, _, _, high, low]) =
                self.tx.get(at..).and_then(<[u8]>::first_chunk::<HEADER>)
            else {
                break;
            };
            if kind == APPLICATION && sealed {
                seq = seq.saturating_sub(1);
            }
            at += HEADER + usize::from(u16::from_be_bytes([high, low]));
        }
        if let Some(mark) = first.and_then(|index| self.marks.get_mut(index)) {
            self.output_keys = mark.secret.take().map(Keys::new);
        }
        if let Some(keys) = &mut self.output_keys {
            // The records that took these numbers are dropped unsent.
            keys.key.set_sequence_less_safe(seq);
        }
        self.tx.truncate(kept);
        self.unmark();
        self.reply_end = self.reply_end.min(kept);
    }

    /// The output keys from here on: the keys before, and where they end
    /// in tx, are kept while what they sealed is not yet sent.
    fn rekey(&mut self, keys: Keys) -> Result<(), Error> {
        let at = self.tx.len();
        let marking = at > self.tx_at;
        if marking && self.marked >= MARKS_MAX {
            return Err(Error::Internal);
        }
        let old = self.output_keys.replace(keys);
        if marking && let Some(slot) = self.marks.get_mut(self.marked) {
            let (secret, seq) = match old {
                Some(Keys { secret, key }) => (Some(secret), key.sequence()),
                None => (None, 0),
            };
            *slot = Mark { at, secret, seq };
            self.marked += 1;
        }
        Ok(())
    }

    /// Lets every mark go, wiping their secrets.
    fn unmark(&mut self) {
        for slot in self.marks.iter_mut().take(self.marked) {
            *slot = UNMARKED;
        }
        self.marked = 0;
    }

    fn take(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let mut taken = 0;
        for _ in 0..RECORDS_PER_INPUT {
            if matches!(self.state, State::Closed | State::Abandoned) {
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
        // legacy_record_version is ignored, as RFC 9846 5.1 says.
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

    /// Opens the protected record in rx in place (RFC 9846 5.2).
    fn protected(&mut self) -> Result<(), Error> {
        let Some(keys) = &mut self.input_keys else {
            return Err(Error::Unexpected);
        };
        let (header, body) = self.rx.split_at_mut_checked(HEADER).ok_or(Error::Decode)?;
        let at = body.len().checked_sub(TAG).ok_or(Error::Forged)?;
        let (data, tag) = body.split_at_mut_checked(at).ok_or(Error::Forged)?;
        let tag = tag.first_chunk::<TAG>().ok_or(Error::Forged)?;
        keys.key.open(header, data, tag)?;
        // TLSInnerPlaintext, padding and all, is 2^14 + 1 bytes at most
        // (RFC 9846 5.4).
        if data.len() > RECORD_MAX + 1 {
            return Err(Error::Overflow);
        }
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
                if end == 0 {
                    self.idle()?;
                } else {
                    self.idle = 0;
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
    /// Finished (RFC 9846 5).
    fn change_cipher_spec(&mut self) -> Result<(), Error> {
        let late = matches!(self.state, State::Connected | State::Closed);
        if late || !self.hs.is_empty() || self.rx.get(HEADER..) != Some(&[1][..]) {
            return Err(Error::Unexpected);
        }
        self.idle()
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
        // An alert record without content is unexpected_message (RFC 9846
        // 5.4), and so is one inside a handshake message.
        if !self.hs.is_empty() || start == stop {
            return Err(Error::Unexpected);
        }
        let Some(&[_, description]) = self.rx.get(start..stop) else {
            return Err(Error::Decode);
        };
        match description {
            // close_notify ends what the server sends.
            0 if matches!(self.state, State::Connected) => self.state = State::Closed,
            // user_canceled is followed by close_notify (RFC 9846 6.1).
            90 => self.idle()?,
            // Every other alert is an error, whatever its level (6.2).
            _ => return Err(Error::Alert(description)),
        }
        Ok(())
    }

    /// The handshake bytes at rx[start..stop], after any part message
    /// that came before them.
    fn handshake(&mut self, start: usize, stop: usize) -> Result<(), Error> {
        // A handshake record is never empty (RFC 9846 5.1).
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
            (State::Certificate, CERTIFICATE_REQUEST) if !self.requested => {
                self.request(message, body)
            }
            (State::Certificate | State::Trusted, CERTIFICATE) => self.certificate(message, body),
            (State::Verify, CERTIFICATE_VERIFY) => self.verify(message, body),
            (State::Finished, FINISHED) => self.finished(message, body),
            // No resumption: a ticket is of no use.
            (State::Connected, NEW_SESSION_TICKET) => {
                self.idle()?;
                Ok(false)
            }
            (State::Connected, KEY_UPDATE) => {
                self.idle()?;
                self.key_update(body)
            }
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
        // A server below TLS 1.3 may send no extensions at all (RFC 9846
        // E.1), as Go's parser takes it: the version check below answers.
        let block = if fields.rest.is_empty() {
            &[][..]
        } else {
            fields.vector(2)?
        };
        let mut extensions = Reader { rest: block };
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
        // A server below TLS 1.3 sends neither (protocol_version, RFC 9846
        // E.1); one that selects a version the client did not offer is
        // wrong (illegal_parameter, 4.3.1). A ServerHello of TLS 1.2 or
        // below that ends in a downgrade sentinel is illegal_parameter
        // first: 4.2.3 asks every TLS 1.3 client to check it. Go and
        // BoringSSL, which check it only once they accept TLS 1.2, answer
        // protocol_version when TLS 1.3 alone is enabled.
        match (version, selected) {
            (0x0303, Some(TLS13)) => {}
            (0x0303, Some(_)) => return Err(Error::Parameter),
            (..=0x0303, None)
                if random
                    .last_chunk::<8>()
                    .is_some_and(|tail| *tail == DOWNGRADE_TLS12 || *tail == DOWNGRADE_TLS11) =>
            {
                return Err(Error::Parameter);
            }
            _ => return Err(Error::Version),
        }
        if stray {
            return Err(Error::Extension);
        }
        let ours = self.session.as_ref().map_or(&[][..], |id| &id[..]);
        if session != ours || compression != 0 {
            return Err(Error::Parameter);
        }
        // A suite not offered, or after a HelloRetryRequest not the one it
        // named, is illegal_parameter (RFC 9846 4.2.3, 4.2.4).
        self.transcript.select(suite)?;
        if retry {
            return self.retry(message, share, cookie);
        }
        let Some((group, key)) = share else {
            return Err(Error::Parameter);
        };
        let mut shared = [0; 2 * 32];
        let agreed = self.agree(group, key, &mut shared);
        self.secret = None;
        self.p256 = None;
        self.kem = None;
        let length = match agreed {
            Ok(length) => length,
            Err(error) => {
                random::wipe(&mut shared);
                return Err(error);
            }
        };
        self.transcript.update(message);
        let secrets = handshake_secrets(shared.get(..length).unwrap_or_default(), &self.hash());
        random::wipe(&mut shared);
        self.server_finished = derive(&secrets.server, b"finished", &[]);
        let Secrets {
            client,
            server,
            master,
        } = secrets;
        self.master = master;
        self.input_keys = Some(Opening::new(server));
        self.rekey(Keys::new(client))?;
        self.state = State::Extensions;
        Ok(true)
    }

    /// The shared secret of the server's key share for group, into
    /// shared; its length. The group is one this ClientHello shared a
    /// key for: after a HelloRetryRequest, the one it asked for.
    fn agree(&self, group: u16, key: &[u8], shared: &mut [u8; 64]) -> Result<usize, Error> {
        let offered = match self.group {
            Some(asked) => group == asked,
            None => matches!(group, X25519MLKEM768 | X25519),
        };
        if !offered {
            return Err(Error::Parameter);
        }
        let (first, second) = shared.split_at_mut(32);
        match group {
            X25519 => {
                let peer = key.first_chunk::<32>().ok_or(Error::Parameter)?;
                if key.len() != 32 {
                    return Err(Error::Parameter);
                }
                first.copy_from_slice(self.x25519(peer)?.kdf_input());
                Ok(32)
            }
            X25519MLKEM768 => {
                // ML-KEM's secret, then X25519's (draft-ietf-tls-ecdhe-mlkem
                // 3); a ciphertext of the wrong length is illegal_parameter.
                let kem = self.kem.as_ref().ok_or(Error::Parameter)?;
                let (ciphertext, peer) = key
                    .split_first_chunk::<{ mlkem::CIPHERTEXT_BYTES }>()
                    .ok_or(Error::Parameter)?;
                let peer = peer.first_chunk::<32>().ok_or(Error::Parameter)?;
                if key.len() != HYBRID_REPLY {
                    return Err(Error::Parameter);
                }
                first.copy_from_slice(kem.decapsulate(ciphertext).kdf_input());
                second.copy_from_slice(self.x25519(peer)?.kdf_input());
                Ok(64)
            }
            _ => {
                // SECP256R1, the only group a retry may ask for.
                let secret = self.p256.as_ref().ok_or(Error::Parameter)?;
                let Ok(peer) = ecdh::PublicKey::parse(key) else {
                    return Err(Error::Parameter);
                };
                first.copy_from_slice(secret.agree(&peer).kdf_input());
                Ok(32)
            }
        }
    }

    /// The X25519 secret shared with peer; a point of small order is
    /// illegal_parameter (RFC 9846 7.4.2).
    fn x25519(&self, peer: &[u8; x25519::KEY_BYTES]) -> Result<x25519::SharedSecret, Error> {
        let secret = self.secret.as_ref().ok_or(Error::Parameter)?;
        let Ok(shared) = secret.agree(&x25519::PublicKey::from_bytes(peer)) else {
            return Err(Error::Parameter);
        };
        Ok(shared)
    }

    /// A HelloRetryRequest (RFC 9846 4.2.4): the second ClientHello
    /// shares a key for the group it asks for, P-256, the one offered
    /// without a share; and adds the cookie, if any. One that would change
    /// nothing is illegal_parameter.
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
            Some((SECP256R1, _)) => {
                let secret = self.p256.as_ref().ok_or(Error::Parameter)?;
                self.p256_public = Some(*secret.public_key().bytes());
                self.kem = None;
            }
            Some(_) => return Err(Error::Parameter),
            None if cookie.is_none() => return Err(Error::Parameter),
            None => {}
        }
        self.group = share.map(|(group, _)| group);
        if cookie.is_some_and(<[u8]>::is_empty) {
            return Err(Error::Decode);
        }
        let cookie = cookie.unwrap_or_default();
        if cookie.len() > COOKIE_MAX {
            return Err(Error::TooLarge);
        }
        // The first ClientHello stands in the transcript as its hash, by
        // the hash of the suite the retry names (RFC 9846 4.1).
        let first = self.hash();
        let length = u8::try_from(first.bytes().len()).unwrap_or(u8::MAX);
        self.transcript.restart();
        self.transcript.update(&[MESSAGE_HASH, 0, 0, length]);
        self.transcript.update(first.bytes());
        self.transcript.update(message);
        self.state = State::Retried;
        let hello = self.hello(cookie);
        // Middlebox compatibility: change_cipher_spec before it (E.4).
        self.compatible();
        self.handshake_message(&hello, 3)?;
        Ok(true)
    }

    /// Sends middlebox compatibility's change_cipher_spec once, in the
    /// clear, before the client's next record.
    fn compatible(&mut self) {
        if matches!(self.ccs, Ccs::Sent) || self.close_sent || self.session.is_none() {
            return;
        }
        self.ccs = Ccs::Sent;
        self.drained();
        self.tx.extend_from_slice(&CCS_RECORD);
    }

    /// A record that carried nothing: too many in a row end the
    /// connection.
    fn idle(&mut self) -> Result<(), Error> {
        self.idle = self.idle.saturating_add(1);
        if self.idle > IDLE_MAX {
            return Err(Error::Unexpected);
        }
        Ok(())
    }

    fn extensions(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut fields = Reader { rest: body };
        let mut list = Reader {
            rest: fields.vector(2)?,
        };
        fields.end()?;
        let mut seen = Seen::new();
        while !list.rest.is_empty() {
            let kind = list.u16()?;
            let data = list.vector(2)?;
            seen.add(kind)?;
            match kind {
                // The server used the name; nothing comes with it.
                SERVER_NAME if self.literal => return Err(Error::Extension),
                SERVER_NAME if !data.is_empty() => return Err(Error::Decode),
                ALPN => self.choose(data)?,
                // The name used, and the server's groups, information for
                // a later handshake.
                SERVER_NAME | SUPPORTED_GROUPS => {}
                // Offered in the ClientHello, but not for this message:
                // illegal_parameter (RFC 9846 4.3).
                SIGNATURE_ALGORITHMS | SUPPORTED_VERSIONS | COOKIE | KEY_SHARE => {
                    return Err(Error::Parameter);
                }
                // Never offered, known or not: unsupported_extension (RFC
                // 9846 4.3), as BoringSSL and rustls answer it.
                _ => return Err(Error::Extension),
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

    /// A CertificateRequest during the handshake: its context is empty
    /// and signature_algorithms is among its extensions, each once (RFC
    /// 9846 4.4.2). The empty Certificate answers it.
    fn request(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut fields = Reader { rest: body };
        let context = fields.vector(1)?;
        let mut list = Reader {
            rest: fields.vector(2)?,
        };
        fields.end()?;
        if !context.is_empty() {
            return Err(Error::Parameter);
        }
        let mut seen = Seen::new();
        let mut signatures = false;
        while !list.rest.is_empty() {
            let kind = list.u16()?;
            let mut data = Reader {
                rest: list.vector(2)?,
            };
            seen.add(kind)?;
            if kind == SIGNATURE_ALGORITHMS {
                let schemes = data.vector(2)?;
                data.end()?;
                if schemes.is_empty() || schemes.len() % 2 != 0 {
                    return Err(Error::Decode);
                }
                signatures = true;
            }
        }
        if !signatures {
            return Err(Error::Missing);
        }
        self.requested = true;
        self.transcript.update(message);
        Ok(false)
    }

    fn certificate(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        let mut slots: [&[u8]; x509::CHAIN_MAX] = [&[]; x509::CHAIN_MAX];
        let count = certificates(body, &mut slots)?;
        let chain = slots.get(..count).unwrap_or_default();
        let leaf = chain.first().copied().unwrap_or_default();
        match (&self.verify, self.state) {
            (Verify::Store(store), _) => {
                self.approval = Some(x509::verify(chain, store, &self.host, self.now)?);
            }
            (Verify::Caller, State::Trusted) => {}
            (Verify::Caller, _) => {
                self.state = State::Awaiting;
                return Ok(false);
            }
        }
        // The key must be one CertificateVerify can be checked with, and
        // allowed to sign it, whoever verified the chain, as BoringSSL has
        // it (tls13_both.cc): Leaf::approved checks.
        let approval = self.approval.as_ref().ok_or(Error::Approval)?;
        x509::Leaf::approved(leaf, approval)?;
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
        if !matches!(scheme, 0x0403 | 0x0503 | 0x0603 | 0x0804 | 0x0805 | 0x0806) {
            return Err(Error::Parameter);
        }
        // RFC 9846 4.5.2: 64 spaces, the context string and the hash.
        let mut space = [0x20; 64 + VERIFY_CONTEXT.len() + HASH_MAX];
        let hash = self.hash();
        for (byte, value) in space
            .iter_mut()
            .skip(64)
            .zip(VERIFY_CONTEXT.iter().chain(hash.bytes()))
        {
            *byte = *value;
        }
        let covered = 64 + VERIFY_CONTEXT.len() + hash.bytes().len();
        let content = space.get(..covered).unwrap_or_default();
        let approval = self.approval.as_ref().ok_or(Error::Approval)?;
        let leaf = x509::Leaf::approved(&self.leaf, approval)?;
        if leaf.verify_tls13(scheme, content, signature).is_err() {
            return Err(Error::Signature);
        }
        self.leaf = Vec::new();
        self.approval = None;
        self.transcript.update(message);
        self.state = State::Finished;
        Ok(false)
    }

    /// The server's Finished; the client's flight and the application
    /// keys follow it.
    fn finished(&mut self, message: &[u8], body: &[u8]) -> Result<bool, Error> {
        verify_mac(&self.server_finished, &self.hash(), body)?;
        self.transcript.update(message);
        let hash = self.hash();
        let client = derive(&self.master, b"c ap traffic", hash.bytes());
        let server = derive(&self.master, b"s ap traffic", hash.bytes());
        self.input_keys = Some(Opening::new(server));
        // Middlebox compatibility: change_cipher_spec before the client's
        // encrypted flight, unless it went before a second ClientHello.
        self.compatible();
        if self.requested {
            // An empty Certificate: an empty context, and no certificates.
            let [kind, high, middle, low] = message_header(CERTIFICATE, 4);
            self.handshake_message(&[kind, high, middle, low, 0, 0, 0, 0], 3)?;
        }
        let Some(keys) = &self.output_keys else {
            return Err(Error::Unexpected);
        };
        let key = derive(&keys.secret, b"finished", &[]);
        let verify = mac(&key, &self.hash());
        let size = verify.bytes().len();
        let mut ours = [0; 4 + HASH_MAX];
        for (byte, value) in ours
            .iter_mut()
            .zip(message_header(FINISHED, size).iter().chain(verify.bytes()))
        {
            *byte = *value;
        }
        self.handshake_message(ours.get(..4 + size).unwrap_or_default(), 3)?;
        self.rekey(Keys::new(client))?;
        // Of the ALPN offer, only the choice is kept, for alpn.
        if let Some((at, length)) = self.chosen {
            self.offer.drain(..at);
            self.offer.truncate(length);
            self.chosen = Some((0, length));
        } else {
            self.offer.clear();
        }
        self.offer.shrink_to_fit();
        self.master = self.master.zero();
        self.server_finished = self.server_finished.zero();
        // The transcript is done with: SHA-384's box goes.
        self.transcript = Transcript::Sha256(Sha256::new());
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
        self.rekey(next)
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
                .is_some_and(|keys| keys.key.sequence() >= KEY_RECORDS_MAX)
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
            self.unmark();
        }
    }

    /// A handshake message into the transcript and out in records.
    /// A handshake message of the client's: in the transcript, and sent
    /// unless close_notify went, after which nothing is.
    fn handshake_message(&mut self, message: &[u8], minor: u8) -> Result<(), Error> {
        self.transcript.update(message);
        if self.close_sent {
            return Ok(());
        }
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

    /// The transcript's hash so far, by the suite's hash.
    fn hash(&self) -> Digest {
        self.transcript.hash()
    }

    /// A ClientHello with the cookie, if any (RFC 9846 4.2.2). The
    /// limits on host, ALPN and cookie keep every length in its field.
    fn hello(&self, cookie: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(256 + self.host.len() + self.offer.len() + cookie.len());
        m.extend_from_slice(&[CLIENT_HELLO, 0, 0, 0, 3, 3]);
        m.extend_from_slice(&self.random);
        // A session ID of 32 random bytes, for middlebox compatibility
        // (RFC 9846 E.4); the suites, AES-128 first as Go and BoringSSL
        // order them where the CPU has AES instructions, and no
        // compression.
        let session = self.session.as_ref().map_or(&[][..], |id| &id[..]);
        m.push(u8::try_from(session.len()).unwrap_or(0));
        m.extend_from_slice(session);
        m.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02, 1, 0]);
        let extensions = m.len();
        m.extend_from_slice(&[0, 0]);
        if !self.literal {
            let host = self.host.as_bytes();
            put(&mut m, &[0, 0], host.len() + 5);
            put(&mut m, &[], host.len() + 3);
            put(&mut m, &[0], host.len());
            m.extend_from_slice(host);
        }
        // supported_groups: X25519MLKEM768, X25519, P-256, as Go offers
        // them.
        m.extend_from_slice(&[0, 10, 0, 8, 0, 6, 0x11, 0xec, 0, 0x1d, 0, 0x17]);
        // signature_algorithms: what CertificateVerify may use, then
        // PKCS #1, which only certificates may (RFC 9846 4.3.3).
        m.extend_from_slice(&[
            0, 13, 0, 20, 0, 18, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1,
        ]);
        // supported_versions: TLS 1.3.
        m.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
        // key_share: P-256's alone after a retry that asked for it;
        // else X25519MLKEM768's and X25519's, one X25519 key for both.
        match (self.p256_public, &self.kem) {
            (Some(public), _) if self.group == Some(SECP256R1) => {
                put(&mut m, &[0, 51], public.len() + 6);
                put(&mut m, &[], public.len() + 4);
                put(&mut m, &[0x00, 0x17], public.len());
                m.extend_from_slice(&public);
            }
            (_, Some(kem)) => {
                put(&mut m, &[0, 51], SHARES_BYTES - 4);
                put(&mut m, &[], SHARES_BYTES - 6);
                put(&mut m, &[0x11, 0xec], HYBRID_SHARE);
                m.extend_from_slice(&kem.encapsulation_key());
                m.extend_from_slice(&self.public);
                put(&mut m, &[0, 0x1d], x25519::KEY_BYTES);
                m.extend_from_slice(&self.public);
            }
            // The shares are sent before ServerHello drops them.
            _ => {}
        }
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

/// The extension types of one block, which may each come once (RFC 9846
/// 4.3): a block of more than SEEN_MAX is refused, as no server sends
/// one.
struct Seen {
    kinds: [u16; SEEN_MAX],
    count: usize,
}

const SEEN_MAX: usize = 32;

impl Seen {
    const fn new() -> Seen {
        Seen {
            kinds: [0; SEEN_MAX],
            count: 0,
        }
    }

    /// Notes kind; a second of a kind does not decode.
    fn add(&mut self, kind: u16) -> Result<(), Error> {
        let seen = self.kinds.get(..self.count).unwrap_or_default();
        if seen.contains(&kind) {
            return Err(Error::Decode);
        }
        let slot = self.kinds.get_mut(self.count).ok_or(Error::Decode)?;
        *slot = kind;
        self.count += 1;
        Ok(())
    }
}

/// The certificates of a Certificate message's body into out, leaf
/// first; how many. More than out holds is refused, and so is none
/// (RFC 9846 4.5.1.3).
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
    let mut unsolicited = false;
    while !list.rest.is_empty() {
        let der = list.vector(3)?;
        let mut extensions = Reader {
            rest: list.vector(2)?,
        };
        // Each extension framed whole, or decode_error.
        while !extensions.rest.is_empty() {
            extensions.u16()?;
            extensions.vector(2)?;
            unsolicited = true;
        }
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
    // The client asks for neither status_request nor SCTs, so an entry's
    // extension answers nothing it sent: unsupported_extension (RFC 9846
    // 4.3, 4.5.1), as BoringSSL and rustls refuse it.
    if unsolicited {
        return Err(Error::Extension);
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

/// Seals data as one record of kind at the end of tx (RFC 9846 5.2):
/// the header, the data, its type and the tag, sealed in place. A record
/// past the client's own limits is internal_error.
fn seal(keys: &mut Keys, tx: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<(), Error> {
    let Ok(length) = u16::try_from(data.len() + 1 + TAG) else {
        return Err(Error::Internal);
    };
    if tx.len() + HEADER + usize::from(length) > TX_MAX {
        return Err(Error::Internal);
    }
    let start = tx.len();
    let [high, low] = length.to_be_bytes();
    tx.extend_from_slice(&[APPLICATION, 3, 3, high, low]);
    // rr: escape(copy): the record is sealed in place in the pending
    // buffer, and the caller's data is borrowed.
    tx.extend_from_slice(data);
    tx.push(kind);
    let (head, body) = tx
        .split_at_mut_checked(start + HEADER)
        .ok_or(Error::Internal)?;
    let header = head.get(start..).unwrap_or_default();
    match keys.key.seal(header, body) {
        Ok(tag) => tx.extend_from_slice(&tag.into_bytes()),
        Err(error) => {
            // A record that has no number is never begun.
            tx.truncate(start);
            return Err(local(&error));
        }
    }
    Ok(())
}

/// An error sealing a record of the client's own, which only a limit of
/// its own can cause: internal_error.
fn local(error: &aesgcm::Error) -> Error {
    match error {
        aesgcm::Error::TooLong | aesgcm::Error::Forged | aesgcm::Error::Exhausted => {
            Error::Internal
        }
    }
}

/// The secrets ServerHello's key share leads to (RFC 9846 7.1).
struct Secrets {
    client: Digest,
    server: Digest,
    master: Digest,
}

/// The handshake traffic secrets and the master secret, from the key
/// exchange's shared secret and the hash of ClientHello..ServerHello, by
/// that hash's function. Without a PSK the early secret is HKDF-Extract
/// of zeros.
fn handshake_secrets(shared: &[u8], hash: &Digest) -> Secrets {
    let zero = hash.zero();
    let empty = hash.of(&[]);
    let early = zero.extract(zero.bytes());
    let handshake = derive(&early, b"derived", empty.bytes()).extract(shared);
    Secrets {
        client: derive(&handshake, b"c hs traffic", hash.bytes()),
        server: derive(&handshake, b"s hs traffic", hash.bytes()),
        master: derive(&handshake, b"derived", empty.bytes()).extract(zero.bytes()),
    }
}

/// Derive-Secret: HKDF-Expand-Label of a transcript hash, or of nothing,
/// as long as the secret.
fn derive(secret: &Digest, label: &[u8], hash: &[u8]) -> Digest {
    let mut out = secret.zero();
    expand(secret, label, hash, out.bytes_mut());
    out
}

/// HKDF-Expand-Label (RFC 9846 7.1). The labels are this file's, at most
/// 12 bytes, and a context is a hash at most: info fits 80 bytes.
fn expand(secret: &Digest, label: &[u8], context: &[u8], out: &mut [u8]) {
    let mut info = [0; 80];
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
    let expanded = match secret {
        Digest::Sha256(key) => sha256::Prk::new_less_safe(key).expand(info, out).is_ok(),
        Digest::Sha384(key) => sha384::Prk::new_less_safe(key).expand(info, out).is_ok(),
    };
    if !expanded {
        // rr: escape(panic): out is at most 48 bytes, far under HKDF's
        // limit of 255 hashes.
        unreachable!();
    }
}

/// HMAC of data under key by the suite's hash, which HKDF-Extract is
/// with key as the salt: a Finished's verify_data (RFC 9846 4.5.3).
fn mac(key: &Digest, data: &Digest) -> Digest {
    key.extract(data.bytes())
}

/// Checks a Finished's verify_data, received: the HMAC of data under
/// key by the suite's hash, compared in constant time by sha256's or
/// sha384's verify. Another length is decode_error, another MAC
/// decrypt_error (RFC 9846 4.4.4).
fn verify_mac(key: &Digest, data: &Digest, received: &[u8]) -> Result<(), Error> {
    let verified = match key {
        Digest::Sha256(key) => {
            let Ok(tag) = received.try_into() else {
                return Err(Error::Decode);
            };
            let mut hmac = sha256::Hmac::new(key);
            hmac.update(data.bytes());
            hmac.verify(tag).is_ok()
        }
        Digest::Sha384(key) => {
            let Ok(tag) = received.try_into() else {
                return Err(Error::Decode);
            };
            let mut hmac = sha384::Hmac384::new(key);
            hmac.update(data.bytes());
            hmac.verify(tag).is_ok()
        }
    };
    if !verified {
        return Err(Error::Finished);
    }
    Ok(())
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
    assert!(
        store
            .add_der(&x509::test_certificate("test.root").unwrap())
            .is_ok()
    );
    let mut client = Client::new(
        "api.example.test",
        &[b"h2"],
        Verify::Store(&store),
        x509::TEST_NOW,
        Random::fixed([0x5c; 32]),
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
    assert!(
        store
            .add_der(&x509::test_certificate("test.root").unwrap())
            .is_ok()
    );
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
        Random::fixed([0x5c; 32]),
    )
    .unwrap();
    assert!(client.sent(client.pending().len()).is_ok());
    let mut hello = Vec::from([HANDSHAKE, 3, 3, 0, 90, SERVER_HELLO, 0, 0, 86, 3, 3]);
    hello.extend_from_slice(&[0x7e; 32]);
    hello.extend_from_slice(&[0, 0x13, 0x01, 0, 0, 46, 0, 43, 0, 2, 3, 4]);
    hello.extend_from_slice(&[0, 51, 0, 36, 0, 0x1d, 0, 32]);
    let server = x25519::Secret::new(random::Seed32::for_tests([0x3a; 32]));
    hello.extend_from_slice(server.public_key().bytes());
    assert!(
        client
            .input(&hello)
            .is_ok_and(|taken| taken.count() == hello.len())
    );
    // The client's keys for reading are the server's for writing.
    let secret = match &client.input_keys.as_ref().unwrap().secret {
        Digest::Sha256(bytes) => Digest::Sha256(*bytes),
        Digest::Sha384(bytes) => Digest::Sha384(*bytes),
    };
    let mut keys = Keys::new(secret);
    let mut bytes = Vec::new();
    for piece in rest.chunks(usize::from(seed >> 1) * 32 + 1) {
        if seal(&mut keys, &mut bytes, HANDSHAKE, piece).is_err() {
            break;
        }
    }
    fuzz_feed(&mut client, &bytes, bytes.len().max(1));
}

/// Feeds input to the client in pieces of piece bytes, reading and
/// sending what it gives and approving any chain it awaits a verdict on,
/// as the system would; a failure sticks.
#[cfg(fuzzing)]
fn fuzz_feed(client: &mut Client<'_>, input: &[u8], piece: usize) {
    for mut part in input.chunks(piece) {
        while !part.is_empty() {
            match client.input(part) {
                Ok(taken) => {
                    let taken = taken.count();
                    part = part.get(taken..).unwrap_or_default();
                    let count = client.read().len();
                    let waited = client.awaiting();
                    if waited {
                        let mut chain: [&[u8]; x509::CHAIN_MAX] = [&[]; x509::CHAIN_MAX];
                        assert!(client.chain(&mut chain).is_some_and(|n| n > 0));
                        let approval = x509::Approval::system(chain[0], "api.example.test");
                        // rr: escape(discard): a refusal sticks, and the
                        // next input says it.
                        let _: Result<(), Error> = client.verified(approval);
                    }
                    assert!(taken > 0 || count > 0 || waited);
                    assert!(count <= RECORD_MAX);
                    client.consume(count);
                    assert!(client.sent(client.pending().len()).is_ok());
                }
                Err(error) => {
                    assert!(client.input(&[APPLICATION]).err() == Some(error));
                    assert!(!client.connected());
                    assert!(client.write(b"x").err() == Some(error));
                    return;
                }
            }
        }
    }
}
