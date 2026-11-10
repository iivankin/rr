//! A TLS 1.3 client (RFC 9846) without I/O: TLS_AES_128_GCM_SHA256 and
//! TLS_AES_256_GCM_SHA384 with X25519MLKEM768 and X25519 key shares and P-256
//! on a retry, ECDSA and RSA-PSS server signatures, SNI, ALPN, middlebox
//! compatibility, HelloRetryRequest, KeyUpdate and close_notify; bytes in any
//! split, application records opened in place in the receive buffer and sealed
//! in place in the pending one; counts that must be used, loud errors for a
//! step a loop forgets, eof that refuses a truncation, a caller's verdict as
//! an x509::Approval bound to the leaf and host, and secrets wiped; its
//! randomness drawn from random, records numbered by aesgcm's keys.
//!
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
//! The tests' program runs it:
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
//! socket closes. An io::Io loop: send what pending holds, and receive
//! again once it is sent. When the client awaits, start trust's check on
//! the chain (Trust::check, on the Io's pool) and stop receiving; keep
//! unread bytes. When the check's Event came and its poll answers, call
//! verified with its approval or refused, then go on with the kept bytes
//! and the socket as before. Never call verify_blocking on the loop's
//! thread.

// rr: checked(0.5.2)
// rr: needs(random, sha256, sha384, aesgcm, x25519, mlkem, ecdh, x509)
// rr: option(roots, one): Where does TLS take the roots it trusts from?
// rr: choice(roots = system, default, needs(trust)): the operating system verifies the chain (trust, Verify::Caller): its roots, updated with it, enterprise roots included
// rr: choice(roots = system-mozilla, needs(trust, roots)): the operating system verifies (trust, Verify::Caller), with Mozilla's roots built in where it has none, as Linux in an empty container (roots)
// rr: choice(roots = mozilla, needs(roots)): x509 verifies against Mozilla's roots built in (roots, Verify::Store): the same everywhere; rr add --overwrite roots refreshes it
// rr: choice(roots = none): x509 verifies against a store the program fills itself (Verify::Store)
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none

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
// rr: section(tests = yes)
#[cfg_attr(any(test, fuzzing), derive(Debug, PartialEq))]
// rr: end(tests = yes)
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
// rr: section(tests = yes)
#[cfg_attr(test, derive(Debug, PartialEq))]
// rr: end(tests = yes)
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

    // rr: section(tests = yes)
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
    // rr: end(tests = yes)
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
    #[must_use]
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
    #[must_use]
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

// rr: section(tests = yes)
#[cfg(test)]
mod tests {
    //! The client against RFC 8448's trace, and against a TLS 1.3 server of
    //! the tests' own: it signs with the test PKI's keys of x509-tests.pem
    //! and retries, splits, tampers and misbehaves as each test asks.

    use super::{
        AES_128_GCM_SHA256, AES_256_GCM_SHA384, ALERT, APPLICATION, CHANGE_CIPHER_SPEC, Client,
        Digest, Error, HANDSHAKE, HELLO_RETRY, IDLE_MAX, KEY_RECORDS_MAX, Keys, MESSAGE_MAX,
        Opening, PENDING_MAX, RECORD_MAX, RECORDS_PER_INPUT, Random, Reader, SECP256R1, State,
        Taken, Transcript, VERIFY_CONTEXT, Verify, X25519, X25519MLKEM768, derive, expand,
        handshake_secrets, mac,
    };
    use crate::base::ecdh;
    use crate::base::mlkem;
    use crate::base::random::{Seed32, Seed64};
    use crate::base::sha256::{self, Sha256};
    use crate::base::sha384;
    use crate::base::x509::{self, Approval, Store, TEST_NOW, test_certificate};
    use crate::base::x25519;
    use alloc::vec::Vec;
    use test::Bencher;

    /// The session ID the client sends, from random().
    const SESSION: [u8; 32] = [0x5c; 32];
    const HOST: &str = "api.example.test";
    /// A split that brings everything at once.
    const WHOLE: usize = 1 << 24;

    /// The client's randomness in every test: the bytes 0x5c.
    fn random() -> Random {
        Random::fixed([0x5c; 32])
    }

    /// Bytes from hex digits; anything between them is skipped.
    fn hex(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut high = None;
        for c in text.chars() {
            let Some(digit) = c.to_digit(16) else {
                continue;
            };
            let digit = u8::try_from(digit).unwrap();
            match high.take() {
                None => high = Some(digit),
                Some(top) => out.push((top << 4) | digit),
            }
        }
        out
    }

    /// Numbers as 64-bit limbs, least first, for the server's signatures:
    /// slow and in variable time, which a test may be.
    type Limbs = Vec<u64>;

    fn limbs(bytes: &[u8], count: usize) -> Limbs {
        let mut out = Vec::new();
        out.resize(count, 0);
        for (at, byte) in bytes.iter().rev().enumerate() {
            out[at / 8] |= u64::from(*byte) << (8 * (at % 8));
        }
        out
    }

    fn big_endian(value: &[u64], length: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for at in (0..length).rev() {
            out.push(u8::try_from((value[at / 8] >> (8 * (at % 8))) & 0xff).unwrap());
        }
        out
    }

    fn low(sum: u128) -> u64 {
        u64::try_from(sum & u128::from(u64::MAX)).unwrap()
    }

    fn high(sum: u128) -> u64 {
        u64::try_from(sum >> 64).unwrap()
    }

    /// a += b; the carry out.
    fn add_into(a: &mut [u64], b: &[u64]) -> bool {
        let mut carry = false;
        for (x, y) in a.iter_mut().zip(b) {
            let (sum, first) = x.overflowing_add(*y);
            let (total, second) = sum.overflowing_add(u64::from(carry));
            *x = total;
            carry = first | second;
        }
        carry
    }

    /// a -= b; the borrow out.
    fn sub_from(a: &mut [u64], b: &[u64]) -> bool {
        let mut borrow = false;
        for (x, y) in a.iter_mut().zip(b) {
            let (difference, first) = x.overflowing_sub(*y);
            let (rest, second) = difference.overflowing_sub(u64::from(borrow));
            *x = rest;
            borrow = first | second;
        }
        borrow
    }

    fn below(a: &[u64], b: &[u64]) -> bool {
        for (x, y) in a.iter().zip(b).rev() {
            if x != y {
                return x < y;
            }
        }
        false
    }

    /// An odd modulus for Montgomery multiplication.
    struct Modulus {
        n: Limbs,
        /// -n^-1 mod 2^64.
        inverse: u64,
        /// R^2 mod n, R being 2^(64 * limbs).
        square: Limbs,
        bytes: usize,
    }

    impl Modulus {
        fn new(bytes: &[u8]) -> Modulus {
            let count = bytes.len().div_ceil(8);
            let n = limbs(bytes, count);
            // Newton's iteration doubles the bits of n^-1 that are right.
            let mut inverse: u64 = 1;
            for _ in 0..6 {
                inverse = inverse.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inverse)));
            }
            let mut modulus = Modulus {
                n,
                inverse: inverse.wrapping_neg(),
                square: limbs(&[1], count),
                bytes: bytes.len(),
            };
            for _ in 0..128 * count {
                modulus.square = modulus.add(&modulus.square, &modulus.square);
            }
            modulus
        }

        fn add(&self, a: &[u64], b: &[u64]) -> Limbs {
            let mut sum = Limbs::new();
            let mut carry = false;
            for (x, y) in a.iter().zip(b) {
                let (part, first) = x.overflowing_add(*y);
                let (total, second) = part.overflowing_add(u64::from(carry));
                sum.push(total);
                carry = first | second;
            }
            if carry || !below(&sum, &self.n) {
                sub_from(&mut sum, &self.n);
            }
            sum
        }

        fn sub(&self, a: &[u64], b: &[u64]) -> Limbs {
            let mut difference = Limbs::new();
            let mut borrow = false;
            for (x, y) in a.iter().zip(b) {
                let (part, first) = x.overflowing_sub(*y);
                let (rest, second) = part.overflowing_sub(u64::from(borrow));
                difference.push(rest);
                borrow = first | second;
            }
            if borrow {
                add_into(&mut difference, &self.n);
            }
            difference
        }

        /// a mod n for a below 2n.
        fn reduce(&self, mut a: Limbs) -> Limbs {
            if !below(&a, &self.n) {
                sub_from(&mut a, &self.n);
            }
            a
        }

        /// a b / R mod n, word by word of b (CIOS).
        fn montgomery(&self, a: &[u64], b: &[u64]) -> Limbs {
            let k = self.n.len();
            let mut t = Limbs::new();
            t.resize(k + 2, 0);
            for &word in b {
                let mut carry = 0;
                for j in 0..k {
                    let sum =
                        u128::from(t[j]) + u128::from(a[j]) * u128::from(word) + u128::from(carry);
                    t[j] = low(sum);
                    carry = high(sum);
                }
                let top = u128::from(t[k]) + u128::from(carry);
                t[k] = low(top);
                t[k + 1] = high(top);
                let m = t[0].wrapping_mul(self.inverse);
                let mut shifted = high(u128::from(t[0]) + u128::from(m) * u128::from(self.n[0]));
                for j in 1..k {
                    let sum = u128::from(t[j])
                        + u128::from(m) * u128::from(self.n[j])
                        + u128::from(shifted);
                    t[j - 1] = low(sum);
                    shifted = high(sum);
                }
                let last = u128::from(t[k]) + u128::from(shifted);
                t[k - 1] = low(last);
                t[k] = t[k + 1] + high(last);
                t[k + 1] = 0;
            }
            let over = t[k];
            t.truncate(k);
            if over != 0 || !below(&t, &self.n) {
                sub_from(&mut t, &self.n);
            }
            t
        }

        fn product(&self, a: &[u64], b: &[u64]) -> Limbs {
            self.montgomery(&self.montgomery(a, b), &self.square)
        }

        fn pow(&self, base: &[u64], exponent: &[u8]) -> Limbs {
            let mut x = limbs(&[1], self.n.len());
            for byte in exponent {
                for bit in (0..8).rev() {
                    x = self.product(&x, &x);
                    if (byte >> bit) & 1 == 1 {
                        x = self.product(&x, base);
                    }
                }
            }
            x
        }

        /// a^-1 for a prime n, as a^(n - 2).
        fn invert(&self, a: &[u64]) -> Limbs {
            let two = limbs(&[2], self.n.len());
            let zero = limbs(&[], self.n.len());
            // n - 2 is below n: sub does not wrap it.
            let exponent = self.sub(&zero, &two);
            self.pow(a, &big_endian(&exponent, self.bytes))
        }
    }

    /// A short Weierstrass curve with a = -3, in affine coordinates.
    struct Curve {
        p: Modulus,
        n: Modulus,
        g: (Limbs, Limbs),
    }

    type Point = Option<(Limbs, Limbs)>;

    impl Curve {
        fn new(p: &str, n: &str, x: &str, y: &str) -> Curve {
            let field = Modulus::new(&hex(p));
            let count = field.n.len();
            Curve {
                g: (limbs(&hex(x), count), limbs(&hex(y), count)),
                p: field,
                n: Modulus::new(&hex(n)),
            }
        }

        fn p256() -> Curve {
            Curve::new(
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            )
        }

        fn p384() -> Curve {
            Curve::new(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
             ffffffff0000000000000000ffffffff",
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
             581a0db248b0a77aecec196accc52973",
                "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab7",
                "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
             0a60b1ce1d7e819d7a431d7c90ea0e5f",
            )
        }

        /// a + b; None is the point at infinity.
        fn add(&self, a: Point, b: Point) -> Point {
            let (Some((x1, y1)), Some((x2, y2))) = (&a, &b) else {
                return a.or(b);
            };
            let p = &self.p;
            let slope = if x1 == x2 {
                if y1 != y2 || y1.iter().all(|word| *word == 0) {
                    return None;
                }
                let square = p.product(x1, x1);
                let three = limbs(&[3], square.len());
                let numerator = p.sub(&p.add(&p.add(&square, &square), &square), &three);
                p.product(&numerator, &p.invert(&p.add(y1, y1)))
            } else {
                p.product(&p.sub(y2, y1), &p.invert(&p.sub(x2, x1)))
            };
            let x3 = p.sub(&p.sub(&p.product(&slope, &slope), x1), x2);
            let y3 = p.sub(&p.product(&slope, &p.sub(x1, &x3)), y1);
            Some((x3, y3))
        }

        /// k G, by doubling and adding.
        fn times(&self, k: &[u8]) -> Point {
            let mut point = None;
            for byte in k {
                for bit in (0..8).rev() {
                    // rr: escape(copy): a point is added to itself.
                    let twice = point.clone();
                    point = self.add(point, twice);
                    if (byte >> bit) & 1 == 1 {
                        // rr: escape(copy): the base point is added again.
                        point = self.add(point, Some(self.g.clone()));
                    }
                }
            }
            point
        }

        /// ECDSA (FIPS 186-4) of a digest no longer than n, with a nonce
        /// from the key and the digest, DER-encoded.
        fn sign(&self, key: &[u8], digest: &[u8]) -> Vec<u8> {
            let n = &self.n;
            let count = n.n.len();
            let e = n.reduce(limbs(digest, count));
            let mut seed = Sha256::new();
            seed.update(key);
            seed.update(digest);
            let k = n.reduce(limbs(&seed.finish(), count));
            let (x, _) = self.times(&big_endian(&k, n.bytes)).unwrap();
            let r = n.reduce(x);
            let rd = n.product(&r, &limbs(key, count));
            let s = n.product(&n.invert(&k), &n.add(&e, &rd));
            let mut der = Vec::from([0x30, 0]);
            integer(&mut der, &big_endian(&r, n.bytes));
            integer(&mut der, &big_endian(&s, n.bytes));
            der[1] = u8::try_from(der.len() - 2).unwrap();
            der
        }
    }

    /// A DER INTEGER of a big-endian unsigned number, onto out.
    fn integer(out: &mut Vec<u8>, value: &[u8]) {
        let start = value
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(value.len() - 1);
        let digits = &value[start..];
        let pad = digits[0] >= 0x80;
        out.push(0x02);
        out.push(u8::try_from(digits.len() + usize::from(pad)).unwrap());
        if pad {
            out.push(0);
        }
        out.extend_from_slice(digits);
    }

    fn hashed(wide: bool, data: &[u8]) -> Vec<u8> {
        if wide {
            Vec::from(sha384::digest384(data))
        } else {
            Vec::from(sha256::digest(data))
        }
    }

    /// RSASSA-PSS (RFC 8017 8.1) with MGF1 and a salt as long as the hash,
    /// for a modulus of whole bytes whose top bit is set.
    fn pss(modulus: &Modulus, exponent: &[u8], wide: bool, message: &[u8]) -> Vec<u8> {
        let size = modulus.bytes;
        let digest = hashed(wide, message);
        let mut salt = Vec::new();
        salt.resize(digest.len(), 0xa5);
        let mut prime = Vec::new();
        prime.resize(8, 0);
        prime.extend_from_slice(&digest);
        prime.extend_from_slice(&salt);
        let h = hashed(wide, &prime);
        let mut db = Vec::new();
        db.resize(size - 2 * digest.len() - 2, 0);
        db.push(1);
        db.extend_from_slice(&salt);
        let mut seed = Vec::new();
        let mut at = 0;
        for counter in 0u32.. {
            if at >= db.len() {
                break;
            }
            seed.clear();
            seed.extend_from_slice(&h);
            seed.extend_from_slice(&counter.to_be_bytes());
            for byte in hashed(wide, &seed) {
                if let Some(slot) = db.get_mut(at) {
                    *slot ^= byte;
                }
                at += 1;
            }
        }
        // emBits is one under the modulus's bits: its top bit is cleared.
        db[0] &= 0x7f;
        db.extend_from_slice(&h);
        db.push(0xbc);
        let signature = modulus.pow(&limbs(&db, modulus.n.len()), exponent);
        big_endian(&signature, size)
    }

    /// The key a server signs CertificateVerify with.
    enum Signer {
        P256(Vec<u8>),
        P384(Vec<u8>),
        Rsa(Modulus, Vec<u8>),
    }

    /// The server's certificates and key, from x509-tests.pem.
    #[derive(Clone, Copy)]
    enum Kind {
        P256,
        P384,
        RsaSha256,
        RsaSha384,
    }

    /// A server's chain, the anchor that trusts it, its key and the scheme
    /// it signs with.
    struct Identity {
        chain: Vec<Vec<u8>>,
        anchor: Vec<u8>,
        signer: Signer,
        scheme: u16,
    }

    /// test.rsaleaf's private exponent.
    const RSA_EXPONENT: &str = "\
    091961c6b983d26363a138b62fc8903e39384af207a1216aa6d4c0f8ede3c7ef03e543654a9a4d1ebbad16333f3ca5f8\
    bab07ad0524aea1bec5358741e6a704478eb63cae3b0fdb1b7eb7a23e276a89c03cf571fc5a43f663a13a4422c9da7b6\
    afbb4efa2cdbad7bffed993bb621d6eeb7bfcd36e0a3e303b8cf58c4ce45d663d3817e17741fe7ec6dd1fa395ed70fd1\
    0b1efa2cb2bf04351ce29b1c56b591656120f08841a367647bf409e47f23944074c728a1fa8db3a442a449cbd9a22d81\
    ce108e61a45c4f07dfae418516a65cd9d00ff44f7a5b819560cbde6be91c72f9f05bcdbb261eeebca44c86128a7424e9\
    c6e6d0803fb2ba985455fe472f501981";

    impl Identity {
        fn new(kind: Kind) -> Identity {
            let der = |name: &str| test_certificate(name).unwrap();
            match kind {
                Kind::P256 => Identity {
                    chain: Vec::from([der("test.leaf"), der("test.inter")]),
                    anchor: der("test.root"),
                    signer: Signer::P256(hex(
                        "9f8036daa9ec08582c6de4f6b0b14d03c49abb1d6424ab0b34f8c2c800239fce",
                    )),
                    scheme: 0x0403,
                },
                Kind::P384 => Identity {
                    chain: Vec::from([der("test.leaf384"), der("test.inter")]),
                    anchor: der("test.root"),
                    signer: Signer::P384(hex(
                        "9c2b3d342af932742c4ef49e2aa4a871deb6c37e246942027c45a907b524b7e0\
                     bb5f8ad1479bc74f15df145a386e439e",
                    )),
                    scheme: 0x0503,
                },
                Kind::RsaSha256 | Kind::RsaSha384 => {
                    let leaf = der("test.rsaleaf");
                    let x509::Key::Rsa { modulus, .. } = x509::parse(&leaf).unwrap().key else {
                        panic!("test.rsaleaf has an RSA key");
                    };
                    let signer = Signer::Rsa(Modulus::new(modulus), hex(RSA_EXPONENT));
                    let scheme = if matches!(kind, Kind::RsaSha256) {
                        0x0804
                    } else {
                        0x0805
                    };
                    Identity {
                        chain: Vec::from([leaf]),
                        anchor: der("test.rsaroot"),
                        signer,
                        scheme,
                    }
                }
            }
        }

        fn store(&self) -> Store {
            let mut store = Store::new();
            assert_eq!(store.add_der(&self.anchor), Ok(()));
            store
        }

        fn sign(&self, content: &[u8]) -> Vec<u8> {
            match &self.signer {
                Signer::P256(key) => Curve::p256().sign(key, &sha256::digest(content)),
                Signer::P384(key) => Curve::p384().sign(key, &sha384::digest384(content)),
                Signer::Rsa(modulus, exponent) => {
                    pss(modulus, exponent, self.scheme == 0x0805, content)
                }
            }
        }
    }

    /// What the server does besides a plain handshake.
    struct Script {
        identity: Identity,
        /// A HelloRetryRequest first, with this cookie, this group or both.
        cookie: Option<&'static [u8]>,
        retry_group: Option<u16>,
        /// The group ServerHello chooses without a retry that names one.
        group: u16,
        /// The suite ServerHello chooses, and the one a HelloRetryRequest
        /// names.
        suite: u16,
        retry_suite: u16,
        /// The protocol EncryptedExtensions chooses, if any.
        alpn: Option<&'static [u8]>,
        /// Extensions added to EncryptedExtensions, as on the wire.
        extensions: Vec<u8>,
        /// The leaf's CertificateEntry extensions, as on the wire.
        entry: Vec<u8>,
        /// A CertificateRequest's body, before the Certificate.
        request: Option<Vec<u8>>,
        /// A change_cipher_spec after ServerHello.
        compatible: bool,
        /// Whether the flight after ServerHello is sent.
        flight: bool,
        /// The most handshake plaintext of one record.
        piece: usize,
    }

    impl Script {
        fn new(kind: Kind) -> Script {
            Script {
                identity: Identity::new(kind),
                cookie: None,
                retry_group: None,
                group: X25519MLKEM768,
                suite: AES_128_GCM_SHA256,
                retry_suite: AES_128_GCM_SHA256,
                alpn: None,
                extensions: Vec::new(),
                entry: Vec::new(),
                request: None,
                compatible: false,
                flight: true,
                piece: RECORD_MAX,
            }
        }
    }

    /// What the client's ClientHello said.
    struct Hello {
        name: Option<Vec<u8>>,
        // rr: escape(bound): one ClientHello's.
        alpn: Vec<Vec<u8>>,
        cookie: Option<Vec<u8>>,
        session: Vec<u8>,
        /// The key shares, by group.
        // rr: escape(bound): one ClientHello's.
        shares: Vec<(u16, Vec<u8>)>,
        // rr: escape(bound): one ClientHello's.
        suites: Vec<u16>,
        // rr: escape(bound): one ClientHello's.
        signatures: Vec<u16>,
    }

    /// The test server: it answers each record the client sends.
    struct Server {
        script: Script,
        transcript: Transcript,
        read: Option<Opening>,
        write: Option<Keys>,
        master: Digest,
        client_secret: Option<Digest>,
        retried: bool,
        input: Vec<u8>,
        /// Bytes for the client.
        // rr: escape(bound): a test's few records.
        output: Vec<u8>,
        /// The client's application data.
        received: Vec<u8>,
        /// The descriptions of the client's alerts.
        // rr: escape(bound): a test's few records.
        alerts: Vec<u8>,
        hello: Hello,
        /// The Certificate that answered a CertificateRequest.
        certificate: Option<Vec<u8>>,
        /// KeyUpdates the client sent.
        updates: usize,
        /// change_cipher_spec records the client sent.
        ccs: usize,
        finished: bool,
    }

    impl Server {
        fn new(script: Script) -> Server {
            Server {
                script,
                transcript: Transcript::new(),
                read: None,
                write: None,
                master: Digest::Sha256([0; 32]),
                client_secret: None,
                retried: false,
                input: Vec::new(),
                output: Vec::new(),
                received: Vec::new(),
                alerts: Vec::new(),
                hello: Hello {
                    name: None,
                    alpn: Vec::new(),
                    cookie: None,
                    session: Vec::new(),
                    shares: Vec::new(),
                    suites: Vec::new(),
                    signatures: Vec::new(),
                },
                certificate: None,
                updates: 0,
                ccs: 0,
                finished: false,
            }
        }

        fn hash(&self) -> Digest {
            self.transcript.hash()
        }

        /// Takes the client's bytes and answers each whole record.
        fn receive(&mut self, bytes: &[u8]) {
            self.input.extend_from_slice(bytes);
            while self.input.len() >= 5 {
                let length = usize::from(u16::from_be_bytes([self.input[3], self.input[4]]));
                if self.input.len() < 5 + length {
                    break;
                }
                let rest = self.input.split_off(5 + length);
                let mut record = core::mem::replace(&mut self.input, rest);
                if record[0] == CHANGE_CIPHER_SPEC {
                    // Middlebox compatibility's, in the clear.
                    assert_eq!(record[5..], [1]);
                    self.ccs += 1;
                    continue;
                }
                let kind = match &mut self.read {
                    Some(keys) => opened(keys, &mut record),
                    None => {
                        let kind = record[0];
                        record.drain(..5);
                        kind
                    }
                };
                match kind {
                    HANDSHAKE => self.message(&record),
                    APPLICATION => self.received.extend_from_slice(&record),
                    ALERT => self.alerts.push(record[1]),
                    _ => panic!("record type {kind}"),
                }
            }
        }

        fn message(&mut self, message: &[u8]) {
            match message[0] {
                1 => self.hello(message),
                11 => {
                    self.transcript.update(message);
                    // rr: escape(copy): the test looks at it later.
                    self.certificate = Some(message.to_vec());
                }
                20 => {
                    let key = derive(&self.read.as_ref().unwrap().secret, b"finished", &[]);
                    assert_eq!(message[4..], *mac(&key, &self.hash()).bytes());
                    self.read = self.client_secret.take().map(Opening::new);
                    self.finished = true;
                }
                24 => {
                    self.read = Some(self.read.as_ref().unwrap().next());
                    self.updates += 1;
                }
                kind => panic!("handshake message {kind}"),
            }
        }

        fn hello(&mut self, message: &[u8]) {
            let hello = &mut self.hello;
            hello.alpn.clear();
            hello.name = None;
            hello.cookie = None;
            let mut fields = Reader {
                rest: &message[4..],
            };
            assert_eq!(fields.u16().unwrap(), 0x0303);
            fields.take(32).unwrap();
            // rr: escape(copy): ServerHello echoes it.
            hello.session = fields.vector(1).unwrap().to_vec();
            let mut suites = Reader {
                rest: fields.vector(2).unwrap(),
            };
            hello.suites.clear();
            while let Ok(suite) = suites.u16() {
                hello.suites.push(suite);
            }
            assert_eq!(fields.vector(1).unwrap(), [0]);
            let mut extensions = Reader {
                rest: fields.vector(2).unwrap(),
            };
            fields.end().unwrap();
            while !extensions.rest.is_empty() {
                let kind = extensions.u16().unwrap();
                let mut data = Reader {
                    rest: extensions.vector(2).unwrap(),
                };
                let mut list = Reader {
                    rest: data.vector(if kind == 43 { 1 } else { 2 }).unwrap(),
                };
                match kind {
                    0 => {
                        assert_eq!(list.u8().unwrap(), 0);
                        // rr: escape(copy): the test looks at it later.
                        hello.name = Some(list.vector(2).unwrap().to_vec());
                    }
                    10 => assert_eq!(list.rest, [0x11, 0xec, 0, 0x1d, 0, 0x17]),
                    13 => {
                        hello.signatures.clear();
                        while let Ok(scheme) = list.u16() {
                            hello.signatures.push(scheme);
                        }
                    }
                    16 => {
                        while let Ok(name) = list.vector(1) {
                            // rr: escape(copy): the test looks at it later.
                            hello.alpn.push(name.to_vec());
                        }
                    }
                    43 => assert_eq!(list.rest, [3, 4]),
                    // rr: escape(copy): the test looks at it later.
                    44 => hello.cookie = Some(list.rest.to_vec()),
                    51 => {
                        hello.shares.clear();
                        while let Ok(group) = list.u16() {
                            // rr: escape(copy): the server's key share needs it.
                            hello.shares.push((group, list.vector(2).unwrap().to_vec()));
                        }
                    }
                    other => panic!("extension {other}"),
                }
                data.end().unwrap();
            }
            self.transcript.update(message);
            let asks = self.script.cookie.is_some() || self.script.retry_group.is_some();
            if asks && !self.retried {
                self.retried = true;
                return self.retry();
            }
            if self.retried {
                assert_eq!(self.hello.cookie.as_deref(), self.script.cookie);
                if let Some(group) = self.script.retry_group {
                    // A key for the group asked for, alone.
                    assert_eq!(self.hello.shares.len(), 1);
                    assert_eq!(self.hello.shares[0].0, group);
                }
            }
            self.server_hello();
        }

        fn retry(&mut self) {
            let mut extensions = Vec::from([0, 43, 0, 2, 3, 4]);
            if let Some(group) = self.script.retry_group {
                extensions.extend_from_slice(&[0, 51, 0, 2]);
                extensions.extend_from_slice(&group.to_be_bytes());
            }
            if let Some(cookie) = self.script.cookie {
                extensions.extend_from_slice(&[0, 44]);
                prefixed(&mut extensions, 2 + cookie.len(), &[]);
                prefixed(&mut extensions, cookie.len(), cookie);
            }
            let suite = self.script.retry_suite;
            let retry = hello_message(&HELLO_RETRY, &self.hello.session, suite, &extensions);
            self.transcript.select(suite).unwrap();
            let first = self.hash();
            self.transcript.restart();
            let length = u8::try_from(first.bytes().len()).unwrap();
            self.transcript.update(&[254, 0, 0, length]);
            self.transcript.update(first.bytes());
            self.transcript.update(&retry);
            self.plain(HANDSHAKE, &retry);
        }

        /// The server's key share for group, from the client's, and the
        /// shared secret.
        fn agree(&self, group: u16) -> (Vec<u8>, Vec<u8>) {
            let (_, share) = self
                .hello
                .shares
                .iter()
                .find(|(offered, _)| *offered == group)
                .expect("no key share for the group");
            let secret = x25519::Secret::new(Seed32::for_tests([0x3a; 32]));
            let x25519 = |peer: &[u8]| {
                let peer = x25519::PublicKey::from_bytes(peer.try_into().unwrap());
                secret.agree(&peer).unwrap()
            };
            let (mut key, mut shared) = (Vec::new(), Vec::new());
            match group {
                X25519 => {
                    key.extend_from_slice(secret.public_key().bytes());
                    shared.extend_from_slice(x25519(share).kdf_input());
                }
                X25519MLKEM768 => {
                    let (encapsulation, peer) = share.split_at(mlkem::ENCAPSULATION_KEY_BYTES);
                    let encapsulation = encapsulation.try_into().unwrap();
                    let seed = Seed32::for_tests([0x4d; 32]);
                    let (ciphertext, kem) = mlkem::encapsulate(encapsulation, seed).unwrap();
                    key.extend_from_slice(&ciphertext);
                    key.extend_from_slice(secret.public_key().bytes());
                    shared.extend_from_slice(kem.kdf_input());
                    shared.extend_from_slice(x25519(peer).kdf_input());
                }
                _ => {
                    let p256 = ecdh::Secret::new(Seed64::for_tests([0x3a; 64]));
                    key.extend_from_slice(p256.public_key().bytes());
                    let peer = ecdh::PublicKey::parse(share).unwrap();
                    shared.extend_from_slice(p256.agree(&peer).kdf_input());
                }
            }
            (key, shared)
        }

        fn server_hello(&mut self) {
            let group = self.script.retry_group.unwrap_or(self.script.group);
            let (share, shared) = self.agree(group);
            let mut extensions = Vec::from([0, 43, 0, 2, 3, 4, 0, 51]);
            prefixed(&mut extensions, share.len() + 4, &group.to_be_bytes());
            prefixed(&mut extensions, share.len(), &share);
            let suite = self.script.suite;
            let hello = hello_message(&[0x7e; 32], &self.hello.session, suite, &extensions);
            if self.transcript.select(suite).is_err() {
                // Another suite than the retry's: the client refuses it at
                // once, and the server goes no further.
                return self.plain(HANDSHAKE, &hello);
            }
            self.transcript.update(&hello);
            self.plain(HANDSHAKE, &hello);
            if self.script.compatible {
                self.output
                    .extend_from_slice(&[CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
            }
            let secrets = handshake_secrets(&shared, &self.hash());
            let finished = derive(&secrets.server, b"finished", &[]);
            self.read = Some(Opening::new(secrets.client));
            self.write = Some(Keys::new(secrets.server));
            self.master = secrets.master;
            if !self.script.flight {
                return;
            }
            let mut flight = Vec::new();
            let mut encrypted = Vec::new();
            if let Some(alpn) = self.script.alpn {
                encrypted.extend_from_slice(&[0, 16]);
                prefixed(&mut encrypted, alpn.len() + 3, &[]);
                prefixed(
                    &mut encrypted,
                    alpn.len() + 1,
                    &[u8::try_from(alpn.len()).unwrap()],
                );
                encrypted.extend_from_slice(alpn);
            }
            encrypted.extend_from_slice(&self.script.extensions);
            let mut body = Vec::new();
            prefixed(&mut body, encrypted.len(), &encrypted);
            self.add(&mut flight, 8, &body);
            if let Some(request) = self.script.request.take() {
                self.add(&mut flight, 13, &request);
            }
            let mut list = Vec::new();
            for (at, der) in self.script.identity.chain.iter().enumerate() {
                list.extend_from_slice(&u24(der.len()));
                list.extend_from_slice(der);
                let entry = if at == 0 { &self.script.entry[..] } else { &[] };
                prefixed(&mut list, entry.len(), entry);
            }
            body.clear();
            body.push(0);
            body.extend_from_slice(&u24(list.len()));
            body.extend_from_slice(&list);
            self.add(&mut flight, 11, &body);
            let mut content = Vec::from([0x20; 64]);
            content.extend_from_slice(VERIFY_CONTEXT);
            content.extend_from_slice(self.hash().bytes());
            let signature = self.script.identity.sign(&content);
            body.clear();
            body.extend_from_slice(&self.script.identity.scheme.to_be_bytes());
            prefixed(&mut body, signature.len(), &signature);
            self.add(&mut flight, 15, &body);
            let verify = mac(&finished, &self.hash());
            self.add(&mut flight, 20, verify.bytes());
            for piece in flight.chunks(self.script.piece) {
                self.send(HANDSHAKE, piece);
            }
            let hash = self.hash();
            self.client_secret = Some(derive(&self.master, b"c ap traffic", hash.bytes()));
            let server = derive(&self.master, b"s ap traffic", hash.bytes());
            self.write = Some(Keys::new(server));
        }

        /// A message of kind into the flight and the transcript.
        fn add(&mut self, flight: &mut Vec<u8>, kind: u8, body: &[u8]) {
            let start = flight.len();
            flight.push(kind);
            flight.extend_from_slice(&u24(body.len()));
            flight.extend_from_slice(body);
            self.transcript.update(&flight[start..]);
        }

        fn plain(&mut self, kind: u8, data: &[u8]) {
            self.output.extend_from_slice(&[kind, 3, 3]);
            prefixed(&mut self.output, data.len(), data);
        }

        /// data as a record of kind, sealed once the server has keys.
        fn send(&mut self, kind: u8, data: &[u8]) {
            if self.write.is_none() {
                return self.plain(kind, data);
            }
            let mut inner = Vec::with_capacity(data.len() + 1);
            inner.extend_from_slice(data);
            inner.push(kind);
            self.raw(inner);
        }

        /// inner, the plaintext with its type and any padding, as one
        /// sealed record.
        fn raw(&mut self, mut inner: Vec<u8>) {
            let keys = self.write.as_mut().unwrap();
            let length = u16::try_from(inner.len() + 16).unwrap().to_be_bytes();
            let header = [APPLICATION, 3, 3, length[0], length[1]];
            let tag = keys.key.seal(&header, &mut inner).unwrap();
            self.output.extend_from_slice(&header);
            self.output.extend_from_slice(&inner);
            self.output.extend_from_slice(tag.bytes());
        }

        /// A KeyUpdate, then records under the next keys.
        fn update(&mut self, request: bool) {
            self.send(HANDSHAKE, &[24, 0, 0, 1, u8::from(request)]);
            self.write = Some(self.write.as_ref().unwrap().next());
        }

        /// Everything the server has for the client.
        fn take(&mut self) -> Vec<u8> {
            core::mem::take(&mut self.output)
        }
    }

    /// A ServerHello, or a HelloRetryRequest by its random, echoing the
    /// client's session ID and choosing suite.
    fn hello_message(random: &[u8; 32], session: &[u8], suite: u16, extensions: &[u8]) -> Vec<u8> {
        let mut m = Vec::from([2, 0, 0, 0, 3, 3]);
        m.extend_from_slice(random);
        m.push(u8::try_from(session.len()).unwrap());
        m.extend_from_slice(session);
        m.extend_from_slice(&suite.to_be_bytes());
        m.push(0);
        prefixed(&mut m, extensions.len(), extensions);
        let length = u24(m.len() - 4);
        m[1..4].copy_from_slice(&length);
        m
    }

    /// Opens a record in place with the server's keys: its type, and the
    /// record cut to its plaintext.
    fn opened(keys: &mut Opening, record: &mut Vec<u8>) -> u8 {
        let (header, body) = record.split_at_mut(5);
        let at = body.len() - 16;
        let (data, tag) = body.split_at_mut(at);
        let tag: &[u8; 16] = (&*tag).try_into().unwrap();
        keys.key.open(header, data, tag).unwrap();
        let end = data.iter().rposition(|byte| *byte != 0).unwrap();
        let kind = data[end];
        record.truncate(5 + end);
        record.drain(..5);
        kind
    }

    fn u24(length: usize) -> [u8; 3] {
        let [_, a, b, c] = u32::try_from(length).unwrap().to_be_bytes();
        [a, b, c]
    }

    /// Appends length as two bytes, then data.
    fn prefixed(out: &mut Vec<u8>, length: usize, data: &[u8]) {
        out.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        out.extend_from_slice(data);
    }

    /// Sizes of the pieces the server's bytes come in: piece bytes each, or
    /// from 1 to piece at random when seed is not 0.
    struct Split {
        piece: usize,
        seed: u64,
    }

    impl Split {
        fn next(&mut self) -> usize {
            if self.seed == 0 {
                return self.piece;
            }
            // xorshift64.
            self.seed ^= self.seed << 13;
            self.seed ^= self.seed >> 7;
            self.seed ^= self.seed << 17;
            usize::try_from(self.seed % u64::try_from(self.piece).unwrap()).unwrap() + 1
        }
    }

    fn whole() -> Split {
        Split {
            piece: WHOLE,
            seed: 0,
        }
    }

    /// Feeds bytes in pieces as reads would bring them, reading what each
    /// input decrypts into got.
    fn feed(
        client: &mut Client<'_>,
        bytes: &[u8],
        split: &mut Split,
        got: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut at = 0;
        while at < bytes.len() {
            let end = (at + split.next()).min(bytes.len());
            let mut piece = &bytes[at..end];
            while !piece.is_empty() || !client.read().is_empty() {
                let taken = client.input(piece)?.count();
                piece = &piece[taken..];
                let data = client.read();
                let count = data.len();
                assert!(taken > 0 || count > 0);
                assert!(count <= RECORD_MAX);
                got.extend_from_slice(data);
                client.consume(count);
            }
            at = end;
        }
        Ok(())
    }

    /// Moves bytes both ways until neither side has more; what the client
    /// read.
    fn exchange(
        client: &mut Client<'_>,
        server: &mut Server,
        split: &mut Split,
    ) -> Result<Vec<u8>, Error> {
        let mut got = Vec::new();
        for _ in 0..16 {
            let sent = client.pending().len();
            server.receive(client.pending());
            client.sent(sent)?;
            let back = server.take();
            if sent == 0 && back.is_empty() {
                return Ok(got);
            }
            if let Err(error) = feed(client, &back, split, &mut got) {
                // The alert the client queued reaches the server.
                server.receive(client.pending());
                return Err(error);
            }
        }
        panic!("the exchange does not end");
    }

    /// A handshake with the server, its bytes in the split's pieces.
    fn connect<'a>(
        store: &'a Store,
        server: &mut Server,
        host: &str,
        alpn: &[&[u8]],
        split: &mut Split,
    ) -> Result<Client<'a>, Error> {
        let mut client = Client::new(host, alpn, Verify::Store(store), TEST_NOW, random())?;
        let got = exchange(&mut client, server, split)?;
        assert!(got.is_empty());
        Ok(client)
    }

    /// The handshake's outcome with a script, and the alerts the server got.
    fn outcome(script: Script, host: &str, alpn: &[&[u8]], now: i64) -> (Option<Error>, Vec<u8>) {
        let store = script.identity.store();
        let mut server = Server::new(script);
        let mut client = Client::new(host, alpn, Verify::Store(&store), now, random()).unwrap();
        let result = exchange(&mut client, &mut server, &mut whole());
        (result.err(), server.alerts)
    }

    /// A connected client and its server.
    fn connected(store: &Store) -> (Client<'_>, Server) {
        let mut server = Server::new(Script::new(Kind::P256));
        let client = connect(store, &mut server, HOST, &[], &mut whole()).unwrap();
        (client, server)
    }

    /// What the client makes of records the server sends once connected:
    /// the result, what it read and the alerts the server got back.
    fn after(records: impl FnOnce(&mut Server), piece: usize) -> (Option<Error>, Vec<u8>, Vec<u8>) {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        records(&mut server);
        let bytes = server.take();
        let mut got = Vec::new();
        let mut split = Split { piece, seed: 0 };
        let result = feed(&mut client, &bytes, &mut split, &mut got);
        server.receive(client.pending());
        (result.err(), got, server.alerts)
    }

    /// What the client makes of bytes after ServerHello: a record of kind
    /// the server seals with its handshake keys, or bytes as they are.
    fn after_hello(kind: Option<u8>, bytes: &[u8]) -> Option<Error> {
        let mut script = Script::new(Kind::P256);
        script.flight = false;
        let store = script.identity.store();
        let mut server = Server::new(script);
        let mut client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        match kind {
            Some(sealed) => server.send(sealed, bytes),
            None => server.output.extend_from_slice(bytes),
        }
        let all = server.take();
        feed(
            &mut client,
            &all,
            &mut Split { piece: 1, seed: 0 },
            &mut Vec::new(),
        )
        .err()
    }

    // RFC 8448 section 3, "Simple 1-RTT Handshake".
    const CLIENT_PRIVATE: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
    const CLIENT_HELLO: &str = "\
    010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef\
    6283024dece7000006130113031302010000910000000b000900000673657276\
    6572ff01000100000a00140012001d0017001800190100010101020103010400\
    230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e\
    51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603\
    020308040805080604010501060102010402050206020202002d00020101001c\
    00024001";
    const SERVER_HELLO_RECORD: &str = "\
    160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb\
    1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095\
    fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
    const CLIENT_HS: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    const SERVER_HS: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    const MASTER: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    const SERVER_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
    const SERVER_HS_IV: &str = "5d313eb2671276ee13000b30";
    const CLIENT_HS_KEY: &str = "dbfaa693d1762c5b666af5d950258d01";
    const CLIENT_HS_IV: &str = "5bd3c71b836e0b76bb73265f";
    const SERVER_FINISHED_KEY: &str =
        "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8";
    const SERVER_FLIGHT: &str = "\
    17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35e\
    df7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78\
    b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b\
    d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9\
    d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2e\
    d65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092\
    8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead68694\
    5ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b368\
    4596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f\
    4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26\
    f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b65962224531\
    7b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e\
    1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da\
    8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d4\
    61e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe\
    5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb\
    992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c859\
    77b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038\
    ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b84\
    5e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5\
    d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e\
    750edc53370d2b";
    const SERVER_FLIGHT_PLAIN: &str = "\
    080000240022000a00140012001d00170018001901000101010201030104001c\
    00024001000000000b0001b9000001b50001b0308201ac30820115a003020102\
    020102300d06092a864886f70d01010b0500300e310c300a0603550403130372\
    7361301e170d3136303733303031323335395a170d3236303733303031323335\
    395a300e310c300a0603550403130372736130819f300d06092a864886f70d01\
    0101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c\
    0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19e\
    aa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e2\
    2a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a\
    8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304\
    023000300b0603551d0f0404030205a0300d06092a864886f70d01010b050003\
    81810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594\
    365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd\
    335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb\
    2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4\
    2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f82\
    4cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef78\
    0c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671\
    459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda\
    65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de\
    da4ab42c309572cb7fffee5454b78f0718";
    const CLIENT_AP: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    const SERVER_AP: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    const SERVER_AP_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
    const SERVER_AP_IV: &str = "cf782b88dd83549aadf1e984";
    const CLIENT_AP_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
    const CLIENT_AP_IV: &str = "5b78923dee08579033e523d9";
    const CLIENT_FINISHED_RECORD: &str = "\
    170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc\
    44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546";
    const CLIENT_DATA: &str = "\
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
    202122232425262728292a2b2c2d2e2f3031";
    const CLIENT_DATA_RECORD: &str = "\
    1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f\
    2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6\
    3aeebb21694915e4";

    fn key_of(secret: &Digest) -> Vec<u8> {
        let mut key = [0; 16];
        expand(secret, b"key", &[], &mut key);
        Vec::from(key)
    }

    /// The IV of a traffic secret, which aesgcm's keys keep to themselves.
    fn iv_of(secret: &Digest) -> Vec<u8> {
        let mut iv = [0; 12];
        expand(secret, b"iv", &[], &mut iv);
        Vec::from(iv)
    }

    /// The trace's key schedule and records through the client. Its
    /// ClientHello is not this client's, so the trace's takes our own's
    /// place in the transcript, and its EncryptedExtensions, an answer to
    /// that ClientHello, goes in as it is; its certificate is 1024-bit RSA,
    /// outside x509's profile, so Certificate and CertificateVerify go into the
    /// transcript unchecked. The rest is the client's own: the secrets from
    /// ServerHello, the opening of the flight, the check of the server's
    /// Finished, and the exact bytes of the client's Finished and of its
    /// first application record.
    #[test]
    fn rfc8448_simple_1rtt() {
        let store = Store::new();
        let random = Random {
            client: [0; 32],
            session: [0; 32],
            x25519: Seed32::for_tests(hex(CLIENT_PRIVATE).try_into().unwrap()),
            mlkem: Seed64::for_tests([0; 64]),
            p256: Seed64::for_tests([0; 64]),
        };
        let mut client = Client::new("server", &[], Verify::Store(&store), 0, random).unwrap();
        // RFC 8448's client offers X25519 alone, without middlebox
        // compatibility.
        client.session = None;
        client.kem = None;
        client.sent(client.pending().len()).unwrap();
        client.transcript = Transcript::new();
        client.transcript.update(&hex(CLIENT_HELLO));
        let hello = hex(SERVER_HELLO_RECORD);
        assert_eq!(client.input(&hello), Ok(Taken(hello.len())));
        let reading = client.input_keys.as_ref().unwrap();
        let writing = client.output_keys.as_ref().unwrap();
        assert_eq!(reading.secret.bytes(), hex(SERVER_HS));
        assert_eq!(writing.secret.bytes(), hex(CLIENT_HS));
        assert_eq!(client.master.bytes(), hex(MASTER));
        assert_eq!(key_of(&reading.secret), hex(SERVER_HS_KEY));
        assert_eq!(iv_of(&reading.secret), hex(SERVER_HS_IV));
        assert_eq!(key_of(&writing.secret), hex(CLIENT_HS_KEY));
        assert_eq!(iv_of(&writing.secret), hex(CLIENT_HS_IV));
        assert_eq!(client.server_finished.bytes(), hex(SERVER_FINISHED_KEY));
        let mut flight = hex(SERVER_FLIGHT);
        let keys = client.input_keys.as_mut().unwrap();
        let kind = opened(keys, &mut flight);
        assert_eq!(kind, HANDSHAKE);
        assert_eq!(flight, hex(SERVER_FLIGHT_PLAIN));
        let mut rest = &flight[..];
        while !rest.is_empty() {
            let length = usize::from(rest[2]) * 256 + usize::from(rest[3]);
            let (message, next) = rest.split_at(4 + length);
            match message[0] {
                // Its EncryptedExtensions answers the trace's ClientHello,
                // which offered record_size_limit; this client never does,
                // so it refuses the extension (RFC 9846 4.3), and the message
                // goes into the transcript as the trace has it.
                8 => {
                    assert_eq!(client.message(8, message), Err(Error::Extension));
                    assert!(matches!(client.state, State::Extensions));
                    client.transcript.update(message);
                    client.state = State::Certificate;
                }
                11 => client.transcript.update(message),
                15 => {
                    client.transcript.update(message);
                    client.state = State::Finished;
                }
                _ => assert_eq!(client.message(20, message), Ok(true)),
            }
            rest = next;
        }
        assert!(client.connected());
        assert_eq!(client.pending(), hex(CLIENT_FINISHED_RECORD));
        let app_reading = client.input_keys.as_ref().unwrap();
        let app_writing = client.output_keys.as_ref().unwrap();
        assert_eq!(app_reading.secret.bytes(), hex(SERVER_AP));
        assert_eq!(app_writing.secret.bytes(), hex(CLIENT_AP));
        assert_eq!(key_of(&app_reading.secret), hex(SERVER_AP_KEY));
        assert_eq!(iv_of(&app_reading.secret), hex(SERVER_AP_IV));
        assert_eq!(key_of(&app_writing.secret), hex(CLIENT_AP_KEY));
        assert_eq!(iv_of(&app_writing.secret), hex(CLIENT_AP_IV));
        client.sent(client.pending().len()).unwrap();
        let data = hex(CLIENT_DATA);
        assert_eq!(client.write(&data), Ok(Taken(data.len())));
        assert_eq!(client.pending(), hex(CLIENT_DATA_RECORD));
    }

    /// What the ClientHello offers, as the server parsed it; an IP literal
    /// goes without SNI.
    #[test]
    fn client_hello() {
        let store = Identity::new(Kind::P256).store();
        let mut server = Server::new(Script::new(Kind::P256));
        let named = Client::new(
            "api.example.test.",
            &[b"h2", b"http/1.1"],
            Verify::Store(&store),
            0,
            random(),
        );
        let client = named.unwrap();
        assert_eq!(client.pending()[..3], [22, 3, 1]);
        server.receive(client.pending());
        let hello = &server.hello;
        assert_eq!(hello.name.as_deref(), Some(&b"api.example.test"[..]));
        assert_eq!(hello.alpn, [&b"h2"[..], b"http/1.1"]);
        assert_eq!(hello.suites, [AES_128_GCM_SHA256, AES_256_GCM_SHA384]);
        assert_eq!(
            hello.signatures,
            [
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601
            ]
        );
        assert_eq!(hello.cookie, None);
        let mut other = Server::new(Script::new(Kind::P256));
        let literal = Client::new("192.0.2.1", &[], Verify::Store(&store), 0, random()).unwrap();
        other.receive(literal.pending());
        assert_eq!(other.hello.name, None);
        assert!(other.hello.alpn.is_empty());
    }

    #[test]
    fn refuses_bad_arguments() {
        let store = Store::new();
        let long = "a".repeat(254);
        for host in ["", "a..b", ".a", "a b", "\u{e9}.test", "a/b", &long] {
            let made = Client::new(host, &[], Verify::Store(&store), 0, random());
            assert_eq!(made.err(), Some(Error::Host), "{host}");
        }
        for host in [
            "localhost",
            "a-b_c.test",
            "[2001:db8::1]",
            "::1",
            "10.0.0.1",
        ] {
            assert!(
                Client::new(host, &[], Verify::Store(&store), 0, random()).is_ok(),
                "{host}"
            );
        }
        let name = [b'x'; 256];
        let many = [&name[..200]; 8];
        for alpn in [&[&b""[..]][..], &[&name[..]], &many] {
            let made = Client::new(HOST, alpn, Verify::Store(&store), 0, random());
            assert_eq!(made.err(), Some(Error::Alpn));
        }
    }

    /// Each kind of key and scheme, then data both ways and close_notify
    /// both ways.
    #[test]
    fn handshakes() {
        for kind in [Kind::P256, Kind::P384, Kind::RsaSha256, Kind::RsaSha384] {
            let store = Identity::new(kind).store();
            let mut server = Server::new(Script::new(kind));
            let mut split = whole();
            let mut client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
            assert!(client.connected() && !client.closed());
            assert!(server.finished);
            assert_eq!(client.alpn(), None);
            assert_eq!(client.write(b"ping"), Ok(Taken(4)));
            server.send(APPLICATION, b"pong");
            assert_eq!(
                exchange(&mut client, &mut server, &mut split),
                Ok(Vec::from(*b"pong"))
            );
            assert_eq!(server.received, b"ping");
            server.send(ALERT, &[1, 0]);
            server.send(APPLICATION, b"ignored");
            assert_eq!(
                exchange(&mut client, &mut server, &mut split),
                Ok(Vec::new())
            );
            assert!(client.closed() && client.connected());
            // The write side stays open until close.
            assert_eq!(client.write(b"late"), Ok(Taken(4)));
            client.close();
            assert_eq!(client.write(b"x"), Err(Error::Closed));
            assert_eq!(
                exchange(&mut client, &mut server, &mut split),
                Ok(Vec::new())
            );
            assert_eq!(server.received, b"pinglate");
            assert_eq!(server.alerts, [0]);
        }
    }

    /// The server's bytes for a handshake, two records of data and
    /// close_notify.
    fn recorded(store: &Store) -> Vec<u8> {
        let mut server = Server::new(Script::new(Kind::P256));
        let mut client = Client::new(HOST, &[], Verify::Store(store), TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        let mut bytes = server.take();
        feed(&mut client, &bytes, &mut whole(), &mut Vec::new()).unwrap();
        server.receive(client.pending());
        assert!(server.finished);
        server.send(APPLICATION, b"hello, ");
        server.send(APPLICATION, b"world");
        server.send(ALERT, &[1, 0]);
        bytes.append(&mut server.output);
        bytes
    }

    /// bytes into a fresh client in parts, each in the split's pieces.
    fn replay(store: &Store, parts: &[&[u8]], split: &mut Split) -> Vec<u8> {
        let mut client = Client::new(HOST, &[], Verify::Store(store), TEST_NOW, random()).unwrap();
        let mut got = Vec::new();
        for part in parts {
            feed(&mut client, part, split, &mut got).unwrap();
        }
        assert!(client.connected() && client.closed());
        got
    }

    /// The server's bytes in every split in two, a byte at a time and in
    /// random pieces give the same handshake and data.
    #[test]
    fn any_split() {
        let store = Identity::new(Kind::P256).store();
        let bytes = recorded(&store);
        let bytewise = replay(&store, &[&bytes], &mut Split { piece: 1, seed: 0 });
        assert_eq!(bytewise, b"hello, world");
        for seed in 1..40 {
            let got = replay(&store, &[&bytes], &mut Split { piece: 300, seed });
            assert_eq!(got, b"hello, world");
        }
        for cut in 1..bytes.len() {
            let (first, second) = bytes.split_at(cut);
            let got = replay(&store, &[first, second], &mut whole());
            assert_eq!(got, b"hello, world", "cut at {cut}");
        }
    }

    /// Handshake messages split across records, down to a byte each, and
    /// a change_cipher_spec after ServerHello, which is dropped.
    #[test]
    fn fragmented_messages() {
        for piece in [1, 2, 7, 100, 1000] {
            let mut script = Script::new(Kind::P256);
            script.piece = piece;
            script.compatible = piece == 7;
            let store = script.identity.store();
            let mut server = Server::new(script);
            let seed = u64::try_from(piece).unwrap();
            let mut split = Split { piece: 500, seed };
            let client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
            assert!(client.connected());
        }
    }

    /// Each group the client shares a key for, and P-256 in a retry that
    /// asks for it, with a cookie or not; the client sends one
    /// change_cipher_spec, before its second flight.
    #[test]
    fn groups() {
        for (group, retry, cookie) in [
            (X25519MLKEM768, None, None),
            (X25519, None, None),
            (X25519, Some(SECP256R1), None),
            (X25519, Some(SECP256R1), Some(&b"\x01"[..])),
        ] {
            let mut script = Script::new(Kind::P256);
            script.group = group;
            script.retry_group = retry;
            script.cookie = cookie;
            let store = script.identity.store();
            let mut server = Server::new(script);
            let mut client = connect(&store, &mut server, HOST, &[], &mut whole()).unwrap();
            assert!(client.connected() && server.finished);
            assert_eq!(server.ccs, 1);
            assert_eq!(server.hello.session, SESSION);
            assert!(client.kem.is_none() && client.p256.is_none() && client.secret.is_none());
            assert_eq!(client.write(b"x"), Ok(Taken(1)));
            assert_eq!(
                exchange(&mut client, &mut server, &mut whole()),
                Ok(Vec::new())
            );
            assert_eq!(server.received, b"x");
        }
        // The first ClientHello shares X25519MLKEM768's key and X25519's.
        let store = Store::new();
        let mut server = Server::new(Script::new(Kind::P256));
        let client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        let shares = &server.hello.shares;
        assert_eq!(shares.len(), 2);
        assert_eq!(
            (shares[0].0, shares[0].1.len()),
            (X25519MLKEM768, 1184 + 32)
        );
        assert_eq!((shares[1].0, shares[1].1.len()), (X25519, 32));
    }

    /// A ServerHello whose key share is for a group without one, or after
    /// a retry for another than it asked, or of the wrong length, or a
    /// session ID that is not the client's.
    #[test]
    fn server_hello_refused() {
        for (share, asked, session) in [
            ("0017 0041", None, true),
            ("001d 0020", Some("0017"), true),
            ("11ec 0441", None, true),
            ("001d 001f", None, true),
            ("001d 0020", None, false),
        ] {
            let store = Store::new();
            let mut client =
                Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
            client.sent(client.pending().len()).unwrap();
            if let Some(group) = asked {
                let mut all = hex("002b 0002 0304  0033 0002");
                all.extend(hex(group));
                let retry = hello_message(&HELLO_RETRY, &SESSION, AES_128_GCM_SHA256, &all);
                let mut record = Vec::from([22, 3, 3]);
                prefixed(&mut record, retry.len(), &retry);
                assert_eq!(client.input(&record), Ok(Taken(record.len())));
            }
            let mut all = hex("002b 0002 0304  0033");
            let mut entry = hex(share);
            let length = usize::from(entry[2]) * 256 + usize::from(entry[3]);
            entry.resize(4 + length, 9);
            prefixed(&mut all, entry.len(), &entry);
            let echo = if session { &SESSION[..] } else { &[][..] };
            let hello = hello_message(&[0x7e; 32], echo, AES_128_GCM_SHA256, &all);
            let mut record = Vec::from([22, 3, 3]);
            prefixed(&mut record, hello.len(), &hello);
            assert_eq!(client.input(&record), Err(Error::Parameter), "{share}");
        }
    }

    /// Records that carry nothing, IDLE_MAX in a row, are taken; one more
    /// ends the connection. Data in between starts the count again.
    #[test]
    fn idle_records() {
        let (result, got, _) = after(
            |server| {
                for round in 0..2 * IDLE_MAX {
                    server.send(APPLICATION, b"");
                    if round == IDLE_MAX - 1 {
                        server.send(APPLICATION, b"!");
                    }
                }
            },
            WHOLE,
        );
        assert_eq!((result, got), (None, Vec::from(*b"!")));
        let (flooded, _, alerts) = after(
            |server| {
                for _ in 0..=IDLE_MAX {
                    server.send(HANDSHAKE, &[4, 0, 0, 0]);
                }
            },
            WHOLE,
        );
        assert_eq!(flooded, Some(Error::Unexpected));
        assert_eq!(alerts, [10]);
    }

    #[test]
    fn hello_retry() {
        let mut script = Script::new(Kind::P256);
        script.cookie = Some(b"\xc0\x0c\xee");
        script.compatible = true;
        let store = script.identity.store();
        let mut server = Server::new(script);
        let mut split = Split { piece: 3, seed: 9 };
        let mut client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
        assert!(client.connected());
        assert_eq!(server.hello.cookie.as_deref(), Some(&b"\xc0\x0c\xee"[..]));
        assert_eq!(client.write(b"after retry"), Ok(Taken(11)));
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert_eq!(server.received, b"after retry");
    }

    /// What the client makes of a HelloRetryRequest with these extensions
    /// after supported_versions, sent once or twice.
    fn retried(extensions: Vec<u8>, twice: bool) -> Option<Error> {
        let store = Store::new();
        let mut all = hex("002b 0002 0304");
        all.extend(extensions);
        let retry = hello_message(&HELLO_RETRY, &SESSION, AES_128_GCM_SHA256, &all);
        let mut record = Vec::from([22, 3, 3]);
        prefixed(&mut record, retry.len(), &retry);
        let mut client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        client.sent(client.pending().len()).unwrap();
        let first = client.input(&record).err();
        if first.is_some() || !twice {
            if first.is_some() {
                // The alert goes in the clear: the client has no keys yet.
                assert_eq!(client.pending()[..5], [21, 3, 3, 0, 2]);
            }
            return first;
        }
        client.input(&record).err()
    }

    /// P-256, with a cookie or not; a group not offered, one already shared,
    /// nothing to change, a cookie too long, and a second retry.
    #[test]
    fn hello_retry_refused() {
        for (extensions, twice, error) in [
            ("0033 0002 0017  002c 0003 0001 01", false, None),
            ("0033 0002 0017", false, None),
            ("0033 0002 0018", false, Some(Error::Parameter)),
            ("0033 0002 11ec", false, Some(Error::Parameter)),
            (
                "0033 0002 001d  002c 0003 0001 01",
                false,
                Some(Error::Parameter),
            ),
            ("", false, Some(Error::Parameter)),
            ("002c 0002 0000", false, Some(Error::Decode)),
            (
                "002c 0003 0001 01  002c 0003 0001 01",
                false,
                Some(Error::Decode),
            ),
            ("002c 0003 0001 01", true, Some(Error::Unexpected)),
            ("002c 0003 0001 01", false, None),
        ] {
            assert_eq!(retried(hex(extensions), twice), error, "{extensions}");
        }
        let mut long = hex("002c 1003 1001");
        long.resize(long.len() + 4097, 1);
        assert_eq!(retried(long, false), Some(Error::TooLarge));
    }

    #[test]
    fn alpn() {
        let offer: [&[u8]; 2] = [b"h2", b"http/1.1"];
        for chosen in [&b"http/1.1"[..], b"h2"] {
            let mut script = Script::new(Kind::P256);
            script.alpn = Some(chosen);
            let store = script.identity.store();
            let mut server = Server::new(script);
            let client = connect(&store, &mut server, HOST, &offer, &mut whole()).unwrap();
            assert_eq!(client.alpn(), Some(chosen));
        }
        for (chosen, offered, error) in [
            (&b"h3"[..], &offer[..], Error::Parameter),
            (b"", &offer, Error::Decode),
            (b"h2", &[], Error::Extension),
        ] {
            let mut script = Script::new(Kind::P256);
            script.alpn = Some(chosen);
            let (result, alerts) = outcome(script, HOST, offered, TEST_NOW);
            assert_eq!(result, Some(error));
            // The client's alert goes under its handshake keys.
            assert_eq!(alerts, [error.alert().unwrap()]);
        }
    }

    /// EncryptedExtensions: unknown and informational extensions pass,
    /// those that do not belong there fail.
    #[test]
    fn encrypted_extensions() {
        for (extensions, error) in [
            ("000a 0004 0002 001d  0000 0000", None),
            ("0000 0001 00", Some(Error::Decode)),
            // Offered in the ClientHello, not for this message (RFC 9846 4.3).
            ("002b 0002 0304", Some(Error::Parameter)),
            ("0033 0000", Some(Error::Parameter)),
            // Never offered, known or not (4.3): pre_shared_key, early_data,
            // ALPN without protocols offered, and a type of no meaning.
            ("0029 0002 0000", Some(Error::Extension)),
            ("002a 0000", Some(Error::Extension)),
            ("0010 0005 0003 0268 32", Some(Error::Extension)),
            ("ff99 0000", Some(Error::Extension)),
            ("0010", Some(Error::Decode)),
            // Each extension once (4.3).
            (
                "000a 0004 0002 001d  000a 0004 0002 001d",
                Some(Error::Decode),
            ),
        ] {
            let mut script = Script::new(Kind::P256);
            script.extensions = hex(extensions);
            let (result, _) = outcome(script, HOST, &[], TEST_NOW);
            assert_eq!(result, error, "{extensions}");
        }
        let mut script = Script::new(Kind::P256);
        script.extensions = hex("0000 0000");
        let (result, _) = outcome(script, "192.0.2.1", &[], TEST_NOW);
        assert_eq!(result, Some(Error::Extension));
    }

    /// RFC 9846 4.5.1: without a certificate the client answers a request
    /// with an empty Certificate, and the handshake goes on.
    #[test]
    fn certificate_request() {
        let mut script = Script::new(Kind::P384);
        // An empty context and signature_algorithms, as RFC 9846 4.4.2 asks.
        script.request = Some(hex("00 0008 000d 0004 0002 0403"));
        let store = script.identity.store();
        let mut server = Server::new(script);
        let client = connect(&store, &mut server, HOST, &[], &mut whole()).unwrap();
        assert!(client.connected() && server.finished);
        assert_eq!(server.certificate, Some(hex("0b000004 00 000000")));
        for (request, error) in [
            // A context, which only a request after the handshake has.
            ("02 c0de 0008 000d 0004 0002 0403", Error::Parameter),
            // No signature_algorithms.
            ("00 0004 002f 0000", Error::Missing),
            ("00 0000", Error::Missing),
            // signature_algorithms twice.
            (
                "00 0010 000d 0004 0002 0403 000d 0004 0002 0403",
                Error::Decode,
            ),
            ("00 0006 000d 0002 0000", Error::Decode),
        ] {
            let mut refused = Script::new(Kind::P384);
            refused.request = Some(hex(request));
            let (error_found, alerts) = outcome(refused, HOST, &[], TEST_NOW);
            assert_eq!(error_found, Some(error), "{request}");
            assert_eq!(alerts.len(), 1);
        }
    }

    #[test]
    fn certificates_refused() {
        let p256 = || Script::new(Kind::P256);
        for (host, now, error) in [
            ("other.example.test", TEST_NOW, Error::Name),
            (HOST, 2_200_000_000, Error::Expired),
            (HOST, 1_700_000_000, Error::Expired),
        ] {
            let (result, alerts) = outcome(p256(), host, &[], now);
            assert_eq!(result, Some(error));
            // The alert reached the server under the handshake keys.
            assert_eq!(alerts, [error.alert().unwrap()]);
        }
        let mut untrusted = p256();
        untrusted.identity.anchor = Identity::new(Kind::RsaSha256).anchor;
        assert_eq!(
            outcome(untrusted, HOST, &[], TEST_NOW),
            (Some(Error::Untrusted), Vec::from([48]))
        );
        let mut short = p256();
        short.identity.chain.truncate(1);
        assert_eq!(
            outcome(short, HOST, &[], TEST_NOW).0,
            Some(Error::Untrusted)
        );
        let mut empty = p256();
        empty.identity.chain.clear();
        assert_eq!(outcome(empty, HOST, &[], TEST_NOW).0, Some(Error::Decode));
        // An IP literal the leaf names.
        assert_eq!(outcome(p256(), "192.0.2.1", &[], TEST_NOW).0, None);
    }

    /// A signature by another key, and a scheme not offered.
    #[test]
    fn certificate_verify_refused() {
        let mut forged = Script::new(Kind::P256);
        forged.identity.signer = Identity::new(Kind::P384).signer;
        assert_eq!(
            outcome(forged, HOST, &[], TEST_NOW),
            (Some(Error::Signature), Vec::from([51]))
        );
        let mut pkcs1 = Script::new(Kind::P256);
        pkcs1.identity.scheme = 0x0401;
        assert_eq!(
            outcome(pkcs1, HOST, &[], TEST_NOW).0,
            Some(Error::Parameter)
        );
    }

    /// The server's KeyUpdates are honoured; requests that come before the
    /// client's answer is sent share it.
    #[test]
    fn key_update() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        let mut split = whole();
        server.update(true);
        server.send(APPLICATION, b"one");
        server.update(true);
        server.send(APPLICATION, b"two");
        server.update(false);
        server.send(APPLICATION, b"three");
        let mut got = Vec::new();
        feed(&mut client, &server.take(), &mut split, &mut got).unwrap();
        assert_eq!(got, b"onetwothree");
        assert_eq!(client.write(b"four"), Ok(Taken(4)));
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert_eq!(server.updates, 1);
        assert_eq!(server.received, b"four");
        // Asked again once that answer is sent.
        server.update(true);
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert_eq!(server.updates, 2);
        // The client's own, every 2^24 records.
        client
            .output_keys
            .as_mut()
            .unwrap()
            .key
            .set_sequence_less_safe(KEY_RECORDS_MAX);
        server
            .read
            .as_mut()
            .unwrap()
            .key
            .set_sequence_for_tests(KEY_RECORDS_MAX);
        assert_eq!(client.write(b"five"), Ok(Taken(4)));
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::new())
        );
        assert_eq!(server.updates, 3);
        assert_eq!(server.received, b"fourfive");
        assert_eq!(client.output_keys.as_ref().unwrap().key.sequence(), 1);
    }

    /// A request value other than 0 or 1, a KeyUpdate of two bytes, and one
    /// whose record goes on.
    #[test]
    fn key_update_refused() {
        for (body, error) in [
            (&[24, 0, 0, 1, 2][..], Error::Parameter),
            (&[24, 0, 0, 2, 0, 0], Error::Decode),
            (&[24, 0, 0, 1, 0, 4, 0, 0, 0], Error::Unexpected),
        ] {
            let (result, _, alerts) = after(|server| server.send(HANDSHAKE, body), WHOLE);
            assert_eq!(result, Some(error));
            assert_eq!(alerts, [error.alert().unwrap()]);
        }
    }

    #[test]
    fn alerts() {
        let store = Store::new();
        // Before ServerHello, in the clear; no alert answers the server's.
        let mut client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        client.sent(client.pending().len()).unwrap();
        assert_eq!(
            client.input(&[21, 3, 3, 0, 2, 2, 40]),
            Err(Error::Alert(40))
        );
        assert_eq!(client.input(&[22]), Err(Error::Alert(40)));
        assert!(client.pending().is_empty());
        // After it, sealed; a warning is an error too, but user_canceled.
        for (alert, error) in [
            ([2, 80], Some(Error::Alert(80))),
            ([1, 42], Some(Error::Alert(42))),
            ([1, 90], None),
        ] {
            let send = |server: &mut Server| {
                server.send(ALERT, &alert);
                server.send(APPLICATION, b"after");
            };
            let (result, got, alerts) = after(send, 1);
            assert_eq!(result, error);
            assert_eq!(got.is_empty(), error.is_some());
            assert!(alerts.is_empty());
        }
        // A long alert.
        let (result, _, alerts) = after(|server| server.send(ALERT, &[2, 80, 0]), 1);
        assert_eq!((result, alerts), (Some(Error::Decode), Vec::from([50])));
        // An empty one, sealed: unexpected_message (RFC 9846 5.4).
        let (empty, _, refused) = after(|server| server.send(ALERT, &[]), 1);
        assert_eq!((empty, refused), (Some(Error::Unexpected), Vec::from([10])));
        // close_notify during the handshake.
        assert_eq!(after_hello(Some(ALERT), &[1, 0]), Some(Error::Alert(0)));
    }

    /// Every byte of a sealed record flipped, header and tag included,
    /// fails it, and the client tells the server; a record replayed fails.
    #[test]
    fn tampered() {
        let store = Identity::new(Kind::P256).store();
        let (_, mut first) = connected(&store);
        first.send(APPLICATION, b"data");
        let record = first.take();
        for at in 0..record.len() {
            let error = match at {
                0 => Some(Error::Unexpected),
                3 => Some(Error::Overflow),
                // The record now looks longer: the client waits for it.
                4 => None,
                // legacy_record_version is ignored, but it is in the AAD.
                _ => Some(Error::Forged),
            };
            let flip = |server: &mut Server| {
                server.output.extend_from_slice(&record);
                server.output[at] ^= 0x80;
            };
            let (result, _, alerts) = after(flip, 1);
            assert_eq!(result, error, "byte {at}");
            assert_eq!(alerts, Vec::from_iter(error.and_then(Error::alert)));
        }
        let twice = |server: &mut Server| {
            server.output.extend_from_slice(&record);
            server.output.extend_from_slice(&record);
        };
        assert_eq!(after(twice, WHOLE).0, Some(Error::Forged));
    }

    /// Records over their limits, before and after decryption, and inner
    /// content types.
    #[test]
    fn record_limits() {
        let store = Identity::new(Kind::P256).store();
        // Ciphertext over 2^14 + 256 is refused at the header.
        let (mut over, _) = connected(&store);
        assert_eq!(over.input(&[23, 3, 3, 0x41, 0x01]), Err(Error::Overflow));
        let (mut most, _) = connected(&store);
        assert_eq!(most.input(&[23, 3, 3, 0x41, 0x00]), Ok(Taken(5)));
        // Plaintext records over 2^14, before keys, and bytes that are not
        // TLS.
        for (bytes, result) in [
            (&[22, 3, 3, 0x40, 0x01][..], Err(Error::Overflow)),
            (&[22, 3, 3, 0x40, 0x00], Ok(Taken(5))),
            (b"HTTP/1.1 400", Err(Error::Unexpected)),
        ] {
            let mut client =
                Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
            assert_eq!(client.input(bytes), result);
        }
        // 2^14 bytes and the content type pass: TLSInnerPlaintext is 2^14 + 1
        // bytes at most (RFC 9846 5.4), so one byte of padding more does not,
        // nor one more byte of data.
        let full = |server: &mut Server| {
            let mut inner = Vec::new();
            inner.resize(RECORD_MAX, b'a');
            inner.push(APPLICATION);
            server.raw(inner);
        };
        let (result, got, _) = after(full, 1000);
        assert_eq!((result, got.len()), (None, RECORD_MAX));
        let padded = |server: &mut Server| {
            let mut inner = Vec::new();
            inner.resize(RECORD_MAX, b'a');
            inner.push(APPLICATION);
            inner.push(0);
            server.raw(inner);
        };
        assert_eq!(
            after(padded, 1000),
            (Some(Error::Overflow), Vec::new(), Vec::from([22]))
        );
        let large = |server: &mut Server| {
            let mut inner = Vec::new();
            inner.resize(RECORD_MAX + 1, b'a');
            inner.push(APPLICATION);
            server.raw(inner);
        };
        assert_eq!(
            after(large, 1000),
            (Some(Error::Overflow), Vec::new(), Vec::from([22]))
        );
        for (inner, error) in [
            (&[0, 0, 0][..], Some(Error::Unexpected)),
            (&[1, 20], Some(Error::Unexpected)),
            (&[1, 99, 0], Some(Error::Unexpected)),
            (&[HANDSHAKE, 0], Some(Error::Unexpected)),
            (&[], Some(Error::Unexpected)),
            (&[APPLICATION, 0, 0], None),
        ] {
            // rr: escape(copy): raw seals a buffer of its own.
            let (typed, _, _) = after(|server| server.raw(inner.to_vec()), WHOLE);
            assert_eq!(typed, error);
        }
    }

    /// A handshake message of MESSAGE_MAX passes, one byte more does not.
    #[test]
    fn message_limit() {
        for (length, error) in [
            (MESSAGE_MAX, None),
            (MESSAGE_MAX + 1, Some(Error::TooLarge)),
        ] {
            let ticket = |server: &mut Server| {
                let mut message = Vec::from([4]);
                message.extend_from_slice(&u24(length));
                message.resize(4 + length, 0);
                for piece in message.chunks(RECORD_MAX) {
                    server.send(HANDSHAKE, piece);
                }
                server.send(APPLICATION, b"after");
            };
            let (result, got, _) = after(ticket, WHOLE);
            assert_eq!(result, error);
            assert_eq!(got.is_empty(), error.is_some());
        }
    }

    /// A message before a change of keys ends its record; records do not
    /// interleave with a message that spans them.
    #[test]
    fn record_boundaries() {
        // ServerHello with a byte more in its record.
        let mut script = Script::new(Kind::P256);
        script.flight = false;
        let store = script.identity.store();
        let mut first = Server::new(script);
        let mut client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        first.receive(client.pending());
        let mut bytes = first.take();
        bytes[4] += 1;
        bytes.push(8);
        let result = feed(
            &mut client,
            &bytes,
            &mut Split { piece: 1, seed: 0 },
            &mut Vec::new(),
        );
        assert_eq!(result, Err(Error::Unexpected));
        // Data in the middle of a ticket that spans two records.
        let split = |server: &mut Server| {
            server.send(HANDSHAKE, &[4, 0, 0, 4, 0]);
            server.send(APPLICATION, b"x");
        };
        assert_eq!(after(split, 1).0, Some(Error::Unexpected));
        // A change_cipher_spec after the handshake, or of another value.
        let late = |server: &mut Server| server.output.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        assert_eq!(after(late, 1).0, Some(Error::Unexpected));
        let mut fresh = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        assert_eq!(fresh.input(&[20, 3, 3, 0, 1, 1]), Ok(Taken(6)));
        assert_eq!(fresh.input(&[20, 3, 3, 0, 1, 2]), Err(Error::Unexpected));
        // Data before the handshake is done; a handshake record in the clear
        // after ServerHello.
        assert_eq!(
            after_hello(Some(APPLICATION), b"early"),
            Some(Error::Unexpected)
        );
        let clear = [22, 3, 3, 0, 4, 8, 0, 0, 0];
        assert_eq!(after_hello(None, &clear), Some(Error::Unexpected));
    }

    /// What the client makes of a ServerHello of TLS 1.2, without
    /// supported_versions: random's last 8 bytes, and its extensions block
    /// or none; and the alert it sends back.
    fn tls12(tail: [u8; 8], extensions: Option<&[u8]>) -> (Option<Error>, Vec<u8>) {
        let store = Store::new();
        let mut client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        client.sent(client.pending().len()).unwrap();
        let mut body = Vec::from([3, 3]);
        body.extend_from_slice(&[0x11; 24]);
        body.extend_from_slice(&tail);
        body.extend_from_slice(&[0, 0xc0, 0x2f, 0]);
        if let Some(block) = extensions {
            prefixed(&mut body, block.len(), block);
        }
        let mut message = Vec::from([2]);
        message.extend_from_slice(&u24(body.len()));
        message.extend_from_slice(&body);
        let mut record = Vec::from([22, 3, 3]);
        prefixed(&mut record, message.len(), &message);
        let error = client.input(&record).err();
        // rr: escape(copy): the client goes, its alert stays for the test.
        (error, client.pending().to_vec())
    }

    /// A ServerHello of TLS 1.2, with extensions or without the block (RFC
    /// 9846 E.1): protocol_version; one that ends in a downgrade sentinel:
    /// illegal_parameter (4.2.3).
    #[test]
    fn version() {
        let plain = [0x11; 8];
        let renegotiation: &[u8] = &[0xff, 1, 0, 1, 0];
        for (tail, extensions, error) in [
            (plain, Some(renegotiation), Error::Version),
            (plain, None, Error::Version),
            (*b"DOWNGRD\x01", Some(renegotiation), Error::Parameter),
            (*b"DOWNGRD\x01", None, Error::Parameter),
            (*b"DOWNGRD\x00", None, Error::Parameter),
            (*b"DOWNGRD\x02", None, Error::Version),
        ] {
            let (found, pending) = tls12(tail, extensions);
            assert_eq!(found, Some(error));
            // The alert alone, in the clear.
            assert_eq!(pending, [21, 3, 3, 0, 2, 2, error.alert().unwrap()]);
        }
    }

    /// The server chooses TLS_AES_256_GCM_SHA384, with or without a retry
    /// that names it: the handshake by SHA-384, AES-256-GCM records both
    /// ways, a KeyUpdate each way, and close_notify.
    #[test]
    fn aes_256_gcm_sha384() {
        for (retry, cookie) in [
            (None, None),
            (Some(SECP256R1), None),
            (None, Some(&b"\x07"[..])),
        ] {
            let mut script = Script::new(Kind::P384);
            script.suite = AES_256_GCM_SHA384;
            script.retry_suite = AES_256_GCM_SHA384;
            script.retry_group = retry;
            script.cookie = cookie;
            let store = script.identity.store();
            let mut server = Server::new(script);
            let mut split = Split { piece: 50, seed: 5 };
            let mut client = connect(&store, &mut server, HOST, &[], &mut split).unwrap();
            assert!(client.connected() && server.finished);
            let keys = client.output_keys.as_ref().unwrap();
            assert!(matches!(keys.secret, Digest::Sha384(_)));
            assert!(matches!(client.transcript, Transcript::Sha256(_)));
            assert_eq!(client.write(b"ping"), Ok(Taken(4)));
            server.update(true);
            server.send(APPLICATION, b"pong");
            assert_eq!(
                exchange(&mut client, &mut server, &mut split),
                Ok(Vec::from(*b"pong"))
            );
            assert_eq!(client.write(b"again"), Ok(Taken(5)));
            client.close();
            assert_eq!(
                exchange(&mut client, &mut server, &mut split),
                Ok(Vec::new())
            );
            assert_eq!(server.received, b"pingagain");
            assert_eq!((server.updates, server.alerts.as_slice()), (1, &[0][..]));
        }
    }

    /// A suite the client did not offer, in a ServerHello or a retry, and a
    /// ServerHello whose suite is not the retry's (RFC 9846 4.2.4):
    /// illegal_parameter.
    #[test]
    fn suites_refused() {
        for suite in [0x1303, 0x1304, 0xc02f, 0] {
            let mut script = Script::new(Kind::P256);
            script.suite = suite;
            assert_eq!(
                outcome(script, HOST, &[], TEST_NOW),
                (Some(Error::Parameter), Vec::from([47]))
            );
            let retry = hello_message(
                &HELLO_RETRY,
                &SESSION,
                suite,
                &hex("002b 0002 0304 0033 0002 0017"),
            );
            let store = Store::new();
            let mut client =
                Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
            let mut record = Vec::from([22, 3, 3]);
            prefixed(&mut record, retry.len(), &retry);
            assert_eq!(client.input(&record), Err(Error::Parameter));
        }
        for (first, second) in [
            (AES_128_GCM_SHA256, AES_256_GCM_SHA384),
            (AES_256_GCM_SHA384, AES_128_GCM_SHA256),
        ] {
            let mut script = Script::new(Kind::P256);
            script.retry_group = Some(SECP256R1);
            script.retry_suite = first;
            script.suite = second;
            let (error, alerts) = outcome(script, HOST, &[], TEST_NOW);
            assert_eq!((error, alerts), (Some(Error::Parameter), Vec::from([47])));
        }
    }

    /// An extension in a CertificateEntry: the client asks for none, so any
    /// is unsupported_extension (RFC 9846 4.5.1), with Verify::Caller before
    /// the caller is asked; one that does not frame is decode_error.
    #[test]
    fn certificate_entry_extensions() {
        for (entry, error) in [
            ("", None),
            // status_request and signed_certificate_timestamp, unsolicited.
            ("0005 0000", Some(Error::Extension)),
            ("0012 0003 000102", Some(Error::Extension)),
            ("ff99 0000", Some(Error::Extension)),
            ("0005", Some(Error::Decode)),
            ("0005 0002 00", Some(Error::Decode)),
            ("0005 0000 0012", Some(Error::Decode)),
        ] {
            let mut script = Script::new(Kind::P256);
            script.entry = hex(entry);
            let (found, alerts) = outcome(script, HOST, &[], TEST_NOW);
            assert_eq!(found, error, "{entry}");
            assert_eq!(alerts, Vec::from_iter(error.and_then(Error::alert)));
            let mut asked = Script::new(Kind::P256);
            asked.entry = hex(entry);
            let verdict = caller(asked, HOST, WHOLE, &Judge::Always(true));
            assert_eq!(verdict.error, error, "{entry}");
            assert_eq!(verdict.waits, usize::from(error.is_none()));
        }
    }

    /// The client's own limits are internal_error: a sequence number that
    /// would wrap, either way (RFC 9846 5.3), and a record past the pending
    /// buffer or a record's length.
    #[test]
    fn internal_errors() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        let last = u64::MAX;
        client
            .output_keys
            .as_mut()
            .unwrap()
            .key
            .set_sequence_less_safe(last);
        assert_eq!(client.write(b"x"), Err(Error::Internal));
        // No number is left for the alert either.
        assert!(client.pending().is_empty());
        server.receive(client.pending());
        assert!(server.received.is_empty() && server.alerts.is_empty());
        let (mut reading, mut other) = connected(&store);
        reading
            .input_keys
            .as_mut()
            .unwrap()
            .key
            .set_sequence_for_tests(last);
        other.send(APPLICATION, b"x");
        assert_eq!(reading.input(&other.take()), Err(Error::Internal));
        other.receive(reading.pending());
        assert_eq!(other.alerts, [80]);
        let mut keys = Keys::new(Digest::Sha256([1; 32]));
        let mut tx = Vec::new();
        tx.resize(super::TX_MAX - 20, 0);
        assert_eq!(
            super::seal(&mut keys, &mut tx, APPLICATION, &[0; 4]),
            Err(Error::Internal)
        );
        tx.clear();
        let mut large = Vec::new();
        large.resize(1 << 16, 0);
        assert_eq!(
            super::seal(&mut keys, &mut tx, APPLICATION, &large),
            Err(Error::Internal)
        );
        assert_eq!((tx.len(), keys.key.sequence()), (0, 0));
        assert_eq!(Error::Internal.alert(), Some(80));
    }

    /// input stops after RECORDS_PER_INPUT records, and at plaintext not yet
    /// read.
    #[test]
    fn input_backpressure() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        // As many empty records as are taken in a row (IDLE_MAX), then more
        // after a byte of data.
        assert!(RECORDS_PER_INPUT <= usize::from(IDLE_MAX));
        for at in 0..RECORDS_PER_INPUT + 8 {
            if at == RECORDS_PER_INPUT {
                server.send(APPLICATION, b"!");
            }
            server.send(APPLICATION, b"");
        }
        let empty = server.take();
        let size = (empty.len() - 1) / (RECORDS_PER_INPUT + 9);
        assert_eq!(client.input(&empty), Ok(Taken(RECORDS_PER_INPUT * size)));
        let rest = &empty[RECORDS_PER_INPUT * size..];
        assert_eq!(client.input(rest), Ok(Taken(size + 1)));
        assert_eq!(client.read(), b"!");
        client.consume(1);
        assert_eq!(client.input(&rest[size + 1..]), Ok(Taken(8 * size)));
        server.send(APPLICATION, b"first");
        server.send(APPLICATION, b"second");
        let bytes = server.take();
        let first = 5 + 5 + 1 + 16;
        assert_eq!(client.input(&bytes), Ok(Taken(first)));
        assert_eq!(client.read(), b"first");
        // The next record waits until this one is read, and input says so.
        assert_eq!(client.input(&bytes[first..]), Err(Error::Unconsumed));
        client.consume(2);
        assert_eq!(client.read(), b"rst");
        client.consume(10);
        assert_eq!(
            client.input(&bytes[first..]),
            Ok(Taken(bytes.len() - first))
        );
        assert_eq!(client.read(), b"second");
    }

    /// write takes what fits under PENDING_MAX, and nothing more until
    /// pending is sent.
    #[test]
    fn write_backpressure() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        let mut data = Vec::new();
        data.resize(1 << 20, 7);
        let mut total = client.write(&data).unwrap().count();
        assert_eq!(total, RECORD_MAX);
        assert_eq!(client.pending().len(), PENDING_MAX);
        assert!(client.pending().len() <= PENDING_MAX);
        assert_eq!(client.write(&data), Ok(Taken(0)));
        server.receive(&client.pending()[..1000]);
        client.sent(1000).unwrap();
        assert_eq!(client.write(&data), Ok(Taken(0)));
        while total < data.len() {
            server.receive(client.pending());
            client.sent(client.pending().len()).unwrap();
            total += client.write(&data[total..]).unwrap().count();
        }
        server.receive(client.pending());
        assert_eq!(server.received, data);
        assert_eq!(client.write(&[]), Ok(Taken(0)));
        // Before the handshake nothing is written, and close_notify goes in
        // the clear.
        let mut fresh = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        assert_eq!(fresh.write(b"x"), Err(Error::NotConnected));
        fresh.close();
        let pending = fresh.pending();
        assert_eq!(pending[pending.len() - 7..], [21, 3, 3, 0, 2, 1, 0]);
    }

    /// A failure sticks, and drops the data waiting to be read.
    #[test]
    fn failure_sticks() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        server.send(APPLICATION, b"unread");
        let mut bytes = server.take();
        let first = bytes.len();
        bytes.extend_from_slice(&[99, 3, 3, 0, 0]);
        assert_eq!(client.input(&bytes), Ok(Taken(first)));
        client.consume(6);
        assert_eq!(client.input(&bytes[first..]), Err(Error::Unexpected));
        assert_eq!(client.input(&bytes), Err(Error::Unexpected));
        assert_eq!(client.write(b"x"), Err(Error::Unexpected));
        assert!(client.read().is_empty() && !client.connected());
        let alert = client.pending().len();
        client.close();
        assert_eq!(client.pending().len(), alert);
    }

    /// One 16 KiB record sealed and sent.
    #[bench]
    fn write_record(b: &mut Bencher) {
        let store = Identity::new(Kind::P256).store();
        let (mut client, _) = connected(&store);
        let mut data = Vec::new();
        data.resize(RECORD_MAX, 0x61);
        b.iter(|| {
            assert_eq!(client.write(&data), Ok(Taken(RECORD_MAX)));
            client.sent(client.pending().len()).unwrap();
        });
    }

    /// One 16 KiB record taken in, opened in place and read.
    #[bench]
    fn input_record(b: &mut Bencher) {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        let mut data = Vec::new();
        data.resize(RECORD_MAX, 0x62);
        server.send(APPLICATION, &data);
        let record = server.take();
        let seq = client.input_keys.as_ref().unwrap().key.sequence();
        b.iter(|| {
            client
                .input_keys
                .as_mut()
                .unwrap()
                .key
                .set_sequence_for_tests(seq);
            assert_eq!(client.input(&record), Ok(Taken(record.len())));
            assert_eq!(client.read().len(), RECORD_MAX);
            client.consume(RECORD_MAX);
        });
    }

    /// A whole handshake against the server's recorded flight: X25519 twice,
    /// the chain's two ECDSA signatures and CertificateVerify's, and the key
    /// schedule.
    #[bench]
    fn handshake(b: &mut Bencher) {
        let store = Identity::new(Kind::P256).store();
        let mut server = Server::new(Script::new(Kind::P256));
        let client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        let flight = server.take();
        b.iter(|| {
            let mut fresh =
                Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
            assert_eq!(fresh.input(&flight), Ok(Taken(flight.len())));
            assert!(fresh.connected());
        });
    }

    /// The same with the server choosing TLS_AES_256_GCM_SHA384: SHA-384
    /// beside SHA-256 until ServerHello, then alone.
    #[bench]
    fn handshake_aes256(b: &mut Bencher) {
        let mut script = Script::new(Kind::P256);
        script.suite = AES_256_GCM_SHA384;
        let store = script.identity.store();
        let mut server = Server::new(script);
        let client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        let flight = server.take();
        b.iter(|| {
            let mut fresh =
                Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
            assert_eq!(fresh.input(&flight), Ok(Taken(flight.len())));
            assert!(fresh.connected());
        });
    }

    /// The bytes a Client holds after a handshake, its buffers' capacities
    /// included, and what is left once data both ways and a KeyUpdate are
    /// done.
    fn held(client: &Client<'_>) -> usize {
        let kem = client
            .kem
            .as_ref()
            .map_or(0, |_| size_of::<mlkem::DecapsulationKey>());
        size_of::<Client<'_>>()
            + client.rx.capacity()
            + client.tx.capacity()
            + client.hs.capacity()
            + client.leaf.capacity()
            + client.offer.capacity()
            + client.host.capacity()
            + kem
    }

    #[test]
    fn memory() {
        let mut script = Script::new(Kind::RsaSha256);
        script.alpn = Some(b"h2");
        script.request = Some(hex("00 0008 000d 0004 0002 0403"));
        let store = script.identity.store();
        let mut server = Server::new(script);
        let mut split = Split { piece: 7, seed: 3 };
        let alpn: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let mut client = connect(&store, &mut server, HOST, &alpn, &mut split).unwrap();
        let after = held(&client);
        server.update(true);
        server.send(APPLICATION, b"data");
        assert_eq!(client.write(b"ping"), Ok(Taken(4)));
        assert_eq!(
            exchange(&mut client, &mut server, &mut split),
            Ok(Vec::from(*b"data"))
        );
        assert_eq!(client.alpn(), Some(&b"h2"[..]));
        assert_eq!(held(&client), after);
        // The structure, one record in, one out, and the ALPN choice.
        let buffers = 5 + RECORD_MAX + 256 + super::TX_MAX + 2;
        assert_eq!(after, size_of::<Client<'_>>() + buffers);
    }

    /// Requests for a KeyUpdate while pending holds a full record that goes
    /// out a piece at a time: each is answered once, and pending stays
    /// within its bound.
    #[test]
    fn key_update_pending() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        let mut data = Vec::new();
        data.resize(RECORD_MAX, 3);
        client
            .output_keys
            .as_mut()
            .unwrap()
            .key
            .set_sequence_less_safe(KEY_RECORDS_MAX);
        server
            .read
            .as_mut()
            .unwrap()
            .key
            .set_sequence_for_tests(KEY_RECORDS_MAX);
        let mut written = 0;
        for _ in 0..6 {
            written += client.write(&data).unwrap().count();
            server.update(true);
            feed(&mut client, &server.take(), &mut whole(), &mut Vec::new()).unwrap();
            assert!(client.tx.len() <= super::TX_MAX);
            // All but the last byte goes out: pending never drains.
            let ready = client.pending().len() - 1;
            server.receive(&client.pending()[..ready]);
            client.sent(ready).unwrap();
        }
        server.receive(client.pending());
        client.sent(1).unwrap();
        assert_eq!(server.received.len(), written);
        // The client's own KeyUpdate, and one answer: the requests after it
        // came while its last byte was still pending.
        assert_eq!(server.updates, 2);
        client.close();
        assert!(client.tx.len() <= super::TX_MAX);
    }

    /// What a client that verifies through its caller made of a server.
    struct Verdict {
        error: Option<Error>,
        /// How often it awaited a verdict, and how many bytes the input that
        /// first stopped there left untaken.
        waits: usize,
        left: usize,
        connected: bool,
        /// What it read after the handshake, and the alerts the server got.
        got: Vec<u8>,
        alerts: Vec<u8>,
    }

    /// How the caller decides on a chain.
    enum Judge<'s> {
        /// A system that approves any chain for the host, or none.
        Always(bool),
        /// x509 against the store, for the host.
        X509(&'s Store, &'static str),
    }

    impl Judge<'_> {
        /// The approval of chain for host, or none.
        fn approval(&self, chain: &[&[u8]], host: &str) -> Option<Approval> {
            match self {
                Judge::Always(true) => Some(Approval::system(chain[0], host)),
                Judge::Always(false) => None,
                Judge::X509(store, name) => x509::verify(chain, store, name, TEST_NOW).ok(),
            }
        }
    }

    /// A handshake with Verify::Caller, the server's bytes in pieces of
    /// piece, and the judge's verdict on the chain; then data from the
    /// server and back.
    fn caller(script: Script, host: &str, piece: usize, judge: &Judge<'_>) -> Verdict {
        let mut server = Server::new(script);
        let mut client = Client::new(host, &[], Verify::Caller, TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        let mut bytes = server.take();
        let mut verdict = Verdict {
            error: None,
            waits: 0,
            left: 0,
            connected: false,
            got: Vec::new(),
            alerts: Vec::new(),
        };
        let mut at = 0;
        while verdict.error.is_none() && (at < bytes.len() || !client.read().is_empty()) {
            let end = (at + piece).min(bytes.len());
            match client.input(&bytes[at..end]) {
                Ok(taken) => at += taken.count(),
                Err(error) => verdict.error = Some(error),
            }
            if client.awaiting() {
                assert!(client.chain(&mut []).is_none());
                let approval = {
                    let mut slots = [&[][..]; x509::CHAIN_MAX];
                    let count = client.chain(&mut slots).unwrap();
                    assert_eq!(slots[..count], server.script.identity.chain[..]);
                    judge.approval(&slots[..count], host)
                };
                if verdict.waits == 0 {
                    verdict.left = end - at;
                }
                verdict.waits += 1;
                // Nothing more is taken until the verdict, and loudly.
                assert_eq!(client.input(&bytes[at..]), Err(Error::Awaiting));
                match approval {
                    Some(approval) => {
                        if let Err(error) = client.verified(approval) {
                            verdict.error = Some(error);
                        }
                    }
                    None => client.refused(),
                }
                // A refusal ends the wait: a loop that asks awaiting before
                // input sees it fail, not wait again.
                assert!(!client.awaiting());
                let mut slots = [&[][..]; x509::CHAIN_MAX];
                assert!(client.chain(&mut slots).is_none());
                if let Err(error) = client.input(&[]) {
                    verdict.error = Some(error);
                }
            }
            let count = client.read().len();
            verdict.got.extend_from_slice(client.read());
            client.consume(count);
            server.receive(client.pending());
            client.sent(client.pending().len()).unwrap();
            if at == bytes.len() && server.finished && verdict.got.is_empty() {
                server.send(APPLICATION, b"after");
                bytes.append(&mut server.output);
            }
        }
        verdict.connected = client.connected();
        if verdict.connected {
            assert_eq!(client.write(b"back"), Ok(Taken(4)));
            server.receive(client.pending());
            assert_eq!(server.received, b"back");
        }
        verdict.alerts = server.alerts;
        verdict
    }

    /// Trusted: the handshake ends and data flows, for any split of the
    /// server's bytes and with Certificate across records or in one with the
    /// rest of the flight. The host is the caller's to match, not the
    /// client's.
    #[test]
    fn caller_trusts() {
        for (piece, records) in [
            (1, RECORD_MAX),
            (7, 100),
            (1000, 300),
            (WHOLE, RECORD_MAX),
            (WHOLE, 500),
        ] {
            let mut script = Script::new(Kind::P256);
            script.piece = records;
            let verdict = caller(script, HOST, piece, &Judge::Always(true));
            assert_eq!(verdict.error, None);
            assert_eq!(verdict.waits, 1);
            assert!(verdict.connected);
            assert_eq!(verdict.got, b"after");
        }
        // Certificate's record ends the flight's first record: the rest
        // waits untaken, and goes in after the verdict.
        let mut split = Script::new(Kind::RsaSha256);
        split.piece = 600;
        let verdict = caller(split, HOST, WHOLE, &Judge::Always(true));
        assert!(verdict.left > 0 && verdict.connected);
        let elsewhere = caller(
            Script::new(Kind::P384),
            "other.example.test",
            3,
            &Judge::Always(true),
        );
        assert!(elsewhere.connected);
    }

    /// close while the client awaits the verdict: close_notify is the last
    /// thing it sends, and the trusted verdict after it sends no Finished.
    #[test]
    fn close_while_awaiting() {
        let mut server = Server::new(Script::new(Kind::P256));
        let mut client = Client::new(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        let bytes = server.take();
        let mut at = 0;
        while !client.awaiting() {
            at += client.input(&bytes[at..]).unwrap().count();
        }
        client.close();
        let closing = client.pending().len();
        assert!(closing > 0);
        let leaf = &server.script.identity.chain[0];
        let late = client.verified(Approval::system(leaf, HOST));
        assert_eq!(late, Err(Error::NotAwaiting));
        assert!(client.input(&bytes[at..]).is_ok());
        assert_eq!(client.pending().len(), closing);
    }

    /// Refused: Untrusted, and unknown_ca reaches the server.
    #[test]
    fn caller_refuses() {
        for piece in [1, WHOLE] {
            let verdict = caller(Script::new(Kind::P256), HOST, piece, &Judge::Always(false));
            assert_eq!(verdict.error, Some(Error::Untrusted));
            assert_eq!((verdict.waits, verdict.connected), (1, false));
            assert_eq!(verdict.alerts, [48]);
        }
    }

    /// A trusted chain still has its key check CertificateVerify, and its
    /// leaf must parse.
    #[test]
    fn caller_checks_the_signature() {
        let mut forged = Script::new(Kind::P256);
        forged.identity.signer = Identity::new(Kind::P384).signer;
        let verdict = caller(forged, HOST, 5, &Judge::Always(true));
        assert_eq!(verdict.error, Some(Error::Signature));
        assert_eq!(verdict.alerts, [51]);
        let mut garbage = Script::new(Kind::P256);
        garbage.identity.chain[0].truncate(40);
        let broken = caller(garbage, HOST, WHOLE, &Judge::Always(true));
        assert_eq!(broken.error, Some(Error::Certificate));
    }

    /// The caller's verdict from x509, as a program that verifies on its
    /// own thread would give it.
    #[test]
    fn caller_with_x509() {
        let store = Identity::new(Kind::P256).store();
        let judge = Judge::X509(&store, HOST);
        assert!(caller(Script::new(Kind::P256), HOST, 9, &judge).connected);
        let other = Judge::X509(&store, "x.test");
        let refused = caller(Script::new(Kind::P256), HOST, 9, &other);
        assert_eq!(refused.error, Some(Error::Untrusted));
    }

    /// A connected client with "queued" written and not sent, and its server.
    fn queued(store: &Store) -> (Client<'_>, Server) {
        let (mut client, server) = connected(store);
        assert_eq!(client.write(b"queued"), Ok(Taken(6)));
        (client, server)
    }

    /// After a failure nothing that was queued goes out (RFC 9846 6, 6.2):
    /// the server's fatal alert leaves nothing to send, the client's own
    /// error only its alert, under the keys and number the server expects.
    #[test]
    fn failure_drops_pending() {
        let store = Identity::new(Kind::P256).store();
        let (mut alerted, mut sender) = queued(&store);
        sender.send(ALERT, &[2, 40]);
        assert_eq!(alerted.input(&sender.take()), Err(Error::Alert(40)));
        assert!(alerted.pending().is_empty());
        let (mut client, mut server) = queued(&store);
        server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
        assert_eq!(client.input(&server.take()), Err(Error::Unexpected));
        server.receive(client.pending());
        assert!(server.received.is_empty());
        assert_eq!(server.alerts, [10]);
        // A close_notify not yet begun gives way to the error's alert.
        let (mut closing, mut its_server) = queued(&store);
        closing.close();
        its_server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
        assert_eq!(closing.input(&its_server.take()), Err(Error::Unexpected));
        its_server.receive(closing.pending());
        assert!(its_server.received.is_empty());
        assert_eq!(its_server.alerts, [10]);
    }

    /// A record the caller began to send is finished before the alert: a
    /// torn one would garble it.
    #[test]
    fn failure_finishes_a_begun_record() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = queued(&store);
        assert_eq!(client.write(b"dropped"), Ok(Taken(7)));
        server.receive(&client.pending()[..10]);
        client.sent(10).unwrap();
        server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
        assert_eq!(client.input(&server.take()), Err(Error::Unexpected));
        server.receive(client.pending());
        assert_eq!(server.received, b"queued");
        assert_eq!(server.alerts, [10]);
        // close_notify begun: nothing goes after it.
        let (mut closing, mut its_server) = connected(&store);
        closing.close();
        its_server.receive(&closing.pending()[..3]);
        closing.sent(3).unwrap();
        its_server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
        assert_eq!(closing.input(&its_server.take()), Err(Error::Unexpected));
        its_server.receive(closing.pending());
        assert_eq!(its_server.alerts, [0]);
    }

    /// Dropped records past a change of keys take the keys back: data before
    /// a KeyUpdate the client answers with, and the client's Finished with
    /// data after it, are not sent, and the alert goes under the keys the
    /// server reads with.
    #[test]
    fn failure_takes_the_keys_back() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = queued(&store);
        server.update(true);
        server.output.extend_from_slice(&[99, 3, 3, 0, 0]);
        let bytes = server.take();
        assert_eq!(client.input(&bytes), Err(Error::Unexpected));
        server.receive(client.pending());
        assert!(server.received.is_empty());
        assert_eq!((server.updates, server.alerts.as_slice()), (0, &[10][..]));
        // The whole flight in, the client's own not yet sent.
        let mut fresh = Server::new(Script::new(Kind::P256));
        let mut early = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        fresh.receive(early.pending());
        early.sent(early.pending().len()).unwrap();
        let flight = fresh.take();
        assert_eq!(early.input(&flight), Ok(Taken(flight.len())));
        assert!(early.connected());
        assert_eq!(early.write(b"early"), Ok(Taken(5)));
        assert_eq!(early.input(&[99, 3, 3, 0, 0]), Err(Error::Unexpected));
        fresh.receive(early.pending());
        assert!(!fresh.finished && fresh.received.is_empty());
        assert_eq!((fresh.ccs, fresh.alerts.as_slice()), (0, &[10][..]));
    }

    /// close before the handshake is complete ends it: the client's Finished
    /// never goes, it never connects, and what the server sends after is
    /// taken and ignored.
    #[test]
    fn close_during_handshake() {
        let store = Identity::new(Kind::P256).store();
        let mut server = Server::new(Script::new(Kind::P256));
        let mut client = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        let flight = server.take();
        let hello = 5 + usize::from(u16::from_be_bytes([flight[3], flight[4]]));
        assert_eq!(client.input(&flight[..hello]), Ok(Taken(hello)));
        client.close();
        assert_eq!(
            client.input(&flight[hello..]),
            Ok(Taken(flight.len() - hello))
        );
        assert!(!client.connected() && !client.awaiting() && !client.closed());
        assert_eq!(client.write(b"x"), Err(Error::Closed));
        server.receive(client.pending());
        assert!(!server.finished);
        assert_eq!(server.alerts, [0]);
    }

    /// A chain the caller trusts still needs a leaf whose key may sign the
    /// handshake: keyUsage keyEncipherment alone is refused before the
    /// server's CertificateVerify.
    #[test]
    fn caller_needs_a_signing_key() {
        let mut script = Script::new(Kind::P256);
        script.identity.chain = Vec::from([test_certificate("test.kencleaf").unwrap()]);
        let verdict = caller(script, HOST, WHOLE, &Judge::Always(true));
        assert_eq!(verdict.error, Some(Error::Certificate));
        assert!(!verdict.connected);
    }

    /// A socket to a test server, as a program sees one: reads and writes
    /// of at most piece bytes, and a read of nothing once the server has no
    /// more to say. Once the whole request is in, the server answers with
    /// the response, then close_notify unless it hangs up without.
    struct Socket {
        server: Server,
        inbound: Vec<u8>,
        at: usize,
        piece: usize,
        request: usize,
        response: Vec<u8>,
        closes: bool,
        answered: bool,
    }

    impl Socket {
        fn new(script: Script, piece: usize, request: usize, closes: bool) -> Socket {
            let mut response = Vec::new();
            for at in 0..20_000 {
                response.push(u8::try_from(at % 251).unwrap());
            }
            Socket {
                server: Server::new(script),
                inbound: Vec::new(),
                at: 0,
                piece,
                request,
                response,
                closes,
                answered: false,
            }
        }

        fn write(&mut self, bytes: &[u8]) -> usize {
            let count = bytes.len().min(self.piece);
            self.server.receive(&bytes[..count]);
            count
        }

        fn read(&mut self, buffer: &mut [u8]) -> usize {
            if self.at == self.inbound.len() {
                if !self.answered && self.server.received.len() == self.request {
                    for record in self.response.chunks(RECORD_MAX) {
                        self.server.send(APPLICATION, record);
                    }
                    if self.closes {
                        self.server.send(ALERT, &[1, 0]);
                    }
                    self.answered = true;
                }
                self.inbound = self.server.take();
                self.at = 0;
            }
            let count = (self.inbound.len() - self.at)
                .min(self.piece)
                .min(buffer.len());
            buffer[..count].copy_from_slice(&self.inbound[self.at..self.at + count]);
            self.at += count;
            count
        }
    }

    /// The module's loop, as a program writes it: send what is pending, ask
    /// the verifier when the client awaits (x509 against store, standing for
    /// the system's), write the request, read until the socket ends. Every
    /// count is used and every error goes up, the alert sent first; what it
    /// read is in got.
    fn program(
        client: &mut Client<'_>,
        socket: &mut Socket,
        request: &[u8],
        store: &Store,
        got: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let result = converse(client, socket, request, store, got);
        if result.is_err() {
            while !client.pending().is_empty() {
                let count = socket.write(client.pending());
                client.sent(count)?;
            }
        }
        result
    }

    /// program's loop, until it ends or fails.
    fn converse(
        client: &mut Client<'_>,
        socket: &mut Socket,
        mut request: &[u8],
        store: &Store,
        got: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut buffer = [0; 1024];
        let (mut at, mut end) = (0, 0);
        for _ in 0..200_000 {
            while !client.pending().is_empty() {
                let count = socket.write(client.pending());
                client.sent(count)?;
            }
            if client.awaiting() {
                let mut chain = [&[][..]; x509::CHAIN_MAX];
                let count = client.chain(&mut chain).unwrap_or(0);
                let verdict = x509::verify(&chain[..count], store, HOST, TEST_NOW);
                match verdict {
                    Ok(approval) => client.verified(approval)?,
                    Err(_) => client.refused(),
                }
                continue;
            }
            if client.connected() && !request.is_empty() {
                let taken = client.write(request)?.count();
                request = &request[taken..];
                continue;
            }
            if at == end {
                (at, end) = (0, socket.read(&mut buffer));
                if end == 0 {
                    return client.eof();
                }
            }
            at += client.input(&buffer[at..end])?.count();
            got.extend_from_slice(client.read());
            let count = client.read().len();
            client.consume(count);
        }
        panic!("the program does not end");
    }

    /// The loop of the module's doc, over short reads and writes: the
    /// whole response once close_notify ends it, Truncated when the socket
    /// ends without, and the chain's refusal or the server's error as they
    /// are, with their alerts.
    #[test]
    fn a_program() {
        let store = Identity::new(Kind::P256).store();
        let mut request = Vec::new();
        request.resize(40_000, b'q');
        let mut got = Vec::new();
        for piece in [1, 7, 100, 5000, WHOLE] {
            for closes in [true, false] {
                let mut socket = Socket::new(Script::new(Kind::P256), piece, request.len(), closes);
                let mut client =
                    Client::new(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
                got.clear();
                let result = program(&mut client, &mut socket, &request, &store, &mut got);
                let ending = if closes { None } else { Some(Error::Truncated) };
                assert_eq!(result.err(), ending, "{piece}");
                assert_eq!(got, socket.response, "{piece}");
                assert_eq!(socket.server.received, request, "{piece}");
                // A failure sticks, and the end of the socket says it again.
                assert_eq!(client.eof().err(), ending);
            }
        }
        // A chain the verifier refuses: unknown_ca, and nothing read.
        let other = Identity::new(Kind::RsaSha256).store();
        let mut socket = Socket::new(Script::new(Kind::P256), 9, 4, true);
        let mut client = Client::new(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
        got.clear();
        let refused = program(&mut client, &mut socket, b"ping", &other, &mut got);
        assert_eq!(refused, Err(Error::Untrusted));
        assert_eq!((got.len(), socket.server.alerts.as_slice()), (0, &[48][..]));
        // A server whose signature does not verify: decrypt_error.
        let mut forged = Script::new(Kind::P256);
        forged.identity.signer = Identity::new(Kind::P384).signer;
        let mut signed = Socket::new(forged, 9, 4, true);
        let mut checking = Client::new(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
        let wrong = program(&mut checking, &mut signed, b"ping", &store, &mut got);
        assert_eq!(wrong, Err(Error::Signature));
        assert_eq!(signed.server.alerts, [51]);
    }

    /// A client of Verify::Caller with the server's first flight in, at
    /// the Certificate: the server, its bytes and how many the client took.
    fn awaiting() -> (Client<'static>, Server, Vec<u8>, usize) {
        let mut server = Server::new(Script::new(Kind::P256));
        let mut client = Client::new(HOST, &[], Verify::Caller, TEST_NOW, random()).unwrap();
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        let bytes = server.take();
        let mut at = 0;
        while !client.awaiting() {
            at += client.input(&bytes[at..]).unwrap().count();
        }
        (client, server, bytes, at)
    }

    /// The caller's mistakes are loud: a count of more than pending, input
    /// that would take nothing while a verdict is awaited or plaintext is
    /// unread, a verdict with nothing to judge; and an approval of another
    /// leaf or host ends the connection with internal_error.
    #[test]
    fn mistakes_are_loud() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server, bytes, at) = awaiting();
        assert_eq!(client.sent(1), Err(Error::Sent));
        // Forgetting the verdict: input refuses, each time, and waits on.
        for _ in 0..2 {
            assert_eq!(client.input(&bytes[at..]), Err(Error::Awaiting));
            assert!(client.awaiting());
        }
        let (leaf, inter) = (
            test_certificate("test.leaf").unwrap(),
            test_certificate("test.inter").unwrap(),
        );
        let approval = x509::verify(&[&leaf, &inter], &store, HOST, TEST_NOW).unwrap();
        assert_eq!(client.verified(approval), Ok(()));
        assert_eq!(client.input(&bytes[at..]), Ok(Taken(bytes.len() - at)));
        assert!(client.connected());
        let again = x509::verify(&[&leaf, &inter], &store, HOST, TEST_NOW).unwrap();
        assert_eq!(client.verified(again), Err(Error::NotAwaiting));
        server.receive(client.pending());
        client.sent(client.pending().len()).unwrap();
        // Plaintext unread: the next record waits, and input says so.
        server.send(APPLICATION, b"one");
        server.send(APPLICATION, b"two");
        let records = server.take();
        let first = client.input(&records).unwrap().count();
        assert_eq!(client.input(&records[first..]), Err(Error::Unconsumed));
        assert_eq!(client.read(), b"one");
        client.consume(3);
        assert_eq!(
            client.input(&records[first..]),
            Ok(Taken(records.len() - first))
        );
        assert_eq!(client.read(), b"two");
        client.consume(3);
        // The socket ends with no close_notify: Truncated, and it sticks.
        assert_eq!(client.eof(), Err(Error::Truncated));
        assert_eq!(client.write(b"x"), Err(Error::Truncated));
        // Approvals of the leaf for another host, and of another leaf.
        let elsewhere = Approval::system(&leaf, "other.example.test");
        let other = test_certificate("test.leaf384").unwrap();
        for wrong in [elsewhere, Approval::system(&other, HOST)] {
            let (mut misled, mut its_server, flight, taken) = awaiting();
            assert_eq!(misled.verified(wrong), Err(Error::Approval));
            assert!(!misled.awaiting() && !misled.connected());
            assert_eq!(misled.input(&flight[taken..]), Err(Error::Approval));
            its_server.receive(misled.pending());
            assert_eq!(its_server.alerts, [80]);
        }
        // The same host, as written another way, is the same.
        let (mut written, _, _, _) = awaiting();
        let dotted = Approval::system(&leaf, "API.example.test.");
        assert_eq!(written.verified(dotted), Ok(()));
    }

    /// Secrets are not left behind: the marks the caller's sending let go,
    /// and a failure's, hold none, and a KeyUpdate's old secret is gone.
    #[test]
    fn secrets_let_go() {
        let store = Identity::new(Kind::P256).store();
        let (mut client, mut server) = connected(&store);
        client
            .output_keys
            .as_mut()
            .unwrap()
            .key
            .set_sequence_less_safe(KEY_RECORDS_MAX);
        server
            .read
            .as_mut()
            .unwrap()
            .key
            .set_sequence_for_tests(KEY_RECORDS_MAX);
        let mut data = Vec::new();
        data.resize(100, 1);
        assert_eq!(client.write(&data), Ok(Taken(100)));
        // The client's own KeyUpdate before the record: one mark.
        assert_eq!(client.marked, 1);
        assert!(client.marks[0].secret.is_some());
        let ready = client.pending().len();
        server.receive(client.pending());
        client.sent(ready - 1).unwrap();
        assert_eq!(client.marked, 0);
        assert!(client.marks.iter().all(|mark| mark.secret.is_none()));
        client.sent(1).unwrap();
        assert_eq!(server.received, data);
        // A failure with marks queued lets them go.
        let (mut failing, mut its_server) = connected(&store);
        its_server.update(true);
        feed(
            &mut failing,
            &its_server.take(),
            &mut whole(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(failing.marked, 1);
        let result = failing.input(&[99, 3, 3, 0, 0]);
        assert_eq!(result, Err(Error::Unexpected));
        assert_eq!(failing.marked, 0);
        assert!(failing.marks.iter().all(|mark| mark.secret.is_none()));
    }

    /// Random::system draws from the system: two clients' ClientHellos are
    /// as long, and differ in their random, session ID and key shares.
    #[test]
    fn system_randomness() {
        let store = Store::new();
        let a = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, Random::system()).unwrap();
        let b = Client::new(HOST, &[], Verify::Store(&store), TEST_NOW, Random::system()).unwrap();
        assert_eq!(a.pending().len(), b.pending().len());
        assert_eq!(a.pending()[..11], b.pending()[..11]);
        assert_ne!(a.pending()[11..43], b.pending()[11..43]);
        assert_ne!((a.random, a.session), (b.random, b.session));
        assert_ne!(a.public, b.public);
    }
}
// rr: end(tests = yes)

// rr: section(tests = yes)
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
// rr: end(tests = yes)

// rr: section(tests = yes)
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
// rr: end(tests = yes)

// rr: section(tests = yes)
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
// rr: end(tests = yes)
