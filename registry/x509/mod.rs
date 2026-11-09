//! X.509 certificates (RFC 5280) as the web PKI uses them to
//! authenticate a TLS server: a strict DER parser that borrows the
//! certificate's bytes, a store of trust anchors, and verification of
//! a server's chain for a host name at a given time.
//!
//! The profile: keys P-256, P-384, P-521 (uncompressed) and RSA of 2048
//! to 8192 bits, as webpki and Go's TLS take them; signatures ECDSA, RSA
//! PKCS #1 v1.5 and RSA-PSS, each
//! with SHA-256, SHA-384 or SHA-512, RSA-PSS with MGF1 of the same hash
//! and a salt of its length (RFC 4055's parameters in DER, as Go and
//! OpenSSL write them). An anchor's own signature is never checked, so
//! one of any algorithm loads. DER is required everywhere but in three
//! places where real certificates commonly differ and the meaning is
//! the same: an explicit FALSE for a BOOLEAN DEFAULT FALSE, a key usage
//! BIT STRING with trailing zero bits, and GeneralizedTime before 2050.
//!
//! Issuer and subject are compared as raw Name DER, byte for byte. The
//! host is matched against subjectAltName only (the common name is
//! ignored): dNSName with one left-most wildcard label (RFC 6125), and
//! iPAddress for an IP literal. A leaf that is a CA is refused, as
//! Firefox and webpki refuse one. When ExtKeyUsage is present only
//! serverAuth allows a TLS server, on a leaf as on a CA:
//! anyExtendedKeyUsage counts nowhere, as in Firefox and webpki.
//!
//! Name constraints on dNSName and iPAddress are enforced as Go's
//! crypto/x509 does, and on directoryName as Chrome does (RFC 5280
//! 4.2.1.10), against the subject and the directoryNames of every
//! certificate below the CA that sets them; a self-issued intermediate's
//! subject aside. A constraint on a form this does not compare (an
//! rfc822Name, a URI, any other) refuses a certificate below that has a
//! name of that form, as webpki does, critical or not; for rfc822Name,
//! a subject's emailAddress counts when there is no subjectAltName, as
//! in Chrome. Mozilla's constraints imposed on a CA's name (a store's
//! "# name-constraints:" lines) hold as its own do.
//!
//! An anchor is trusted by being in the store: any certificate in the
//! profile loads. It issues when it is a CA or a v1 certificate, which
//! has no basicConstraints to say so, as in Firefox; any anchor, a
//! self-signed server certificate among them, also verifies as the leaf
//! itself, as in Go and Firefox.
//!
//! verify's yes is an Approval, SHA-256 of the leaf and of the host,
//! with private fields: only verify makes one, and the trust component
//! when the system's verifier said yes, so tls takes no verdict a
//! program made up, nor one for another leaf or host. Leaf::approved
//! gives the approved leaf's key for CertificateVerify. A Policy is
//! distrust without trust (roots::policy): revocations, distrust dates
//! and imposed constraints that Store::add_policy lays over anchors and
//! screen over a path the system built, leaf first; it is no Store, so
//! no verify trusts its anchors. Loading an anchor says why it failed.

use crate::base::digest::Digest;
use crate::base::ecdsa;
use crate::base::rsa;
use crate::base::sha256;
use crate::base::sha384;
use alloc::vec::Vec;

/// Why a certificate or a chain was refused.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// Not DER, or not a certificate's structure.
    Malformed,
    /// A key outside the profile: a curve other than P-256, P-384 and
    /// P-521, a compressed point, or RSA outside 2048 to 8192 bits.
    Unsupported,
    /// A critical extension this does not process.
    Critical,
    /// The same extension twice.
    Duplicate,
    /// The time is outside a certificate's validity.
    Expired,
    /// A key usage or extended key usage that does not allow a TLS
    /// server certificate, or a CA's that does not allow issuing it; a
    /// leaf that is a CA.
    Usage,
    /// The leaf does not name the host.
    Host,
    /// An issuer that is not a CA.
    NotCa,
    /// A CA's pathLenConstraint is exceeded.
    PathLength,
    /// A CA's name constraints, or those imposed on its name, refuse a
    /// name below it, or constrain a form of name below it that this
    /// does not compare.
    Constrained,
    /// A signature that does not verify.
    Signature,
    /// No issuer leads to an anchor.
    Untrusted,
    /// The path's anchor is distrusted for leaves issued when this was.
    Distrusted,
    /// A certificate the store holds revoked (Mozilla's OneCRL), and no
    /// path around it.
    Revoked,
    /// More certificates, signatures or name comparisons than allowed.
    TooMany,
    /// A path given to screen that is not leaf first, each certificate
    /// issued by the next (by their names).
    Order,
    /// An approval of another certificate than the one given.
    Approval,
}

/// A public key in the profile, borrowed from its certificate.
#[derive(Clone, Copy)]
pub enum Key<'a> {
    /// The uncompressed point 04 || X || Y.
    P256(&'a [u8]),
    P384(&'a [u8]),
    P521(&'a [u8]),
    /// Big-endian integers without a sign byte.
    Rsa {
        modulus: &'a [u8],
        exponent: &'a [u8],
    },
}

/// A parsed certificate. Nothing in it is authenticated until verify
/// has built a path from it to an anchor.
pub struct Certificate<'a> {
    pub der: &'a [u8],
    /// tbsCertificate with its header: what the signature covers.
    tbs: &'a [u8],
    algorithm: Algorithm,
    signature: &'a [u8],
    /// Name DER with its header.
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// The serial number's INTEGER contents, a leading zero and all.
    serial: &'a [u8],
    /// Unix seconds, both inclusive.
    pub not_before: i64,
    pub not_after: i64,
    /// SubjectPublicKeyInfo with its header, to tell keys apart.
    spki: &'a [u8],
    pub key: Key<'a>,
    ext: Extensions<'a>,
    /// A v1 certificate: no extensions, so nothing says whether it is a
    /// CA; as an anchor it may issue.
    version1: bool,
}

/// A yes to a server's leaf for a host: SHA-256 of the leaf's DER and
/// of the host, as approves compares them (without case, brackets or a
/// dot at the end). Only verify makes one, when x509 verified the chain,
/// and the trust component, when the system's verifier did: a program
/// cannot make one up, nor take one for another leaf or host unseen, as
/// tls::Client::verified compares it with its own.
pub struct Approval {
    leaf: [u8; sha256::DIGEST_BYTES],
    host: [u8; sha256::DIGEST_BYTES],
}

/// The server's certificate once an approval vouches for it: its key
/// checks the handshake's CertificateVerify.
pub struct Leaf<'a> {
    key: Key<'a>,
}

/// Mozilla's distrust without its trust, as roots::policy gives it:
/// revocations, distrust dates of anchors and name constraints imposed
/// on CAs' names. Its anchors are never trusted, so it is a type of its
/// own, which no verify takes in place of a store: Store::add_policy
/// lays it over anchors, screen over a path another verifier built.
pub struct Policy {
    store: Store,
}

/// Trust anchors. It owns their DER, and where each subject is in it,
/// to find the candidates for an issuer without parsing every anchor.
pub struct Store {
    bytes: Vec<u8>,
    // rr: escape(bound): one for each anchor, whose DER STORE_BYTES_MAX
    // bounds.
    anchors: Vec<Anchor>,
    skipped: usize,
    /// The revoked certificates' digests (revocation_digest), sorted;
    /// add_revoked holds them to REVOKED_MAX.
    revoked: Vec<[u8; 32]>,
    // rr: escape(bound): one for each "# name-constraints:" line kept,
    // whose bytes STORE_BYTES_MAX bounds.
    imposed: Vec<Imposed>,
}

/// Where an anchor's DER and subject are in a store.
struct Anchor {
    der: (usize, usize),
    subject: (usize, usize),
    /// Leaves issued after this time do not chain to it.
    distrust: Option<i64>,
}

/// Name constraints imposed on every CA of a name, as Firefox imposes
/// them (NSS's CERT_GetImposedNameConstraints): where the name's DER and
/// the NameConstraints DER are in a store's bytes.
struct Imposed {
    subject: (usize, usize),
    constraints: (usize, usize),
}

/// The signature algorithms of the profile; Other never verifies.
enum Algorithm {
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    Pkcs1Sha256,
    Pkcs1Sha384,
    Pkcs1Sha512,
    PssSha256,
    PssSha384,
    PssSha512,
    Other,
}

enum Scheme {
    Ecdsa,
    Pkcs1,
    Pss,
}

/// The hash a signature algorithm names, which the message is hashed by.
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// The extensions this processes.
struct Extensions<'a> {
    ca: bool,
    path_length: Option<usize>,
    /// KeyUsage's first sixteen bits, digitalSignature the highest.
    key_usage: Option<u16>,
    /// What ExtKeyUsage, when present, allows of serverAuth.
    server_auth: Option<Purpose>,
    /// SubjectAltName's GeneralNames, without the SEQUENCE header.
    names: Option<&'a [u8]>,
    /// NameConstraints' GeneralSubtrees, without their headers.
    permitted: Option<&'a [u8]>,
    excluded: Option<&'a [u8]>,
    subject_key: Option<&'a [u8]>,
    authority_key: Option<&'a [u8]>,
}

/// Permitted and excluded subtrees of NameConstraints.
type Subtrees<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);

/// What path building reads: the certificates sent, the store and the
/// time.
struct Search<'s, 'c> {
    pool: &'s [Certificate<'c>],
    store: &'s Store,
    now: i64,
}

/// One DER element: its identifier octet, its contents and the whole
/// encoding.
struct Element<'a> {
    id: u8,
    body: &'a [u8],
    whole: &'a [u8],
}

/// Elements one after another, from the front.
struct Reader<'a> {
    rest: &'a [u8],
}

/// An issuer that path building may try.
#[derive(Clone, Copy)]
enum Candidate {
    Anchor(usize),
    Peer(usize),
}

/// A certificate on the path being built, with the issuers to try for
/// it, best first, and the next one.
struct Frame {
    node: usize,
    candidates: Vec<(u8, Candidate)>,
    next: usize,
}

/// What path building spends, against the limits.
struct Budget {
    signatures: usize,
    comparisons: usize,
}

/// Larger than any certificate the web PKI uses.
pub const CERTIFICATE_BYTES_MAX: usize = 64 * 1024;
/// Certificates on a path, the leaf and the anchor included.
pub const DEPTH_MAX: usize = 8;
/// Certificates a peer may send, the leaf included.
pub const CHAIN_MAX: usize = 16;
/// Signatures checked for one chain, as in Go: each candidate costs one,
/// and a peer may send many that share an issuer's name.
const SIGNATURES_MAX: usize = 100;
/// Name constraint comparisons for one chain.
const COMPARISONS_MAX: usize = 100_000;
const EXTENSIONS_MAX: usize = 32;
const STORE_BYTES_MAX: usize = 16 << 20;
/// The most revocations a store holds: OneCRL lists about 2,000.
const REVOKED_MAX: usize = 1 << 16;

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
/// [0] EXPLICIT version and [3] EXPLICIT extensions of TBSCertificate.
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;
/// GeneralName's [1] rfc822Name, [2] dNSName and [7] iPAddress, IMPLICIT,
/// and [4] directoryName, EXPLICIT as Name is a CHOICE.
const RFC822_NAME: u8 = 0x81;
const DNS_NAME: u8 = 0x82;
const DIRECTORY_NAME: u8 = 0xa4;
const IP_ADDRESS: u8 = 0x87;
/// The string types of attribute values Chrome compares without case.
const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const IA5_STRING: u8 = 0x16;
const UNIVERSAL_STRING: u8 = 0x1c;
const BMP_STRING: u8 = 0x1e;
/// The most attributes of one RDN that names are compared by.
const ATTRIBUTES_MAX: usize = 16;
/// AuthorityKeyIdentifier's [0] keyIdentifier.
const KEY_ID: u8 = 0x80;
/// NameConstraints' [0] permittedSubtrees and [1] excludedSubtrees.
const PERMITTED: u8 = 0xa0;
const EXCLUDED: u8 = 0xa1;

/// KeyUsage bits as Extensions keeps them.
const DIGITAL_SIGNATURE: u16 = 0x8000;
const KEY_CERT_SIGN: u16 = 0x0400;

const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
/// RSASSA-PSS-params: the hash, MGF1 with the same hash, a salt of the
/// hash's length and the default trailer.
const PSS_SHA256: &[u8] = &[
    0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
];
const PSS_SHA384: &[u8] = &[
    0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x02, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0xa2, 0x03, 0x02, 0x01, 0x30,
];
const PSS_SHA512: &[u8] = &[
    0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x03, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0xa2, 0x03, 0x02, 0x01, 0x40,
];
const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// PKCS #9's emailAddress, of a Name.
const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];

const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";
const DISTRUST_AFTER: &[u8] = b"# distrust-after: ";
const NAME_CONSTRAINTS_LINE: &[u8] = b"# name-constraints: ";

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn end(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    /// The next element, in DER's one encoding: a low-tag identifier, a
    /// definite length in the fewest bytes, and contents that fit.
    fn element(&mut self) -> Result<Element<'a>, Error> {
        let input = self.rest;
        let Some(([id, first], after)) = input.split_first_chunk::<2>() else {
            return Err(Error::Malformed);
        };
        if id & 0x1f == 0x1f {
            return Err(Error::Malformed);
        }
        let (header, length) = if *first < 0x80 {
            (2, usize::from(*first))
        } else {
            // Up to three bytes of length: 16 MiB, past any certificate.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 3 {
                return Err(Error::Malformed);
            }
            let bytes = after.get(..count).ok_or(Error::Malformed)?;
            if bytes.first() == Some(&0) {
                return Err(Error::Malformed);
            }
            let length = bytes
                .iter()
                .fold(0, |length, byte| (length << 8) | usize::from(*byte));
            if length < 0x80 {
                return Err(Error::Malformed);
            }
            (2 + count, length)
        };
        let end = header.checked_add(length).ok_or(Error::Malformed)?;
        let (whole, rest) = input.split_at_checked(end).ok_or(Error::Malformed)?;
        let body = whole.get(header..).ok_or(Error::Malformed)?;
        self.rest = rest;
        Ok(Element {
            id: *id,
            body,
            whole,
        })
    }

    fn expect(&mut self, id: u8) -> Result<Element<'a>, Error> {
        let element = self.element()?;
        if element.id == id {
            Ok(element)
        } else {
            Err(Error::Malformed)
        }
    }

    fn take(&mut self, id: u8) -> Result<&'a [u8], Error> {
        Ok(self.expect(id)?.body)
    }

    fn optional(&mut self, id: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.peek() == Some(id) {
            self.take(id).map(Some)
        } else {
            Ok(None)
        }
    }

    /// An OBJECT IDENTIFIER's contents: subidentifiers in the fewest
    /// base-128 digits, the last complete.
    fn oid(&mut self) -> Result<&'a [u8], Error> {
        let body = self.take(OID)?;
        let mut start = true;
        for byte in body {
            if start && *byte == 0x80 {
                return Err(Error::Malformed);
            }
            start = *byte < 0x80;
        }
        if start && !body.is_empty() {
            Ok(body)
        } else {
            Err(Error::Malformed)
        }
    }

    /// The contents of a SEQUENCE that must fill the rest.
    fn only_sequence(&mut self) -> Result<&'a [u8], Error> {
        let body = self.take(SEQUENCE)?;
        self.end()?;
        Ok(body)
    }
}

/// BOOLEAN's contents.
fn boolean(body: &[u8]) -> Result<bool, Error> {
    match body {
        [0] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Error::Malformed),
    }
}

/// A non-negative INTEGER without its sign byte; zero is [0].
fn unsigned(body: &[u8]) -> Result<&[u8], Error> {
    match body {
        [] => Err(Error::Malformed),
        [first, ..] if *first >= 0x80 => Err(Error::Malformed),
        [0, second, ..] if *second < 0x80 => Err(Error::Malformed),
        [0, rest @ ..] if !rest.is_empty() => Ok(rest),
        [..] => Ok(body),
    }
}

/// A non-negative INTEGER that fits a usize.
fn small(body: &[u8]) -> Result<usize, Error> {
    unsigned(body)?.iter().try_fold(0_usize, |value, byte| {
        value
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(Error::Malformed)
    })
}

/// A BIT STRING of whole bytes, as keys and signatures are.
fn whole_bytes(body: &[u8]) -> Result<&[u8], Error> {
    match body.split_first() {
        Some((0, bytes)) => Ok(bytes),
        _ => Err(Error::Malformed),
    }
}

/// The certificate in der, checked against the profile but not
/// authenticated.
pub fn parse(der: &[u8]) -> Result<Certificate<'_>, Error> {
    if der.len() > CERTIFICATE_BYTES_MAX {
        return Err(Error::TooMany);
    }
    let mut outer = Reader::new(Reader::new(der).only_sequence()?);
    let tbs = outer.expect(SEQUENCE)?;
    let algorithm_id = outer.expect(SEQUENCE)?;
    let signature = whole_bytes(outer.take(BIT_STRING)?)?;
    outer.end()?;
    let mut fields = Reader::new(tbs.body);
    // Absent is v1, which has no extensions; DER leaves out the default,
    // and v2 added only the unique identifiers RFC 5280 says to omit.
    let v3 = match fields.optional(VERSION)? {
        None => false,
        Some(version) => {
            let mut version = Reader::new(version);
            if small(version.take(INTEGER)?)? != 2 {
                return Err(Error::Malformed);
            }
            version.end()?;
            true
        }
    };
    // At most 20 bytes (RFC 5280 4.1.2.2), and not negative.
    let serial = fields.take(INTEGER)?;
    if unsigned(serial)?.len() > 20 {
        return Err(Error::Malformed);
    }
    if fields.expect(SEQUENCE)?.whole != algorithm_id.whole {
        return Err(Error::Malformed);
    }
    let algorithm = algorithm(algorithm_id.body)?;
    let issuer = name(&mut fields)?;
    let (not_before, not_after) = validity(fields.take(SEQUENCE)?)?;
    let subject = name(&mut fields)?;
    let spki = fields.expect(SEQUENCE)?;
    let key = public_key(spki.body)?;
    let ext = match fields.optional(EXTENSIONS)? {
        None => Extensions::NONE,
        Some(body) if v3 => extensions(Reader::new(body).only_sequence()?)?,
        Some(_) => return Err(Error::Malformed),
    };
    fields.end()?;
    // Every certificate has an issuer; one without a subject names
    // itself in subjectAltName (4.1.2.6).
    if issuer.len() == 2 || (subject.len() == 2 && ext.names.is_none()) {
        return Err(Error::Malformed);
    }
    Ok(Certificate {
        der,
        tbs: tbs.whole,
        algorithm,
        signature,
        issuer,
        subject,
        serial,
        not_before,
        not_after,
        spki: spki.whole,
        key,
        ext,
        version1: !v3,
    })
}

/// AlgorithmIdentifier's contents, of a signature.
fn algorithm(body: &[u8]) -> Result<Algorithm, Error> {
    let mut fields = Reader::new(body);
    let oid = fields.oid()?;
    let parameters = fields.rest;
    match (oid, parameters) {
        (ECDSA_SHA256, []) => Ok(Algorithm::EcdsaSha256),
        (ECDSA_SHA384, []) => Ok(Algorithm::EcdsaSha384),
        (ECDSA_SHA512, []) => Ok(Algorithm::EcdsaSha512),
        // NULL, or absent as some encoders write it (RFC 4055 5).
        (RSA_SHA256, [] | [NULL, 0]) => Ok(Algorithm::Pkcs1Sha256),
        (RSA_SHA384, [] | [NULL, 0]) => Ok(Algorithm::Pkcs1Sha384),
        (RSA_SHA512, [] | [NULL, 0]) => Ok(Algorithm::Pkcs1Sha512),
        (RSA_PSS, PSS_SHA256) => Ok(Algorithm::PssSha256),
        (RSA_PSS, PSS_SHA384) => Ok(Algorithm::PssSha384),
        (RSA_PSS, PSS_SHA512) => Ok(Algorithm::PssSha512),
        (ECDSA_SHA256 | ECDSA_SHA384 | ECDSA_SHA512 | RSA_SHA256 | RSA_SHA384 | RSA_SHA512, _) => {
            Err(Error::Malformed)
        }
        _ => Ok(Algorithm::Other),
    }
}

impl Algorithm {
    fn scheme(&self) -> Option<(Scheme, Hash)> {
        match self {
            Algorithm::EcdsaSha256 => Some((Scheme::Ecdsa, Hash::Sha256)),
            Algorithm::EcdsaSha384 => Some((Scheme::Ecdsa, Hash::Sha384)),
            Algorithm::EcdsaSha512 => Some((Scheme::Ecdsa, Hash::Sha512)),
            Algorithm::Pkcs1Sha256 => Some((Scheme::Pkcs1, Hash::Sha256)),
            Algorithm::Pkcs1Sha384 => Some((Scheme::Pkcs1, Hash::Sha384)),
            Algorithm::Pkcs1Sha512 => Some((Scheme::Pkcs1, Hash::Sha512)),
            Algorithm::PssSha256 => Some((Scheme::Pss, Hash::Sha256)),
            Algorithm::PssSha384 => Some((Scheme::Pss, Hash::Sha384)),
            Algorithm::PssSha512 => Some((Scheme::Pss, Hash::Sha512)),
            Algorithm::Other => None,
        }
    }
}

/// The next field, a Name: SEQUENCE OF SET OF AttributeTypeAndValue,
/// whole, as issuers and subjects are compared.
fn name<'a>(fields: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let element = fields.expect(SEQUENCE)?;
    let mut names = Reader::new(element.body);
    while !names.is_empty() {
        let mut set = Reader::new(names.take(SET)?);
        if set.is_empty() {
            return Err(Error::Malformed);
        }
        while !set.is_empty() {
            let mut pair = Reader::new(set.take(SEQUENCE)?);
            pair.oid()?;
            pair.element()?;
            pair.end()?;
        }
    }
    Ok(element.whole)
}

/// Validity's contents: notBefore and notAfter in Unix seconds.
fn validity(body: &[u8]) -> Result<(i64, i64), Error> {
    let mut times = Reader::new(body);
    let not_before = time(&times.element()?)?;
    let not_after = time(&times.element()?)?;
    times.end()?;
    Ok((not_before, not_after))
}

/// UTCTime YYMMDDHHMMSSZ, its years 1950 to 2049, or GeneralizedTime
/// YYYYMMDDHHMMSSZ (RFC 5280 4.1.2.5): UTC, seconds and no fraction.
fn time(element: &Element<'_>) -> Result<i64, Error> {
    let Some((b'Z', digits)) = element.body.split_last() else {
        return Err(Error::Malformed);
    };
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::Malformed);
    }
    let mut pairs = [0_i64; 7];
    for ([tens, ones], value) in digits.as_chunks::<2>().0.iter().zip(pairs.iter_mut()) {
        *value = i64::from(tens - b'0') * 10 + i64::from(ones - b'0');
    }
    let [p0, p1, p2, p3, p4, p5, p6] = pairs;
    let (year, month, day, hour, minute, second) = match (element.id, digits.len()) {
        (UTC_TIME, 12) => {
            let century = if p0 < 50 { 2000 } else { 1900 };
            (century + p0, p1, p2, p3, p4, p5)
        }
        (GENERALIZED_TIME, 14) => (p0 * 100 + p1, p2, p3, p4, p5, p6),
        _ => return Err(Error::Malformed),
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => return Err(Error::Malformed),
    };
    if year == 0 || !(1..=days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return Err(Error::Malformed);
    }
    Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar
/// from year 1 (H. Hinnant's days_from_civil), with years from March so
/// that a leap day ends one.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    era * 146_097 + of_era_days - 719_468
}

/// SubjectPublicKeyInfo's contents.
fn public_key(body: &[u8]) -> Result<Key<'_>, Error> {
    let mut fields = Reader::new(body);
    let mut algorithm = Reader::new(fields.take(SEQUENCE)?);
    let key = whole_bytes(fields.take(BIT_STRING)?)?;
    fields.end()?;
    match algorithm.oid()? {
        EC_PUBLIC_KEY => {
            let curve = algorithm.oid()?;
            algorithm.end()?;
            match (curve, key.len(), key.first()) {
                (P256, 65, Some(4)) => Ok(Key::P256(key)),
                (P384, 97, Some(4)) => Ok(Key::P384(key)),
                (P521, 133, Some(4)) => Ok(Key::P521(key)),
                _ => Err(Error::Unsupported),
            }
        }
        RSA_ENCRYPTION => {
            // NULL parameters (RFC 3279 2.3.1).
            if !algorithm.take(NULL)?.is_empty() {
                return Err(Error::Malformed);
            }
            algorithm.end()?;
            let mut numbers = Reader::new(Reader::new(key).only_sequence()?);
            let modulus = unsigned(numbers.take(INTEGER)?)?;
            let exponent = unsigned(numbers.take(INTEGER)?)?;
            numbers.end()?;
            // rsa takes 2048 to 8192 bits and exponents of 33 bits at most.
            let fits = match modulus.len() {
                256 => modulus.first().is_some_and(|top| *top >= 0x80),
                257..=1024 => true,
                _ => false,
            };
            if fits && exponent.len() <= 5 {
                Ok(Key::Rsa { modulus, exponent })
            } else {
                Err(Error::Unsupported)
            }
        }
        _ => Err(Error::Unsupported),
    }
}

impl Extensions<'_> {
    const NONE: Extensions<'static> = Extensions {
        ca: false,
        path_length: None,
        key_usage: None,
        server_auth: None,
        names: None,
        permitted: None,
        excluded: None,
        subject_key: None,
        authority_key: None,
    };
}

/// Extensions' contents: each once, none unknown that is critical.
fn extensions(body: &[u8]) -> Result<Extensions<'_>, Error> {
    let mut list = Reader::new(body);
    let mut out = Extensions::NONE;
    let mut seen: [&[u8]; EXTENSIONS_MAX] = [&[]; EXTENSIONS_MAX];
    let mut count = 0;
    if list.is_empty() {
        return Err(Error::Malformed);
    }
    while !list.is_empty() {
        let mut extension = Reader::new(list.take(SEQUENCE)?);
        let id = extension.oid()?;
        let earlier = seen.get(..count).ok_or(Error::TooMany)?;
        if earlier.contains(&id) {
            return Err(Error::Duplicate);
        }
        *seen.get_mut(count).ok_or(Error::TooMany)? = id;
        count += 1;
        let critical = match extension.optional(BOOLEAN)? {
            Some(flag) => boolean(flag)?,
            None => false,
        };
        let value = extension.take(OCTET_STRING)?;
        extension.end()?;
        let mut value = Reader::new(value);
        match id {
            BASIC_CONSTRAINTS => (out.ca, out.path_length) = basic_constraints(&mut value)?,
            KEY_USAGE => out.key_usage = Some(key_usage(value.take(BIT_STRING)?)?),
            EXTENDED_KEY_USAGE => out.server_auth = Some(server_auth(value.take(SEQUENCE)?)?),
            SUBJECT_ALT_NAME => out.names = Some(general_names(value.take(SEQUENCE)?)?),
            NAME_CONSTRAINTS => {
                (out.permitted, out.excluded) = name_constraints(value.take(SEQUENCE)?)?;
            }
            SUBJECT_KEY_ID => out.subject_key = Some(value.take(OCTET_STRING)?),
            AUTHORITY_KEY_ID => {
                let mut fields = Reader::new(value.take(SEQUENCE)?);
                out.authority_key = fields.optional(KEY_ID)?;
                // authorityCertIssuer and authorityCertSerialNumber.
                fields.optional(0xa1)?;
                fields.optional(0x82)?;
                fields.end()?;
            }
            _ if critical => return Err(Error::Critical),
            // Unknown and not critical: its value need not be DER.
            _ => continue,
        }
        value.end()?;
    }
    Ok(out)
}

/// BasicConstraints: cA, and pathLenConstraint, which only a CA has.
fn basic_constraints(value: &mut Reader<'_>) -> Result<(bool, Option<usize>), Error> {
    let mut fields = Reader::new(value.take(SEQUENCE)?);
    let ca = match fields.optional(BOOLEAN)? {
        Some(flag) => boolean(flag)?,
        None => false,
    };
    let path_length = match fields.optional(INTEGER)? {
        Some(number) if ca => Some(small(number)?),
        Some(_) => return Err(Error::Malformed),
        None => None,
    };
    fields.end()?;
    Ok((ca, path_length))
}

/// KeyUsage's BIT STRING: one bit set at least, unused bits zero.
fn key_usage(body: &[u8]) -> Result<u16, Error> {
    let (first, second, last) = match body {
        [unused, first] if *unused < 8 => (*first, 0, *first & ((1 << unused) - 1)),
        [unused, first, second] if *unused < 8 => (*first, *second, *second & ((1 << unused) - 1)),
        _ => return Err(Error::Malformed),
    };
    let bits = (u16::from(first) << 8) | u16::from(second);
    if bits == 0 || last != 0 {
        return Err(Error::Malformed);
    }
    Ok(bits)
}

/// What ExtKeyUsage says of serverAuth.
#[derive(Clone, Copy, PartialEq)]
enum Purpose {
    /// It names serverAuth.
    Server,
    /// It does not. anyExtendedKeyUsage is no serverAuth, on a leaf or
    /// a CA, as Firefox (pkixcheck.cpp's MatchEKU) and webpki (its
    /// ExtendedKeyUsage::validate) have it, and the CA/Browser Forum's
    /// baseline requirements forbid it in a TLS server certificate.
    Other,
}

/// ExtKeyUsageSyntax: what it allows of serverAuth.
fn server_auth(body: &[u8]) -> Result<Purpose, Error> {
    let mut purposes = Reader::new(body);
    if purposes.is_empty() {
        return Err(Error::Malformed);
    }
    let mut allows = Purpose::Other;
    while !purposes.is_empty() {
        if purposes.oid()? == SERVER_AUTH {
            allows = Purpose::Server;
        }
    }
    Ok(allows)
}

/// GeneralNames, checked for the forms the host is matched against:
/// dNSName in printable ASCII, iPAddress of 4 or 16 bytes.
fn general_names(body: &[u8]) -> Result<&[u8], Error> {
    let mut names = Reader::new(body);
    if names.is_empty() {
        return Err(Error::Malformed);
    }
    while !names.is_empty() {
        let name = names.element()?;
        let valid = match name.id {
            DNS_NAME => name.body.iter().all(|byte| (0x21..0x7f).contains(byte)),
            IP_ADDRESS => matches!(name.body.len(), 4 | 16),
            // otherName, rfc822Name, x400Address, directoryName,
            // ediPartyName, uniformResourceIdentifier, registeredID.
            0xa0 | 0x81 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x88 => true,
            _ => false,
        };
        if !valid {
            return Err(Error::Malformed);
        }
    }
    Ok(body)
}

/// NameConstraints: permitted and excluded GeneralSubtrees, one at
/// least. A subtree has only its base: minimum and maximum are absent
/// in RFC 5280's profile. A base of a form this does not compare is
/// kept: it refuses names of its form below (within).
fn name_constraints(body: &[u8]) -> Result<Subtrees<'_>, Error> {
    let mut fields = Reader::new(body);
    let permitted = fields.optional(PERMITTED)?;
    let excluded = fields.optional(EXCLUDED)?;
    fields.end()?;
    if permitted.is_none() && excluded.is_none() {
        return Err(Error::Malformed);
    }
    for subtrees in [permitted, excluded].into_iter().flatten() {
        let mut list = Reader::new(subtrees);
        if list.is_empty() {
            return Err(Error::Malformed);
        }
        while !list.is_empty() {
            let mut subtree = Reader::new(list.take(SEQUENCE)?);
            let base = subtree.element()?;
            subtree.end()?;
            let valid = match base.id {
                DNS_NAME => base.body.iter().all(|byte| (0x21..0x7f).contains(byte)),
                IP_ADDRESS => matches!(base.body.len(), 8 | 32) && prefix_mask(base.body),
                DIRECTORY_NAME => {
                    let mut inner = Reader::new(base.body);
                    name(&mut inner).is_ok() && inner.is_empty()
                }
                _ => true,
            };
            if !valid {
                return Err(Error::Malformed);
            }
        }
    }
    Ok((permitted, excluded))
}

/// Whether the second half of an address and mask is a prefix mask:
/// ones, then zeros.
fn prefix_mask(constraint: &[u8]) -> bool {
    let mask = constraint.get(constraint.len() / 2..).unwrap_or_default();
    let mut ended = false;
    for byte in mask {
        if byte.leading_ones() + byte.trailing_zeros() != 8 || (ended && *byte != 0) {
            return false;
        }
        ended = *byte != 0xff;
    }
    true
}

impl Certificate<'_> {
    fn current(&self, now: i64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    fn self_issued(&self) -> bool {
        self.issuer == self.subject
    }

    /// Whether the key may sign a TLS handshake (CertificateVerify): no
    /// keyUsage, or one with digitalSignature, as BoringSSL requires of
    /// a TLS 1.3 server's certificate whoever verified it (RFC 5280
    /// 4.2.1.3; ssl/tls13_both.cc).
    fn signs_handshake(&self) -> bool {
        self.ext
            .key_usage
            .is_none_or(|bits| bits & DIGITAL_SIGNATURE != 0)
    }

    /// Whether key signed this certificate.
    fn signed_by(&self, key: &Key<'_>) -> bool {
        match self.algorithm.scheme() {
            Some((scheme, hash)) => signed(key, &scheme, &hash, self.tbs, self.signature),
            None => false,
        }
    }
}

/// Whether signature, made by scheme with hash, signs message under key.
fn signed(key: &Key<'_>, scheme: &Scheme, hash: &Hash, message: &[u8], signature: &[u8]) -> bool {
    let check = |digest: &Digest<'_>| match (scheme, key) {
        (Scheme::Ecdsa, Key::P256(point)) => {
            ecdsa::verify(&ecdsa::Curve::P256, point, digest, signature).is_ok()
        }
        (Scheme::Ecdsa, Key::P384(point)) => {
            ecdsa::verify(&ecdsa::Curve::P384, point, digest, signature).is_ok()
        }
        (Scheme::Ecdsa, Key::P521(point)) => {
            ecdsa::verify(&ecdsa::Curve::P521, point, digest, signature).is_ok()
        }
        (Scheme::Pkcs1, Key::Rsa { modulus, exponent }) => {
            rsa::verify_pkcs1(modulus, exponent, digest, signature).is_ok()
        }
        (Scheme::Pss, Key::Rsa { modulus, exponent }) => {
            rsa::verify_pss(modulus, exponent, digest, signature).is_ok()
        }
        (Scheme::Ecdsa, Key::Rsa { .. })
        | (Scheme::Pkcs1 | Scheme::Pss, Key::P256(_) | Key::P384(_) | Key::P521(_)) => false,
    };
    match hash {
        Hash::Sha256 => check(&Digest::Sha256(&sha256::digest(message))),
        Hash::Sha384 => check(&Digest::Sha384(&sha384::digest384(message))),
        Hash::Sha512 => check(&Digest::Sha512(&sha384::digest512(message))),
    }
}

impl Approval {
    fn new(leaf: &[u8], host: &str) -> Approval {
        Approval {
            leaf: sha256::digest(leaf),
            host: host_digest(host),
        }
    }

    /// The system's verifier approved leaf (DER) for host: for the trust
    /// component, which asked it. Seen by the components of base alone,
    /// not by the program.
    pub(in crate::base) fn system(leaf: &[u8], host: &str) -> Approval {
        Approval::new(leaf, host)
    }

    /// Whether this approves leaf (DER) for host.
    #[must_use]
    pub fn approves(&self, leaf: &[u8], host: &str) -> bool {
        same_digest(&sha256::digest(leaf), &self.leaf)
            && same_digest(&host_digest(host), &self.host)
    }
}

/// Whether two digests are equal, in time that does not depend on where
/// they differ.
fn same_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    core::hint::black_box(a.iter().zip(b).fold(0, |differ, (x, y)| differ | (x ^ y))) == 0
}

/// SHA-256 of host as approvals compare it: an IPv6 literal without its
/// brackets, a name without the dot after it, letters in lower case.
fn host_digest(host: &str) -> [u8; 32] {
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    let bare = bare.strip_suffix('.').unwrap_or(bare);
    let mut hash = sha256::Sha256::new();
    for chunk in bare.as_bytes().chunks(64) {
        let mut lower = [0; 64];
        for (out, byte) in lower.iter_mut().zip(chunk) {
            *out = byte.to_ascii_lowercase();
        }
        hash.update(lower.get(..chunk.len()).unwrap_or_default());
    }
    hash.finish()
}

impl<'a> Leaf<'a> {
    /// The leaf in der, which approval approved: its key, once it is in
    /// the profile and allowed to sign a handshake, as BoringSSL has it of
    /// a TLS 1.3 server's certificate whoever verified it
    /// (tls13_both.cc). Error::Approval when approval is another leaf's.
    pub fn approved(der: &'a [u8], approval: &Approval) -> Result<Leaf<'a>, Error> {
        if !same_digest(&sha256::digest(der), &approval.leaf) {
            return Err(Error::Approval);
        }
        let certificate = parse(der)?;
        if !certificate.signs_handshake() {
            return Err(Error::Usage);
        }
        Ok(Leaf {
            key: certificate.key,
        })
    }

    /// Checks that signature is the server's CertificateVerify of
    /// message, the TLS 1.3 content it signs (RFC 9846 4.5.2), under
    /// scheme: ecdsa_secp256r1_sha256, _secp384r1_sha384 or
    /// _secp521r1_sha512, or rsa_pss_rsae_sha256, _sha384 or _sha512. The
    /// scheme's curve must be the key's: another scheme is
    /// Error::Unsupported, a signature that does not verify
    /// Error::Signature.
    pub fn verify_tls13(&self, scheme: u16, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let (method, hash) = match (scheme, &self.key) {
            (0x0403, Key::P256(_)) => (Scheme::Ecdsa, Hash::Sha256),
            (0x0503, Key::P384(_)) => (Scheme::Ecdsa, Hash::Sha384),
            (0x0603, Key::P521(_)) => (Scheme::Ecdsa, Hash::Sha512),
            (0x0804, Key::Rsa { .. }) => (Scheme::Pss, Hash::Sha256),
            (0x0805, Key::Rsa { .. }) => (Scheme::Pss, Hash::Sha384),
            (0x0806, Key::Rsa { .. }) => (Scheme::Pss, Hash::Sha512),
            _ => return Err(Error::Unsupported),
        };
        if signed(&self.key, &method, &hash, message, signature) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

impl Store {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            anchors: Vec::new(),
            skipped: 0,
            revoked: Vec::new(),
            imposed: Vec::new(),
        }
    }

    /// The revocations held.
    pub fn revocations(&self) -> usize {
        self.revoked.len()
    }

    /// Revokes the certificates of revoked's digests, one per line in
    /// hex, as roots-gen.py writes them from Mozilla's OneCRL; text from
    /// '#' to the line's end is a comment. A certificate revoked is used
    /// nowhere on a path, leaf, intermediate or anchor, as Firefox does
    /// with OneCRL; a path around it may still verify. Returns how many
    /// it added; a line that is not 64 hex digits is skipped.
    pub fn add_revoked(&mut self, text: &[u8]) -> usize {
        let mut added = 0;
        for line in text.split(|byte| *byte == b'\n') {
            let line = line
                .split(|byte| *byte == b'#')
                .next()
                .unwrap_or_default()
                .trim_ascii();
            if line.is_empty() {
                continue;
            }
            match hex_digest(line) {
                Some(digest) if self.revoked.len() < REVOKED_MAX => {
                    self.revoked.push(digest);
                    added += 1;
                }
                Some(_) | None => self.skipped += 1,
            }
        }
        self.revoked.sort_unstable();
        self.revoked.dedup();
        added
    }

    /// Whether certificate is revoked here: by its issuer and serial
    /// number, or by its subject and key.
    fn revokes(&self, certificate: &Certificate<'_>) -> bool {
        self.revokes_names(&Names {
            issuer: certificate.issuer,
            serial: certificate.serial,
            subject: certificate.subject,
            spki: certificate.spki,
        })
    }

    fn revokes_names(&self, names: &Names<'_>) -> bool {
        if self.revoked.is_empty() {
            return false;
        }
        let by_serial = revocation_digest(ISSUER_SERIAL, names.issuer, names.serial);
        let key = sha256::digest(names.spki);
        let by_key = revocation_digest(SUBJECT_KEY, names.subject, &key);
        self.revoked.binary_search(&by_serial).is_ok()
            || self.revoked.binary_search(&by_key).is_ok()
    }

    /// The anchors loaded.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The entries refused: not DER, or outside the profile.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Adds each CERTIFICATE of PEM text, such as a CA bundle; the text
    /// around them is ignored but for two lines before a block, which
    /// roots-gen.py writes from Mozilla's data: "# distrust-after:
    /// YYYY-MM-DDTHH:MM:SSZ", which add_der_distrust_after's time is, and
    /// "# name-constraints: " and the hex of a NameConstraints, which
    /// holds for every CA of the block's subject as its own would.
    /// Returns how many it added.
    ///
    /// A first scan counts the blocks and the bytes they decode to, so
    /// that the store grows once, to the size it needs; then each block
    /// is decoded straight into the store and parsed there.
    pub fn add_pem(&mut self, text: &[u8]) -> usize {
        let (blocks, size) = pem_size(text);
        self.bytes.reserve_exact(size);
        self.anchors.reserve_exact(blocks);
        self.add_blocks(text, false)
    }

    /// The blocks of add_pem's text; with distrust alone, those with a
    /// distrust date or imposed name constraints, as a policy keeps.
    fn add_blocks(&mut self, text: &[u8], distrust_alone: bool) -> usize {
        let mut rest = text;
        let mut added = 0;
        while let Some((before, body, after)) = pem_block(rest) {
            rest = after;
            let start = self.bytes.len();
            // A date or constraints it cannot read leave the anchor out,
            // not trusted fully.
            let (Ok(distrust), Ok(imposed)) = (distrust_after(before), imposed_line(before)) else {
                self.skipped += 1;
                continue;
            };
            if distrust_alone && distrust.is_none() && imposed.is_none() {
                continue;
            }
            if self.bytes.len() >= STORE_BYTES_MAX
                || !base64(body, &mut self.bytes)
                || self.keep(start, distrust).is_err()
            {
                self.bytes.truncate(start);
                self.skipped += 1;
                continue;
            }
            if let Some(hex) = imposed {
                let subject = self.anchors.last().map_or((0, 0), |anchor| anchor.subject);
                if !self.impose(subject, hex) {
                    self.anchors.pop();
                    self.bytes.truncate(start);
                    self.skipped += 1;
                    continue;
                }
            }
            added += 1;
        }
        added
    }

    /// Adds one anchor: a certificate in the profile; else why not,
    /// TooMany when the store or the certificate is over its limit. Each
    /// call grows the store by what it adds; add_ders grows it once for
    /// many.
    pub fn add_der(&mut self, der: &[u8]) -> Result<(), Error> {
        self.bytes.reserve_exact(der.len());
        self.anchors.reserve_exact(1);
        self.append(der, None)
    }

    /// Adds one anchor, as add_der does, that Mozilla distrusts for
    /// certificates issued after a time: a path ending at it fails when
    /// the leaf's notBefore is later than after (Unix seconds), as in
    /// Firefox.
    pub fn add_der_distrust_after(&mut self, der: &[u8], after: i64) -> Result<(), Error> {
        self.bytes.reserve_exact(der.len());
        self.anchors.reserve_exact(1);
        self.append(der, Some(after))
    }

    /// Adds each of ders, as add_der does, growing the store once.
    /// Returns how many it added.
    pub fn add_ders(&mut self, ders: &[&[u8]]) -> usize {
        self.bytes
            .reserve_exact(ders.iter().map(|der| der.len()).sum());
        self.anchors.reserve_exact(ders.len());
        ders.iter()
            .filter(|der| self.append(der, None).is_ok())
            .count()
    }

    fn append(&mut self, der: &[u8], distrust: Option<i64>) -> Result<(), Error> {
        let start = self.bytes.len();
        // A certificate is at most CERTIFICATE_BYTES_MAX past the limit.
        let kept = if self.bytes.len() < STORE_BYTES_MAX && der.len() <= CERTIFICATE_BYTES_MAX {
            self.bytes.extend_from_slice(der);
            self.keep(start, distrust)
        } else {
            Err(Error::TooMany)
        };
        if kept.is_err() {
            self.bytes.truncate(start);
            self.skipped += 1;
        }
        kept
    }

    /// Keeps the bytes from start as an anchor when they are one: a
    /// certificate in the profile. Its subject is found in its DER; any
    /// place with the same bytes will do, as only the bytes are compared.
    fn keep(&mut self, start: usize, distrust: Option<i64>) -> Result<(), Error> {
        let der = self.bytes.get(start..).ok_or(Error::Malformed)?;
        let anchor = parse(der)?;
        let at = find(der, anchor.subject).ok_or(Error::Malformed)?;
        let subject = start + at;
        let (end, length) = (self.bytes.len(), anchor.subject.len());
        self.anchors.push(Anchor {
            der: (start, end),
            subject: (subject, subject + length),
            distrust,
        });
        Ok(())
    }

    /// Anchor index, parsed; it parsed when it was added.
    fn certificate(&self, index: usize) -> Option<Certificate<'_>> {
        let anchor = self.anchors.get(index)?;
        parse(self.bytes.get(anchor.der.0..anchor.der.1)?).ok()
    }

    /// Imposes the NameConstraints in hex on the name at subject in
    /// bytes; whether it was one.
    fn impose(&mut self, subject: (usize, usize), hex: &[u8]) -> bool {
        let start = self.bytes.len();
        let decoded = hex.len().is_multiple_of(2)
            && hex
                .as_chunks::<2>()
                .0
                .iter()
                .all(|pair| hex_byte(*pair).map(|byte| self.bytes.push(byte)).is_some());
        let end = self.bytes.len();
        let valid = decoded
            && self.bytes.get(start..end).is_some_and(|der| {
                Reader::new(der)
                    .only_sequence()
                    .and_then(name_constraints)
                    .is_ok()
            });
        if valid && self.bytes.len() < STORE_BYTES_MAX {
            self.imposed.push(Imposed {
                subject,
                constraints: (start, end),
            });
            true
        } else {
            self.bytes.truncate(start);
            false
        }
    }

    /// The name constraints imposed on CAs named subject, when there are.
    fn imposed_on(&self, subject: &[u8]) -> Option<Subtrees<'_>> {
        let imposed = self.imposed.iter().find(|imposed| {
            self.bytes.get(imposed.subject.0..imposed.subject.1) == Some(subject)
        })?;
        let der = self
            .bytes
            .get(imposed.constraints.0..imposed.constraints.1)?;
        Reader::new(der)
            .only_sequence()
            .and_then(name_constraints)
            .ok()
    }

    /// The anchor whose DER is der, when there is one.
    fn anchor_of(&self, der: &[u8]) -> Option<usize> {
        self.anchors
            .iter()
            .position(|anchor| self.bytes.get(anchor.der.0..anchor.der.1) == Some(der))
    }

    /// Takes on policy's distrust of what this store trusts, as a store
    /// of the system's anchors may from roots::policy, which carries
    /// Mozilla's: its revocations, the constraints it imposes on names,
    /// and the distrust date of each of its anchors for an anchor here
    /// with the same subject and key (the earlier date winning). Returns
    /// how many anchors here took a date.
    pub fn add_policy(&mut self, policy: &Policy) -> usize {
        let policy = &policy.store;
        let room = REVOKED_MAX.saturating_sub(self.revoked.len());
        self.revoked
            .extend(policy.revoked.iter().take(room).copied());
        self.revoked.sort_unstable();
        self.revoked.dedup();
        for imposed in &policy.imposed {
            let (Some(subject), Some(constraints)) = (
                policy.bytes.get(imposed.subject.0..imposed.subject.1),
                policy
                    .bytes
                    .get(imposed.constraints.0..imposed.constraints.1),
            ) else {
                continue;
            };
            if self.bytes.len() >= STORE_BYTES_MAX {
                break;
            }
            let start = self.bytes.len();
            self.bytes.extend_from_slice(subject);
            self.bytes.extend_from_slice(constraints);
            let middle = start + subject.len();
            self.imposed.push(Imposed {
                subject: (start, middle),
                constraints: (middle, self.bytes.len()),
            });
        }
        let mut dated = 0;
        for (index, theirs) in policy.anchors.iter().enumerate() {
            let (Some(after), Some(certificate)) = (theirs.distrust, policy.certificate(index))
            else {
                continue;
            };
            for mine in 0..self.anchors.len() {
                let same = self.certificate(mine).is_some_and(|anchor| {
                    anchor.subject == certificate.subject && anchor.spki == certificate.spki
                });
                if let Some(anchor) = self.anchors.get_mut(mine).filter(|_| same) {
                    anchor.distrust = Some(anchor.distrust.map_or(after, |date| date.min(after)));
                    dated += 1;
                }
            }
        }
        dated
    }
}

impl Policy {
    pub fn new() -> Policy {
        Policy {
            store: Store::new(),
        }
    }

    /// Adds the blocks of PEM text that carry a "# distrust-after:" or a
    /// "# name-constraints:" line, as Store::add_pem reads them; a block
    /// without either means nothing here, and is passed over. Returns how
    /// many it added.
    pub fn add_pem(&mut self, text: &[u8]) -> usize {
        self.store.add_blocks(text, true)
    }

    /// Distrusts the anchor of der's subject and key for certificates
    /// issued after a time, as Store::add_der_distrust_after does.
    pub fn add_der_distrust_after(&mut self, der: &[u8], after: i64) -> Result<(), Error> {
        self.store.add_der_distrust_after(der, after)
    }

    /// Revokes certificates, as Store::add_revoked does.
    pub fn add_revoked(&mut self, text: &[u8]) -> usize {
        self.store.add_revoked(text)
    }

    /// The anchors it distrusts after a date or constrains.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// The entries refused.
    pub fn skipped(&self) -> usize {
        self.store.skipped()
    }

    /// The revocations held.
    pub fn revocations(&self) -> usize {
        self.store.revocations()
    }
}

/// What a certificate's revocation is looked up by.
struct Names<'a> {
    issuer: &'a [u8],
    serial: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
}

/// The names of a certificate in der, read as far as they go, for one
/// that another verifier accepted and parse may not: its key or its
/// extensions outside this profile.
fn names_of(der: &[u8]) -> Option<Names<'_>> {
    let mut outer = Reader::new(Reader::new(der).only_sequence().ok()?);
    let mut fields = Reader::new(outer.take(SEQUENCE).ok()?);
    fields.optional(VERSION).ok()?;
    let serial = fields.take(INTEGER).ok()?;
    fields.take(SEQUENCE).ok()?;
    let issuer = fields.expect(SEQUENCE).ok()?.whole;
    fields.take(SEQUENCE).ok()?;
    let subject = fields.expect(SEQUENCE).ok()?.whole;
    let spki = fields.expect(SEQUENCE).ok()?.whole;
    Some(Names {
        issuer,
        serial,
        subject,
        spki,
    })
}

/// The kinds of a revocation: by issuer and serial number, or by
/// subject and the SHA-256 of the key's SubjectPublicKeyInfo, as OneCRL
/// names a certificate.
const ISSUER_SERIAL: u8 = 1;
const SUBJECT_KEY: u8 = 2;

/// A revocation's digest: SHA-256 of its kind, the name's DER (which
/// says its own length) and the other field.
fn revocation_digest(kind: u8, name: &[u8], other: &[u8]) -> [u8; 32] {
    let mut hash = sha256::Sha256::new();
    hash.update(&[kind]);
    hash.update(name);
    hash.update(other);
    hash.finish()
}

/// 64 hex digits, as 32 bytes.
fn hex_digest(text: &[u8]) -> Option<[u8; 32]> {
    let mut digest = [0u8; 32];
    if text.len() != 64 {
        return None;
    }
    for (byte, pair) in digest.iter_mut().zip(text.as_chunks::<2>().0) {
        *byte = hex_byte(*pair)?;
    }
    Some(digest)
}

/// Two hex digits as a byte.
fn hex_byte([high, low]: [u8; 2]) -> Option<u8> {
    let high = char::from(high).to_digit(16)?;
    let low = char::from(low).to_digit(16)?;
    u8::try_from(high * 16 + low).ok()
}

/// The text before the next BEGIN CERTIFICATE line, the base64 between
/// it and END CERTIFICATE, and the text after.
fn pem_block(text: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let begin = find(text, PEM_BEGIN)?;
    let after = text.get(begin + PEM_BEGIN.len()..)?;
    let end = find(after, PEM_END)?;
    Some((
        text.get(..begin)?,
        after.get(..end)?,
        after.get(end + PEM_END.len()..)?,
    ))
}

/// The time of the last line "# distrust-after: YYYY-MM-DDTHH:MM:SSZ"
/// in text, Ok(None) when there is none, Err when one is not that form.
fn distrust_after(text: &[u8]) -> Result<Option<i64>, Error> {
    let mut found = None;
    for line in text.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(stamp) = line.strip_prefix(DISTRUST_AFTER) else {
            continue;
        };
        let Ok(
            [
                y0,
                y1,
                y2,
                y3,
                b'-',
                m0,
                m1,
                b'-',
                d0,
                d1,
                b'T',
                h0,
                h1,
                b':',
                i0,
                i1,
                b':',
                s0,
                s1,
                b'Z',
            ],
        ) = <&[u8; 20]>::try_from(stamp)
        else {
            return Err(Error::Malformed);
        };
        let digits = [
            *y0, *y1, *y2, *y3, *m0, *m1, *d0, *d1, *h0, *h1, *i0, *i1, *s0, *s1, b'Z',
        ];
        found = Some(time(&Element {
            id: GENERALIZED_TIME,
            body: &digits,
            whole: &digits,
        })?);
    }
    Ok(found)
}

/// The hex after the last line "# name-constraints: " in text, Ok(None)
/// when there is none, Err when one holds anything but hex digits.
fn imposed_line(text: &[u8]) -> Result<Option<&[u8]>, Error> {
    let mut found = None;
    for line in text.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(hex) = line.strip_prefix(NAME_CONSTRAINTS_LINE) {
            if hex.is_empty() || !hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(Error::Malformed);
            }
            found = Some(hex);
        }
    }
    Ok(found)
}

/// The CERTIFICATE blocks of PEM text, and the bytes their base64
/// decodes to: three for every four digits, padding and whitespace
/// aside.
fn pem_size(text: &[u8]) -> (usize, usize) {
    let (mut blocks, mut size, mut rest) = (0, 0, text);
    while let Some((_, body, after)) = pem_block(rest) {
        rest = after;
        let digits = body
            .iter()
            .filter(|byte| byte.is_ascii_alphanumeric() || **byte == b'+' || **byte == b'/')
            .count();
        blocks += 1;
        size += digits * 3 / 4;
    }
    (blocks, size)
}

/// Where needle first is in text: a scan for its first byte, which
/// is rare in what this searches, then a comparison.
fn find(text: &[u8], needle: &[u8]) -> Option<usize> {
    let (first, _) = needle.split_first()?;
    let mut from = 0;
    while let Some(offset) = text.get(from..)?.iter().position(|byte| byte == first) {
        let at = from + offset;
        if text.get(at..at + needle.len())? == needle {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Appends the bytes of base64 text to out; whitespace is skipped, and
/// padding ends it. False on anything else.
fn base64(text: &[u8], out: &mut Vec<u8>) -> bool {
    let mut group = [0_u8; 4];
    let mut filled = 0;
    let mut padded = false;
    for byte in text {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padded = true;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return false,
        };
        let Some(slot) = group.get_mut(filled) else {
            return false;
        };
        if padded {
            return false;
        }
        *slot = value;
        filled += 1;
        if filled == 4 {
            let [a, b, c, d] = group;
            out.extend_from_slice(&[(a << 2) | (b >> 4), (b << 4) | (c >> 2), (c << 6) | d]);
            filled = 0;
        }
    }
    // Six bits of a quartet make no byte; the bits past the last are zero.
    let [a, b, c, _] = group;
    match filled {
        0 => true,
        2 if b & 0x0f == 0 => {
            out.push((a << 2) | (b >> 4));
            true
        }
        3 if c & 0x03 == 0 => {
            out.extend_from_slice(&[(a << 2) | (b >> 4), (b << 4) | (c >> 2)]);
            true
        }
        _ => false,
    }
}

/// Verifies a server's chain, leaf first as TLS sends it, for host at
/// now (Unix seconds): the leaf for a TLS server and the host, then a
/// path through the other certificates, in any order and with any
/// extras, to an anchor of store, unless the leaf is an anchor itself.
/// Returns the approval of the leaf for host, which Leaf::approved takes
/// to check the handshake's signature with the leaf's key.
pub fn verify(chain: &[&[u8]], store: &Store, host: &str, now: i64) -> Result<Approval, Error> {
    if chain.len() > CHAIN_MAX {
        return Err(Error::TooMany);
    }
    let Some((first, rest)) = chain.split_first() else {
        return Err(Error::Malformed);
    };
    let leaf = parse(first)?;
    if !leaf.current(now) {
        return Err(Error::Expired);
    }
    // A CA is no leaf: the baseline requirements' 7.1.2.3, Firefox's
    // CheckBasicConstraints and webpki's check_basic_constraints.
    if leaf.ext.ca || !leaf.signs_handshake() || leaf.ext.server_auth == Some(Purpose::Other) {
        return Err(Error::Usage);
    }
    if !covers(leaf.ext.names, host) {
        return Err(Error::Host);
    }
    if store.revokes(&leaf) {
        return Err(Error::Revoked);
    }
    let found = Approval::new(leaf.der, host);
    // An anchor is trusted as it is, as the leaf too: Go's Verify takes
    // a leaf that its roots hold as the whole chain, as Firefox takes an
    // end entity it trusts as an anchor.
    if store
        .anchor_of(leaf.der)
        .is_some_and(|index| !distrusted(store, index, &leaf))
    {
        return Ok(found);
    }
    let mut pool = Vec::with_capacity(chain.len());
    pool.push(leaf);
    // One that does not parse cannot be on the path: an extra is no error.
    for der in rest {
        if let Ok(certificate) = parse(der) {
            pool.push(certificate);
        }
    }
    path(&Search {
        pool: &pool,
        store,
        now,
    })?;
    Ok(found)
}

/// Searches depth first, without recursion, for a path from the pool's
/// first certificate through the others to an anchor; each step tries
/// anchors before peers, and issuers whose key identifier matches first
/// (as Go does). The first reason a candidate failed is the error when
/// none succeeds.
fn path(search: &Search<'_, '_>) -> Result<(), Error> {
    let (pool, store) = (search.pool, search.store);
    let leaf = pool.first().ok_or(Error::Malformed)?;
    let mut frames = Vec::with_capacity(DEPTH_MAX);
    frames.push(Frame {
        node: 0,
        candidates: candidates(leaf, pool, store, true),
        next: 0,
    });
    let mut budget = Budget {
        signatures: SIGNATURES_MAX,
        comparisons: COMPARISONS_MAX,
    };
    let mut reason = None;
    // Each turn tries one candidate or leaves a certificate whose
    // candidates are spent; frames never exceed DEPTH_MAX - 1.
    while let Some(frame) = frames.last_mut() {
        let child = pool.get(frame.node).ok_or(Error::Malformed)?;
        let Some((_, candidate)) = frame.candidates.get(frame.next).copied() else {
            frames.pop();
            continue;
        };
        frame.next += 1;
        let outcome = match candidate {
            Candidate::Anchor(index) if distrusted(store, index, leaf) => Err(Error::Distrusted),
            Candidate::Anchor(index) => match store.certificate(index) {
                Some(anchor) if store.revokes(&anchor) => Err(Error::Revoked),
                // An anchor issues when it is a CA, or a v1 certificate,
                // which cannot say so, as Firefox's CheckBasicConstraints
                // has it for a trust anchor.
                Some(anchor) => {
                    let ca = anchor.ext.ca || anchor.version1;
                    search.issues(&anchor, ca, child, &frames, &mut budget)
                }
                None => Err(Error::Untrusted),
            },
            Candidate::Peer(index) => {
                let peer = pool.get(index).ok_or(Error::Malformed)?;
                if on_path(peer, pool, &frames) {
                    continue;
                }
                if store.revokes(peer) {
                    Err(Error::Revoked)
                } else {
                    search.issues(peer, peer.ext.ca, child, &frames, &mut budget)
                }
            }
        };
        match (outcome, candidate) {
            (Ok(()), Candidate::Anchor(_)) => return Ok(()),
            (Ok(()), Candidate::Peer(index)) => {
                let peer = pool.get(index).ok_or(Error::Malformed)?;
                // Its own peers make the path the frames, it, one of
                // them and an anchor.
                let deeper = frames.len() + 3 <= DEPTH_MAX;
                frames.push(Frame {
                    node: index,
                    candidates: candidates(peer, pool, store, deeper),
                    next: 0,
                });
            }
            (Err(Error::TooMany), _) => return Err(Error::TooMany),
            (Err(error), _) => {
                reason.get_or_insert(error);
            }
        }
    }
    Err(reason.unwrap_or(Error::Untrusted))
}

/// Whether anchor index distrusts leaf: it was issued after the date.
fn distrusted(store: &Store, index: usize, leaf: &Certificate<'_>) -> bool {
    store
        .anchors
        .get(index)
        .and_then(|anchor| anchor.distrust)
        .is_some_and(|after| leaf.not_before > after)
}

/// The issuers to try for child, best first: anchors, then (when the
/// path may grow) peers, each by how their key identifiers agree.
fn candidates(
    child: &Certificate<'_>,
    pool: &[Certificate<'_>],
    store: &Store,
    peers: bool,
) -> Vec<(u8, Candidate)> {
    let mut found = Vec::new();
    for (index, anchor) in store.anchors.iter().enumerate() {
        if store.bytes.get(anchor.subject.0..anchor.subject.1) != Some(child.issuer) {
            continue;
        }
        if let Some(certificate) = store.certificate(index) {
            found.push((rank(child, &certificate), Candidate::Anchor(index)));
        }
    }
    if peers {
        for (index, peer) in pool.iter().enumerate() {
            if peer.subject == child.issuer {
                found.push((3 + rank(child, peer), Candidate::Peer(index)));
            }
        }
    }
    found.sort_by_key(|(rank, _)| *rank);
    found
}

/// 0 when the identifiers match or neither has one, 1 when one is
/// missing, 2 when they differ.
fn rank(child: &Certificate<'_>, parent: &Certificate<'_>) -> u8 {
    match (child.ext.authority_key, parent.ext.subject_key) {
        (Some(authority), Some(subject)) => {
            if authority == subject {
                0
            } else {
                2
            }
        }
        (None, None) => 0,
        (Some(_), None) | (None, Some(_)) => 1,
    }
}

/// Whether a certificate with peer's subject and key is on the path:
/// another would only go round.
fn on_path(peer: &Certificate<'_>, pool: &[Certificate<'_>], frames: &[Frame]) -> bool {
    frames
        .iter()
        .filter_map(|frame| pool.get(frame.node))
        .any(|below| below.subject == peer.subject && below.spki == peer.spki)
}

impl Search<'_, '_> {
    /// Whether parent may issue child, the top of the path in frames: it
    /// is current, a CA (ca) for TLS servers, its constraints and those
    /// imposed on its name hold for everything below it, and its key
    /// signed child.
    fn issues(
        &self,
        parent: &Certificate<'_>,
        ca: bool,
        child: &Certificate<'_>,
        frames: &[Frame],
        budget: &mut Budget,
    ) -> Result<(), Error> {
        if !parent.current(self.now) {
            return Err(Error::Expired);
        }
        if !ca {
            return Err(Error::NotCa);
        }
        if parent
            .ext
            .key_usage
            .is_some_and(|bits| bits & KEY_CERT_SIGN == 0)
            || parent.ext.server_auth == Some(Purpose::Other)
        {
            return Err(Error::Usage);
        }
        // pathLenConstraint counts the intermediates below, self-issued
        // ones aside (RFC 5280 6.1.4 (l)); the leaf is the first frame.
        if let Some(limit) = parent.ext.path_length {
            let below = frames
                .iter()
                .skip(1)
                .filter_map(|frame| self.pool.get(frame.node))
                .filter(|below| !below.self_issued())
                .count();
            if below > limit {
                return Err(Error::PathLength);
            }
        }
        let own = (parent.ext.permitted, parent.ext.excluded);
        let own =
            Some(own).filter(|(permitted, excluded)| permitted.is_some() || excluded.is_some());
        for subtrees in [own, self.store.imposed_on(parent.subject)]
            .into_iter()
            .flatten()
        {
            let below = frames.iter().filter_map(|frame| self.pool.get(frame.node));
            for (depth, certificate) in below.enumerate() {
                within(&subtrees, certificate, depth == 0, &mut budget.comparisons)?;
            }
        }
        budget.signatures = budget.signatures.checked_sub(1).ok_or(Error::TooMany)?;
        if child.signed_by(&parent.key) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }
}

/// Checks a path that another verifier built, such as the system's,
/// leaf first and its anchor last, against policy, such as
/// roots::policy gives with Mozilla's distrust: a path in another order,
/// each certificate not issued by the next by their names, is
/// Error::Order, as the anchor would be taken from the wrong end and its
/// distrust missed; then a certificate on it that
/// policy revokes, an anchor of policy with the last one's subject and
/// key that distrusts the leaf (issued after its date), or constraints
/// policy imposes on the name of a CA on it that a name below breaks.
/// A certificate outside the profile is looked up by its names alone.
pub fn screen(path: &[&[u8]], policy: &Policy) -> Result<(), Error> {
    let policy = &policy.store;
    if path.len() > CHAIN_MAX {
        return Err(Error::TooMany);
    }
    let leaf = parse(path.first().ok_or(Error::Malformed)?)?;
    let mut child: Option<Names<'_>> = None;
    for der in path {
        let names = names_of(der).ok_or(Error::Malformed)?;
        if child
            .as_ref()
            .is_some_and(|issued| issued.issuer != names.subject)
        {
            return Err(Error::Order);
        }
        if policy.revokes_names(&names) {
            return Err(Error::Revoked);
        }
        child = Some(names);
    }
    let top = path.last().and_then(|der| names_of(der));
    for index in 0..policy.anchors.len() {
        let same = |anchor: Certificate<'_>| {
            top.as_ref()
                .is_some_and(|top| top.subject == anchor.subject && top.spki == anchor.spki)
        };
        if distrusted(policy, index, &leaf) && policy.certificate(index).is_some_and(same) {
            return Err(Error::Distrusted);
        }
    }
    let mut comparisons = COMPARISONS_MAX;
    for (at, der) in path.iter().enumerate().skip(1) {
        let Some(subtrees) = names_of(der).and_then(|names| policy.imposed_on(names.subject))
        else {
            continue;
        };
        for (depth, below) in path.iter().take(at).enumerate() {
            within(&subtrees, &parse(below)?, depth == 0, &mut comparisons)?;
        }
    }
    Ok(())
}

/// Whether certificate's names are inside subtrees, a CA's name
/// constraints: dNSName, iPAddress and directoryName each in no excluded
/// subtree, and in a permitted one when they permit any of its form;
/// a name of another form they constrain refuses it, as webpki has it
/// (check_presented_id_conforms_to_constraints). The subject counts as a
/// directoryName unless it is empty or a self-issued intermediate's
/// (RFC 5280 6.1.3 (b)), and when there is no subjectAltName its
/// emailAddress as an rfc822Name (Chrome's IsPermittedCert, after RFC
/// 5280 4.2.1.10).
fn within(
    subtrees: &Subtrees<'_>,
    certificate: &Certificate<'_>,
    leaf: bool,
    comparisons: &mut usize,
) -> Result<(), Error> {
    let mut list = Reader::new(certificate.ext.names.unwrap_or_default());
    while !list.is_empty() {
        name_within(subtrees, &list.element()?, comparisons)?;
    }
    if certificate.subject.len() > 2 && (leaf || !certificate.self_issued()) {
        let subject = Element {
            id: DIRECTORY_NAME,
            body: certificate.subject,
            whole: certificate.subject,
        };
        name_within(subtrees, &subject, comparisons)?;
    }
    if certificate.ext.names.is_none()
        && constrains(subtrees, RFC822_NAME)
        && has_email(certificate.subject)?
    {
        return Err(Error::Constrained);
    }
    Ok(())
}

/// Whether subtrees constrain names of form id.
fn constrains(subtrees: &Subtrees<'_>, id: u8) -> bool {
    has_form(subtrees.0, id) || has_form(subtrees.1, id)
}

/// Whether one name is inside subtrees, as within says.
fn name_within(
    subtrees: &Subtrees<'_>,
    name: &Element<'_>,
    comparisons: &mut usize,
) -> Result<(), Error> {
    match name.id {
        DNS_NAME | IP_ADDRESS | DIRECTORY_NAME => {}
        _ if constrains(subtrees, name.id) => return Err(Error::Constrained),
        _ => return Ok(()),
    }
    if subtrees_hold(subtrees.1, name, true, comparisons)? {
        return Err(Error::Constrained);
    }
    if has_form(subtrees.0, name.id) && !subtrees_hold(subtrees.0, name, false, comparisons)? {
        return Err(Error::Constrained);
    }
    Ok(())
}

/// Whether a subtree of name's form in subtrees holds name.
fn subtrees_hold(
    subtrees: Option<&[u8]>,
    name: &Element<'_>,
    excluded: bool,
    comparisons: &mut usize,
) -> Result<bool, Error> {
    let mut list = Reader::new(subtrees.unwrap_or_default());
    while !list.is_empty() {
        let base = Reader::new(list.take(SEQUENCE)?).element()?;
        if base.id != name.id {
            continue;
        }
        *comparisons = comparisons.checked_sub(1).ok_or(Error::TooMany)?;
        let holds = match name.id {
            DNS_NAME => domain_within(name.body, base.body, excluded)?,
            IP_ADDRESS => address_within(name.body, base.body),
            _ => directory_within(name.body, base.body)?,
        };
        if holds {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_form(subtrees: Option<&[u8]>, id: u8) -> bool {
    let mut list = Reader::new(subtrees.unwrap_or_default());
    while let Ok(subtree) = list.take(SEQUENCE) {
        if Reader::new(subtree).peek() == Some(id) {
            return true;
        }
    }
    false
}

/// Whether the Name DER name has an emailAddress attribute.
fn has_email(name: &[u8]) -> Result<bool, Error> {
    let mut rdns = Reader::new(Reader::new(name).only_sequence()?);
    while !rdns.is_empty() {
        let mut set = Reader::new(rdns.take(SET)?);
        while !set.is_empty() {
            if Reader::new(set.take(SEQUENCE)?).oid()? == EMAIL_ADDRESS {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Chrome's VerifyNameInSubtree (verify_name_match.cc): whether the
/// Name DER name begins with the RDNs of base, each matching as RFC 5280
/// 7.1 has it. Err when either is not a Name.
fn directory_within(name: &[u8], base: &[u8]) -> Result<bool, Error> {
    let mut names = Reader::new(Reader::new(name).only_sequence()?);
    let mut bases = Reader::new(Reader::new(base).only_sequence()?);
    while !bases.is_empty() {
        let theirs = bases.take(SET)?;
        if names.is_empty() {
            return Ok(false);
        }
        if !rdn_matches(names.take(SET)?, theirs)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether two RDNs match: as many attributes, and each of a matching
/// one of b, which is then used up (Chrome's VerifyRdnMatch).
fn rdn_matches(a: &[u8], b: &[u8]) -> Result<bool, Error> {
    // b's attributes; an empty one is used up, as none is empty.
    let mut theirs: [&[u8]; ATTRIBUTES_MAX] = [&[]; ATTRIBUTES_MAX];
    let mut count = 0;
    let mut list = Reader::new(b);
    while !list.is_empty() {
        *theirs.get_mut(count).ok_or(Error::Constrained)? = list.take(SEQUENCE)?;
        count += 1;
    }
    let mut ours = Reader::new(a);
    let mut matched = 0;
    while !ours.is_empty() {
        let attribute = ours.take(SEQUENCE)?;
        let mut found = None;
        for (slot, other) in theirs.iter().take(count).enumerate() {
            if !other.is_empty() && attribute_matches(attribute, other)? {
                found = Some(slot);
                break;
            }
        }
        let Some(slot) = found.and_then(|slot| theirs.get_mut(slot)) else {
            return Ok(false);
        };
        *slot = &[];
        matched += 1;
    }
    Ok(matched == count)
}

/// Whether two AttributeTypeAndValue contents match: one type, and
/// values that do (Chrome's VerifyValueMatch): strings of the five types
/// Chrome normalizes compared folded, others byte for byte with their
/// tags.
fn attribute_matches(a: &[u8], b: &[u8]) -> Result<bool, Error> {
    let (mut a, mut b) = (Reader::new(a), Reader::new(b));
    if a.oid()? != b.oid()? {
        return Ok(false);
    }
    let (ours, theirs) = (a.element()?, b.element()?);
    let foldable = |id| {
        matches!(
            id,
            PRINTABLE_STRING | UTF8_STRING | IA5_STRING | UNIVERSAL_STRING | BMP_STRING
        )
    };
    if !foldable(ours.id) || !foldable(theirs.id) {
        return Ok(ours.id == theirs.id && ours.body == theirs.body);
    }
    let (mut left, mut right) = (Folded::new(), Folded::new());
    let folded = left.fold(&ours) && right.fold(&theirs);
    Ok(folded && left.text == right.text)
}

/// The characters a string type allows once folded.
#[derive(Clone, Copy)]
enum Charset {
    Printable,
    Ascii,
    Any,
}

/// A string as Chrome's NormalizeDirectoryString leaves it: UTF-8, A to
/// Z folded to a to z, spaces at either end dropped and a run of them
/// one.
struct Folded {
    // rr: escape(bound): at most 1.5 bytes for each byte of the value
    // folded, which a certificate's size bounds.
    text: Vec<u8>,
    /// A space waits for what follows it.
    space: bool,
}

impl Folded {
    fn new() -> Self {
        Self {
            text: Vec::new(),
            space: false,
        }
    }

    /// Folds the string value; false when a character is not of its
    /// type, or the value not of whole characters.
    fn fold(&mut self, value: &Element<'_>) -> bool {
        let body = value.body;
        match value.id {
            PRINTABLE_STRING => body.iter().all(|byte| self.byte(*byte, Charset::Printable)),
            IA5_STRING => body.iter().all(|byte| self.byte(*byte, Charset::Ascii)),
            UTF8_STRING => body.iter().all(|byte| self.byte(*byte, Charset::Any)),
            BMP_STRING => {
                let (units, rest) = body.as_chunks::<2>();
                rest.is_empty()
                    && units
                        .iter()
                        .all(|unit| self.character(u32::from(u16::from_be_bytes(*unit))))
            }
            UNIVERSAL_STRING => {
                let (units, rest) = body.as_chunks::<4>();
                rest.is_empty()
                    && units
                        .iter()
                        .all(|unit| self.character(u32::from_be_bytes(*unit)))
            }
            _ => false,
        }
    }

    fn character(&mut self, code: u32) -> bool {
        let Some(character) = char::from_u32(code) else {
            return false;
        };
        let mut buffer = [0; 4];
        let encoded = character.encode_utf8(&mut buffer);
        encoded.bytes().all(|byte| self.byte(byte, Charset::Any))
    }

    fn byte(&mut self, byte: u8, charset: Charset) -> bool {
        if byte == b' ' {
            self.space = !self.text.is_empty();
            return true;
        }
        if self.space {
            self.text.push(b' ');
            self.space = false;
        }
        let byte = byte.to_ascii_lowercase();
        let allowed = match charset {
            Charset::Printable => {
                byte.is_ascii_lowercase()
                    || (b'\''..=b':').contains(&byte)
                    || byte == b'='
                    || byte == b'?'
            }
            Charset::Ascii => byte.is_ascii(),
            Charset::Any => true,
        };
        self.text.push(byte);
        allowed
    }
}

/// Go's matchDomainConstraint: an empty constraint holds every name, a
/// leading dot only subdomains, and otherwise the domain and those
/// under it, label by label without case. An excluded constraint also
/// holds a wildcard that could stand for a name in it: *.a.b for x.a.b.
fn domain_within(domain: &[u8], constraint: &[u8], excluded: bool) -> Result<bool, Error> {
    if constraint.is_empty() {
        return Ok(true);
    }
    let (subdomains, constraint) = match constraint.strip_prefix(b".") {
        Some(rest) => (true, rest),
        None => (false, constraint),
    };
    let (Some(domain_labels), Some(constraint_labels)) = (labels(domain), labels(constraint))
    else {
        return Err(Error::Constrained);
    };
    let suffix =
        domain_labels > constraint_labels || (domain_labels == constraint_labels && !subdomains);
    if suffix && ends_with_labels(domain, constraint) {
        return Ok(true);
    }
    let Some(wildcard) = domain.strip_prefix(b"*.") else {
        return Ok(false);
    };
    match constraint.iter().position(|byte| *byte == b'.') {
        Some(dot) if excluded && !subdomains => Ok(constraint
            .get(dot + 1..)
            .is_some_and(|rest| rest.eq_ignore_ascii_case(wildcard))),
        _ => Ok(false),
    }
}

/// The labels of a name as Go reads one for constraints: none when it
/// is empty, else each non-empty and printable ASCII; None otherwise.
fn labels(name: &[u8]) -> Option<usize> {
    if name.is_empty() {
        return Some(0);
    }
    let mut count = 0;
    for label in name.split(|byte| *byte == b'.') {
        if label.is_empty() || !label.iter().all(|byte| (0x21..0x7f).contains(byte)) {
            return None;
        }
        count += 1;
    }
    Some(count)
}

/// Whether domain's last labels are constraint's, without case.
fn ends_with_labels(domain: &[u8], constraint: &[u8]) -> bool {
    domain
        .rsplit(|byte| *byte == b'.')
        .zip(constraint.rsplit(|byte| *byte == b'.'))
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Whether address is in the network of constraint, an address and
/// mask of the same family.
fn address_within(address: &[u8], constraint: &[u8]) -> bool {
    let (network, mask) = constraint.split_at(constraint.len() / 2);
    address.len() == network.len()
        && address
            .iter()
            .zip(network.iter().zip(mask))
            .all(|(a, (n, m))| a & m == n & m)
}

/// Whether the certificate (DER) names host, as verify checks its leaf:
/// for a verifier that built the path itself, such as the system's, so
/// that a host means the same on every system.
pub fn names(der: &[u8], host: &str) -> Result<(), Error> {
    if covers(parse(der)?.ext.names, host) {
        Ok(())
    } else {
        Err(Error::Host)
    }
}

/// Whether subjectAltName names host: an IP literal (IPv6 maybe in
/// brackets) by iPAddress, a DNS name by dNSName, with a dot after it or
/// not. The subject's common name never counts (RFC 9525), and a name
/// that ends in a number is no DNS name, as the WHATWG URL standard
/// reads one as an address: 192.0.2.1. is the address.
fn covers(names: Option<&[u8]>, host: &str) -> bool {
    let Some(names) = names else {
        return false;
    };
    let address = match host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        Some(inner) => inner
            .parse::<core::net::Ipv6Addr>()
            .map(core::net::IpAddr::V6),
        // An IPv4 address may end with a dot, as a DNS name may.
        None => host.parse::<core::net::IpAddr>().or_else(|error| {
            host.strip_suffix('.')
                .ok_or(error)?
                .parse::<core::net::Ipv4Addr>()
                .map(core::net::IpAddr::V4)
        }),
    };
    let host = host.as_bytes();
    let host = host.strip_suffix(b".").unwrap_or(host);
    if address.is_err() && (!valid_host(host) || numeric_end(host)) {
        return false;
    }
    let mut list = Reader::new(names);
    while let Ok(name) = list.element() {
        let found = match (&address, name.id) {
            (Ok(core::net::IpAddr::V4(v4)), IP_ADDRESS) => name.body == v4.octets(),
            (Ok(core::net::IpAddr::V6(v6)), IP_ADDRESS) => name.body == v6.octets(),
            (Err(_), DNS_NAME) => host_matches(name.body, host),
            _ => false,
        };
        if found {
            return true;
        }
    }
    false
}

/// A DNS name to look for: labels of letters, digits, hyphens and
/// underscores, 1 to 63 bytes each, 253 in all.
fn valid_host(host: &[u8]) -> bool {
    host.len() <= 253
        && host.split(|byte| *byte == b'.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        })
}

/// Whether a name's last label is a number, decimal or 0x hex.
fn numeric_end(host: &[u8]) -> bool {
    let last = host.rsplit(|byte| *byte == b'.').next().unwrap_or(host);
    let hex = last
        .strip_prefix(b"0x")
        .or_else(|| last.strip_prefix(b"0X"))
        .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit));
    hex || last.iter().all(u8::is_ascii_digit)
}

/// RFC 6125 6.4: the names equal without case, or a pattern's whole
/// left-most label * stands for one of host's, above two labels at
/// least (*.com stands for too much). Partial wildcards match nothing.
fn host_matches(pattern: &[u8], host: &[u8]) -> bool {
    let pattern = pattern.strip_suffix(b".").unwrap_or(pattern);
    let Some(suffix) = pattern.strip_prefix(b"*.") else {
        return !pattern.contains(&b'*') && pattern.eq_ignore_ascii_case(host);
    };
    if suffix.contains(&b'*') || !suffix.contains(&b'.') {
        return false;
    }
    let Some(dot) = host.iter().position(|byte| *byte == b'.') else {
        return false;
    };
    match host.split_at_checked(dot) {
        Some((label, rest)) => {
            !label.is_empty()
                && rest
                    .get(1..)
                    .is_some_and(|rest| rest.eq_ignore_ascii_case(suffix))
        }
        None => false,
    }
}

/// Any bytes as a certificate: parse answers without a panic, and what
/// it accepts matches hosts and its own constraints, and loads as an
/// anchor.
#[cfg(fuzzing)]
pub fn fuzz_parse(input: &[u8]) {
    let Ok(certificate) = parse(input) else {
        return;
    };
    assert!(certificate.tbs.len() < input.len());
    certificate.signed_by(&certificate.key);
    for host in [
        "api.example.test",
        "x.wild.example.test",
        "192.0.2.1",
        "[2001:db8::1]",
    ] {
        covers(certificate.ext.names, host);
    }
    let subtrees = (certificate.ext.permitted, certificate.ext.excluded);
    let mut comparisons = COMPARISONS_MAX;
    let outcome = within(&subtrees, &certificate, true, &mut comparisons);
    assert!(matches!(
        outcome,
        Ok(()) | Err(Error::Constrained | Error::TooMany | Error::Malformed)
    ));
    let mut store = Store::new();
    assert!(store.add_der(input).is_ok());
}

/// Test certificates and the input's as a chain, for paths deeper than
/// mutation alone reaches: the first byte picks which of eight come
/// first, and the rest is certificates each after a two-byte length,
/// then one more. Verify answers without a panic, and a chain it
/// accepts has a leaf that names the host.
#[cfg(fuzzing)]
pub fn fuzz_verify(input: &[u8]) {
    let Some((pick, mut rest)) = input.split_first() else {
        return;
    };
    let mut picked = Vec::new();
    for (bit, name) in [
        "test.leaf",
        "test.inter",
        "test.twin",
        "test.nc",
        "test.ncgood",
        "test.zero",
        "test.below",
        "test.deep",
    ]
    .into_iter()
    .enumerate()
    {
        if (pick >> bit) & 1 == 1 {
            picked.push(test_certificate(name).unwrap());
        }
    }
    let mut chain: Vec<&[u8]> = Vec::new();
    for der in &picked {
        chain.push(der);
    }
    while let Some((length, after)) = rest.split_first_chunk::<2>() {
        let length = usize::from(u16::from_be_bytes(*length));
        let Some((der, after)) = after.split_at_checked(length) else {
            break;
        };
        chain.push(der);
        rest = after;
    }
    chain.push(rest);
    let mut store = Store::new();
    assert!(
        store
            .add_der(&test_certificate("test.root").unwrap())
            .is_ok()
    );
    for host in ["api.example.test", "good.example.test"] {
        if verify(&chain, &store, host, TEST_NOW).is_ok() {
            assert!(parse(chain[0]).is_ok_and(|leaf| covers(leaf.ext.names, host)));
        }
    }
}

/// 2026-11-05 00:00:00 UTC: every certificate of TESTS is current.
#[cfg(any(test, fuzzing))]
pub const TEST_NOW: i64 = 1_793_836_800;

/// x509-tests.pem: real chains and a test PKI, each certificate under
/// a line "# name".
#[cfg(any(test, fuzzing))]
const TESTS: &str = include_str!("x509-tests.pem");

/// The DER of the certificate named name in TESTS.
#[cfg(any(test, fuzzing))]
pub fn test_certificate(name: &str) -> Option<Vec<u8>> {
    let mut rest = TESTS.as_bytes();
    while let Some(at) = find(rest, b"\n# ") {
        rest = rest.get(at + 3..)?;
        let line = rest.split(|byte| *byte == b'\n').next()?;
        if line == name.as_bytes() {
            let (_, body, _) = pem_block(rest)?;
            let mut der = Vec::new();
            return base64(body, &mut der).then_some(der);
        }
    }
    None
}

/// A line of revoked.txt that revokes the certificate in der, by its
/// subject and key, for other components' tests.
#[cfg(test)]
pub fn test_revocation(der: &[u8]) -> Vec<u8> {
    let mut line = Vec::new();
    if let Ok(certificate) = parse(der) {
        let key = sha256::digest(certificate.spki);
        for byte in revocation_digest(SUBJECT_KEY, certificate.subject, &key) {
            for nibble in [byte >> 4, byte & 15] {
                line.extend_from_slice(
                    b"0123456789abcdef"
                        .get(usize::from(nibble)..=usize::from(nibble))
                        .unwrap_or_default(),
                );
            }
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::{
        Error, ISSUER_SERIAL, Leaf, PEM_END, Policy, Reader, SUBJECT_KEY, Store, TEST_NOW as NOW,
        TESTS, address_within, attribute_matches, directory_within, domain_within, extensions,
        find, host_matches, key_usage, parse, revocation_digest, screen, test_certificate, time,
        unsigned, verify,
    };
    use crate::base::sha256;
    use alloc::vec::Vec;
    use test::Bencher;

    /// The test PKI's notAfter, 2036-01-01 00:00:00 UTC.
    const LAST: i64 = 2_082_758_400;

    fn der(name: &str) -> Vec<u8> {
        test_certificate(name).unwrap()
    }

    /// The anchors the real chains end at, and the test PKI's roots.
    fn anchors() -> Store {
        let mut store = Store::new();
        for name in [
            "anchor.sectigo-e46",
            "anchor.gts-r4",
            "anchor.isrg-x2",
            "anchor.digicert-g2",
            "anchor.amazon-1",
            "test.root",
            "test.rsaroot",
            "test.anyroot",
            "test.p521root",
            "test.rsa512root",
            "test.v1root",
            "test.rsa8192root",
        ] {
            assert_eq!(store.add_der(&der(name)), Ok(()));
        }
        store
    }

    /// verify on the named certificates, the leaf first.
    fn check(names: &[&str], host: &str, now: i64) -> Result<(), Error> {
        let mut owned = Vec::new();
        for name in names {
            owned.push(der(name));
        }
        let mut chain = Vec::new();
        for certificate in &owned {
            chain.push(&certificate[..]);
        }
        verify(&chain, &anchors(), host, now).map(|_| ())
    }

    /// Bytes from hex digits, two at a time.
    fn bytes(digits: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for pair in digits.as_bytes().as_chunks::<2>().0 {
            let pair = core::str::from_utf8(pair).unwrap();
            out.push(u8::from_str_radix(pair, 16).unwrap());
        }
        out
    }

    /// The chains as the servers sent them verify at NOW.
    #[test]
    fn real_chains() {
        for (names, host) in [
            (
                &["github.leaf", "github.e36", "github.e46"][..],
                "github.com",
            ),
            (
                &["google.leaf", "google.we2", "google.r4cross"],
                "www.google.com",
            ),
            (
                &["openai.leaf", "openai.we1", "openai.r4cross"],
                "api.openai.com",
            ),
            (
                &[
                    "letsencrypt.leaf",
                    "letsencrypt.ye2",
                    "letsencrypt.rootye",
                    "letsencrypt.x2cross",
                ],
                "letsencrypt.org",
            ),
            (
                &[
                    "microsoft.leaf",
                    "microsoft.ocsp04",
                    "microsoft.rootg2cross",
                ],
                "www.microsoft.com",
            ),
            (
                &["amazon.leaf", "amazon.m04", "amazon.root1cross"],
                "www.amazon.com",
            ),
        ] {
            assert_eq!(check(names, host, NOW), Ok(()), "{host}");
        }
    }

    /// The intermediates in any order, with the root, unrelated extras
    /// and duplicates.
    #[test]
    fn any_order() {
        for (names, host) in [
            (
                &["github.leaf", "github.e46", "github.e36"][..],
                "github.com",
            ),
            (
                &[
                    "letsencrypt.leaf",
                    "letsencrypt.x2cross",
                    "letsencrypt.rootye",
                    "letsencrypt.ye2",
                ],
                "letsencrypt.org",
            ),
            (
                &[
                    "google.leaf",
                    "github.e36",
                    "amazon.m04",
                    "google.r4cross",
                    "google.we2",
                ],
                "www.google.com",
            ),
            (
                &["openai.leaf", "openai.we1", "anchor.gts-r4"],
                "api.openai.com",
            ),
            (
                &["github.leaf", "github.e36", "github.e36", "github.leaf"],
                "github.com",
            ),
            (
                &["test.leaf", "test.twin", "test.inter"],
                "api.example.test",
            ),
        ] {
            assert_eq!(check(names, host, NOW), Ok(()), "{host}");
        }
    }

    #[test]
    fn missing_issuer() {
        for names in [
            &["openai.leaf"][..],
            &["openai.leaf", "github.e36"],
            &["letsencrypt.leaf", "letsencrypt.ye2", "letsencrypt.x2cross"],
            &["microsoft.leaf", "microsoft.rootg2cross"],
        ] {
            let host = if names[0] == "openai.leaf" {
                "api.openai.com"
            } else {
                "www.microsoft.com"
            };
            let host = if names[0] == "letsencrypt.leaf" {
                "letsencrypt.org"
            } else {
                host
            };
            assert_eq!(check(names, host, NOW), Err(Error::Untrusted));
        }
        // twin has the issuer's name, not its key.
        assert_eq!(
            check(&["test.leaf", "test.twin"], "api.example.test", NOW),
            Err(Error::Signature)
        );
        assert_eq!(check(&[], "api.example.test", NOW), Err(Error::Malformed));
    }

    /// Validity is inclusive at both ends, for leaves and issuers.
    #[test]
    fn expiry() {
        let openai = ["openai.leaf", "openai.we1"];
        // openai.leaf's notBefore is 2026-11-03 03:44:41.
        assert_eq!(
            check(&openai, "api.openai.com", 1_793_577_600),
            Err(Error::Expired)
        );
        assert_eq!(
            check(&openai, "api.openai.com", 1_803_859_200),
            Err(Error::Expired)
        );
        let test = ["test.leaf", "test.inter"];
        assert_eq!(check(&test, "api.example.test", LAST), Ok(()));
        assert_eq!(
            check(&test, "api.example.test", LAST + 1),
            Err(Error::Expired)
        );
        assert_eq!(check(&test, "api.example.test", 1_767_225_600), Ok(()));
        assert_eq!(
            check(&test, "api.example.test", 1_767_225_599),
            Err(Error::Expired)
        );
    }

    #[test]
    fn hosts() {
        let openai = ["openai.leaf", "openai.we1"];
        for (host, valid) in [
            ("api.openai.com", true),
            ("API.OpenAI.com", true),
            ("api.openai.com.", true),
            ("x.api.openai.com", true),
            ("y.x.api.openai.com", false),
            ("openai.com", false),
            ("", false),
            (".", false),
            ("api.openai.com/", false),
            ("api..openai.com", false),
            ("api.openai.com\0", false),
        ] {
            let expected = if valid { Ok(()) } else { Err(Error::Host) };
            assert_eq!(check(&openai, host, NOW), expected, "{host}");
        }
        let test = ["test.leaf", "test.inter"];
        for (host, valid) in [
            ("b.wild.example.test", true),
            ("wild.example.test", false),
            ("c.b.wild.example.test", false),
            ("192.0.2.1", true),
            ("192.0.2.2", false),
            ("2001:db8::1", true),
            ("[2001:db8::1]", true),
            ("2001:0db8:0:0:0:0:0:1", true),
            ("2001:db8::2", false),
            ("[192.0.2.1]", false),
            // The address, with a dot after it: no DNS name.
            ("192.0.2.1.", true),
            ("192.0.2.2.", false),
            ("2001:db8::1.", false),
            ("3221225985", false),
            ("192.0.0x2.1", false),
        ] {
            let expected = if valid { Ok(()) } else { Err(Error::Host) };
            assert_eq!(check(&test, host, NOW), expected, "{host}");
        }
        // A dNSName that spells an IP address is no iPAddress.
        assert_eq!(check(&["test.ncgood", "test.nc"], "192.0.2.5", NOW), Ok(()));
        // The leaf's names alone, as a system that verified the path asks.
        let leaf = der("openai.leaf");
        assert_eq!(super::names(&leaf, "api.openai.com."), Ok(()));
        assert_eq!(super::names(&leaf, "openai.com"), Err(Error::Host));
        assert_eq!(super::names(b"\x30\x00", "a.test"), Err(Error::Malformed));
    }

    /// RFC 6125's rules, as the leaf's names are matched.
    #[test]
    fn wildcards() {
        for (pattern, host, matches) in [
            ("*.a.com", "b.a.com", true),
            ("*.a.com", "B.A.COM", true),
            ("*.a.com.", "b.a.com", true),
            ("*.a.com", "a.com", false),
            ("*.a.com", "c.b.a.com", false),
            ("*.a.com", ".a.com", false),
            ("*.com", "a.com", false),
            ("b*.a.com", "b1.a.com", false),
            ("*b.a.com", "bb.a.com", false),
            ("*.*.a.com", "b.c.a.com", false),
            ("a.*.com", "a.b.com", false),
            ("a.com", "a.com", true),
            ("A.com", "a.COM", true),
            ("a.com", "b.com", false),
            ("", "a.com", false),
        ] {
            assert_eq!(
                host_matches(pattern.as_bytes(), host.as_bytes()),
                matches,
                "{pattern} {host}"
            );
        }
    }

    #[test]
    fn path_length() {
        assert_eq!(
            check(
                &["test.deep", "test.below", "test.zero"],
                "api.example.test",
                NOW
            ),
            Err(Error::PathLength)
        );
    }

    /// nc permits example.test and 192.0.2.0/24 and excludes
    /// bad.example.test, for every name below it.
    #[test]
    fn name_constraints() {
        for (leaf, host, outcome) in [
            ("test.ncgood", "good.example.test", Ok(())),
            ("test.ncgood", "192.0.2.5", Ok(())),
            ("test.ncother", "good.example.test", Err(Error::Constrained)),
            ("test.ncbad", "x.bad.example.test", Err(Error::Constrained)),
            ("test.ncstar", "a.example.test", Err(Error::Constrained)),
            ("test.ncip", "good.example.test", Err(Error::Constrained)),
        ] {
            assert_eq!(check(&[leaf, "test.nc"], host, NOW), outcome, "{leaf}");
        }
    }

    /// Go's matchDomainConstraint cases, and the wildcard an excluded
    /// subtree also holds.
    #[test]
    fn domains() {
        for (domain, constraint, excluded, holds) in [
            ("example.com", "", false, true),
            ("example.com", "example.com", false, true),
            ("EXAMPLE.com", "example.COM", false, true),
            ("a.example.com", "example.com", false, true),
            ("a.example.com", ".example.com", false, true),
            ("example.com", ".example.com", false, false),
            ("notexample.com", "example.com", false, false),
            ("example.com", "a.example.com", false, false),
            ("*.example.com", "example.com", false, true),
            ("*.example.com", "a.example.com", false, false),
            ("*.example.com", "a.example.com", true, true),
            ("*.example.com", ".a.example.com", true, false),
            ("*.example.com", "a.b.example.com", true, false),
            ("*.example.com", "a.other.com", true, false),
        ] {
            assert_eq!(
                domain_within(domain.as_bytes(), constraint.as_bytes(), excluded),
                Ok(holds),
                "{domain} {constraint}"
            );
        }
        for (domain, constraint) in [("a..com", "com"), ("a.com.", "com"), ("a.com", "c..om")] {
            assert_eq!(
                domain_within(domain.as_bytes(), constraint.as_bytes(), false),
                Err(Error::Constrained)
            );
        }
        let network = [192, 0, 2, 0, 255, 255, 255, 0];
        assert!(address_within(&[192, 0, 2, 200], &network));
        assert!(!address_within(&[192, 0, 3, 1], &network));
        assert!(!address_within(&[0; 16], &network));
    }

    #[test]
    fn usages() {
        assert_eq!(
            check(&["test.client", "test.inter"], "api.example.test", NOW),
            Err(Error::Usage)
        );
        assert_eq!(
            check(&["test.undercl", "test.cl"], "api.example.test", NOW),
            Err(Error::Usage)
        );
        assert_eq!(
            check(
                &["test.undernotca", "test.notca", "test.inter"],
                "api.example.test",
                NOW
            ),
            Err(Error::NotCa)
        );
        assert_eq!(
            check(&["test.crit", "test.inter"], "api.example.test", NOW),
            Err(Error::Critical)
        );
        // anyExtendedKeyUsage serves neither a leaf nor a CA.
        for names in [
            &["test.anyleaf", "test.anyroot"][..],
            &["test.underany", "test.anyca"],
            // A CA is no leaf, and a key that cannot sign signs no
            // handshake.
            &["test.caleaf"],
            &["test.kencleaf"],
        ] {
            assert_eq!(
                check(names, "api.example.test", NOW),
                Err(Error::Usage),
                "{names:?}"
            );
        }
        let kenc = der("test.kencleaf");
        assert!(!parse(&kenc).unwrap().signs_handshake());
        assert!(parse(&der("test.leaf")).unwrap().signs_handshake());
    }

    /// ncmail constrains rfc822Name and URI, which are not compared: a
    /// certificate below with a name of either form, or an emailAddress
    /// in a subject without subjectAltName, is refused; one without, as
    /// a TLS server's, is not.
    #[test]
    fn unprocessed_forms() {
        for (names, outcome) in [
            (&["test.ncmaildns", "test.ncmail"][..], Ok(())),
            (&["test.ncmailbox", "test.ncmail"], Err(Error::Constrained)),
            (&["test.ncmailuri", "test.ncmail"], Err(Error::Constrained)),
            (
                &["test.ncmailsubleaf", "test.ncmailsub", "test.ncmail"],
                Err(Error::Constrained),
            ),
        ] {
            assert_eq!(check(names, "api.example.test", NOW), outcome, "{names:?}");
        }
    }

    /// ncdir permits C=XX, O=rr Test: a subject under it passes, folded
    /// as Chrome folds it too, and one elsewhere does not.
    #[test]
    fn directory_names() {
        for (leaf, outcome) in [
            ("test.ncdirgood", Ok(())),
            ("test.ncdirfold", Ok(())),
            ("test.ncdirbad", Err(Error::Constrained)),
        ] {
            assert_eq!(
                check(&[leaf, "test.ncdir"], "api.example.test", NOW),
                outcome,
                "{leaf}"
            );
        }
        // C=XX, O=rr Test; that and CN=server; C=XX alone.
        let base = bytes("301f310b30090603550406130258583110300e060355040a0c0772722054657374");
        let deeper = bytes(
            "3030310b30090603550406130258583110300e060355040a0c0772722054657374\
             310f300d06035504030c06736572766572",
        );
        let country = bytes("300d310b3009060355040613025858");
        assert_eq!(directory_within(&deeper, &base), Ok(true));
        assert_eq!(directory_within(&base, &base), Ok(true));
        assert_eq!(directory_within(&base, &deeper), Ok(false));
        assert_eq!(directory_within(&country, &base), Ok(false));
        assert!(directory_within(&[0x30, 0x01, 0x00], &base).is_err());
        // O=rr Test as UTF8String against PrintableString, IA5String,
        // BMPString and UniversalString, and against values that differ.
        let utf8 = bytes("060355040a0c0772722054657374");
        for (other, matches) in [
            ("060355040a13085252205445535420", true),
            ("060355040a1609207272202074657374", true),
            ("060355040a1e0e0072007200200054006500730074", true),
            (
                "060355040a1c1c00000072000000720000002000000054000000650000007300000074",
                true,
            ),
            ("060355040a1306727220746573", false),
            ("060355040b0c0772722054657374", false),
            // A PrintableString may not hold '@': it matches nothing.
            ("060355040a13087272205465737440", false),
            // An OCTET STRING is compared as it is, with its tag.
            ("060355040a040772722054657374", false),
        ] {
            assert_eq!(
                attribute_matches(&utf8, &bytes(other)),
                Ok(matches),
                "{other}"
            );
        }
    }

    /// NameConstraints DER permitting dNSName .tr, as NSS imposes it on
    /// TUBITAK's root (genname.c).
    const TR: &str = "3009a007300582032e7472";

    /// The PEM block under "# name" in TESTS, its line and all, after
    /// lines.
    fn block(lines: &str, name: &str) -> Vec<u8> {
        let tests = TESTS.as_bytes();
        let line = ["# ", name, "\n"].concat();
        let at = find(tests, line.as_bytes()).unwrap();
        let end = at + find(&tests[at..], PEM_END).unwrap() + PEM_END.len();
        let mut text = Vec::new();
        text.extend_from_slice(lines.as_bytes());
        text.extend_from_slice(&tests[at..end]);
        text
    }

    /// Constraints imposed on imposedroot's name hold as its own would:
    /// api.example.tr passes, api.example.test does not; from add_pem's
    /// line, and from a policy over a store that holds the root plainly.
    #[test]
    fn imposed() {
        let lines = ["# name-constraints: ", TR, "\n"].concat();
        let text = block(&lines, "test.imposedroot");
        let mut constrained = Store::new();
        assert_eq!(constrained.add_pem(&text), 1);
        let mut policy = Policy::new();
        assert_eq!(policy.add_pem(&text), 1);
        // A block without the line means nothing to a policy.
        assert_eq!(policy.add_pem(&block("", "test.root")), 0);
        assert_eq!((policy.len(), policy.skipped()), (1, 0));
        let mut plain = Store::new();
        assert_eq!(plain.add_der(&der("test.imposedroot")), Ok(()));
        let (tr, test) = (der("test.imposedtr"), der("test.imposedtest"));
        assert!(verify(&[&test], &plain, "api.example.test", NOW).is_ok());
        assert_eq!(plain.add_policy(&policy), 0);
        for store in [&constrained, &plain] {
            assert!(verify(&[&tr], store, "api.example.tr", NOW).is_ok());
            let refused = verify(&[&test], store, "api.example.test", NOW);
            assert_eq!(refused.map(|_| ()), Err(Error::Constrained));
        }
        // And over a path another verifier built.
        let root = der("test.imposedroot");
        assert_eq!(screen(&[&tr, &root], &policy), Ok(()));
        assert_eq!(screen(&[&test, &root], &policy), Err(Error::Constrained));
        // A line that is not NameConstraints in hex leaves the root out.
        for odd in ["# name-constraints: 30\n", "# name-constraints: zz\n"] {
            let mut refused = Store::new();
            assert_eq!(refused.add_pem(&block(odd, "test.imposedroot")), 0);
            assert_eq!(refused.skipped(), 1);
        }
    }

    /// A v1 anchor issues; a self-signed server certificate in the store
    /// verifies as itself, and issues nothing, as it is no CA.
    #[test]
    fn anchors_as_they_are() {
        assert_eq!(
            check(&["test.v1leaf", "test.v1root"], "api.example.test", NOW),
            Ok(())
        );
        let (own, under) = (der("test.selfleaf"), der("test.underself"));
        let mut store = Store::new();
        assert_eq!(store.add_der(&own), Ok(()));
        assert!(verify(&[&own], &store, "api.example.test", NOW).is_ok());
        assert_eq!(
            verify(&[&under], &store, "api.example.test", NOW).map(|_| ()),
            Err(Error::NotCa)
        );
        // Not in the store, it is a leaf with no issuer.
        assert_eq!(
            check(&["test.selfleaf"], "api.example.test", NOW),
            Err(Error::Untrusted)
        );
        // Distrusted for what it was issued after: no path at all.
        let mut dated = Store::new();
        assert_eq!(dated.add_der_distrust_after(&own, 0), Ok(()));
        assert_eq!(
            verify(&[&own], &dated, "api.example.test", NOW).map(|_| ()),
            Err(Error::Distrusted)
        );
    }

    /// An RSA-8192 root signs a leaf with PKCS #1 and SHA-256.
    #[test]
    fn rsa_8192() {
        assert_eq!(
            check(
                &["test.rsa8192leaf", "test.rsa8192root"],
                "api.example.test",
                NOW
            ),
            Ok(())
        );
    }

    /// A policy's revocations and distrust dates over a path another
    /// verifier built, and taken on by a store of the same anchors.
    #[test]
    fn policies() {
        let (root, inter, leaf, late) = (
            der("test.root"),
            der("test.inter"),
            der("test.leaf"),
            der("test.late"),
        );
        let mut policy = Policy::new();
        assert_eq!(policy.add_der_distrust_after(&root, 1_772_323_200), Ok(()));
        let path = [&leaf[..], &inter, &root];
        let late_path = [&late[..], &inter, &root];
        assert_eq!(screen(&path, &policy), Ok(()));
        assert_eq!(screen(&late_path, &policy), Err(Error::Distrusted));
        // Backwards, the anchor would be the leaf: refused, not passed.
        let backwards = [&root[..], &inter, &late];
        assert_eq!(screen(&backwards, &policy), Err(Error::Order));
        let skipping = [&late[..], &root];
        assert_eq!(screen(&skipping, &policy), Err(Error::Order));
        let mut lines = Vec::new();
        revocation_line(&inter, true, &mut lines);
        policy.add_revoked(&lines);
        assert_eq!(screen(&path, &policy), Err(Error::Revoked));
        assert_eq!(screen(&[], &policy), Err(Error::Malformed));
        let mut system = Store::new();
        assert_eq!(system.add_der(&root), Ok(()));
        assert!(verify(&[&late, &inter], &system, "api.example.test", NOW).is_ok());
        assert_eq!(system.add_policy(&policy), 1);
        assert_eq!(system.revocations(), 1);
        let refused = verify(&[&leaf, &inter], &system, "api.example.test", NOW);
        assert_eq!(refused.map(|_| ()), Err(Error::Revoked));
    }

    /// PSS and PKCS #1 certificate signatures, and the four TLS 1.3
    /// schemes with the leaf's key.
    #[test]
    fn signatures() {
        assert_eq!(check(&["test.rsaleaf"], "api.example.test", NOW), Ok(()));
        assert_eq!(check(&["test.rsapkcs"], "api.example.test", NOW), Ok(()));
        let mut message = Vec::new();
        message.extend_from_slice(&[b' '; 64]);
        message.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        for byte in 0..32 {
            message.push(byte);
        }
        let p256 = bytes(
            "30440220213be345f2b9cef7c60c590657df3ceee6b9f2a7263fbda2673f1a73\
             aa2a643102200b402eb469426ca1d339e55d6b026178e6441a5b2d2206559812\
             3e17aea3057a",
        );
        let p384 = bytes(
            "3065023028144676ffc0f5f05cd14c014598beade1f14a53edd81f1c9068d559\
             dbe01c85c879b7f3216edb317192c611ea30a6e6023100edbad5bdc8314d17ad\
             c4957e58fd6c0a064a077aa5a138331b607596922c87037ec5907cfa7ffe6245\
             bf710806374a13",
        );
        let pss256 = bytes(
            "99b64844d3a8931be7d6e5eb9eeb3cc203f5398ab92f8648c7ff97c34d3d6387\
             ad3ffcb77069fe93c7f70d9b861522eddf47c052d6c38533b68f1a7a268b3b09\
             6787a87c4056060f379aaa02f5bc62b2645229ada9202301bfd7bc9a6ab0c40f\
             71ca78286a1eb5d4e780bb53f90ec7458d6ce9afe8c215b62ff0bd1484d812c8\
             ae70a111a8aeb0192bc2053effbeb236b0fdd283a681522d42803b57f836f418\
             e323ebc22253eb77bb1ec2e1e6ae046f099bde850bd19c5e6c95e2b06f6def50\
             c5eb66cd33754f5d3f6c2c504333b46153bc088558c646ad08c642ef119321bb\
             61e22fb18438fb397c9258547aa16fcc7cebfa36a1a0900c56ce193af5d909d8",
        );
        let pss384 = bytes(
            "570e815e667ff11049d5398184574f642dcc2aac912863e391f0f673c64b2c34\
             ca1de987b8db532a0b501bd03ba24a8851cc709c52dc0f950c26b7d59412d739\
             3d49bb4159d4617a82b0c34587269089b2005cd1d1ea2c3bcb43ca88a4c0916b\
             2756dc67d2bc5289d7d42556f1b297908d9cb8aefc6d6e682728346d8b26b026\
             d9f5cb68745081e4f38b602eea80616138718e5ea87372863325299466fba7a6\
             ad69fd8177ac18e7caa1630220b7d371a1c5161a8bd3ceb2a4a63b231893fb9c\
             1c437310258b36915dedf71e381a5b1a64b4af29bca15250c51791abcd2ba141\
             7a29e8b2c1c548f3b9236a8a66c4ccd925f2d92ec7b057521ab6c0e06b2ede8e",
        );
        let p521 = bytes(
            "3081860241633adf157108257310f6737c0e399810cab369d3c9fe907912d703\
             39a18ed67b9b2ddd2e3c61f6a5d88e7250f3fc8b65b8fe209a70730419bb7730\
             c8042d6e19d002412c6c753fdd888af9c6a558dbdefc33b4a9761b5ef722a67f\
             71331ac8f1b90f7fd2d311a37f1137b23d2f5c97fef4a5dcf862cc769dbf5015\
             41f033bfea33e9641b",
        );
        let pss512 = bytes(
            "3f44b06d73d297d92fe1a5ae967978fc38da70b1abd9f8e61fdfc6736dfe13a1\
             d0bb265f529924031e16b4ca871c0d12b3cd5503490b0e8c40b1f2079a6158dc\
             c09d4c02ab2c3d96460cefaa4814c2427457ebbe65862134c70cd0ee8802e11e\
             3d530baa250aac764b7bdd84e56d45dad7583ec2ad6911faed8e6f7653070b0e\
             9a23b693d96de930e65c927bd55a1f64ae5e462848784b8154546a7f314110c8\
             7baf6561882ef9d205b7b4d25813cb0a6cb2bd4ff265c1eeb3d884b0f1fde726\
             90458306b495859c93643ba2c365f90d4bba5848eb1bc215d5115a0171a3fcfc\
             3b61df8a0fe6103c1dfe119f3eb3dcbaf91805b5e960ff1ad770953ac6799d71",
        );
        let store = anchors();
        // rr: escape(copy): the message stays as it was signed, beside it.
        let mut changed = message.clone();
        changed[100] ^= 1;
        for (leaf, issuer, scheme, signature, wrong) in [
            ("test.leaf", "test.inter", 0x0403, &p256, 0x0503),
            ("test.leaf384", "test.inter", 0x0503, &p384, 0x0403),
            ("test.rsaleaf", "test.rsaroot", 0x0804, &pss256, 0x0805),
            ("test.rsaleaf", "test.rsaroot", 0x0805, &pss384, 0x0804),
            // P-521 and SHA-512 certificates, and their TLS 1.3 schemes.
            ("test.p521leaf", "test.p521root", 0x0603, &p521, 0x0503),
            (
                "test.rsa512leaf",
                "test.rsa512root",
                0x0806,
                &pss512,
                0x0805,
            ),
            (
                "test.rsa512pkcs",
                "test.rsa512root",
                0x0806,
                &pss512,
                0x0804,
            ),
        ] {
            let (leaf, issuer) = (der(leaf), der(issuer));
            let approval = verify(&[&leaf, &issuer], &store, "api.example.test", NOW).unwrap();
            let verified = Leaf::approved(&leaf, &approval).unwrap();
            assert_eq!(verified.verify_tls13(scheme, &message, signature), Ok(()));
            let refused = verified.verify_tls13(scheme, &changed, signature);
            assert_eq!(refused, Err(Error::Signature));
            // Another curve's scheme is no scheme of the key; another
            // hash's does not verify.
            let another = verified.verify_tls13(wrong, &message, signature);
            assert!(matches!(
                another,
                Err(Error::Unsupported | Error::Signature)
            ));
            let pkcs = verified.verify_tls13(0x0401, &message, signature);
            assert_eq!(pkcs, Err(Error::Unsupported));
            // The approval is of this leaf, for this host alone.
            assert!(approval.approves(&leaf, "API.example.test."));
            assert!(!approval.approves(&leaf, "x.example.test"));
            assert!(!approval.approves(&issuer, "api.example.test"));
            let other = Leaf::approved(&issuer, &approval).map(|_| ());
            assert_eq!(other, Err(Error::Approval));
        }
        // A changed byte of the subject's common name, in the signed
        // part, or of the signature.
        let issuer = der("test.inter");
        let leaf = der("test.leaf");
        let name = leaf
            .windows(16)
            .position(|w| w == b"api.example.test")
            .unwrap();
        for at in [name, leaf.len() - 10] {
            let mut forged = der("test.leaf");
            forged[at] ^= 1;
            let outcome = verify(&[&forged, &issuer], &store, "api.example.test", NOW).map(|_| ());
            assert_eq!(outcome, Err(Error::Signature));
        }
    }

    /// An anchor distrusted after 2026-03-01 takes leaf, issued on
    /// 2026-01-01, and refuses late, issued on 2026-06-01; by add_pem's
    /// line as by add_der_distrust_after.
    #[test]
    fn distrust() {
        let (root, inter) = (der("test.root"), der("test.inter"));
        let (leaf, late) = (der("test.leaf"), der("test.late"));
        let mut store = Store::new();
        assert_eq!(store.add_der_distrust_after(&root, 1_772_323_200), Ok(()));
        let mut text = Vec::new();
        text.extend_from_slice(b"Root\r\n# distrust-after: 2026-03-01T00:00:00Z\r\n");
        let tests = TESTS.as_bytes();
        let at = find(tests, b"# test.root").unwrap();
        let end = at + find(&tests[at..], PEM_END).unwrap() + PEM_END.len();
        text.extend_from_slice(&tests[at..end]);
        let mut bundle = Store::new();
        assert_eq!(bundle.add_pem(&text), 1);
        for anchors in [&store, &bundle] {
            let early = verify(&[&leaf, &inter], anchors, "api.example.test", NOW);
            assert!(early.is_ok());
            let refused = verify(&[&late, &inter], anchors, "api.example.test", NOW);
            assert_eq!(refused.map(|_| ()), Err(Error::Distrusted));
        }
        let mut open = Store::new();
        assert_eq!(open.add_der(&root), Ok(()));
        assert!(verify(&[&late, &inter], &open, "api.example.test", NOW).is_ok());
        // A date in another form leaves the anchor out.
        let mut odd = Vec::new();
        for line in [
            "# distrust-after: 2026-03-01",
            "# distrust-after: 2026-02-30T00:00:00Z",
        ] {
            odd.clear();
            odd.extend_from_slice(line.as_bytes());
            odd.extend_from_slice(&text[44..]);
            let mut refused = Store::new();
            assert_eq!(refused.add_pem(&odd), 0);
            assert_eq!(refused.skipped(), 1);
        }
    }

    /// A line of revoked.txt for certificate: by its issuer and serial,
    /// or by its subject and key.
    fn revocation_line(certificate: &[u8], by_key: bool, out: &mut Vec<u8>) {
        let parsed = parse(certificate).unwrap();
        let key = sha256::digest(parsed.spki);
        let digest = if by_key {
            revocation_digest(SUBJECT_KEY, parsed.subject, &key)
        } else {
            revocation_digest(ISSUER_SERIAL, parsed.issuer, parsed.serial)
        };
        for byte in digest {
            for nibble in [byte >> 4, byte & 15] {
                out.push(char::from_digit(u32::from(nibble), 16).unwrap() as u8);
            }
        }
        out.push(b'\n');
    }

    /// A certificate revoked is used nowhere on a path: as the leaf, an
    /// intermediate or the anchor, by issuer and serial or by subject and
    /// key; one revoked off the path changes nothing. Comments and blank
    /// lines are skipped, a malformed line is counted.
    #[test]
    fn revoked() {
        let (root, inter, leaf) = (der("test.root"), der("test.inter"), der("test.leaf"));
        let chain = [&leaf[..], &inter];
        let mut lines = Vec::new();
        for (revoked, by_key) in [
            (&leaf, false),
            (&inter, true),
            (&inter, false),
            (&root, true),
        ] {
            lines.clear();
            lines.extend_from_slice(b"# OneCRL\n\n");
            revocation_line(revoked, by_key, &mut lines);
            let mut store = Store::new();
            assert_eq!(store.add_der(&root), Ok(()));
            assert_eq!(store.add_revoked(&lines), 1);
            let refused = verify(&chain, &store, "api.example.test", NOW);
            assert_eq!(refused.map(|_| ()), Err(Error::Revoked));
        }
        lines.clear();
        revocation_line(&der("github.leaf"), false, &mut lines);
        lines.extend_from_slice(b"not hex\n");
        let mut store = Store::new();
        assert_eq!(store.add_der(&root), Ok(()));
        assert_eq!(store.add_revoked(&lines), 1);
        assert_eq!((store.revocations(), store.skipped()), (1, 1));
        assert!(verify(&chain, &store, "api.example.test", NOW).is_ok());
    }

    /// The store loads every certificate of a bundle in the profile, and
    /// counts the rest.
    #[test]
    fn store() {
        let mut store = Store::new();
        // All but test.crit, with its critical extension of no meaning.
        assert_eq!(store.add_pem(TESTS.as_bytes()), 77);
        assert_eq!((store.len(), store.skipped()), (77, 1));
        let bad = b"x\n-----BEGIN CERTIFICATE-----\nMII!\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nAAAA";
        assert_eq!(store.add_pem(bad), 0);
        assert_eq!((store.len(), store.skipped()), (77, 3));
        assert_eq!(store.add_der(&[0x30, 0]), Err(Error::Malformed));
        assert_eq!((store.len(), store.skipped()), (77, 4));
        // A list of DER loads as the same blocks do, and verifies alike.
        let (root, inter, leaf) = (der("test.root"), der("test.inter"), der("test.leaf"));
        let mut list = Store::new();
        assert_eq!(list.add_ders(&[&root, &inter, &[0x30, 0]]), 2);
        assert_eq!((list.len(), list.skipped()), (2, 1));
        assert!(verify(&[&leaf], &list, "api.example.test", NOW).is_ok());
        assert!(Store::new().is_empty());
    }

    #[test]
    fn limits() {
        let names = ["test.leaf"; 17];
        assert_eq!(check(&names, "api.example.test", NOW), Err(Error::TooMany));
        let twins = [
            "test.leaf",
            "test.twin",
            "test.twin",
            "test.twin",
            "test.inter",
        ];
        assert_eq!(check(&twins, "api.example.test", NOW), Ok(()));
    }

    /// DER's one encoding and nothing else.
    #[test]
    fn der_strict() {
        for bad in [
            &[0x30, 0x80, 0, 0][..],
            &[0x04, 0x81, 0x01, 0],
            &[0x04, 0x82, 0x00, 0x80],
            &[0x04, 0x84, 0, 0, 1, 0],
            &[0x04, 0x02, 0],
            &[0x1f, 0x01, 0],
            &[0x04],
        ] {
            assert!(Reader::new(bad).element().is_err());
        }
        let mut reader = Reader::new(&[0x04, 0x81, 0x80]);
        assert!(reader.element().is_err());
        let long = [0x04, 0x81, 0x80];
        let mut owned = Vec::new();
        owned.extend_from_slice(&long);
        owned.extend_from_slice(&[7; 128]);
        let element = Reader::new(&owned).element().unwrap();
        assert_eq!((element.body.len(), element.whole.len()), (128, 131));
        for (body, magnitude) in [
            (&[0][..], Some(&[0][..])),
            (&[0, 0x80], Some(&[0x80])),
            (&[1, 2], Some(&[1, 2])),
        ] {
            assert_eq!(unsigned(body).ok(), magnitude);
        }
        for bad in [&[][..], &[0x80], &[0, 1], &[0xff, 0x80]] {
            assert!(unsigned(bad).is_err());
        }
        // A certificate with a byte after it, or cut short.
        let mut leaf = der("test.leaf");
        leaf.push(0);
        assert!(parse(&leaf).is_err());
        assert!(parse(&leaf[..leaf.len() - 2]).is_err());
    }

    #[test]
    fn times() {
        let mut encoded = Vec::new();
        for (id, text, seconds) in [
            (0x17, "700101000000Z", Some(0)),
            (0x17, "500101000000Z", Some(-631_152_000)),
            (0x17, "491231235959Z", Some(2_524_607_999)),
            (0x18, "20000229000000Z", Some(951_782_400)),
            (0x18, "21000301000000Z", Some(4_107_542_400)),
            (0x18, "19000229000000Z", None),
            (0x18, "20261131000000Z", None),
            (0x18, "20260001000000Z", None),
            (0x18, "20261301000000Z", None),
            (0x18, "20260100000000Z", None),
            (0x18, "20260101240000Z", None),
            (0x18, "20260101006000Z", None),
            (0x18, "20260101000060Z", None),
            (0x18, "20260101000000.5Z", None),
            (0x18, "20260101000000+0000", None),
            (0x18, "2026010100000Z", None),
            (0x17, "20260101000000Z", None),
            (0x18, "260101000000Z", None),
            (0x04, "260101000000Z", None),
            (0x18, "2026-1-1000000Z", None),
        ] {
            encoded.clear();
            encoded.push(id);
            encoded.push(u8::try_from(text.len()).unwrap());
            encoded.extend_from_slice(text.as_bytes());
            let element = Reader::new(&encoded).element().unwrap();
            assert_eq!(time(&element).ok(), seconds, "{text}");
        }
    }

    #[test]
    fn extension_rules() {
        let unknown = [0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x04, 0x00];
        assert!(extensions(&unknown).is_ok());
        let mut twice = Vec::new();
        twice.extend_from_slice(&unknown);
        twice.extend_from_slice(&unknown);
        assert_eq!(extensions(&twice).err(), Some(Error::Duplicate));
        let critical = [
            0x30, 0x09, 0x06, 0x02, 0x2a, 0x03, 0x01, 0x01, 0xff, 0x04, 0x00,
        ];
        assert_eq!(extensions(&critical).err(), Some(Error::Critical));
        let flagged = [
            0x30, 0x09, 0x06, 0x02, 0x2a, 0x03, 0x01, 0x01, 0x01, 0x04, 0x00,
        ];
        assert_eq!(extensions(&flagged).err(), Some(Error::Malformed));
        assert_eq!(extensions(&[]).err(), Some(Error::Malformed));
        // Key usage: unused bits zero and counted, a bit set.
        assert_eq!(key_usage(&[7, 0x80]), Ok(0x8000));
        assert_eq!(key_usage(&[1, 0x06]), Ok(0x0600));
        assert_eq!(key_usage(&[0, 0x06]), Ok(0x0600));
        for bad in [
            &[8, 0x80][..],
            &[0, 0],
            &[7, 0x81],
            &[0],
            &[0, 0x80, 0x80, 0],
        ] {
            assert!(key_usage(bad).is_err());
        }
    }

    /// One verification of OpenAI's chain as sent: a P-256 signature by
    /// WE1, and WE1's P-384 one by GTS Root R4.
    #[bench]
    fn verify_openai(b: &mut Bencher) {
        let store = anchors();
        let (leaf, we1, cross) = (der("openai.leaf"), der("openai.we1"), der("openai.r4cross"));
        let chain = [&leaf[..], &we1, &cross];
        b.iter(|| verify(&chain, &store, "api.openai.com", NOW).is_ok());
    }

    /// One parse of a leaf.
    #[bench]
    fn parse_leaf(b: &mut Bencher) {
        let leaf = der("github.leaf");
        b.iter(|| parse(&leaf).is_ok());
    }
}
