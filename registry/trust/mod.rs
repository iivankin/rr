//! TLS server authentication by the operating system's trust, as Go's
//! crypto/x509 does it since 1.18.
//!
//! Trust checks a server's chain for a host at a time. macOS and Windows
//! verify it themselves, as Go has them do: SecTrustEvaluateWithError
//! with the SSL policy, and CertGetCertificateChain with the SSL chain
//! policy, each on one of wait.rs's threads, as either may fetch a
//! missing intermediate or a revocation status over the network; a poll
//! loop waits on a pipe or a loopback socket, as for resolve. Linux
//! has no verifier of its own: Trust loads the system's anchors once and
//! x509::verify checks the chain at once.
//!
//! system() and store() load the anchors themselves, Go's way up to 1.17,
//! for a program that verifies with x509 on every system. On macOS and
//! Windows Trust is the right path: Windows keeps only the roots it has
//! needed so far in its store and fetches the rest as a chain asks for
//! them, macOS applies trust settings and Apple's own constraints on its
//! roots that a list of anchors does not carry, and loading macOS's
//! anchors takes about 80 ms.
//!
//! Loading: Linux reads the bundle and directories Go reads, or those
//! SSL_CERT_FILE and SSL_CERT_DIR name, on its own system calls. macOS
//! asks the Security framework for the certificates of its three trust
//! domains and their settings for SSL, as Go's loadSystemRoots did up to
//! 1.17. Windows enumerates the ROOT system store, which holds Group
//! Policy and enterprise roots as well, less what is disabled for server
//! authentication and what the Disallowed store holds. A certificate
//! found twice is added once; one the system denies is left out
//! wherever else it is found.
//!
//! A program that also added the roots component can fall back to
//! Mozilla's anchors when the system has none, as Go's x509roots/fallback
//! does: `if n == 0 { store = roots::mozilla() }`, and on Linux
//! `Trust::with(roots::mozilla())`.

mod sys;

pub use sys::*;
