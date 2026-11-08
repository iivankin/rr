//! TLS server authentication by the operating system's trust, as Go's
//! crypto/x509 does it: the system's verifier where it has one, unless
//! SSL_CERT_FILE or SSL_CERT_DIR names anchors to verify with instead,
//! which Go honours on every system since 1.27 (root.go).
//!
//! Trust checks a server's chain for a host at a time. macOS and Windows
//! verify it themselves, as Go has them do: SecTrustEvaluateWithError
//! with the SSL policy, and CertGetCertificateChain with the SSL chain
//! policy, each on one of wait.rs's threads, as either may fetch a
//! missing intermediate over the network (neither is asked to check
//! revocation, as Go does not); a poll
//! loop waits on a pipe or a loopback socket, as for resolve. Linux
//! has no verifier of its own: Trust loads the system's anchors once and
//! x509::verify checks the chain at once. With SSL_CERT_FILE or
//! SSL_CERT_DIR set, macOS and Windows do as Linux, on the files they
//! name alone (Go's certFiles and certDirectories are empty there), and
//! the system's verifier is not asked; SSL_CERT_DIR's list is separated
//! by ':', or ';' on Windows.
//!
//! Windows builds more than one chain where cross-signatures allow it:
//! as Go's systemVerify, trust asks for the lower-quality chain contexts
//! as well (CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS) and weighs each,
//! the best first, as it weighs the best: its trust status, then the SSL
//! policy for the host. A chain passes when one of them does, and the
//! policy below screens each that did; when none passes, the best's
//! error is the answer, as in Go. Freeing the best context frees the
//! rest.
//!
//! A policy laid over the trust (Trust::with_policy), such as Mozilla's
//! OneCRL and distrust dates that roots::policy gives, holds wherever the
//! chain is verified: x509's anchors take it on, and the path the
//! system's verifier built (on Windows, each it took, until one passes)
//! is screened with x509::screen, as Go screens the system's chains for
//! its own blocklist (root_darwin.go, root_windows.go). The dependency stays one way: trust needs only
//! x509, and a program that adds roots hands its policy over:
//! `Trust::new()?.with_policy(roots::policy())`.
//!
//! system() and store() load the anchors themselves, Go's way up to 1.17,
//! for a program that verifies with x509 on every system. On macOS and
//! Windows Trust is the right path: Windows keeps only the roots it has
//! needed so far in its store and fetches the rest as a chain asks for
//! them, macOS applies trust settings and Apple's own constraints on its
//! roots that a list of anchors does not carry, and loading macOS's
//! anchors takes about 80 ms. `store.add_policy(&roots::policy())` lays
//! Mozilla's distrust over what they load.
//!
//! Loading: Linux reads the bundle and directories Go reads, or those
//! SSL_CERT_FILE and SSL_CERT_DIR name, on its own system calls, as
//! macOS and Windows read those the variables name. macOS
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
