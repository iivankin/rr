//! Mozilla's trust anchors for TLS servers: roots.pem, which
//! roots-gen.py makes from NSS's certdata.txt at a release tag (named
//! in its header, with the file's SHA-256). It keeps the roots NSS
//! trusts to issue server certificates, and for a root Mozilla
//! distrusts after a date, a "# distrust-after:" line that
//! x509::Store::add_pem reads: leaves issued later do not chain to it.
//! Chrome's announced distrusts of roots Mozilla still trusts (Chunghwa
//! Telecom's and NetLock's, after 2025-07-31) come in the same lines,
//! the earlier date winning; Chrome has since removed those roots from
//! its store, and as no leaf issued before the date is still current,
//! the date now refuses what Chrome does. curl's cacert.pem drops those
//! dates. A root on which Firefox imposes name constraints (NSS's
//! genname.c: TUBITAK's, to .tr) has a "# name-constraints:" line, which
//! add_pem imposes on every CA of its name. The data is Mozilla's, under
//! the Mozilla Public License 2.0.
//!
//! revoked.txt is Mozilla's OneCRL: the certificates Firefox refuses
//! wherever they stand on a path, intermediates revoked and roots
//! distrusted (DigiNotar's among them, which certdata.txt no longer
//! carries), as digests that x509::Store::add_revoked reads. A bundle
//! from the system carries none of it: policy() gives Mozilla's
//! distrust alone, to lay over the system's anchors
//! (x509::Store::add_policy) or a path the system verified
//! (x509::screen, trust's Trust::with_policy).
//!
//! To refresh both, run `python3 registry/roots/roots-gen.py --tag
//! NSS_3_xxx_RTM` there, or scripts/roots-gen.py in a project, and update the
//! counts in the test below; `--check` says whether
//! roots.pem is what its tag gives and revoked.txt what OneCRL holds now. A root outside x509's profile is
//! skipped and counted.
//!
//! A program may trust the system's anchors instead, or as well: the
//! trust component's system() loads them on Linux, macOS and Windows.
//! On Linux they are the file SSL_CERT_FILE names, or else the first
//! that reads of Go's list: /etc/ssl/certs/ca-certificates.crt (Debian,
//! Ubuntu, Arch), /etc/pki/tls/certs/ca-bundle.crt (Fedora, RHEL 6),
//! /etc/ssl/ca-bundle.pem (SUSE), /etc/pki/tls/cacert.pem (OpenELEC),
//! /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem (CentOS, RHEL 7)
//! and /etc/ssl/cert.pem (Alpine), with the certificate directories;
//! such bundles carry no distrust dates.

use crate::base::x509;

const MOZILLA: &[u8] = include_bytes!("roots.pem");
const REVOKED: &[u8] = include_bytes!("revoked.txt");

const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

/// A store of Mozilla's anchors, decoded and checked, and OneCRL's
/// revocations: about 200 KB of PEM and 125 KB of digests, once per
/// program.
pub fn mozilla() -> x509::Store {
    let mut store = x509::Store::new();
    store.add_pem(MOZILLA);
    store.add_revoked(REVOKED);
    store
}

/// Mozilla's distrust without its trust: OneCRL's revocations, and the
/// anchors that carry a distrust date or imposed name constraints, for
/// x509::Store::add_policy and x509::screen to apply to anchors and
/// paths of another source, such as the system's.
pub fn policy() -> x509::Store {
    let mut store = x509::Store::new();
    let mut rest = MOZILLA;
    while let Some(end) = position(rest, PEM_END) {
        let (block, after) = rest.split_at(end + PEM_END.len());
        if position(block, b"\n# distrust-after: ").is_some()
            || position(block, b"\n# name-constraints: ").is_some()
        {
            store.add_pem(block);
        }
        rest = after;
    }
    store.add_revoked(REVOKED);
    store
}

fn position(text: &[u8], needle: &[u8]) -> Option<usize> {
    text.windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{MOZILLA, mozilla, policy};
    use crate::base::x509::{Store, TEST_NOW, test_certificate, verify};
    use alloc::vec::Vec;
    use test::Bencher;

    /// NSS 3.133 trusts 118 roots for TLS servers, all in x509's profile;
    /// Izenpe.com is distrusted after 2026-04-15, and HiPKI Root CA - G1
    /// and NetLock Arany by Chrome after 2025-07-31.
    #[test]
    fn anchors() {
        let store = mozilla();
        // Every anchor loads, e-Szigno's P-521 root among them.
        assert_eq!((store.len(), store.skipped()), (118, 0));
        // OneCRL at timestamp 1793748796854: 1,920 records, 1,916 distinct.
        assert_eq!(store.revocations(), 1916);
        let dates = MOZILLA
            .split(|byte| *byte == b'\n')
            .filter(|line| line.starts_with(b"# distrust-after: "))
            .count();
        assert_eq!(dates, 3);
        // TUBITAK's root, constrained to .tr as NSS's genname.c has it.
        let imposed = MOZILLA
            .split(|byte| *byte == b'\n')
            .filter(|line| line == b"# name-constraints: 3009a007300582032e7472")
            .count();
        assert_eq!(imposed, 1);
        // The policy: those four anchors, and OneCRL.
        let distrust = policy();
        assert_eq!((distrust.len(), distrust.skipped()), (4, 0));
        assert_eq!(distrust.revocations(), 1916);
    }

    /// Chains of x509's tests end at Mozilla's anchors.
    #[test]
    fn chains() {
        let store = mozilla();
        for (names, host) in [
            (
                &["github.leaf", "github.e36", "github.e46"][..],
                "github.com",
            ),
            (
                &["openai.leaf", "openai.we1", "openai.r4cross"],
                "api.openai.com",
            ),
            (
                &[
                    "microsoft.leaf",
                    "microsoft.ocsp04",
                    "microsoft.rootg2cross",
                ],
                "microsoft.com",
            ),
            (
                &[
                    "letsencrypt.leaf",
                    "letsencrypt.ye2",
                    "letsencrypt.rootye",
                    "letsencrypt.x2cross",
                ],
                "lencr.org",
            ),
        ] {
            assert!(trusted(&store, names, host), "{host}");
        }
    }

    /// Whether the named certificates of x509's tests verify for host.
    fn trusted(store: &Store, names: &[&str], host: &str) -> bool {
        // rr: escape(copy): the test's certificates, decoded once.
        let certificates: Vec<Vec<u8>> = names
            .iter()
            .map(|name| test_certificate(name).unwrap())
            .collect();
        // rr: escape(copy): the chain verify takes, borrowed from them.
        let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
        verify(&chain, store, host, TEST_NOW).is_ok()
    }

    /// Loading the set, as a program does once.
    #[bench]
    fn load(b: &mut Bencher) {
        b.iter(|| mozilla().len());
    }

    /// OpenAI's chain against the whole set.
    #[bench]
    fn verify_openai(b: &mut Bencher) {
        let store = mozilla();
        let leaf = test_certificate("openai.leaf").unwrap();
        let we1 = test_certificate("openai.we1").unwrap();
        let cross = test_certificate("openai.r4cross").unwrap();
        let chain = [&leaf[..], &we1, &cross];
        b.iter(|| verify(&chain, &store, "api.openai.com", TEST_NOW).is_ok());
    }
}
