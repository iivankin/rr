//! The system side of trust: what mod.rs says it is, for each system.

use crate::base::wait;
use crate::base::x509;
use alloc::vec::Vec;

/// What a check waits on: the type every component's poll loop takes.
pub use crate::base::wait::Wait;

/// Why a chain was refused, or the system gave no anchors.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// A system call failed: an errno on Linux, an OSStatus on macOS, a
    /// GetLastError code on Windows.
    System(i32),
    /// Linux: why x509::verify refused the chain.
    Untrusted(x509::Error),
    /// macOS: the OSStatus SecTrustEvaluateWithError refused it with,
    /// such as errSecNotTrusted or errSecHostNameMismatch.
    Refused(i32),
    /// Windows: the chain's CERT_TRUST_* error bits.
    Chain(u32),
    /// Windows: the SSL policy's error, such as CERT_E_CN_NO_MATCH.
    Policy(u32),
    /// Linux: the system has no anchors.
    NoRoots,
    /// No certificate, too many, or one the system cannot read.
    Input,
    /// The check's result was taken by an earlier poll.
    Polled,
    /// macOS, Windows: no thread, or no pipe or socket pair to say it is
    /// done.
    Thread,
}

/// The system's trust, made once for the program.
pub struct Trust {
    os: os::Trust,
}

impl Trust {
    /// The system's trust; on Linux its anchors, an error when it has
    /// none.
    pub fn new() -> Result<Trust, Error> {
        // Only Linux's can fail; the type is the same on every system.
        #[cfg(target_os = "linux")]
        let os = os::Trust::new();
        #[cfg(not(target_os = "linux"))]
        let os: Result<os::Trust, Error> = Ok(os::Trust);
        os.map(|os| Trust { os })
    }

    /// Linux: trust in the anchors of store instead of the system's.
    #[cfg(target_os = "linux")]
    pub fn with(store: x509::Store) -> Trust {
        Trust {
            os: os::Trust { store },
        }
    }

    /// Starts checking chain, DER certificates leaf first, for host at
    /// now (Unix seconds). It never blocks: poll the check. A host that is
    /// empty or holds a NUL is Error::Input on every system: Windows reads
    /// the name as a C string, which would end at the NUL, and checks
    /// none for an empty one.
    pub fn check(&self, chain: &[&[u8]], host: &str, now: i64) -> Check {
        Check {
            os: os::check(&self.os, chain, host, now),
            polled: false,
        }
    }

    /// Checks chain for host at now, and waits for the answer.
    pub fn verify(&self, chain: &[&[u8]], host: &str, now: i64) -> Result<(), Error> {
        let mut check = self.check(chain, host, now);
        // The system's verifier answers in the end; each wait ends when
        // it has.
        loop {
            if let Some(result) = check.poll() {
                return result;
            }
            wait::block(&check.wait());
        }
    }
}

/// One chain's check. Dropping it cancels it.
pub struct Check {
    os: os::Check,
    /// Whether poll gave the answer.
    polled: bool,
}

impl Check {
    /// None while the system works; then the answer, once.
    pub fn poll(&mut self) -> Option<Result<(), Error>> {
        if self.polled {
            return Some(Err(Error::Polled));
        }
        let answer = self.os.poll()?;
        self.polled = true;
        Some(answer)
    }

    /// What to wait on before polling again.
    pub fn wait(&self) -> Wait {
        os::wait(&self.os)
    }
}

/// The most DER kept of what was found, as an x509::Store keeps at most.
const FOUND_BYTES_MAX: usize = 16 << 20;

/// Adds the system's trusted roots for TLS server authentication to
/// store; how many it added. An error only when it added none.
pub fn system(store: &mut x509::Store) -> Result<usize, Error> {
    let mut found = Found::new();
    let result = os::collect(&mut found);
    let added = found.add_to(store);
    match result {
        Err(error) if added == 0 => Err(error),
        Ok(()) | Err(_) => Ok(added),
    }
}

/// A new store of the system's roots, which may be empty.
pub fn store() -> Result<x509::Store, Error> {
    let mut store = x509::Store::new();
    system(&mut store)?;
    Ok(store)
}

/// Certificates found, as DER in one buffer: those trusted, and those
/// the system denies, which are left out wherever else they are found.
struct Found {
    bytes: Vec<u8>,
    // rr: escape(bound): each holds bytes of its own, which
    // FOUND_BYTES_MAX bounds.
    trusted: Vec<(usize, usize)>,
    // rr: escape(bound): each holds bytes of its own, which
    // FOUND_BYTES_MAX bounds.
    denied: Vec<(usize, usize)>,
}

impl Found {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            trusted: Vec::new(),
            denied: Vec::new(),
        }
    }

    /// Whether more DER fits.
    fn room(&self) -> bool {
        self.bytes.len() < FOUND_BYTES_MAX
    }

    /// The certificate in bytes from start to the end, when there is one.
    fn keep(&mut self, start: usize, deny: bool) {
        let end = self.bytes.len();
        if end == start {
            return;
        }
        if deny {
            self.denied.push((start, end));
        } else {
            self.trusted.push((start, end));
        }
    }

    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    fn push(&mut self, der: &[u8], deny: bool) {
        if !self.room() {
            return;
        }
        let start = self.bytes.len();
        self.bytes.extend_from_slice(der);
        self.keep(start, deny);
    }

    /// Adds each CERTIFICATE block of PEM text as trusted. A block that
    /// is not plain base64, such as one with headers, is skipped, as Go
    /// skips it.
    #[cfg(any(target_os = "linux", test))]
    fn pem(&mut self, text: &[u8]) {
        let mut rest = text;
        while let Some((body, after)) = pem_block(rest) {
            rest = after;
            if !self.room() {
                return;
            }
            let start = self.bytes.len();
            if base64(body, &mut self.bytes) {
                self.keep(start, false);
            } else {
                self.bytes.truncate(start);
            }
        }
    }

    /// Adds the trusted certificates to store, each once and none that
    /// is denied; how many the store took.
    fn add_to(mut self, store: &mut x509::Store) -> usize {
        let bytes = &self.bytes;
        self.trusted
            .sort_unstable_by(|a, b| der(bytes, *a).cmp(der(bytes, *b)));
        self.trusted
            .dedup_by(|a, b| der(bytes, *a) == der(bytes, *b));
        self.denied
            .sort_unstable_by(|a, b| der(bytes, *a).cmp(der(bytes, *b)));
        let denied = &self.denied;
        // rr: escape(copy): the slices add_ders takes, borrowed from bytes.
        let kept: Vec<&[u8]> = self
            .trusted
            .iter()
            .map(|range| der(bytes, *range))
            .filter(|certificate| {
                denied
                    .binary_search_by(|other| der(bytes, *other).cmp(certificate))
                    .is_err()
            })
            .collect();
        store.add_ders(&kept)
    }
}

fn der(bytes: &[u8], range: (usize, usize)) -> &[u8] {
    bytes.get(range.0..range.1).unwrap_or_default()
}

/// A host the system's verifiers can take: not empty, and no NUL.
fn named(host: &str) -> bool {
    !host.is_empty() && !host.contains('\0')
}

#[cfg(any(target_os = "linux", test))]
const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
#[cfg(any(target_os = "linux", test))]
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

/// The base64 of the next CERTIFICATE block, and the text after it.
#[cfg(any(target_os = "linux", test))]
fn pem_block(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let begin = position(text, PEM_BEGIN)?;
    let body = text.get(begin + PEM_BEGIN.len()..)?;
    let end = position(body, PEM_END)?;
    Some((body.get(..end)?, body.get(end + PEM_END.len()..)?))
}

#[cfg(any(target_os = "linux", test))]
fn position(text: &[u8], needle: &[u8]) -> Option<usize> {
    text.windows(needle.len())
        .position(|window| window == needle)
}

/// Appends what base64 text decodes to, white space aside; whether it
/// was base64.
#[cfg(any(target_os = "linux", test))]
fn base64(text: &[u8], out: &mut Vec<u8>) -> bool {
    let (mut bits, mut count, mut padding) = (0u32, 0u32, 0u32);
    for &byte in text {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return false,
        };
        if padding > 0 {
            return false;
        }
        // Fewer than 8 bits wait in bits: 6 more stay below 14.
        bits = (bits << 6) | u32::from(digit);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xFF).unwrap_or(0));
            bits &= (1 << count) - 1;
        }
    }
    padding <= 2 && bits == 0
}

/// Linux as Go reads it, on files a Files gives: the first bundle that
/// reads, then every file of the certificate directories.
#[cfg(any(target_os = "linux", test))]
mod unix {
    use super::Found;
    use alloc::vec::Vec;

    /// Go's bundles, the first that reads of them: Debian, Ubuntu,
    /// Gentoo and Arch; Fedora and RHEL 6; OpenSUSE; OpenELEC; CentOS
    /// and RHEL 7; Alpine.
    pub const CERT_FILES: [&[u8]; 6] = [
        b"/etc/ssl/certs/ca-certificates.crt",
        b"/etc/pki/tls/certs/ca-bundle.crt",
        b"/etc/ssl/ca-bundle.pem",
        b"/etc/pki/tls/cacert.pem",
        b"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        b"/etc/ssl/cert.pem",
    ];
    /// Go's directories, SLES and Fedora's, colon-separated as
    /// SSL_CERT_DIR is.
    pub const CERT_DIRECTORIES: &[u8] = b"/etc/ssl/certs:/etc/pki/tls/certs";
    /// The most directories SSL_CERT_DIR names that are read.
    const DIRECTORIES_MAX: usize = 64;
    pub const ENOENT: i32 = 2;

    /// The file system, as the loader needs it.
    pub trait Files {
        /// The file at path into text, which it clears first; the error
        /// number when it cannot be read.
        fn read(&mut self, path: &[u8], text: &mut Vec<u8>) -> Result<(), i32>;
        /// The names of dir's entries into names, each ended by a NUL:
        /// all but . and .. and a link to a file beside it (one with
        /// no '/' in its target), which Go reads once by its own name.
        fn list(&mut self, dir: &[u8], names: &mut Vec<u8>) -> Result<(), i32>;
    }

    /// Reads into found SSL_CERT_FILE's bundle (file) or the first of
    /// Go's that reads, then each file in SSL_CERT_DIR's directories
    /// (dirs) or Go's. Returns the first error other than a missing
    /// file, which counts only when nothing was found.
    pub fn collect(
        files: &mut dyn Files,
        file: Option<&[u8]>,
        dirs: Option<&[u8]>,
        found: &mut Found,
    ) -> Option<i32> {
        let mut first = None;
        let mut text = Vec::new();
        let named;
        let bundles: &[&[u8]] = match file {
            Some(file) => {
                named = [file];
                &named
            }
            None => &CERT_FILES,
        };
        for bundle in bundles {
            match files.read(bundle, &mut text) {
                Ok(()) => {
                    found.pem(&text);
                    break;
                }
                Err(error) => note(&mut first, error),
            }
        }
        let mut names = Vec::new();
        let mut path = Vec::new();
        let dirs = dirs.unwrap_or(CERT_DIRECTORIES);
        for dir in dirs
            .split(|byte| *byte == b':')
            .filter(|dir| !dir.is_empty())
            .take(DIRECTORIES_MAX)
        {
            names.clear();
            if let Err(error) = files.list(dir, &mut names) {
                note(&mut first, error);
                continue;
            }
            for name in names
                .split(|byte| *byte == 0)
                .filter(|name| !name.is_empty())
            {
                path.clear();
                path.extend_from_slice(dir);
                path.push(b'/');
                path.extend_from_slice(name);
                // A file that does not read is passed over, as in Go.
                if files.read(&path, &mut text).is_ok() {
                    found.pem(&text);
                }
            }
        }
        first
    }

    fn note(first: &mut Option<i32>, error: i32) {
        if error != ENOENT && first.is_none() {
            *first = Some(error);
        }
    }
}

#[cfg(target_os = "linux")]
mod os {
    use super::unix::{self, Files};
    use super::{Error, Found, Wait};
    use crate::base::wait::{EINTR, O_CLOEXEC};
    use crate::base::x509;
    use alloc::vec::Vec;
    use core::ffi::{CStr, c_char, c_int, c_void};

    /// struct dirent of glibc and musl on 64-bit Linux: the inode, the
    /// offset, the record's length, the type, then the name.
    #[repr(C)]
    struct Dirent {
        inode: u64,
        offset: i64,
        length: u16,
        // rr: escape(tag): d_type is dirent.h's own field, a DT_ number.
        kind: u8,
        name: [c_char; 256],
    }

    #[link(name = "c")]
    // rr: escape(unsafe): each signature is the C library's, from its headers.
    unsafe extern "C" {
        fn getenv(name: *const c_char) -> *const c_char;
        fn open(path: *const c_char, flags: c_int, ...) -> c_int;
        fn read(fd: c_int, buffer: *mut c_void, size: usize) -> isize;
        fn close(fd: c_int) -> c_int;
        fn opendir(path: *const c_char) -> *mut c_void;
        fn readdir(dir: *mut c_void) -> *mut Dirent;
        fn closedir(dir: *mut c_void) -> c_int;
        fn dirfd(dir: *mut c_void) -> c_int;
        fn readlinkat(fd: c_int, path: *const c_char, buffer: *mut c_char, size: usize) -> isize;
        fn __errno_location() -> *mut c_int;
    }

    // fcntl.h's, dirent.h's and errno.h's, the same on every Linux.
    const O_RDONLY: c_int = 0;
    const DT_UNKNOWN: u8 = 0;
    const DT_LNK: u8 = 10;
    const EINVAL: i32 = 22;
    const EFBIG: i32 = 27;
    /// A bundle larger than this is not one.
    const FILE_BYTES_MAX: usize = 8 << 20;
    /// The entries read of a directory, and the bytes of a path or link.
    const ENTRIES_MAX: usize = 4096;
    const PATH_BYTES_MAX: usize = 4096;
    /// What read takes at once.
    const CHUNK_BYTES: usize = 64 << 10;

    pub fn collect(found: &mut Found) -> Result<(), Error> {
        let file = variable(c"SSL_CERT_FILE");
        let dirs = variable(c"SSL_CERT_DIR");
        match unix::collect(&mut System, file, dirs, found) {
            Some(error) => Err(Error::System(error)),
            None => Ok(()),
        }
    }

    /// The environment's value of name, when it is there and not empty,
    /// as Go's Getenv takes it.
    fn variable(name: &CStr) -> Option<&'static [u8]> {
        // rr: escape(unsafe): name is a C string; the value lives as long
        // as the environment, which the program does not change.
        let value = unsafe { getenv(name.as_ptr()) };
        if value.is_null() {
            return None;
        }
        // rr: escape(unsafe): getenv gave a C string.
        let value = unsafe { CStr::from_ptr(value) }.to_bytes();
        if value.is_empty() { None } else { Some(value) }
    }

    /// This thread's errno.
    fn errno() -> i32 {
        // rr: escape(unsafe): __errno_location gives this thread's errno.
        let at = unsafe { __errno_location() };
        // rr: escape(unsafe): the pointer is to this thread's live errno.
        unsafe { *at }
    }

    /// path with a NUL after it, in buffer; EINVAL-like None when it
    /// holds a NUL or is too long.
    fn terminated<'a>(path: &[u8], buffer: &'a mut [u8; PATH_BYTES_MAX]) -> Option<&'a CStr> {
        if path.contains(&0) || path.len() >= PATH_BYTES_MAX {
            return None;
        }
        let to = buffer.get_mut(..path.len())?;
        to.copy_from_slice(path);
        *buffer.get_mut(path.len())? = 0;
        CStr::from_bytes_until_nul(buffer).ok()
    }

    /// Whether name, in the directory open at dir, is a link to a file
    /// beside it.
    fn same_dir_link(dir: *mut c_void, name: &CStr) -> bool {
        let mut target = [0u8; PATH_BYTES_MAX];
        // rr: escape(unsafe): dir is open until the caller closes it.
        let fd = unsafe { dirfd(dir) };
        // rr: escape(unsafe): fd is open; name is a C string; target holds
        // PATH_BYTES_MAX bytes.
        let n = unsafe {
            readlinkat(
                fd,
                name.as_ptr(),
                target.as_mut_ptr().cast(),
                PATH_BYTES_MAX,
            )
        };
        let Ok(n) = usize::try_from(n) else {
            return false;
        };
        !target.get(..n).unwrap_or_default().contains(&b'/')
    }

    /// The file system, through the C library.
    struct System;

    impl Files for System {
        fn read(&mut self, path: &[u8], text: &mut Vec<u8>) -> Result<(), i32> {
            let mut buffer = [0u8; PATH_BYTES_MAX];
            let path = terminated(path, &mut buffer).ok_or(EINVAL)?;
            // rr: escape(unsafe): path is a C string; the flags open
            // nothing new.
            let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };
            if fd < 0 {
                return Err(errno());
            }
            let result = read_all(fd, text);
            // rr: escape(unsafe): fd is this call's, closed once.
            unsafe { close(fd) };
            result
        }

        fn list(&mut self, dir: &[u8], names: &mut Vec<u8>) -> Result<(), i32> {
            let mut buffer = [0u8; PATH_BYTES_MAX];
            let path = terminated(dir, &mut buffer).ok_or(EINVAL)?;
            // rr: escape(unsafe): path is a C string.
            let stream = unsafe { opendir(path.as_ptr()) };
            if stream.is_null() {
                return Err(errno());
            }
            for _ in 0..ENTRIES_MAX {
                // rr: escape(unsafe): stream is open until closedir below.
                let entry = unsafe { readdir(stream) };
                if entry.is_null() {
                    break;
                }
                // rr: escape(unsafe): readdir's entry lives until the next
                // readdir of the stream.
                let entry = unsafe { &*entry };
                // rr: escape(unsafe): d_name is a C string within the entry.
                let name = unsafe { CStr::from_ptr(entry.name.as_ptr()) };
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                let link = entry.kind == DT_LNK || entry.kind == DT_UNKNOWN;
                if link && same_dir_link(stream, name) {
                    continue;
                }
                names.extend_from_slice(bytes);
                names.push(0);
            }
            // rr: escape(unsafe): stream is this call's, closed once.
            unsafe { closedir(stream) };
            Ok(())
        }
    }

    /// The whole file at fd into text, up to FILE_BYTES_MAX.
    fn read_all(fd: c_int, text: &mut Vec<u8>) -> Result<(), i32> {
        text.clear();
        // Each turn reads a chunk, or ends; the limit ends it too.
        loop {
            if text.len() > FILE_BYTES_MAX {
                return Err(EFBIG);
            }
            let at = text.len();
            text.resize(at + CHUNK_BYTES, 0);
            let Some(into) = text.get_mut(at..) else {
                return Err(EFBIG);
            };
            // rr: escape(unsafe): into holds CHUNK_BYTES bytes.
            let n = unsafe { read(fd, into.as_mut_ptr().cast(), into.len()) };
            let Ok(n) = usize::try_from(n) else {
                text.truncate(at);
                let error = errno();
                if error == EINTR {
                    continue;
                }
                return Err(error);
            };
            text.truncate(at + n);
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// The system's anchors, loaded once.
    pub struct Trust {
        pub store: x509::Store,
    }

    impl Trust {
        pub fn new() -> Result<Self, Error> {
            let store = super::store()?;
            if store.is_empty() {
                return Err(Error::NoRoots);
            }
            Ok(Self { store })
        }
    }

    /// x509::verify, at once.
    pub fn check(trust: &Trust, chain: &[&[u8]], host: &str, now: i64) -> Check {
        let result = if chain.is_empty() || chain.len() > x509::CHAIN_MAX || !super::named(host) {
            Err(Error::Input)
        } else {
            match x509::verify(chain, &trust.store, host, now) {
                Ok(_leaf) => Ok(()),
                Err(error) => Err(Error::Untrusted(error)),
            }
        };
        Check {
            result: Some(result),
        }
    }

    /// A check that was done when it started.
    pub struct Check {
        result: Option<Result<(), Error>>,
    }

    impl Check {
        pub fn poll(&mut self) -> Option<Result<(), Error>> {
            self.result.take()
        }
    }

    /// Nothing: the answer is there from the start.
    pub fn wait(_check: &Check) -> Wait {
        Wait::READY
    }
}

#[cfg(target_os = "macos")]
mod os {
    pub use super::thread::{Check, wait};
    use super::{Error, Found};
    use crate::base::x509;
    use alloc::vec::Vec;
    use core::ffi::c_void;
    use core::ptr::null;

    #[link(name = "CoreFoundation", kind = "framework")]
    // rr: escape(unsafe): each signature is CoreFoundation's, from its headers.
    unsafe extern "C" {
        fn CFRelease(object: *const c_void);
        fn CFArrayGetCount(array: *const c_void) -> isize;
        fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;
        fn CFDataGetLength(data: *const c_void) -> isize;
        fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
        fn CFDictionaryGetValueIfPresent(
            dictionary: *const c_void,
            key: *const c_void,
            value: *mut *const c_void,
        ) -> u8;
        fn CFEqual(a: *const c_void, b: *const c_void) -> u8;
        fn CFNumberGetValue(number: *const c_void, kind: isize, value: *mut c_void) -> u8;
        fn CFStringCreateWithBytes(
            allocator: *const c_void,
            bytes: *const u8,
            length: isize,
            encoding: u32,
            external: u8,
        ) -> *const c_void;
        fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: isize)
        -> *const c_void;
        fn CFArrayCreate(
            allocator: *const c_void,
            values: *const *const c_void,
            count: isize,
            callbacks: *const c_void,
        ) -> *const c_void;
        fn CFDateCreate(allocator: *const c_void, at: f64) -> *const c_void;
        fn CFErrorGetCode(error: *const c_void) -> isize;
        /// CFArrayCallBacks: a version and four functions.
        #[link_name = "kCFTypeArrayCallBacks"]
        static TYPE_ARRAY_CALLBACKS: [usize; 5];
    }

    #[link(name = "Security", kind = "framework")]
    // rr: escape(unsafe): each signature is the Security framework's, from
    // its headers.
    unsafe extern "C" {
        fn SecTrustSettingsCopyCertificates(domain: u32, certificates: *mut *const c_void) -> i32;
        fn SecTrustSettingsCopyTrustSettings(
            certificate: *const c_void,
            domain: u32,
            settings: *mut *const c_void,
        ) -> i32;
        fn SecCertificateCopyData(certificate: *const c_void) -> *const c_void;
        fn SecPolicyCopyProperties(policy: *const c_void) -> *const c_void;
        fn SecCertificateCreateWithData(
            allocator: *const c_void,
            data: *const c_void,
        ) -> *const c_void;
        fn SecPolicyCreateSSL(server: u8, host: *const c_void) -> *const c_void;
        fn SecTrustCreateWithCertificates(
            certificates: *const c_void,
            policies: *const c_void,
            trust: *mut *const c_void,
        ) -> i32;
        fn SecTrustSetVerifyDate(trust: *const c_void, date: *const c_void) -> i32;
        fn SecTrustEvaluateWithError(trust: *const c_void, error: *mut *const c_void) -> u8;
    }

    const ERR_SEC_NOT_TRUSTED: i32 = -67843;
    /// Unix time of CFAbsoluteTime's zero, 2001-01-01.
    const CF_EPOCH: i64 = 978_307_200;

    const DOMAIN_USER: u32 = 0;
    const DOMAIN_ADMIN: u32 = 1;
    const DOMAIN_SYSTEM: u32 = 2;
    const ERR_SEC_NO_TRUST_SETTINGS: i32 = -25263;
    const ERR_SEC_ALLOCATE: i32 = -108;
    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const CF_NUMBER_SINT32: isize = 3;

    /// kSecTrustSettingsResult's values Go acts on.
    #[derive(Clone, Copy)]
    enum Setting {
        TrustRoot,
        TrustAsRoot,
        Deny,
        Unspecified,
    }

    /// A Core Foundation object of ours, released on drop.
    struct Owned(*const c_void);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // rr: escape(unsafe): a Copy or Create function gave it to us.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    /// A CFString of text, or a null one when it cannot be made.
    fn string(text: &[u8]) -> Owned {
        let length = isize::try_from(text.len()).unwrap_or(0);
        // rr: escape(unsafe): text is readable for its length.
        Owned(unsafe {
            CFStringCreateWithBytes(null(), text.as_ptr(), length, CF_STRING_ENCODING_UTF8, 0)
        })
    }

    /// The keys of a trust settings dictionary, and of a policy's
    /// properties: the CFSTR values of Apple's headers.
    struct Keys {
        policy: Owned,
        policy_string: Owned,
        result: Owned,
        policy_oid: Owned,
        apple_ssl: Owned,
    }

    impl Keys {
        fn new() -> Option<Self> {
            let keys = Self {
                policy: string(b"kSecTrustSettingsPolicy"),
                policy_string: string(b"kSecTrustSettingsPolicyString"),
                result: string(b"kSecTrustSettingsResult"),
                policy_oid: string(b"SecPolicyOid"),
                apple_ssl: string(b"1.2.840.113635.100.1.3"),
            };
            let all = [
                &keys.policy,
                &keys.policy_string,
                &keys.result,
                &keys.policy_oid,
                &keys.apple_ssl,
            ];
            if all.iter().any(|key| key.0.is_null()) {
                None
            } else {
                Some(keys)
            }
        }
    }

    pub fn collect(found: &mut Found) -> Result<(), Error> {
        let keys = Keys::new().ok_or(Error::System(ERR_SEC_ALLOCATE))?;
        let mut first = Ok(());
        for domain in [DOMAIN_USER, DOMAIN_ADMIN, DOMAIN_SYSTEM] {
            let mut list = null();
            // rr: escape(unsafe): list is a local out-parameter.
            let status = unsafe { SecTrustSettingsCopyCertificates(domain, &raw mut list) };
            if status == ERR_SEC_NO_TRUST_SETTINGS {
                continue;
            }
            if status != 0 {
                first = first.and(Err(Error::System(status)));
                continue;
            }
            let list = Owned(list);
            // rr: escape(unsafe): list is a CFArray of certificates.
            let count = unsafe { CFArrayGetCount(list.0) };
            for index in 0..count {
                // rr: escape(unsafe): index is below the array's count.
                let certificate = unsafe { CFArrayGetValueAtIndex(list.0, index) };
                // The system's own are trusted; a user's or an admin's
                // "Never Trust" of one comes from their domain.
                let setting = if domain == DOMAIN_SYSTEM {
                    Setting::TrustRoot
                } else {
                    setting(&keys, certificate)
                };
                add(found, certificate, setting);
            }
        }
        first
    }

    /// Adds certificate to found as its setting says: TrustRoot holds
    /// for a self-issued certificate only, TrustAsRoot for another.
    fn add(found: &mut Found, certificate: *const c_void, setting: Setting) {
        // rr: escape(unsafe): certificate is a SecCertificateRef of the array.
        let data = Owned(unsafe { SecCertificateCopyData(certificate) });
        if data.0.is_null() {
            return;
        }
        // rr: escape(unsafe): data is a CFData.
        let length = unsafe { CFDataGetLength(data.0) };
        // rr: escape(unsafe): data is a CFData.
        let bytes = unsafe { CFDataGetBytePtr(data.0) };
        let Ok(length) = usize::try_from(length) else {
            return;
        };
        if bytes.is_null() {
            return;
        }
        // rr: escape(unsafe): a CFData holds length bytes at its pointer
        // while it lives, and data outlives der.
        let der = unsafe { core::slice::from_raw_parts(bytes, length) };
        let root =
            crate::base::x509::parse(der).is_ok_and(|parsed| parsed.issuer == parsed.subject);
        match setting {
            Setting::TrustRoot => {
                if root {
                    found.push(der, false);
                }
            }
            Setting::TrustAsRoot => {
                if !root {
                    found.push(der, false);
                }
            }
            Setting::Deny => found.push(der, true),
            Setting::Unspecified => {}
        }
    }

    /// The value of key in dictionary, when present.
    fn value(dictionary: *const c_void, key: &Owned) -> Option<*const c_void> {
        let mut value = null();
        // rr: escape(unsafe): dictionary is a CFDictionary, value a local
        // out-parameter.
        let present = unsafe { CFDictionaryGetValueIfPresent(dictionary, key.0, &raw mut value) };
        if present == 0 { None } else { Some(value) }
    }

    /// Whether policy is Apple's SSL policy.
    fn ssl(keys: &Keys, policy: *const c_void) -> bool {
        // rr: escape(unsafe): policy is a SecPolicyRef of trust settings.
        let properties = Owned(unsafe { SecPolicyCopyProperties(policy) });
        if properties.0.is_null() {
            return false;
        }
        let Some(oid) = value(properties.0, &keys.policy_oid) else {
            return false;
        };
        // rr: escape(unsafe): both are CF objects that live for the call.
        (unsafe { CFEqual(oid, keys.apple_ssl.0) }) != 0
    }

    /// The user's trust settings of certificate for SSL, else the
    /// admin's: Go's sslTrustSettingsResult, which takes the first
    /// TrustRoot, TrustAsRoot or Deny of the dictionaries for SSL that
    /// name no host.
    fn setting(keys: &Keys, certificate: *const c_void) -> Setting {
        let mut settings = null();
        // rr: escape(unsafe): settings is a local out-parameter.
        let mut status = unsafe {
            SecTrustSettingsCopyTrustSettings(certificate, DOMAIN_USER, &raw mut settings)
        };
        if status != 0 || settings.is_null() {
            settings = null();
            // rr: escape(unsafe): settings is a local out-parameter.
            status = unsafe {
                SecTrustSettingsCopyTrustSettings(certificate, DOMAIN_ADMIN, &raw mut settings)
            };
        }
        let settings = Owned(settings);
        if status != 0 || settings.0.is_null() {
            return Setting::Unspecified;
        }
        // rr: escape(unsafe): settings is a CFArray of dictionaries.
        let count = unsafe { CFArrayGetCount(settings.0) };
        // An empty array is "always trust this certificate".
        if count == 0 {
            return Setting::TrustRoot;
        }
        for index in 0..count {
            // rr: escape(unsafe): index is below the array's count.
            let entry = unsafe { CFArrayGetValueAtIndex(settings.0, index) };
            if value(entry, &keys.policy).is_some_and(|policy| !ssl(keys, policy)) {
                continue;
            }
            // One restricted to a host name is not a root's.
            if value(entry, &keys.policy_string).is_some() {
                continue;
            }
            let Some(number) = value(entry, &keys.result) else {
                return Setting::TrustRoot;
            };
            let mut result: i32 = 0;
            let into = (&raw mut result).cast::<c_void>();
            // rr: escape(unsafe): number is a CFNumber, into an i32 of ours.
            if unsafe { CFNumberGetValue(number, CF_NUMBER_SINT32, into) } == 0 {
                return Setting::Unspecified;
            }
            match result {
                1 => return Setting::TrustRoot,
                2 => return Setting::TrustAsRoot,
                3 => return Setting::Deny,
                _ => {}
            }
        }
        Setting::Unspecified
    }

    /// The system verifies; nothing is kept.
    pub struct Trust;

    pub fn check(_trust: &Trust, chain: &[&[u8]], host: &str, now: i64) -> Check {
        if !super::named(host) {
            return Check::start(Err(Error::Input));
        }
        Check::start(evaluation(chain, host, now).map(|trust| Job { trust }))
    }

    /// What the thread evaluates: a SecTrust of ours.
    pub struct Job {
        trust: Owned,
    }

    impl Job {
        pub fn run(&self) -> Result<(), Error> {
            evaluate(self.trust.0)
        }
    }

    /// Certificates of ours, released on drop.
    struct Certificates(Vec<*const c_void>);

    impl Drop for Certificates {
        fn drop(&mut self) {
            for certificate in &self.0 {
                // rr: escape(unsafe): each was created for this value.
                unsafe { CFRelease(*certificate) };
            }
        }
    }

    /// A SecTrust of chain for host with the SSL policy, at now.
    fn evaluation(chain: &[&[u8]], host: &str, now: i64) -> Result<Owned, Error> {
        if chain.is_empty() || chain.len() > x509::CHAIN_MAX {
            return Err(Error::Input);
        }
        // The certificates, released when the array has retained them.
        let mut certificates = Certificates(Vec::with_capacity(chain.len()));
        for der in chain {
            // An empty CFData makes no certificate.
            let length = isize::try_from(der.len()).unwrap_or(0);
            // rr: escape(unsafe): der is readable for its length.
            let data = Owned(unsafe { CFDataCreate(null(), der.as_ptr(), length) });
            if data.0.is_null() {
                return Err(Error::System(ERR_SEC_ALLOCATE));
            }
            // rr: escape(unsafe): data is a CFData of ours.
            let certificate = Owned(unsafe { SecCertificateCreateWithData(null(), data.0) });
            if certificate.0.is_null() {
                return Err(Error::Input);
            }
            // rr: escape(leak): certificates releases it.
            certificates
                .0
                .push(core::mem::ManuallyDrop::new(certificate).0);
        }
        let pointers = &certificates.0;
        let count = isize::try_from(pointers.len()).unwrap_or(0);
        let callbacks = (&raw const TYPE_ARRAY_CALLBACKS).cast::<c_void>();
        // rr: escape(unsafe): pointers holds count certificates, which the
        // array retains.
        let array = Owned(unsafe { CFArrayCreate(null(), pointers.as_ptr(), count, callbacks) });
        let name = string(host.as_bytes());
        if array.0.is_null() || name.0.is_null() {
            return Err(Error::System(ERR_SEC_ALLOCATE));
        }
        // rr: escape(unsafe): name is a CFString of ours.
        let policy = Owned(unsafe { SecPolicyCreateSSL(1, name.0) });
        let mut trust = null();
        // rr: escape(unsafe): both are CF objects of ours; trust is a local
        // out-parameter.
        let status = unsafe { SecTrustCreateWithCertificates(array.0, policy.0, &raw mut trust) };
        let trust = Owned(trust);
        if status != 0 || trust.0.is_null() {
            return Err(Error::System(status));
        }
        // Seconds of this era are far inside a double's exact integers.
        let at = now.saturating_sub(CF_EPOCH) as f64;
        // rr: escape(unsafe): CFDateCreate takes a plain number.
        let date = Owned(unsafe { CFDateCreate(null(), at) });
        // rr: escape(unsafe): trust and date are CF objects of ours.
        let dated = unsafe { SecTrustSetVerifyDate(trust.0, date.0) };
        if dated != 0 {
            return Err(Error::System(dated));
        }
        Ok(trust)
    }

    /// The system's verdict on trust; it may fetch over the network.
    fn evaluate(trust: *const c_void) -> Result<(), Error> {
        let mut error = null();
        // rr: escape(unsafe): trust is a SecTrust; error a local out-parameter.
        let trusted = unsafe { SecTrustEvaluateWithError(trust, &raw mut error) };
        let error = Owned(error);
        if trusted != 0 {
            return Ok(());
        }
        if error.0.is_null() {
            return Err(Error::Refused(ERR_SEC_NOT_TRUSTED));
        }
        // rr: escape(unsafe): error is a CFError of ours.
        let code = unsafe { CFErrorGetCode(error.0) };
        Err(Error::Refused(
            i32::try_from(code).unwrap_or(ERR_SEC_NOT_TRUSTED),
        ))
    }
}

#[cfg(target_os = "windows")]
mod os {
    pub use super::thread::{Check, wait};
    use super::{Error, Found};
    use crate::base::x509;
    use alloc::vec::Vec;
    use core::ffi::{CStr, c_char, c_void};
    use core::ptr::{null, null_mut, without_provenance};

    /// CERT_CONTEXT, from wincrypt.h.
    #[repr(C)]
    struct Context {
        encoding: u32,
        encoded: *const u8,
        length: u32,
        info: *mut c_void,
        store: *mut c_void,
    }

    /// CERT_ENHKEY_USAGE, from wincrypt.h.
    #[repr(C)]
    struct Usage {
        count: u32,
        identifiers: *const *const c_char,
    }

    /// CERT_USAGE_MATCH: the usages a chain must allow, all of them
    /// (USAGE_MATCH_TYPE_AND). It is a struct of its own in
    /// CERT_CHAIN_PARA, aligned as its pointer is.
    #[repr(C)]
    struct UsageMatch {
        rule: u32,
        usage: Usage,
    }

    /// CERT_CHAIN_PARA with its first member: the fields after it are
    /// those of CERT_CHAIN_PARA_HAS_EXTRA_FIELDS, which size leaves out.
    #[repr(C)]
    struct ChainPara {
        size: u32,
        requested: UsageMatch,
    }

    /// The start of CERT_CHAIN_CONTEXT: its size and CERT_TRUST_STATUS.
    #[repr(C)]
    struct ChainContext {
        size: u32,
        error_status: u32,
        info_status: u32,
    }

    /// SSL_EXTRA_CERT_CHAIN_POLICY_PARA.
    #[repr(C)]
    struct SslPolicyPara {
        size: u32,
        auth_type: u32,
        checks: u32,
        server_name: *const u16,
    }

    /// CERT_CHAIN_POLICY_PARA.
    #[repr(C)]
    struct PolicyPara {
        size: u32,
        flags: u32,
        extra: *const c_void,
    }

    /// CERT_CHAIN_POLICY_STATUS.
    #[repr(C)]
    struct PolicyStatus {
        size: u32,
        error: u32,
        chain_index: i32,
        element_index: i32,
        extra: *mut c_void,
    }

    /// FILETIME: 100 ns since 1601, in two halves.
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    // The sizes wincrypt.h gives them on 64-bit Windows, where a struct
    // within one is aligned as its widest member: CERT_CHAIN_PARA has
    // RequestedUsage at 8 and its Usage at 16.
    const _: () = assert!(size_of::<Context>() == 40);
    const _: () = assert!(size_of::<Usage>() == 16);
    const _: () = assert!(size_of::<UsageMatch>() == 24);
    const _: () = assert!(size_of::<ChainPara>() == 32);
    const _: () = assert!(size_of::<SslPolicyPara>() == 24);
    const _: () = assert!(size_of::<PolicyPara>() == 16);
    const _: () = assert!(size_of::<PolicyStatus>() == 24);
    const _: () = assert!(size_of::<FileTime>() == 8);

    #[link(name = "crypt32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is crypt32's, from its documentation.
    unsafe extern "system" {
        fn CertOpenSystemStoreW(provider: usize, name: *const u16) -> *mut c_void;
        fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
        fn CertEnumCertificatesInStore(
            store: *mut c_void,
            previous: *const Context,
        ) -> *const Context;
        fn CertFreeCertificateContext(context: *const Context) -> i32;
        fn CertGetEnhancedKeyUsage(
            context: *const Context,
            flags: u32,
            usage: *mut Usage,
            size: *mut u32,
        ) -> i32;
        fn CertOpenStore(
            provider: *const c_char,
            encoding: u32,
            crypt_provider: usize,
            flags: u32,
            parameter: *const c_void,
        ) -> *mut c_void;
        fn CertAddEncodedCertificateToStore(
            store: *mut c_void,
            encoding: u32,
            encoded: *const u8,
            length: u32,
            disposition: u32,
            context: *mut *const Context,
        ) -> i32;
        fn CertGetCertificateChain(
            engine: *mut c_void,
            context: *const Context,
            time: *const FileTime,
            additional: *mut c_void,
            parameters: *const ChainPara,
            flags: u32,
            reserved: *mut c_void,
            chain: *mut *const ChainContext,
        ) -> i32;
        fn CertFreeCertificateChain(chain: *const ChainContext);
        fn CertVerifyCertificateChainPolicy(
            policy: *const c_char,
            chain: *const ChainContext,
            parameters: *const PolicyPara,
            status: *mut PolicyStatus,
        ) -> i32;
    }

    #[link(name = "kernel32", kind = "raw-dylib")]
    // rr: escape(unsafe): each signature is kernel32's, from its documentation.
    unsafe extern "system" {
        fn GetLastError() -> u32;
        fn SetLastError(code: u32);
    }

    const X509_PKCS7_ENCODING: u32 = 0x0001_0001;
    /// CERT_STORE_PROV_MEMORY and CERT_CHAIN_POLICY_SSL, numbers that
    /// stand where the functions take a string.
    const STORE_PROVIDER_MEMORY: usize = 2;
    const CHAIN_POLICY_SSL: usize = 4;
    const STORE_ADD_ALWAYS: u32 = 4;
    const USAGE_MATCH_TYPE_AND: u32 = 0;
    const AUTHTYPE_SERVER: u32 = 2;
    const SERVER_AUTH_C: &[u8] = b"1.3.6.1.5.5.7.3.1\0";
    /// 100 ns intervals from 1601 to 1970.
    const FILETIME_1970: i64 = 116_444_736_000_000_000;

    const ROOT: [u16; 5] = [0x52, 0x4F, 0x4F, 0x54, 0];
    const DISALLOWED: [u16; 11] = [
        0x44, 0x69, 0x73, 0x61, 0x6C, 0x6C, 0x6F, 0x77, 0x65, 0x64, 0,
    ];
    const CRYPT_E_NOT_FOUND: u32 = 0x8009_2004;
    const SERVER_AUTH: &[u8] = b"1.3.6.1.5.5.7.3.1";
    /// The certificates enumerated of a store, and the usages read of one.
    const CERTIFICATES_MAX: usize = 1 << 16;
    const USAGES_MAX: usize = 256;

    /// A certificate store, closed on drop.
    struct Store(*mut c_void);

    impl Drop for Store {
        fn drop(&mut self) {
            // rr: escape(unsafe): the store is ours and unused from here.
            unsafe { CertCloseStore(self.0, 0) };
        }
    }

    fn last_error() -> i32 {
        // rr: escape(unsafe): GetLastError takes nothing.
        unsafe { GetLastError() }.cast_signed()
    }

    /// The current user's system store name (UTF-16 with its NUL),
    /// which holds the machine's, Group Policy's and the enterprise's.
    fn open(name: &[u16]) -> Option<Store> {
        // rr: escape(unsafe): name is NUL-terminated.
        let store = unsafe { CertOpenSystemStoreW(0, name.as_ptr()) };
        if store.is_null() {
            None
        } else {
            Some(Store(store))
        }
    }

    pub fn collect(found: &mut Found) -> Result<(), Error> {
        let root = open(&ROOT).ok_or_else(|| Error::System(last_error()))?;
        each(&root, |context, der| {
            if server_auth(context) {
                found.push(der, false);
            }
        });
        // The system's distrusted certificates, when it has the store.
        if let Some(disallowed) = open(&DISALLOWED) {
            each(&disallowed, |_, der| found.push(der, true));
        }
        Ok(())
    }

    /// Calls f with each certificate of store and its DER.
    fn each(store: &Store, mut f: impl FnMut(*const Context, &[u8])) {
        let mut context = null();
        for _ in 0..CERTIFICATES_MAX {
            // Each call frees the context before it.
            // rr: escape(unsafe): context is null or the last one enumerated.
            context = unsafe { CertEnumCertificatesInStore(store.0, context) };
            if context.is_null() {
                return;
            }
            // rr: escape(unsafe): the store keeps the context until the next call.
            let certificate = unsafe { &*context };
            let length = usize::try_from(certificate.length).unwrap_or(0);
            if certificate.encoded.is_null() {
                continue;
            }
            // rr: escape(unsafe): the context holds length bytes of DER.
            let der = unsafe { core::slice::from_raw_parts(certificate.encoded, length) };
            f(context, der);
        }
        // rr: escape(unsafe): stopped early: the last context is ours to free.
        unsafe { CertFreeCertificateContext(context) };
    }

    /// Whether the certificate's usages, its extension's and those the
    /// store sets, allow server authentication, as certmgr shows them.
    fn server_auth(context: *const Context) -> bool {
        let mut size = 0u32;
        // rr: escape(unsafe): a null buffer asks for the size.
        if unsafe { CertGetEnhancedKeyUsage(context, 0, null_mut(), &raw mut size) } == 0 {
            return false;
        }
        let words = usize::try_from(size).unwrap_or(0) / 8 + 1;
        let mut buffer: Vec<u64> = Vec::new();
        buffer.resize(words.max(2), 0);
        let usage = buffer.as_mut_ptr().cast::<Usage>();
        // rr: escape(unsafe): SetLastError takes a plain number.
        unsafe { SetLastError(0) };
        // rr: escape(unsafe): buffer holds size bytes, aligned for Usage.
        if unsafe { CertGetEnhancedKeyUsage(context, 0, usage, &raw mut size) } == 0 {
            return false;
        }
        // rr: escape(unsafe): the call filled the Usage at the start.
        let Usage { count, identifiers } = unsafe { usage.read() };
        if count == 0 {
            // None at all is every usage; an empty list, none.
            return last_error() == CRYPT_E_NOT_FOUND.cast_signed();
        }
        let count = usize::try_from(count).unwrap_or(0).min(USAGES_MAX);
        (0..count).any(|index| {
            // rr: escape(unsafe): identifiers holds count pointers in buffer.
            let identifier = unsafe { identifiers.wrapping_add(index).read() };
            // rr: escape(unsafe): each is a C string in buffer.
            !identifier.is_null() && unsafe { CStr::from_ptr(identifier) }.to_bytes() == SERVER_AUTH
        })
    }

    /// The system verifies; nothing is kept.
    pub struct Trust;

    pub fn check(_trust: &Trust, chain: &[&[u8]], host: &str, now: i64) -> Check {
        if chain.is_empty() || chain.len() > x509::CHAIN_MAX || !super::named(host) {
            return Check::start(Err(Error::Input));
        }
        Check::start(Ok(Job::new(chain, host, now)))
    }

    /// What the thread checks: the chain's DER, where each certificate
    /// is in it, the host in UTF-16 with its NUL, and the time; copies,
    /// as the thread outlives the caller's borrow when the check is
    /// dropped.
    pub struct Job {
        bytes: Vec<u8>,
        ranges: Vec<(usize, usize)>,
        host: Vec<u16>,
        time: FileTime,
    }

    impl Job {
        fn new(chain: &[&[u8]], host: &str, now: i64) -> Job {
            let mut bytes = Vec::new();
            let mut ranges = Vec::with_capacity(chain.len());
            for der in chain {
                let start = bytes.len();
                bytes.extend_from_slice(der);
                ranges.push((start, bytes.len()));
            }
            let name = host.strip_suffix('.').unwrap_or(host);
            // rr: escape(copy): the host in UTF-16, as Windows takes it.
            let mut wide: Vec<u16> = name.encode_utf16().collect();
            wide.push(0);
            Job {
                bytes,
                ranges,
                host: wide,
                time: file_time(now),
            }
        }

        pub fn run(&self) -> Result<(), Error> {
            evaluate(self)
        }
    }

    /// size_of a struct the system takes, as its size member says it.
    fn size32(size: usize) -> u32 {
        u32::try_from(size).unwrap_or(0)
    }

    /// A certificate context of ours, freed on drop.
    struct Certificate(*const Context);

    impl Drop for Certificate {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // rr: escape(unsafe): the context is ours and unused from here.
                unsafe { CertFreeCertificateContext(self.0) };
            }
        }
    }

    /// A chain context of ours, freed on drop.
    struct Chain(*const ChainContext);

    impl Drop for Chain {
        fn drop(&mut self) {
            // rr: escape(unsafe): the chain is ours and unused from here.
            unsafe { CertFreeCertificateChain(self.0) };
        }
    }

    /// The system's verdict on the chain in shared: a chain to a root
    /// it trusts for server authentication, then the SSL policy for the
    /// host, as Go's systemVerify asks. It may fetch over the network.
    fn evaluate(shared: &Job) -> Result<(), Error> {
        let provider = without_provenance::<c_char>(STORE_PROVIDER_MEMORY);
        // rr: escape(unsafe): a memory store takes no parameter.
        let store = unsafe { CertOpenStore(provider, 0, 0, 0, null()) };
        if store.is_null() {
            return Err(Error::System(last_error()));
        }
        let store = Store(store);
        let mut leaf = Certificate(null());
        for (index, range) in shared.ranges.iter().enumerate() {
            let der = shared.bytes.get(range.0..range.1).unwrap_or_default();
            let length = u32::try_from(der.len()).unwrap_or(0);
            let out = if index == 0 {
                &raw mut leaf.0
            } else {
                null_mut()
            };
            // rr: escape(unsafe): der is readable for its length; out is
            // null or leaf's.
            let added = unsafe {
                CertAddEncodedCertificateToStore(
                    store.0,
                    X509_PKCS7_ENCODING,
                    der.as_ptr(),
                    length,
                    STORE_ADD_ALWAYS,
                    out,
                )
            };
            if added == 0 {
                return Err(Error::Input);
            }
        }
        let usages = [SERVER_AUTH_C.as_ptr().cast::<c_char>()];
        let parameters = ChainPara {
            size: size32(size_of::<ChainPara>()),
            requested: UsageMatch {
                rule: USAGE_MATCH_TYPE_AND,
                usage: Usage {
                    count: 1,
                    identifiers: usages.as_ptr(),
                },
            },
        };
        let mut chain = null();
        // rr: escape(unsafe): every pointer is to a value of this function's,
        // and chain a local out-parameter.
        let built = unsafe {
            CertGetCertificateChain(
                null_mut(),
                leaf.0,
                &raw const shared.time,
                store.0,
                &raw const parameters,
                0,
                null_mut(),
                &raw mut chain,
            )
        };
        if built == 0 || chain.is_null() {
            return Err(Error::System(last_error()));
        }
        let chain = Chain(chain);
        // rr: escape(unsafe): the chain context starts with these members.
        let status = unsafe { (*chain.0).error_status };
        if status != 0 {
            return Err(Error::Chain(status));
        }
        policy(&chain, &shared.host)
    }

    /// CERT_CHAIN_POLICY_SSL on chain for a server named host (UTF-16
    /// with its NUL).
    fn policy(chain: &Chain, host: &[u16]) -> Result<(), Error> {
        let ssl = SslPolicyPara {
            size: size32(size_of::<SslPolicyPara>()),
            auth_type: AUTHTYPE_SERVER,
            checks: 0,
            server_name: host.as_ptr(),
        };
        let parameters = PolicyPara {
            size: size32(size_of::<PolicyPara>()),
            flags: 0,
            extra: (&raw const ssl).cast(),
        };
        let mut status = PolicyStatus {
            size: size32(size_of::<PolicyStatus>()),
            error: 0,
            chain_index: 0,
            element_index: 0,
            extra: null_mut(),
        };
        let ssl_policy = without_provenance::<c_char>(CHAIN_POLICY_SSL);
        // rr: escape(unsafe): the chain is ours; the rest are locals.
        let done = unsafe {
            CertVerifyCertificateChainPolicy(
                ssl_policy,
                chain.0,
                &raw const parameters,
                &raw mut status,
            )
        };
        if done == 0 {
            return Err(Error::System(last_error()));
        }
        if status.error != 0 {
            return Err(Error::Policy(status.error));
        }
        Ok(())
    }

    /// now (Unix seconds) as a FILETIME; before 1970 is 1970.
    fn file_time(now: i64) -> FileTime {
        let ticks = now.saturating_mul(10_000_000).saturating_add(FILETIME_1970);
        let ticks = u64::try_from(ticks).unwrap_or(0);
        FileTime {
            low: u32::try_from(ticks & 0xFFFF_FFFF).unwrap_or(0),
            high: u32::try_from(ticks >> 32).unwrap_or(u32::MAX),
        }
    }
}

/// A check the system runs on a thread of its own, on macOS and
/// Windows: the thread and the check share a block, which the last of
/// the two to let go frees, so a check dropped while the thread runs
/// never waits for it.
#[cfg(any(target_os = "macos", target_os = "windows"))]
mod thread {
    use super::Error;
    use super::os::Job;
    use crate::base::wait::{self, Signal, Wait};
    use alloc::boxed::Box;
    use core::cell::UnsafeCell;
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// The thread writes result, then sets done and the signal; the
    /// check reads result only after it saw done.
    struct Shared {
        holders: AtomicUsize,
        done: AtomicBool,
        result: UnsafeCell<Result<(), Error>>,
        signal: Signal,
        job: Job,
    }

    /// Lets go of shared; the last holder frees it.
    fn release(shared: *mut Shared) {
        // rr: escape(unsafe): shared lives until its holders let go.
        let holders = unsafe { &(*shared).holders };
        if holders.fetch_sub(1, Ordering::AcqRel) == 1 {
            // rr: escape(unsafe): no one else holds it now.
            drop(unsafe { Box::from_raw(shared) });
        }
    }

    fn run(argument: *mut c_void) {
        let shared = argument.cast::<Shared>();
        // rr: escape(unsafe): the thread is a holder of shared.
        let state = unsafe { &*shared };
        let result = state.job.run();
        // rr: escape(unsafe): only this thread touches result before done.
        unsafe { *state.result.get() = result };
        state.done.store(true, Ordering::Release);
        state.signal.set();
        release(shared);
    }

    pub struct Check {
        shared: *mut Shared,
        /// The answer, once known and not yet polled.
        taken: Option<Result<(), Error>>,
        /// The work, to take out of spawn's line when dropped before it
        /// started.
        ticket: Option<wait::Ticket>,
    }

    impl Check {
        /// Runs job on a thread of its own, or answers with its error.
        pub fn start(job: Result<Job, Error>) -> Check {
            let mut check = Check {
                shared: null_mut(),
                taken: None,
                ticket: None,
            };
            let job = match job {
                Ok(job) => job,
                Err(error) => {
                    check.taken = Some(Err(error));
                    return check;
                }
            };
            let Some(signal) = Signal::new() else {
                check.taken = Some(Err(Error::Thread));
                return check;
            };
            let shared = Box::new(Shared {
                // rr: escape(shared): the check and the thread both hold it.
                holders: AtomicUsize::new(2),
                // rr: escape(shared): the thread says it is done.
                done: AtomicBool::new(false),
                // rr: escape(shared): the thread's answer, handed over once.
                result: UnsafeCell::new(Err(Error::Polled)),
                signal,
                job,
            });
            // rr: escape(leak): the check and the thread hold it, and release
            // frees it.
            let raw = Box::into_raw(shared);
            check.shared = raw;
            check.ticket = wait::spawn(run, raw.cast());
            if check.ticket.is_none() {
                // The thread never held it.
                release(raw);
                check.taken = Some(Err(Error::Thread));
            }
            check
        }

        pub fn poll(&mut self) -> Option<Result<(), Error>> {
            if self.taken.is_none() && !self.shared.is_null() {
                // rr: escape(unsafe): this check holds shared.
                let shared = unsafe { &*self.shared };
                if !shared.done.load(Ordering::Acquire) {
                    return None;
                }
                // rr: escape(unsafe): the thread is done with result.
                let result = unsafe { &mut *shared.result.get() };
                self.taken = Some(core::mem::replace(result, Err(Error::Polled)));
                release(self.shared);
                self.shared = null_mut();
            }
            self.taken.take()
        }
    }

    pub fn wait(check: &Check) -> Wait {
        if check.taken.is_some() || check.shared.is_null() {
            return Wait::READY;
        }
        // rr: escape(unsafe): this check holds shared.
        let shared = unsafe { &*check.shared };
        shared.signal.wait()
    }

    impl Drop for Check {
        fn drop(&mut self) {
            if self.shared.is_null() {
                return;
            }
            // Work still in line never runs: its holder is let go here.
            if self.ticket.as_ref().is_some_and(wait::Ticket::cancel) {
                release(self.shared);
            }
            // The thread, when it runs on, frees what is left.
            release(self.shared);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::unix::{self, CERT_FILES, ENOENT, Files};
    use super::{Error, Found, pem_block};
    use crate::base::x509::{Store, TEST_NOW, test_certificate};
    use alloc::vec::Vec;

    /// x509's test certificates: anchors, intermediates and leaves.
    const TESTS: &[u8] = include_bytes!("../x509/x509-tests.pem");
    const EACCES: i32 = 13;

    /// A file's path, and its text or the error reading it gives.
    type File<'a> = (&'a [u8], Result<&'a [u8], i32>);

    /// Files from a table, and directories' names.
    struct Fake<'a> {
        files: &'a [File<'a>],
        dirs: &'a [(&'a [u8], &'a [u8])],
    }

    impl Files for Fake<'_> {
        fn read(&mut self, path: &[u8], text: &mut Vec<u8>) -> Result<(), i32> {
            text.clear();
            let found = self.files.iter().find(|(name, _)| *name == path);
            let contents = found.map_or(Err(ENOENT), |(_, contents)| *contents)?;
            text.extend_from_slice(contents);
            Ok(())
        }

        fn list(&mut self, dir: &[u8], names: &mut Vec<u8>) -> Result<(), i32> {
            let found = self.dirs.iter().find(|(name, _)| *name == dir);
            names.extend_from_slice(found.ok_or(ENOENT)?.1);
            Ok(())
        }
    }

    /// The PEM block under "# name" in x509's tests, with its markers.
    fn block(name: &str) -> &'static [u8] {
        let line = [b"# ", name.as_bytes(), b"\n"].concat();
        let at = TESTS.windows(line.len()).position(|w| w == line).unwrap();
        let rest = &TESTS[at + line.len()..];
        let (_, after) = pem_block(rest).unwrap();
        &rest[..rest.len() - after.len()]
    }

    /// The anchors of x509's tests, from them as the only bundle.
    fn anchors() -> usize {
        let mut fake = Fake {
            files: &[(b"/b", Ok(TESTS))],
            dirs: &[],
        };
        load(&mut fake, Some(b"/b"), Some(b"/none")).unwrap()
    }

    fn load(fake: &mut Fake<'_>, file: Option<&[u8]>, dirs: Option<&[u8]>) -> Result<usize, Error> {
        let mut found = Found::new();
        let error = unix::collect(fake, file, dirs, &mut found);
        let added = found.add_to(&mut Store::new());
        match error {
            Some(error) if added == 0 => Err(Error::System(error)),
            Some(_) | None => Ok(added),
        }
    }

    /// Debian: the bundle, and the same certificates again as files of
    /// /etc/ssl/certs, the bundle among them, each added once.
    #[test]
    fn debian() {
        let mut fake = Fake {
            files: &[
                (CERT_FILES[0], Ok(TESTS)),
                (b"/etc/ssl/certs/a.pem", Ok(block("anchor.sectigo-e46"))),
            ],
            dirs: &[(b"/etc/ssl/certs", b"ca-certificates.crt\0a.pem\0")],
        };
        let anchors = anchors();
        assert!(anchors > 4, "{anchors}");
        assert_eq!(load(&mut fake, None, None), Ok(anchors));
    }

    /// The first bundle that reads is the one, past one that does not;
    /// the directories are read whether or not one was.
    #[test]
    fn first_bundle() {
        let mut fake = Fake {
            files: &[
                (CERT_FILES[1], Err(EACCES)),
                (CERT_FILES[4], Ok(block("anchor.sectigo-e46"))),
                (CERT_FILES[5], Ok(block("anchor.gts-r4"))),
                (b"/etc/pki/tls/certs/b.pem", Ok(block("anchor.isrg-x2"))),
            ],
            dirs: &[(b"/etc/pki/tls/certs", b"b.pem\0")],
        };
        assert_eq!(load(&mut fake, None, None), Ok(2));
    }

    /// SSL_CERT_FILE and SSL_CERT_DIR take the place of Go's lists; an
    /// empty directory in SSL_CERT_DIR is none.
    #[test]
    fn environment() {
        let mut fake = Fake {
            files: &[
                (CERT_FILES[0], Ok(TESTS)),
                (b"/x.pem", Ok(block("anchor.sectigo-e46"))),
                (b"/d1/c", Ok(block("anchor.gts-r4"))),
                (b"/d2/c", Ok(block("anchor.isrg-x2"))),
            ],
            dirs: &[
                (b"/etc/ssl/certs", b"ca-certificates.crt\0"),
                (b"/d1", b"c\0"),
                (b"/d2", b"c\0"),
            ],
        };
        assert_eq!(load(&mut fake, Some(b"/x.pem"), Some(b"/d1::/d2")), Ok(3));
    }

    /// Nothing there is no anchor and no error; nothing found past an
    /// error is that error.
    #[test]
    fn nothing() {
        let mut empty = Fake {
            files: &[],
            dirs: &[],
        };
        assert_eq!(load(&mut empty, None, None), Ok(0));
        let mut refused = Fake {
            files: &[(CERT_FILES[2], Err(EACCES))],
            dirs: &[],
        };
        assert_eq!(load(&mut refused, None, None), Err(Error::System(EACCES)));
    }

    /// A denied certificate is left out wherever it was trusted; a
    /// block with headers is not a certificate.
    #[test]
    fn denied_and_headers() {
        let der = test_certificate("letsencrypt.x2cross").unwrap();
        let mut found = Found::new();
        found.pem(TESTS);
        found.push(&der, false);
        found
            .pem(b"-----BEGIN CERTIFICATE-----\nProc-Type: 4\n\nAAAA\n-----END CERTIFICATE-----\n");
        let mut first = Found::new();
        first.pem(block("anchor.sectigo-e46"));
        let denied = first.bytes;
        found.push(&denied, true);
        let mut store = Store::new();
        // The cross-signed root is among the tests: all less the denied one.
        assert_eq!(found.add_to(&mut store), anchors() - 1);
    }

    /// This system's anchors verify chains of x509's tests that end at
    /// roots every system trusts.
    #[cfg(target_os = "macos")]
    #[test]
    fn system_chains() {
        let mut store = Store::new();
        let added = super::system(&mut store).unwrap();
        assert!(added > 100, "{added}");
        assert_eq!(store.len(), added);
        for (names, host) in CHAINS {
            let certificates = certificates(names);
            // rr: escape(copy): the chain verify takes, borrowed from them.
            let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
            assert!(
                crate::base::x509::verify(&chain, &store, host, TEST_NOW).is_ok(),
                "{host}"
            );
        }
    }

    /// x509's test chains: real servers' at TEST_NOW, and its own PKI.
    const CHAINS: [(&[&str], &str); 3] = [
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
            "lencr.org",
        ),
        (&["github.leaf", "github.e36", "github.e46"], "github.com"),
    ];

    fn certificates(names: &[&str]) -> Vec<Vec<u8>> {
        // rr: escape(copy): the test's certificates, decoded once.
        names
            .iter()
            .map(|name| test_certificate(name).unwrap())
            .collect()
    }

    /// The system's own verifier takes the real chains for their hosts,
    /// through the poll loop and blocking, and refuses one for another
    /// host and one of a PKI it does not trust.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn platform() {
        let trust = super::Trust::new().unwrap();
        for (names, host) in CHAINS {
            let certificates = certificates(names);
            // rr: escape(copy): the chain check takes, borrowed from them.
            let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
            assert_eq!(trust.verify(&chain, host, TEST_NOW), Ok(()), "{host}");
            let mut check = trust.check(&chain, host, TEST_NOW);
            let result = (0..1000)
                .find_map(|_| {
                    let result = check.poll();
                    if result.is_none() {
                        crate::base::wait::block(&check.wait());
                    }
                    result
                })
                .unwrap();
            assert_eq!(result, Ok(()), "{host}");
            assert_eq!(check.poll(), Some(Err(Error::Polled)));
            let wrong = trust.verify(&chain, "example.com", TEST_NOW);
            // errSecHostNameMismatch, CERT_E_CN_NO_MATCH.
            #[cfg(target_os = "macos")]
            assert_eq!(wrong, Err(Error::Refused(-67602)));
            #[cfg(target_os = "windows")]
            assert_eq!(wrong, Err(Error::Policy(0x800B_010F)));
            // A check dropped while it runs is let go.
            drop(trust.check(&chain, host, TEST_NOW));
        }
        let certificates = certificates(&["test.leaf", "test.inter", "test.root"]);
        // rr: escape(copy): the chain check takes, borrowed from them.
        let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
        let refused = trust.verify(&chain, "leaf.example.test", TEST_NOW);
        #[cfg(target_os = "macos")]
        assert!(matches!(refused, Err(Error::Refused(_))));
        #[cfg(target_os = "windows")]
        assert!(matches!(refused, Err(Error::Chain(_))));
        assert_eq!(trust.verify(&[], "x.test", TEST_NOW), Err(Error::Input));
        // A NUL would end the name where Windows reads it.
        assert_eq!(
            trust.verify(&chain, "leaf.example.test\0.x", TEST_NOW),
            Err(Error::Input)
        );
        assert_eq!(trust.verify(&chain, "", TEST_NOW), Err(Error::Input));
        assert_eq!(
            trust.verify(&[b"no"], "x.test", TEST_NOW),
            Err(Error::Input)
        );
    }

    /// Linux's Trust is x509::verify on its anchors: here the test
    /// anchors, which the real chains end at.
    #[cfg(target_os = "linux")]
    #[test]
    fn verifies_on_anchors() {
        let mut store = Store::new();
        store.add_pem(TESTS);
        let trust = super::Trust::with(store);
        for (names, host) in CHAINS {
            let certificates = certificates(names);
            // rr: escape(copy): the chain check takes, borrowed from them.
            let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
            assert_eq!(trust.verify(&chain, host, TEST_NOW), Ok(()), "{host}");
            let wrong = trust.verify(&chain, "example.com", TEST_NOW);
            assert_eq!(wrong, Err(Error::Untrusted(crate::base::x509::Error::Host)));
        }
    }

    /// One check of OpenAI's chain by the system's verifier.
    #[cfg(target_os = "macos")]
    #[bench]
    fn platform_check(b: &mut test::Bencher) {
        let trust = super::Trust::new().unwrap();
        let certificates = certificates(CHAINS[0].0);
        // rr: escape(copy): the chain check takes, borrowed from them.
        let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
        b.iter(|| trust.verify(&chain, "api.openai.com", TEST_NOW).is_ok());
    }

    /// Loading the system's anchors, as a program does once.
    #[cfg(target_os = "macos")]
    #[bench]
    fn load_system(b: &mut test::Bencher) {
        b.iter(|| super::store().unwrap().len());
    }
}
