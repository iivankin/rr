//! The targets rr builds for: its host's only. On macOS a program is
//! linked against the system's C library, as Apple requires. rr's own
//! targets, described in targets/*.json and built into the bundle's
//! sysroot, need no C library: `*-rr-linux` calls the kernel,
//! `*-rr-windows` calls kernel32.dll, and both start in `rr_crt`, which
//! hands argc and argv to the program's `main`. On Linux and Windows the
//! host's rr target is the default; a fuzz target is built for the host's
//! own target, with its C library, which libFuzzer needs.

use std::env::consts::ARCH;

/// The targets rr ships a sysroot for, besides macOS.
pub const RR: &[&str] = &[
    "x86_64-rr-linux",
    "aarch64-rr-linux",
    "x86_64-rr-windows",
    "aarch64-rr-windows",
];

/// The target that args name with --target, or the host's default.
pub fn chosen(args: &[String]) -> Option<String> {
    named(args).or_else(|| host().map(str::to_owned))
}

/// The target args name with --target.
pub fn named(args: &[String]) -> Option<String> {
    let i = args.iter().position(|arg| super::has_key(arg, "--target"))?;
    match args[i].strip_prefix("--target=") {
        Some(name) => Some(name.to_owned()),
        None => args.get(i + 1).cloned(),
    }
}

/// The rr target of this host, when it is not macOS.
pub fn host() -> Option<&'static str> {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        return None;
    };
    RR.iter().copied().find(|t| t.starts_with(ARCH) && t.ends_with(os))
}

/// Whether target is one of rr's own.
pub fn is_rr(target: Option<&str>) -> bool {
    target.is_some_and(|t| RR.contains(&t))
}

/// Whether target makes Windows executables, which end in .exe.
pub fn is_windows(target: Option<&str>) -> bool {
    target.is_some_and(|t| t.ends_with("-windows"))
}

/// The compiler flags for args's target: the host's default when args
/// name none; for rr's targets, which the compiler reads from the sysroot,
/// leave to do so, and for a final artifact, `rr_crt`.
pub fn flags(args: &[String], artifact: bool) -> Vec<String> {
    let mut flags = Vec::new();
    let named = named(args);
    let target = named.clone().or_else(|| host().map(str::to_owned));
    if named.is_none()
        && let Some(t) = &target
    {
        flags.extend(["--target".to_owned(), t.clone()]);
    }
    if is_rr(target.as_deref()) {
        flags.push("-Zunstable-options".to_owned());
        if artifact {
            flags.extend(["--extern".to_owned(), "force:rr_crt".to_owned()]);
        }
    }
    flags
}

/// The flags that build one of rr's runtimes, an rlib, for target.
pub fn for_runtime(args: &mut Vec<String>, target: Option<&str>) {
    if let Some(t) = target {
        args.extend(["--target".to_owned(), t.to_owned()]);
    }
    if is_rr(target) {
        args.push("-Zunstable-options".to_owned());
    }
}
