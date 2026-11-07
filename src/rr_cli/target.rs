//! The target and sysroot a command names: rr passes them on as rustc
//! takes them, and builds its runtimes for the same. Which targets there
//! are, and their standard libraries, is the toolchain's: rustup installs
//! them (`rustup target add`).

/// The target args name with --target; none is the host.
pub fn named(args: &[String]) -> Option<String> {
    value(args, "--target")
}

/// The sysroot args name with --sysroot: a runtime is built against the
/// same standard library as the crate it links into.
pub fn sysroot(args: &[String]) -> Option<String> {
    value(args, "--sysroot")
}

/// The value of key in args, as `key value` or `key=value`.
fn value(args: &[String], key: &str) -> Option<String> {
    let i = args.iter().position(|arg| super::has_key(arg, key))?;
    match args[i].strip_prefix(key).and_then(|rest| rest.strip_prefix('=')) {
        Some(value) => Some(value.to_owned()),
        None => args.get(i + 1).cloned(),
    }
}

/// The arguments that pass target and sysroot on to a child rr that
/// builds a runtime.
pub fn for_child(target: Option<&str>, sysroot: Option<&str>) -> Vec<String> {
    let mut args = Vec::new();
    for (key, value) in [("--target", target), ("--sysroot", sysroot)] {
        if let Some(value) = value {
            args.extend([key.to_owned(), value.to_owned()]);
        }
    }
    args
}

/// Whether target, or the host when it names none, makes Windows
/// executables, which end in .exe.
pub fn is_windows(target: Option<&str>) -> bool {
    target.map_or(cfg!(windows), |t| t.contains("-windows"))
}

/// The flags that build one of rr's runtimes, an rlib, for target.
pub fn for_runtime(args: &mut Vec<String>, target: Option<&str>, sysroot: Option<&str>) {
    for (key, value) in [("--target", target), ("--sysroot", sysroot)] {
        if let Some(value) = value {
            args.extend([key.to_owned(), value.to_owned()]);
        }
    }
}
