use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, io};

#[path = "rr_cli/workspace.rs"]
mod workspace;

#[path = "rr_cli/add.rs"]
mod add;

#[path = "rr_cli/fuz.rs"]
mod fuz;

#[path = "rr_cli/prof.rs"]
mod prof;

#[path = "rr_cli/time.rs"]
mod time;

#[path = "rr_cli/fmt.rs"]
mod fmt;

#[path = "rr_cli/test.rs"]
mod test;

#[path = "rr_cli/target.rs"]
mod target;

/// What rr add compares with the rr a component was checked with.
pub const VERSION: &str = "0.5.0";

pub fn main() -> ExitCode {
    // rr builds on the official compiler, a stable one, and uses what only
    // a nightly one takes: a tool attribute (rr::hot), the test harness of
    // a no_std crate, a forced extern for its runtimes. RUSTC_BOOTSTRAP
    // lets it, as the compiler's own build and the Linux kernel's do; the
    // children rr starts, its runtimes' builds, inherit it.
    // SAFETY: no other thread runs yet, so none reads the environment.
    unsafe { env::set_var("RUSTC_BOOTSTRAP", "1") };
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("rr: {error}");
            ExitCode::FAILURE
        },
    }
}

/// The commands other than the compiler's own: what one of them returned,
/// or None when args are a compile.
fn subcommand(raw0: &str, args: &[String]) -> Option<io::Result<ExitCode>> {
    let rest = &args[1..];
    Some(match args[0].as_str() {
        "--help" | "-h" | "help" => {
            help();
            Ok(ExitCode::SUCCESS)
        },
        "--version" | "-V" => {
            println!("rr {VERSION} (Restricted Rust; Clippy and rustc 1.99.1, 58cf8f9c3)");
            Ok(ExitCode::SUCCESS)
        },
        "init" => workspace::init(rest),
        "add" => add::run(rest),
        "fmt" => fmt::run(rest),
        "fuz" => fuz::run(rest),
        "prof" => prof::run(rest),
        "time" => time::run(rest),
        "test" => test::run(rest, false),
        "bench" => test::run(rest, true),
        // Internal: rr test and rr bench build their runtime with this:
        // DIR [counts] [--target TARGET] [--sysroot SYSROOT].
        "__test-runtime" if args.len() >= 2 => {
            let counts = args.iter().any(|a| a == "counts");
            Ok(test::build_runtime(
                raw0,
                Path::new(&args[1]),
                counts,
                target::named(args).as_deref(),
                target::sysroot(args).as_deref(),
            ))
        },
        // Internal: rr build --prof builds its runtime with this, in a
        // child: DIR [--target TARGET] [--sysroot SYSROOT].
        "__prof-runtime" if args.len() >= 2 => Ok(prof::build_runtime(
            raw0,
            Path::new(&args[1]),
            target::named(args).as_deref(),
            target::sysroot(args).as_deref(),
        )),
        _ => return None,
    })
}

fn run() -> io::Result<ExitCode> {
    let dcx = rustc_session::EarlyDiagCtxt::new(rustc_session::config::ErrorOutputType::default());
    let raw = rustc_driver::args::raw_args(&dcx);
    let mut args = rustc_driver::args::arg_expand_all(&dcx, &raw[1..]);
    let Some(first) = args.first().map(String::as_str) else {
        help();
        return Ok(ExitCode::SUCCESS);
    };
    if let Some(done) = subcommand(&raw[0], &args) {
        return done;
    }
    let command = if matches!(first, "build" | "check" | "lint") {
        args.remove(0)
    } else {
        "build".to_owned()
    };
    let checking = command != "build";
    let profiling = args.iter().any(|arg| arg == "--prof");
    // A program is built by rustc; rr builds only what its own commands
    // run: a --prof build for rr prof, and what rr test, rr bench and rr
    // fuz run, which they mark --rr-run.
    let own_run = args.iter().any(|arg| arg == "--rr-run");
    args.retain(|arg| arg != "--rr-run");
    // --print asks the compiler and builds nothing.
    let printing = args.iter().any(|arg| has_key(arg, "--print"));
    if !checking && !profiling && !own_run && !printing {
        return Err(io::Error::other(
            "rr checks a crate (rr check, rr lint); build it with rustc, or with rr build --prof for rr prof",
        ));
    }
    args.retain(|arg| arg != "--prof");
    if profiling && args.iter().any(|arg| arg.contains("strip=")) {
        return Err(io::Error::other("a --prof build keeps its symbols: drop -C strip"));
    }
    if args.iter().any(|arg| arg == "--rustc") {
        return Err(io::Error::other("--rustc cannot bypass rr restrictions"));
    }
    if checking
        && args
            .iter()
            .any(|arg| has_key(arg, "--emit") || has_key(arg, "--out-dir") || arg.starts_with("-o"))
    {
        return Err(io::Error::other(
            "check/lint do not write build artifacts; use build with output flags",
        ));
    }
    let mut compiler = vec![raw[0].clone()];
    if !args.iter().any(|arg| has_key(arg, "--edition")) {
        compiler.push("--edition=2024".into());
    }
    if !args.iter().any(|arg| has_key(arg, "--crate-type"))
        && args
            .iter()
            .any(|arg| Path::new(arg).file_name().is_some_and(|name| name == "lib.rs"))
    {
        compiler.push("--crate-type=rlib".into());
    }
    compiler.push("-Cpanic=abort".into());
    // rr attributes resolve as a registered tool, and `--cfg rr` lets code
    // write them as #[cfg_attr(rr, rr::hot)], which plain rustc and
    // rust-analyzer skip.
    compiler.push("-Zcrate-attr=feature(register_tool)".into());
    compiler.push("-Zcrate-attr=register_tool(rr)".into());
    // Integers to pointers and back are rewritten with addr and with_addr.
    compiler.push("-Zcrate-attr=feature(strict_provenance_lints)".into());
    compiler.extend(["--cfg".into(), "rr".into()]);
    // Checked under cfg(fuzzing) without the harness rr fuz adds, the fuzz
    // targets have no caller; the check without the cfg finds dead code.
    if checking && args.windows(2).any(|pair| pair[0] == "--cfg" && pair[1] == "fuzzing") {
        compiler.push("-Adead_code".into());
    }
    if command != "lint" {
        compiler.push("-Aclippy::all".into());
    }
    let artifact = final_artifact(&args, &compiler);
    let scratch = if checking || profiling {
        Some(workspace::Scratch::new()?)
    } else {
        None
    };
    // Every --prof crate renames the allocator functions it defines; the
    // final artifact also links the runtime that defines the ones called.
    let shim = profiling && !checking;
    if profiling {
        prof::flags(
            &mut compiler,
            artifact && !checking,
            scratch.as_ref().map(|s| s.path.as_path()),
            target::named(&args).as_deref(),
            target::sysroot(&args).as_deref(),
        )?;
    }
    compiler.append(&mut args);
    if checking && let Some(scratch) = &scratch {
        compiler.extend([
            "--emit=metadata".into(),
            "--out-dir".into(),
            scratch.path.to_string_lossy().into_owned(),
        ]);
    }
    Ok(crate::driver_core::run(compiler, true, shim))
}

/// Whether the crate is a final artifact, which links an allocator shim,
/// rather than a library.
fn final_artifact(args: &[String], compiler: &[String]) -> bool {
    args.iter()
        .position(|arg| has_key(arg, "--crate-type"))
        .and_then(|i| {
            args[i]
                .strip_prefix("--crate-type=")
                .or(args.get(i + 1).map(String::as_str))
        })
        .map_or(!compiler.iter().any(|arg| arg == "--crate-type=rlib"), |kind| {
            !matches!(kind, "lib" | "rlib")
        })
}

fn has_key(arg: &str, key: &str) -> bool {
    arg.strip_prefix(key)
        .is_some_and(|tail| tail.is_empty() || tail.starts_with('='))
}

fn executable() -> io::Result<PathBuf> {
    // Resolve launch symlinks so runtime libraries remain relative to the bundle.
    canonical(&env::current_exe()?)
}

/// path with its links resolved. On Windows that is a `\\?\` path, which
/// many programs do not read: a drive path drops the prefix.
fn canonical(path: &Path) -> io::Result<PathBuf> {
    let resolved = path.canonicalize()?;
    let text = resolved.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => Ok(PathBuf::from(rest)),
        _ => Ok(resolved),
    }
}

fn help() {
    println!(
        "rr — Restricted Rust: a checker on the official Rust release it is built on\n\nUsage:\n  rr check FILE [RUSTC FLAGS]    Check with rr's rules\n  rr lint FILE [RUSTC FLAGS]     Check with Clippy's lints too\n  rr fmt [--check] FILE...       Format a crate (--check: show what differs)\n  rr init [DIR] [--lib]          Create a project (or src/lib.rs alone)\n  rr add COMPONENT...            Copy a registry component into src/\n  rr test FILE [--check|--lint] [FLAGS] [-- FILTER]\n                                 Build and run the crate's #[test] items\n  rr bench FILE [FLAGS] [-- FILTER]\n                                 Measure the crate's #[bench] items\n  rr fuz FILE --target PATH [FLAGS] -- [ARGS]\n                                 Fuzz the crate's function at PATH\n  rr build --prof FILE ...       Build to record allocations and copies by stack\n  rr prof -- COMMAND [ARGS]      Run COMMAND and report where it allocates and copies\n  rr time -- COMMAND [ARGS]      Run COMMAND a few times and report how long it took\n\nrustc builds a program; rr checks it, and builds only what its own commands\nrun. No Cargo or project manifest. Edition 2024 and panic=abort by default.\nUse --target, --extern, -L, --crate-type and --cfg like rustc.\nRequires no_std. Type/const generic definitions, impl Trait, dyn Trait,\ncomplex traits, async/await and macros (except no_std compiler builtins and core panic/assert) are forbidden.\nEscape hatches require an adjacent // rr: escape(kind): <reason> naming their kind."
    );
}
