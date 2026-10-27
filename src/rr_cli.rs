use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{env, io};

#[path = "rr_cli/workspace.rs"]
mod workspace;

#[path = "rr_cli/fuz.rs"]
mod fuz;

#[path = "rr_cli/prof.rs"]
mod prof;

#[path = "rr_cli/fmt.rs"]
mod fmt;

#[path = "rr_cli/test.rs"]
mod test;

#[path = "rr_cli/target.rs"]
mod target;

pub fn main() -> ExitCode {
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
            println!("rr 0.3.0 (Restricted Rust; Clippy and rustc 1.99.1, 58cf8f9c3)");
            Ok(ExitCode::SUCCESS)
        },
        "init" => workspace::init(rest),
        "fmt" => fmt::run(rest),
        "fuz" => fuz::run(rest),
        "prof" => prof::run(rest),
        "test" => test::run(rest, false),
        "bench" => test::run(rest, true),
        // Internal: rr test and rr bench build their runtime with this:
        // DIR [counts] [--target TARGET].
        "__test-runtime" if args.len() >= 2 => {
            let counts = args.iter().any(|a| a == "counts");
            Ok(test::build_runtime(
                raw0,
                Path::new(&args[1]),
                counts,
                target::named(args).as_deref(),
            ))
        },
        // Internal: rr build --prof builds its runtime with this, in a
        // child: DIR [--target TARGET].
        "__prof-runtime" if args.len() >= 2 => Ok(prof::build_runtime(
            raw0,
            Path::new(&args[1]),
            target::named(args).as_deref(),
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
    if !args.iter().any(|arg| has_key(arg, "--sysroot")) {
        let bundle = executable()?
            .parent()
            .ok_or_else(|| io::Error::other("missing executable directory"))?
            .to_owned();
        if bundle.join("lib/rustlib").is_dir() {
            // A distribution builds for its host only.
            if let Some(t) = target::named(&args)
                && !bundle.join("lib/rustlib").join(&t).is_dir()
            {
                return Err(io::Error::other(format!(
                    "this rr builds for its host only and has no sysroot for {t}"
                )));
            }
            compiler.extend(["--sysroot".into(), bundle.to_string_lossy().into_owned()]);
        }
    }
    let artifact = final_artifact(&args, &compiler);
    compiler.extend(target::flags(&args, artifact));
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
            target::chosen(&args).as_deref(),
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
        "rr — Restricted Rust\n\nUsage:\n  rr FILE [RUSTC FLAGS]          Compile with restrictions\n  rr build FILE [RUSTC FLAGS]    Compile with restrictions\n  rr check FILE [RUSTC FLAGS]    Check without build artifacts\n  rr lint FILE [RUSTC FLAGS]     Check with Clippy lints too\n  rr fmt [--check] FILE...       Format a crate (--check: show what differs)\n  rr init [DIR] [--lib]          Create a project (or src/lib.rs alone)\n  rr test FILE [--check|--lint] [FLAGS] [-- FILTER]\n                                 Build and run the crate's #[test] items\n  rr bench FILE [FLAGS] [-- FILTER]\n                                 Measure the crate's #[bench] items\n  rr fuz FILE --target PATH [FLAGS] -- [ARGS]\n                                 Fuzz the crate's function at PATH\n  rr fuz FILE [FLAGS] -- [ARGS]  Build and run a libFuzzer harness\n  rr fuz init [DIR]             Create fuz.rs, corpus/ and artifacts/\n  rr build --prof FILE ...       Build to record allocations and copies by stack\n  rr prof -- COMMAND [ARGS]      Run COMMAND and report where it allocates and copies\n\nNo Cargo or project manifest. Edition 2024 and panic=abort by default.\nUse -O, -o, --crate-type, --target, --extern and -L like rustc.\nRequires no_std. Type/const generic definitions, impl Trait, dyn Trait,\ncomplex traits, async/await and macros (except no_std compiler builtins and core panic/assert) are forbidden.\nEscape hatches require an adjacent // rr: escape(kind): <reason> naming their kind.\nBundled sysroot is selected automatically; --sysroot can override it."
    );
}
