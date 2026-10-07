use std::path::Path;
use std::process::ExitCode;
use std::{env, io};

#[path = "rr_cli/workspace.rs"]
mod workspace;

pub fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("rr: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> io::Result<ExitCode> {
    let dcx = rustc_session::EarlyDiagCtxt::new(rustc_session::config::ErrorOutputType::default());
    let raw = rustc_driver::args::raw_args(&dcx);
    let mut args = rustc_driver::args::arg_expand_all(&dcx, &raw[1..]);
    let Some(first) = args.first().map(String::as_str) else {
        help();
        return Ok(ExitCode::SUCCESS);
    };
    match first {
        "--help" | "-h" | "help" => {
            help();
            return Ok(ExitCode::SUCCESS);
        },
        "--version" | "-V" => {
            println!("rr 0.1.0 (Restricted Rust; Clippy rust-1.99.0; rustc 1.99.0-nightly 84b36a78a)");
            return Ok(ExitCode::SUCCESS);
        },
        "init" => return workspace::init(&args[1..]),
        _ => {},
    }
    let command = if matches!(first, "build" | "check" | "lint") {
        args.remove(0)
    } else {
        "build".to_owned()
    };
    let checking = command != "build";
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
    if command != "lint" {
        compiler.push("-Aclippy::all".into());
    }
    if !args.iter().any(|arg| has_key(arg, "--sysroot")) {
        let bundle = env::current_exe()?
            .parent()
            .ok_or_else(|| io::Error::other("missing executable directory"))?
            .to_owned();
        if bundle.join("lib/rustlib").is_dir() {
            compiler.extend(["--sysroot".into(), bundle.to_string_lossy().into_owned()]);
        }
    }
    let scratch = if checking {
        Some(workspace::Scratch::new()?)
    } else {
        None
    };
    compiler.append(&mut args);
    if let Some(scratch) = &scratch {
        compiler.extend([
            "--emit=metadata".into(),
            "--out-dir".into(),
            scratch.path.to_string_lossy().into_owned(),
        ]);
    }
    Ok(crate::driver_core::run(compiler, true))
}

fn has_key(arg: &str, key: &str) -> bool {
    arg.strip_prefix(key)
        .is_some_and(|tail| tail.is_empty() || tail.starts_with('='))
}

fn help() {
    println!(
        "rr — Restricted Rust\n\nUsage:\n  rr FILE [RUSTC FLAGS]          Compile with restrictions\n  rr build FILE [RUSTC FLAGS]    Compile with restrictions\n  rr check FILE [RUSTC FLAGS]    Check without build artifacts\n  rr lint FILE [RUSTC FLAGS]     Check with Clippy lints too\n  rr init [DIR] [--lib|--bin]    Create lib.rs or main.rs (default: bin)\n\nNo Cargo or project manifest. Edition 2024 and panic=abort by default.\nUse -O, -o, --crate-type, --target, --extern and -L like rustc.\nRequires no_std. Type/const generic definitions, impl Trait, dyn Trait,\ncomplex traits, async/await and macros (except core panic/assert) are forbidden.\nEscape hatches require an adjacent // rr: escape: <reason>.\nBundled sysroot is selected automatically; --sysroot can override it."
    );
}
