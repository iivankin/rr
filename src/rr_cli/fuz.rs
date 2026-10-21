use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::{Command, ExitCode, ExitStatus};

use super::{executable, has_key, workspace};

const TEMPLATE: &str = include_str!("../../examples/fuzz/fuzz.rs.in");
/// libFuzzer, as the bundle keeps it for the host.
const FUZZER: &str = if cfg!(windows) { "Fuzzer.lib" } else { "libFuzzer.a" };

/// `--target PATH`, taken out of flags: the crate's own function at PATH, a
/// fn(&[u8]) under cfg(fuzzing), is the target; its corpus and finds live
/// in fuzz/NAME/ under the current directory.
fn take_target(flags: &mut Vec<String>) -> io::Result<Option<String>> {
    match flags.iter().position(|f| f == "--target") {
        Some(i) if i + 1 < flags.len() => {
            let path = flags.remove(i + 1);
            flags.remove(i);
            Ok(Some(path))
        },
        Some(_) => Err(io::Error::other("--target needs the path of a function")),
        None => Ok(None),
    }
}

pub fn run(args: &[String]) -> io::Result<ExitCode> {
    let Some(source) = args.first() else {
        help();
        return Ok(ExitCode::SUCCESS);
    };
    match source.as_str() {
        "--help" | "-h" | "help" => {
            help();
            return Ok(ExitCode::SUCCESS);
        },
        "init" => return init(&args[1..]),
        _ => {},
    }
    if source.starts_with('-') {
        return Err(io::Error::other(
            "usage: rr fuz FILE [--asan] [RUSTC FLAGS] -- [LIBFUZZER ARGS]",
        ));
    }
    let split = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
    let mut flags: Vec<String> = args[1..split].to_vec();
    let target = take_target(&mut flags)?;
    // rr owns the executable and must run a native binary with its matching runtime.
    for arg in &flags {
        if arg.starts_with("-o")
            || ["--emit", "--out-dir", "--target", "--sysroot", "--crate-type"]
                .iter()
                .any(|key| has_key(arg, key))
        {
            return Err(io::Error::other(format!(
                "rr fuz manages native executable output; unsupported flag: {arg}"
            )));
        }
    }
    let asan = flags.iter().any(|arg| arg == "--asan");
    let rr = executable()?;
    let bundle = rr
        .parent()
        .ok_or_else(|| io::Error::other("missing executable directory"))?;
    // libFuzzer needs the host's C and C++ libraries: a fuzz target is
    // built for the host's own target, not rr's library-free one, and
    // linked by the system's linker.
    let host = rustc_session::config::host_tuple();
    let libraries = bundle.join("lib/rustlib").join(host).join("lib");
    let coverage = bundle.join("fuzz/fuzz.flags");
    if !libraries.join(FUZZER).is_file() || !coverage.is_file() {
        return Err(io::Error::other(
            "this rr installation has no bundled native libFuzzer runtime",
        ));
    }
    let asan_runtime = has_asan_runtime(&libraries)?;
    if asan && !asan_runtime {
        return Err(io::Error::other(
            "this rr installation has no bundled AddressSanitizer runtime",
        ));
    }
    let scratch = workspace::Scratch::new()?;
    // The terminal sends Ctrl-C to both processes. Let the compiler/fuzzer child
    // handle it and exit; keeping this parent alive lets Scratch remove its files.
    ctrlc::set_handler(|| {}).map_err(io::Error::other)?;
    let binary = scratch.path.join(if cfg!(windows) { "rr-fuz.exe" } else { "rr-fuz" });
    let mut compiler = Command::new(&rr);
    compiler.args(["build", source, "--target", host]);
    compiler.arg(format!("@{}", coverage.display()));
    compiler.arg(format!("-Lnative={}", libraries.display()));
    compiler.args(flags.iter().filter(|arg| *arg != "--asan"));
    if let Some(path) = &target {
        compiler.arg(format!("--rr-harness=fuzz:{path}"));
        compiler.args(["--cfg", "fuzzing"]);
    }
    compiler.args(["--crate-type=bin", "-o"]).arg(&binary);
    if asan {
        compiler.arg("-Zsanitizer=address");
        if cfg!(target_os = "macos") {
            // Darwin's ASan install name uses @rpath; resolve it inside this bundle.
            compiler.arg(format!("-Clink-arg=-Wl,-rpath,{}", libraries.display()));
        }
    }
    eprintln!("rr fuz: compiling {source}");
    let status = compiler.status()?;
    if !status.success() {
        return Ok(exit_code(status));
    }
    let mut runner = Command::new(&binary);
    let runtime_args = args.get(split + 1..).unwrap_or_default();
    let root = match &target {
        Some(path) => std::env::current_dir()?.join("fuzz").join(path.replace("::", "_")),
        None => Path::new(source)
            .canonicalize()?
            .parent()
            .ok_or_else(|| io::Error::other("missing source directory"))?
            .to_owned(),
    };
    if !runtime_args.iter().any(|arg| !arg.starts_with('-')) {
        let corpus = root.join("corpus");
        fs::create_dir_all(&corpus)?;
        runner.arg(corpus);
    }
    if !runtime_args.iter().any(|arg| arg.starts_with("-artifact_prefix=")) {
        let artifacts = root.join("artifacts");
        fs::create_dir_all(&artifacts)?;
        runner.arg(format!("-artifact_prefix={}/", artifacts.display()));
    }
    runner.args(runtime_args);
    eprintln!("rr fuz: running libFuzzer (Ctrl-C to stop)");
    Ok(exit_code(runner.status()?))
}

/// Whether libraries holds the `AddressSanitizer` runtime, as a static or
/// a dynamic library.
fn has_asan_runtime(libraries: &Path) -> io::Result<bool> {
    Ok(fs::read_dir(libraries)?.filter_map(Result::ok).any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("librustc-nightly_rt.asan")
    }))
}

pub fn exit_code(status: ExitStatus) -> ExitCode {
    ExitCode::from(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
}

fn init(args: &[String]) -> io::Result<ExitCode> {
    let root = match args {
        [] => Path::new("."),
        [path] if !path.starts_with('-') => Path::new(path),
        _ => return Err(io::Error::other("usage: rr fuz init [DIR]")),
    };
    fs::create_dir_all(root)?;
    let file = root.join("fuz.rs");
    // Refuse to overwrite a user's harness, including on repeated initialization.
    let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&file)?;
    output.write_all(TEMPLATE.as_bytes())?;
    fs::create_dir_all(root.join("corpus"))?;
    fs::create_dir_all(root.join("artifacts"))?;
    println!("Created {}", file.display());
    Ok(ExitCode::SUCCESS)
}

fn help() {
    println!(
        "Usage:\n  rr fuz init [DIR]\n  rr fuz FILE --target PATH [--asan] [RUSTC FLAGS] -- [LIBFUZZER ARGS]\n  rr fuz FILE [--asan] [RUSTC FLAGS] -- [LIBFUZZER ARGS]\n\nWith --target, the crate's function at PATH (a fn(&[u8]) under cfg(fuzzing))\nis the target; its corpus/ and artifacts/ are in fuzz/PATH/. Without it, FILE\nis a harness that defines LLVMFuzzerTestOneInput.\n\nBuilds with rr restrictions and bundled libFuzzer coverage, then runs the test.\n--asan enables bundled AddressSanitizer. Fuzzing runs on the host, linked by
its system linker: on Linux cc and libstdc++, on Windows Visual Studio's tools.\nDefault corpus/ and artifacts/ live beside FILE; found crashes are retained.\nThe temporary executable is removed when the command exits.\nExamples:\n  rr fuz fuz.rs -- -runs=100000\n  rr fuz fuz.rs --asan -- -max_total_time=60\n  rr fuz fuz.rs -- artifacts/crash-HASH -runs=1"
    );
}
