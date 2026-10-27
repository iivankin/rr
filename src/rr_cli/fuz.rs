use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus, Stdio};

use super::{executable, has_key, workspace};

const TEMPLATE: &str = include_str!("../../examples/fuzz/fuzz.rs.in");
/// libFuzzer, as the bundle keeps it for the host.
const FUZZER: &str = if cfg!(windows) { "Fuzzer.lib" } else { "libFuzzer.a" };

/// Each `--target PATH`, taken out of flags: the crate's own function at
/// PATH, a fn(&[u8]) under cfg(fuzzing), is a target; its corpus and finds
/// live in fuzz/NAME/ under the current directory.
fn take_targets(flags: &mut Vec<String>) -> io::Result<Vec<String>> {
    let mut targets = Vec::new();
    while let Some(i) = flags.iter().position(|f| f == "--target") {
        if i + 1 >= flags.len() {
            return Err(io::Error::other("--target needs the path of a function"));
        }
        let path = flags.remove(i + 1);
        flags.remove(i);
        if !targets.contains(&path) {
            targets.push(path);
        }
    }
    Ok(targets)
}

/// `--budget SECONDS`, taken out of flags: the time the run takes in all.
fn take_budget(flags: &mut Vec<String>) -> io::Result<Option<u64>> {
    let Some(i) = flags.iter().position(|f| f == "--budget") else {
        return Ok(None);
    };
    let seconds = flags
        .get(i + 1)
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| io::Error::other("--budget needs a number of seconds"))?;
    flags.drain(i..=i + 1);
    Ok(Some(seconds))
}

/// Where a target keeps its corpus and finds: fuzz/NAME/.
fn target_root(path: &str) -> io::Result<PathBuf> {
    Ok(std::env::current_dir()?.join("fuzz").join(path.replace("::", "_")))
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
    let targets = take_targets(&mut flags)?;
    let budget = take_budget(&mut flags)?;
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
    let host = rustc_session::config::host_tuple();
    let (libraries, coverage) = runtime(&rr, host, asan)?;
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
    if !targets.is_empty() {
        compiler.arg(format!("--rr-harness=fuzz:{}", targets.join(",")));
        compiler.args(["--cfg", "fuzzing"]);
    }
    // The report names the functions each target reaches from the line
    // tables, which on macOS stay in the objects unless packed beside.
    if targets.len() > 1 && host.ends_with("-apple-darwin") {
        compiler.arg("-Csplit-debuginfo=packed");
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
    let runtime_args = args.get(split + 1..).unwrap_or_default();
    if targets.len() > 1 {
        let budget = budget.unwrap_or(60);
        return schedule(&binary, &targets, budget, runtime_args);
    }
    let mut runner = Command::new(&binary);
    let root = match targets.first() {
        Some(path) => target_root(path)?,
        None => super::canonical(Path::new(source))?
            .parent()
            .ok_or_else(|| io::Error::other("missing source directory"))?
            .to_owned(),
    };
    if let Some(seconds) = budget
        && !runtime_args.iter().any(|arg| arg.starts_with("-max_total_time="))
    {
        runner.arg(format!("-max_total_time={seconds}"));
    }
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

/// The bundle's `libFuzzer` libraries for the host and its coverage flags,
/// and its `AddressSanitizer` runtime when asked for. `libFuzzer` needs the
/// host's C and C++ libraries: a fuzz target is built for the host's own
/// target, not rr's library-free one, and linked by the system's linker.
fn runtime(rr: &Path, host: &str, asan: bool) -> io::Result<(PathBuf, PathBuf)> {
    let bundle = rr
        .parent()
        .ok_or_else(|| io::Error::other("missing executable directory"))?;
    let libraries = bundle.join("lib/rustlib").join(host).join("lib");
    let coverage = bundle.join("fuzz/fuzz.flags");
    if !libraries.join(FUZZER).is_file() || !coverage.is_file() {
        return Err(io::Error::other(
            "this rr installation has no bundled native libFuzzer runtime",
        ));
    }
    if asan && !has_asan_runtime(&libraries)? {
        return Err(io::Error::other(
            "this rr installation has no bundled AddressSanitizer runtime",
        ));
    }
    Ok((libraries, coverage))
}

/// One target's share of a scheduled run.
struct Share {
    path: String,
    seconds: u64,
    /// Coverage features when its first run started and when its last one
    /// ended, as libFuzzer counts them (`ft:`).
    first: Option<u64>,
    last: Option<u64>,
}

impl Share {
    fn gained(&self) -> u64 {
        match (self.first, self.last) {
            (Some(first), Some(last)) => last.saturating_sub(first),
            _ => 0,
        }
    }
}

/// Several targets of one build in the time of budget seconds: half of it
/// evenly, then the rest to each by the coverage it found in its first
/// share, so a target still finding new paths gets the time one that has
/// stopped does not need. A crash stops the run, as it stops one target's.
fn schedule(binary: &Path, targets: &[String], budget: u64, runtime: &[String]) -> io::Result<ExitCode> {
    let count = u64::try_from(targets.len()).unwrap_or(u64::MAX);
    let mut shares: Vec<Share> = targets
        .iter()
        .map(|path| Share {
            path: path.clone(),
            seconds: 0,
            first: None,
            last: None,
        })
        .collect();
    let first = (budget / 2 / count).max(1);
    for (i, share) in shares.iter_mut().enumerate() {
        if let Some(code) = fuzz_share(binary, i, share, first, runtime)? {
            return Ok(code);
        }
    }
    let spent: u64 = shares.iter().map(|share| share.seconds).sum();
    let rest = budget.saturating_sub(spent);
    let weight: u64 = shares.iter().map(|share| share.gained() + 1).sum();
    for i in 0..shares.len() {
        let Some(share) = shares.get_mut(i) else { break };
        let seconds = rest * (share.gained() + 1) / weight;
        if seconds == 0 {
            continue;
        }
        if let Some(code) = fuzz_share(binary, i, share, seconds, runtime)? {
            return Ok(code);
        }
    }
    report(&shares);
    reach_report(binary, targets, runtime)?;
    Ok(ExitCode::SUCCESS)
}

/// The functions of the program, by name and file, that each target's
/// corpus reaches; then which target reaches nothing another does not,
/// and which reaches nothing past its own module.
fn reach_report(binary: &Path, targets: &[String], runtime: &[String]) -> io::Result<()> {
    let Some(program) = super::prof::load(binary, "LLVMFuzzerTestOneInput") else {
        eprintln!("rr fuz: no line tables to name what the targets reach");
        return Ok(());
    };
    let source = std::env::current_dir()?.join("src");
    let mut reach = Vec::new();
    for (i, path) in targets.iter().enumerate() {
        let mut functions = reached(binary, i, path, runtime, &program, &source)?;
        // The target itself is each one's own: what it reaches is the rest.
        functions.retain(|function, _| !function.ends_with(&format!("::{path}")));
        reach.push(functions);
    }
    for (i, path) in targets.iter().enumerate() {
        let Some(mine) = reach.get(i) else { continue };
        if mine.is_empty() {
            continue;
        }
        let within = targets.iter().enumerate().find(|&(j, _)| {
            j != i
                && reach
                    .get(j)
                    .is_some_and(|theirs| theirs.len() >= mine.len() && mine.keys().all(|f| theirs.contains_key(f)))
                // Of two that reach the same, the later is the one to drop.
                && !(reach.get(j).is_some_and(|theirs| theirs.len() == mine.len()) && j > i)
        });
        if let Some((_, other)) = within {
            eprintln!("rr fuz: {path} reaches nothing that {other} does not: one of them is enough");
        }
        let module = path
            .rsplit_once("::")
            .map_or("", |(module, _)| module)
            .replace("::", "/");
        // What every target reaches, the system layer and its allocator,
        // says nothing of how far one goes.
        if !module.is_empty()
            && mine.values().all(|file| {
                file == &format!("{module}.rs")
                    || file.starts_with(&format!("{module}/"))
                    || file.starts_with("sys/")
                    || file == "sys.rs"
            })
        {
            eprintln!(
                "rr fuz: {path} reaches nothing past src/{module}: a test of its properties over edge values checks as much"
            );
        }
    }
    Ok(())
}

/// The program's functions, by name, and their files under src/, that
/// the target at index i reaches over its corpus.
fn reached(
    binary: &Path,
    i: usize,
    path: &str,
    runtime: &[String],
    program: &super::prof::Program,
    source: &Path,
) -> io::Result<BTreeMap<String, String>> {
    let corpus = target_root(path)?.join("corpus");
    let output = Command::new(binary)
        .arg(&corpus)
        .args(runtime)
        .args(["-runs=0", "-print_full_coverage=1"])
        .arg(format!("--rr-target={i}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let mut reach = BTreeMap::new();
    let text = String::from_utf8_lossy(&output.stderr);
    // Each covered PC, as the harness names it: the functions there, the
    // ones inlined into it too, are reached.
    let mut pcs = Vec::new();
    for line in text.lines() {
        // The harness writes each name whole, without the format's spaces.
        let Some(covered) = line.strip_prefix('C') else {
            continue;
        };
        for word in covered.split("rr+0x") {
            if let Ok(offset) = u64::from_str_radix(word.trim(), 16) {
                // frames looks one byte back, as for a return address.
                pcs.push(program.anchor.wrapping_add(offset).wrapping_add(1));
            }
        }
    }
    pcs.sort_unstable();
    pcs.dedup();
    for frame in super::prof::frames(program, 0, &pcs) {
        // The allocator's shims are the compiler's, at the crate's root.
        if frame.function.starts_with("__rustc::") {
            continue;
        }
        if let Ok(file) = Path::new(&frame.file).strip_prefix(source) {
            reach.insert(frame.function, file.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(reach)
}

/// One run of the target at index i for seconds; the exit code of a run
/// that failed, such as on a crash.
fn fuzz_share(
    binary: &Path,
    i: usize,
    share: &mut Share,
    seconds: u64,
    runtime: &[String],
) -> io::Result<Option<ExitCode>> {
    let root = target_root(&share.path)?;
    let corpus = root.join("corpus");
    let artifacts = root.join("artifacts");
    fs::create_dir_all(&corpus)?;
    fs::create_dir_all(&artifacts)?;
    let output = Command::new(binary)
        .arg(&corpus)
        .arg(format!("-artifact_prefix={}/", artifacts.display()))
        .arg(format!("-max_total_time={seconds}"))
        .args(runtime)
        .arg(format!("--rr-target={i}"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    let log = String::from_utf8_lossy(&output.stderr);
    fs::write(root.join("last.log"), log.as_bytes())?;
    share.seconds += seconds;
    let features = |marker: &str| {
        log.lines()
            .rev()
            .filter(|line| line.contains(marker))
            .find_map(|line| line.split(" ft: ").nth(1)?.split_whitespace().next()?.parse().ok())
    };
    share.first = share.first.or_else(|| features("INITED"));
    share.last = features("DONE").or(share.last);
    eprintln!(
        "rr fuz: {} for {seconds} s: {} coverage features",
        share.path,
        share.last.map_or_else(|| "no".to_owned(), |n| n.to_string())
    );
    if output.status.success() {
        return Ok(None);
    }
    eprintln!(
        "rr fuz: {} failed; the end of its log ({}):",
        share.path,
        root.join("last.log").display()
    );
    let lines: Vec<&str> = log.lines().collect();
    for line in lines.iter().skip(lines.len().saturating_sub(30)) {
        eprintln!("{line}");
    }
    Ok(Some(exit_code(output.status)))
}

/// What each target found in its time, and the targets that found nothing
/// new: their inputs are covered, or what they check is a property that a
/// test over edge values checks as well.
fn report(shares: &[Share]) {
    eprintln!("rr fuz: coverage features by target:");
    for share in shares {
        eprintln!(
            "  {:<48} {:>5} s  {} -> {} (+{})",
            share.path,
            share.seconds,
            share.first.unwrap_or(0),
            share.last.unwrap_or(0),
            share.gained()
        );
    }
    let idle: Vec<&str> = shares
        .iter()
        .filter(|share| share.gained() == 0)
        .map(|share| share.path.as_str())
        .collect();
    if !idle.is_empty() {
        eprintln!(
            "rr fuz: no new coverage in their time: {}. Their corpus covers what they reach, or what they check is a property of a function the program has already parsed for, which a test over edge values checks too; fuzz where outside input enters.",
            idle.join(", ")
        );
    }
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
        "Usage:\n  rr fuz init [DIR]\n  rr fuz FILE --target PATH [--target PATH...] [--budget SECONDS] [--asan] [RUSTC FLAGS] -- [LIBFUZZER ARGS]\n  rr fuz FILE [--asan] [RUSTC FLAGS] -- [LIBFUZZER ARGS]\n\nWith --target, the crate's function at PATH (a fn(&[u8]) under cfg(fuzzing))\nis the target; its corpus/ and artifacts/ are in fuzz/PATH/. Without it, FILE\nis a harness that defines LLVMFuzzerTestOneInput. Several targets build once\nand share --budget seconds (60 by default): half evenly, the rest by the\ncoverage each found; rr then reports what each found, and which found nothing\nnew. Each target's libFuzzer log is in fuzz/PATH/last.log.\n\nBuilds with rr restrictions and bundled libFuzzer coverage, then runs the test.\n--asan enables bundled AddressSanitizer. Fuzzing runs on the host, linked by
its system linker: on Linux cc and libstdc++, on Windows Visual Studio's tools.\nDefault corpus/ and artifacts/ live beside FILE; found crashes are retained.\nThe temporary executable is removed when the command exits.\nExamples:\n  rr fuz fuz.rs -- -runs=100000\n  rr fuz fuz.rs --asan -- -max_total_time=60\n  rr fuz fuz.rs -- artifacts/crash-HASH -runs=1"
    );
}
