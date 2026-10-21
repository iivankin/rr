//! rr test and rr bench: build a crate with its `#[test]` and `#[bench]`
//! items, as rustc's `--test` makes them, against rr's own runtime for
//! them (`test_rt.rs`, built as the crate `test`), then run it. The
//! program's `main` gives way to the run's (see harness.rs). rr test
//! runs each test in a child; rr bench builds with optimization and rr
//! prof's runtime, and measures each bench's time, allocations and bytes
//! copied per iteration. --check and --lint check the crate with its
//! tests instead of building it.

use std::path::Path;
use std::process::{Command, ExitCode};
use std::{fs, io};

use super::{executable, fuz, has_key, workspace};

const RUNTIME: &str = include_str!("test_rt.rs");

/// Build the runtime rlib into dir with this compiler, unrestricted; with
/// counts, it reads rr prof's counters around each measured loop.
pub fn build_runtime(raw0: &str, dir: &Path, counts: bool, target: Option<&str>) -> ExitCode {
    let source = dir.join("rr_test_rt.rs");
    if let Err(error) = fs::write(&source, RUNTIME) {
        eprintln!("rr: {}: {error}", source.display());
        return ExitCode::FAILURE;
    }
    let mut args: Vec<String> = vec![
        raw0.into(),
        "--rustc".into(),
        source.to_string_lossy().into_owned(),
        "--crate-name=test".into(),
        "--crate-type=rlib".into(),
        "--edition=2024".into(),
        "-Cpanic=abort".into(),
        "-Copt-level=2".into(),
        "-Cforce-frame-pointers=yes".into(),
        "--check-cfg=cfg(rr_counts)".into(),
        "--out-dir".into(),
        dir.to_string_lossy().into_owned(),
    ];
    if counts {
        args.extend(["--cfg".into(), "rr_counts".into()]);
    }
    super::target::for_runtime(&mut args, target);
    if let Some(bundle) = super::prof::bundle() {
        args.extend(["--sysroot".into(), bundle.to_string_lossy().into_owned()]);
    }
    crate::driver_core::run(args, false, false)
}

/// The flags that make a crate a test executable over rr's runtime.
fn harness_flags(runtime: &Path) -> Vec<String> {
    vec![
        "--rr-harness=test".into(),
        "--test".into(),
        "-Zpanic_abort_tests".into(),
        "-Zcrate-attr=feature(custom_test_frameworks)".into(),
        "-Zcrate-attr=feature(test)".into(),
        "-Zcrate-attr=reexport_test_harness_main=\"__rr_test_main\"".into(),
        "--extern".into(),
        format!("test={}", runtime.display()),
    ]
}

/// rr test FILE [--check|--lint] [RUSTC FLAGS] [-- FILTER...], or with
/// bench, rr bench FILE [RUSTC FLAGS] [-- FILTER...].
pub fn run(args: &[String], bench: bool) -> io::Result<ExitCode> {
    let usage = if bench {
        "usage: rr bench FILE [RUSTC FLAGS] [-- FILTER...]"
    } else {
        "usage: rr test FILE [--check | --lint] [RUSTC FLAGS] [-- FILTER...]"
    };
    let Some(source) = args.first().filter(|a| !a.starts_with('-')) else {
        return Err(io::Error::other(usage));
    };
    let split = args.iter().position(|arg| arg == "--").unwrap_or(args.len());
    let mut flags: Vec<String> = args[1..split].to_vec();
    let filters = args.get(split + 1..).unwrap_or_default();
    let mode = match flags.iter().position(|f| f == "--check" || f == "--lint") {
        Some(i) if !bench => flags.remove(i).trim_start_matches('-').to_owned(),
        Some(_) => return Err(io::Error::other(usage)),
        None => "build".to_owned(),
    };
    if flags
        .iter()
        .any(|f| f.starts_with("-o") || has_key(f, "--out-dir") || has_key(f, "--emit"))
    {
        return Err(io::Error::other("rr test and rr bench own the executable; drop -o"));
    }
    let rr = executable()?;
    let target = super::target::chosen(&flags);
    let scratch = workspace::Scratch::new()?;
    let status = Command::new(&rr)
        .arg("__test-runtime")
        .arg(&scratch.path)
        .args(bench.then_some("counts"))
        .args(target.iter().flat_map(|t| ["--target", t.as_str()]))
        .status()?;
    if !status.success() {
        return Err(io::Error::other("could not build the rr test runtime"));
    }
    let binary = scratch.path.join(if super::target::is_windows(target.as_deref()) {
        "rr-test.exe"
    } else {
        "rr-test"
    });
    let mut compiler = Command::new(&rr);
    compiler.arg(&mode).arg(source);
    compiler.args(harness_flags(&scratch.path.join("libtest.rlib")));
    if bench {
        // Optimized as a release is, and counting what it allocates and
        // copies.
        if !flags
            .iter()
            .any(|f| f == "-O" || f.starts_with("-Copt-level") || f.starts_with("opt-level"))
        {
            compiler.arg("-Copt-level=3");
        }
        compiler.arg("--prof");
    }
    compiler.args(&flags);
    if mode == "build" {
        compiler.arg("-o").arg(&binary);
    }
    if !compiler.status()?.success() {
        return Ok(ExitCode::FAILURE);
    }
    if mode != "build" {
        return Ok(ExitCode::SUCCESS);
    }
    let mut runner = runner(&binary)?;
    if bench {
        runner.arg("--bench");
    }
    runner.args(filters);
    Ok(fuz::exit_code(runner.status()?))
}

/// The command that runs binary: itself, or under `RR_RUNNER`, which names
/// a program and its arguments, split at spaces, to run it with, as an
/// emulator or a container runs one built for another system.
fn runner(binary: &Path) -> io::Result<Command> {
    let Ok(wrapper) = std::env::var("RR_RUNNER") else {
        return Ok(Command::new(binary));
    };
    let mut words = wrapper.split_whitespace();
    let Some(program) = words.next() else {
        return Err(io::Error::other("RR_RUNNER is empty"));
    };
    let mut command = Command::new(program);
    command.args(words).arg(binary);
    Ok(command)
}
