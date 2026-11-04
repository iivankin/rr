//! rr time: run a command several times and report how long it took, the
//! fastest run and the middle one. A budget fails on the fastest: the
//! others wait on what else the machine does.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

struct Options {
    runs: usize,
    max_ms: Option<u64>,
    stdin: Option<PathBuf>,
}

pub fn run(args: &[String]) -> io::Result<ExitCode> {
    let mut o = Options {
        runs: 5,
        max_ms: None,
        stdin: None,
    };
    let mut i = 0;
    while i < args.len() {
        let value = |i: usize| args.get(i + 1).ok_or_else(|| io::Error::other(usage()));
        match args[i].as_str() {
            "--help" | "-h" | "help" => {
                println!("{}", usage());
                return Ok(ExitCode::SUCCESS);
            },
            "--runs" => o.runs = value(i)?.parse().map_err(|_| io::Error::other(usage()))?,
            "--max-ms" => o.max_ms = Some(value(i)?.parse().map_err(|_| io::Error::other(usage()))?),
            "--stdin" => o.stdin = Some(PathBuf::from(value(i)?)),
            "--" => break,
            _ => return Err(io::Error::other(usage())),
        }
        i += 2;
    }
    let command = args
        .get(i + 1..)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| io::Error::other(usage()))?;
    if o.runs == 0 {
        return Err(io::Error::other(usage()));
    }
    let mut times = Vec::with_capacity(o.runs);
    for _ in 0..o.runs {
        let start = Instant::now();
        // Each run reads the file from its start; what it writes would
        // time the terminal too.
        let status = Command::new(&command[0])
            .args(&command[1..])
            .stdin(input(o.stdin.as_deref())?)
            .stdout(Stdio::null())
            .status()?;
        times.push(start.elapsed());
        if !status.success() {
            eprintln!("rr time: the command failed: {status}");
            return Ok(ExitCode::FAILURE);
        }
    }
    times.sort();
    let fastest = times[0].as_secs_f64() * 1000.0;
    let middle = times[times.len() / 2].as_secs_f64() * 1000.0;
    println!(
        "rr time: {} runs, the fastest {fastest:.1} ms, the middle {middle:.1} ms",
        o.runs
    );
    if let Some(max) = o.max_ms
        && times[0] > Duration::from_millis(max)
    {
        println!("rr time: the fastest run took {fastest:.1} ms, above the budget of {max} ms");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// What a workload reads: the file named, or nothing.
pub fn input(file: Option<&Path>) -> io::Result<Stdio> {
    Ok(match file {
        Some(path) => File::open(path)?.into(),
        None => Stdio::null(),
    })
}

fn usage() -> &'static str {
    "Usage:\n  rr time [--runs N] [--max-ms MS] [--stdin FILE] -- COMMAND [ARGS]\n\nRuns COMMAND N times (5 by default) and reports the fastest run and the\nmiddle one, in milliseconds of wall time. --max-ms fails when the\nfastest run took longer than MS: a budget for tests. --stdin gives each\nrun a file to read; what COMMAND writes to stdout is dropped. Time the program\nas it ships, not a --prof build, whose recording slows it."
}
