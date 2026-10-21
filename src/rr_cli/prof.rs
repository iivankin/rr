//! rr prof: where a program allocates and copies. `rr build --prof` links
//! the runtime in `prof_rt.rs` into the final artifact; `rr prof -- CMD`
//! runs a command with `RR_PROF_DIR` set, so that every process of such a
//! program it starts records its allocations and its copies through
//! memcpy and memmove by stack, then reports them by the first frame of
//! the program's own code and its caller.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{fs, io};

use super::{executable, workspace};

const RUNTIME: &str = include_str!("prof_rt.rs");
const MAGIC: &[u8; 8] = b"RRPROF2\0";
const HEADER: usize = 32 + 1024;

/// Build the runtime rlib into dir with this compiler, unrestricted: it
/// defines the allocator shim's internal symbols, which only the
/// compiler's own attributes can name.
pub fn build_runtime(raw0: &str, dir: &Path, target: Option<&str>) -> ExitCode {
    let source = dir.join("rr_prof_rt.rs");
    if let Err(error) = fs::write(&source, RUNTIME) {
        eprintln!("rr: {}: {error}", source.display());
        return ExitCode::FAILURE;
    }
    let mut args: Vec<String> = vec![
        raw0.into(),
        "--rustc".into(),
        source.to_string_lossy().into_owned(),
        "--crate-name=rr_prof_rt".into(),
        "--crate-type=rlib".into(),
        "--edition=2024".into(),
        "-Cpanic=abort".into(),
        "-Copt-level=2".into(),
        "-Cforce-frame-pointers=yes".into(),
        "--out-dir".into(),
        dir.to_string_lossy().into_owned(),
    ];
    super::target::for_runtime(&mut args, target);
    if let Some(bundle) = bundle() {
        args.extend(["--sysroot".into(), bundle.to_string_lossy().into_owned()]);
    }
    crate::driver_core::run(args, false, true)
}

/// The bundle directory when rr runs from one with its own sysroot.
pub fn bundle() -> Option<PathBuf> {
    let dir = executable().ok()?.parent()?.to_owned();
    dir.join("lib/rustlib").is_dir().then_some(dir)
}

/// The runtime rlib for a --prof build of a final artifact, built into
/// scratch by a child rr.
pub fn runtime(scratch: &Path, target: Option<&str>) -> io::Result<PathBuf> {
    let status = Command::new(executable()?)
        .arg("__prof-runtime")
        .arg(scratch)
        .args(target.map(|t| ["--target", t]).into_iter().flatten())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("could not build the rr prof runtime"));
    }
    Ok(scratch.join("librr_prof_rt.rlib"))
}

/// The flags of a --prof build: frame pointers for the stacks, line
/// tables to name them, and for a final artifact the runtime, built into
/// scratch.
pub fn flags(
    compiler: &mut Vec<String>,
    artifact: bool,
    scratch: Option<&Path>,
    target: Option<&str>,
) -> io::Result<()> {
    compiler.extend([
        "-Cforce-frame-pointers=yes".into(),
        "-Cdebuginfo=line-tables-only".into(),
    ]);
    // On macOS the line tables stay in the objects unless packed beside
    // the executable.
    if target.is_none_or(|t| t.ends_with("-apple-darwin")) {
        compiler.push("-Csplit-debuginfo=packed".into());
    }
    if artifact && let Some(scratch) = scratch {
        let runtime = runtime(scratch, target)?;
        compiler.extend([
            "-Zunstable-options".into(),
            "--extern".into(),
            format!("force:rr_prof_rt={}", runtime.display()),
        ]);
        // The runtime's memcpy and memmove stand for compiler_builtins',
        // which on ELF are weak; on COFF they are not, and the first
        // definition, the runtime's, is to win.
        if super::target::is_rr(target) && super::target::is_windows(target) {
            compiler.push("-Clink-arg=--allow-multiple-definition".into());
        }
    }
    Ok(())
}

struct Options {
    top: usize,
    max: Option<u64>,
    max_copied: Option<u64>,
    keep: Option<PathBuf>,
}

pub fn run(args: &[String]) -> io::Result<ExitCode> {
    let mut o = Options {
        top: 25,
        max: None,
        max_copied: None,
        keep: None,
    };
    let mut i = 0;
    let mut report_dir = None;
    while i < args.len() {
        let value = |i: usize| args.get(i + 1).ok_or_else(|| io::Error::other(usage()));
        match args[i].as_str() {
            "--help" | "-h" | "help" => {
                println!("{}", usage());
                return Ok(ExitCode::SUCCESS);
            },
            "--top" => o.top = value(i)?.parse().map_err(|_| io::Error::other(usage()))?,
            "--max" => o.max = Some(value(i)?.parse().map_err(|_| io::Error::other(usage()))?),
            "--max-copied" => o.max_copied = Some(value(i)?.parse().map_err(|_| io::Error::other(usage()))?),
            "--keep" => o.keep = Some(PathBuf::from(value(i)?)),
            "report" => {
                report_dir = Some(PathBuf::from(value(i)?));
                i += 2;
                continue;
            },
            "--" => break,
            _ => return Err(io::Error::other(usage())),
        }
        i += 2;
    }
    if let Some(dir) = report_dir {
        return report(&dir, &o);
    }
    let command = args
        .get(i + 1..)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| io::Error::other(usage()))?;
    let scratch;
    let dir = if let Some(dir) = &o.keep {
        fs::create_dir_all(dir)?;
        super::canonical(dir)?
    } else {
        scratch = workspace::Scratch::new()?;
        scratch.path.clone()
    };
    let status = Command::new(&command[0])
        .args(&command[1..])
        .env("RR_PROF_DIR", &dir)
        .status()?;
    let reported = report(&dir, &o)?;
    if !status.success() {
        eprintln!("rr prof: the command failed: {status}");
        return Ok(ExitCode::FAILURE);
    }
    Ok(reported)
}

fn usage() -> &'static str {
    "Usage:\n  rr prof [--top N] [--max N] [--max-copied BYTES] [--keep DIR] -- COMMAND [ARGS]\n  rr prof report DIR [--top N] [--max N] [--max-copied BYTES]\n\nRuns COMMAND with RR_PROF_DIR set: each process of a program built with\nrr build --prof records its heap allocations, and the bytes it copies\nthrough memcpy and memmove, by stack. Then reports the places in the\nprogram's own code that allocate and copy most, with their callers.\n--max fails when the allocations are above N, --max-copied when the\nbytes copied are above BYTES: budgets for tests.\nBuild with --prof every crate (for line tables) and the final artifact\n(for the runtime); a --prof build is not stripped."
}

/// One frame: the function and where in it.
struct Frame {
    function: String,
    file: String,
    line: u32,
}

impl Frame {
    /// The runtime, the allocator and the standard library: not the
    /// program's own code.
    fn plumbing(&self) -> bool {
        let f = self.function.as_str();
        f.starts_with("rr_prof_rt::")
            || matches!(f.trim_start_matches('_'), "memcpy" | "memmove")
            || f.contains("__rg_")
            || f.contains("__rust_")
            || f.contains("rr_prof_anchor")
            || f.contains("GlobalAlloc")
            || ["alloc::", "core::", "<alloc::", "<core::"]
                .iter()
                .any(|p| f.starts_with(p))
            || self.file.contains("/library/alloc/")
            || self.file.contains("/library/core/")
    }

    fn place(&self) -> String {
        if self.file.is_empty() {
            return self.function.clone();
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        let file = Path::new(&self.file)
            .strip_prefix(&cwd)
            .map_or(Path::new(&self.file), |p| p);
        format!("{}  {}:{}", self.function, file.display(), self.line)
    }
}

/// A program's line tables, and where `rr_prof_anchor` is in its file: each
/// process image has a load slide of its own.
struct Program {
    loader: addr2line::Loader,
    anchor: u64,
}

#[derive(Default)]
struct Site {
    count: u64,
    bytes: u64,
    callers: BTreeMap<String, u64>,
}

/// The sites of one kind of count, with their totals.
#[derive(Default)]
struct Tally {
    sites: BTreeMap<String, Site>,
    count: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, site: String, caller: Option<String>, count: u64, bytes: u64) {
        self.count += count;
        self.bytes += bytes;
        let s = self.sites.entry(site).or_default();
        s.count += count;
        s.bytes += bytes;
        *s.callers.entry(caller.unwrap_or_default()).or_default() += count;
    }

    /// The top sites, ranked by key, each with its first callers.
    fn print(&self, top: usize, key: fn(&Site) -> u64) {
        let mut ranked: Vec<_> = self.sites.iter().collect();
        ranked.sort_by_key(|(_, site)| core::cmp::Reverse(key(site)));
        for (site, s) in ranked.iter().take(top) {
            println!("{:>9} {:>11}  {site}", s.count, s.bytes);
            let mut callers: Vec<_> = s.callers.iter().filter(|(c, _)| !c.is_empty()).collect();
            callers.sort_by_key(|(_, n)| core::cmp::Reverse(**n));
            for (caller, n) in callers.iter().take(3) {
                println!("{:>9} {:>11}    <- {caller}", n, "");
            }
        }
    }
}

fn report(dir: &Path, o: &Options) -> io::Result<ExitCode> {
    let mut programs: BTreeMap<PathBuf, Option<Program>> = BTreeMap::new();
    let mut allocs = Tally::default();
    let mut copies = Tally::default();
    let (mut images, mut lost) = (0u64, 0u64);
    for entry in fs::read_dir(dir)? {
        let data = fs::read(entry?.path())?;
        if data.len() < HEADER || &data[..8] != MAGIC {
            continue;
        }
        let word = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or_default());
        let half = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap_or_default()) as usize;
        let (depth, slots, anchor) = (half(8), half(12), word(16));
        lost += word(24);
        let exe = &data[32..HEADER];
        let exe = PathBuf::from(
            String::from_utf8_lossy(&exe[..exe.iter().position(|c| *c == 0).unwrap_or(exe.len())]).into_owned(),
        );
        images += 1;
        let program = programs.entry(exe.clone()).or_insert_with(|| load(&exe));
        let slot = 24 + depth * 8;
        for k in 0..slots {
            let at = HEADER + k * slot;
            if at + slot > data.len() {
                break;
            }
            let count = word(at + 8);
            if count == 0 {
                continue;
            }
            let pcs: Vec<u64> = (0..depth)
                .map(|d| word(at + 24 + d * 8))
                .take_while(|pc| *pc != 0)
                .collect();
            let frames = match program {
                Some(p) => frames(p, anchor.wrapping_sub(p.anchor), &pcs),
                None => Vec::new(),
            };
            let mut own = frames.iter().filter(|f| !f.plumbing());
            let (site, caller) = match own.next() {
                Some(site) => {
                    let caller = own.find(|f| f.function != site.function).map(Frame::place);
                    (site.place(), caller)
                },
                None => ("(not in the program's own code)".to_owned(), None),
            };
            let tally = if word(at) == 0 { &mut allocs } else { &mut copies };
            tally.add(site, caller, count, word(at + 16));
        }
    }
    println!(
        "rr prof: {} allocations, {} bytes, in {images} process images of {}",
        allocs.count,
        allocs.bytes,
        programs
            .keys()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if lost > 0 {
        println!("rr prof: {lost} counts on stacks past the table, in neither total");
    }
    allocs.print(o.top, |s| s.count);
    println!(
        "rr prof: {} copies through memcpy and memmove, {} bytes",
        copies.count, copies.bytes
    );
    copies.print(o.top, |s| s.bytes);
    let mut code = ExitCode::SUCCESS;
    if let Some(max) = o.max
        && allocs.count > max
    {
        println!("rr prof: {} allocations, above the budget of {max}", allocs.count);
        code = ExitCode::FAILURE;
    }
    if let Some(max) = o.max_copied
        && copies.bytes > max
    {
        println!("rr prof: {} bytes copied, above the budget of {max}", copies.bytes);
        code = ExitCode::FAILURE;
    }
    Ok(code)
}

/// The program's line tables, and the address its symbol table gives
/// `rr_prof_anchor`.
fn load(exe: &Path) -> Option<Program> {
    use object::{Object as _, ObjectSymbol as _};
    let data = fs::read(exe).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let at = file
        .symbols()
        .find(|s| s.name().is_ok_and(|n| n.trim_start_matches('_') == "rr_prof_anchor"))?
        .address();
    let loader = addr2line::Loader::new(exe).ok()?;
    Some(Program { loader, anchor: at })
}

/// The frames at each return address of an image loaded slide bytes off
/// its file's addresses, inlined ones innermost first.
fn frames(p: &Program, slide: u64, pcs: &[u64]) -> Vec<Frame> {
    let mut out = Vec::new();
    for pc in pcs {
        // A return address is past its call; look at the call.
        let probe = pc.wrapping_sub(slide).wrapping_sub(1);
        let mut found = false;
        if let Ok(mut it) = p.loader.find_frames(probe) {
            while let Ok(Some(f)) = it.next() {
                found = true;
                let function = f
                    .function
                    .as_ref()
                    .and_then(|n| n.demangle().ok().map(|d| strip_hash(&d)))
                    .unwrap_or_default();
                let (file, line) = f
                    .location
                    .map(|l| (l.file.unwrap_or_default().to_owned(), l.line.unwrap_or(0)))
                    .unwrap_or_default();
                out.push(Frame { function, file, line });
            }
        }
        if !found && let Some(name) = p.loader.find_symbol(probe) {
            out.push(Frame {
                function: strip_hash(&addr2line::demangle_auto(name.into(), None)),
                file: String::new(),
                line: 0,
            });
        }
    }
    out
}

/// A legacy-mangled name without its `::h<hash>` suffix.
fn strip_hash(name: &str) -> String {
    match name.rfind("::h") {
        Some(i) if name[i + 3..].len() == 16 && name[i + 3..].bytes().all(|c| c.is_ascii_hexdigit()) => {
            name[..i].to_owned()
        },
        _ => name.to_owned(),
    }
}
