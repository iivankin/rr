//! rr prof: where a program allocates and copies. `rr build --prof` links
//! the runtime in `prof_rt.rs` into the final artifact; `rr prof -- CMD`
//! runs a command with `RR_PROF_DIR` set, so that every process of such a
//! program it starts records its allocations and its copies through
//! memcpy and memmove by stack, then reports them by the first frame of
//! the program's own code and its caller.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::{fs, io};

use super::{executable, workspace};

const RUNTIME: &str = include_str!("prof_rt.rs");
const MAGIC: &[u8; 8] = b"RRPROF3\0";
const HEADER: usize = 40 + 1024;

/// Build the runtime rlib into dir with this compiler, unrestricted: it
/// defines the allocator shim's internal symbols, which only the
/// compiler's own attributes can name.
pub fn build_runtime(raw0: &str, dir: &Path, target: Option<&str>, sysroot: Option<&str>) -> ExitCode {
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
    super::target::for_runtime(&mut args, target, sysroot);
    crate::driver_core::run(args, false, true)
}

/// The runtime rlib for a --prof build of a final artifact, built into
/// scratch by a child rr.
pub fn runtime(scratch: &Path, target: Option<&str>, sysroot: Option<&str>) -> io::Result<PathBuf> {
    let status = Command::new(executable()?)
        .arg("__prof-runtime")
        .arg(scratch)
        .args(super::target::for_child(target, sysroot))
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
    sysroot: Option<&str>,
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
        let runtime = runtime(scratch, target, sysroot)?;
        compiler.extend([
            "-Zunstable-options".into(),
            "--extern".into(),
            format!("force:rr_prof_rt={}", runtime.display()),
        ]);
    }
    Ok(())
}

/// The places listed by how often they copy.
const COUNTED_TOP: usize = 5;

struct Options {
    top: usize,
    max: Option<u64>,
    max_copied: Option<u64>,
    max_heap: Option<u64>,
    keep: Option<PathBuf>,
    stdin: Option<PathBuf>,
}

pub fn run(args: &[String]) -> io::Result<ExitCode> {
    let mut o = Options {
        top: 25,
        max: None,
        max_copied: None,
        max_heap: None,
        keep: None,
        stdin: None,
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
            "--max-heap" => o.max_heap = Some(value(i)?.parse().map_err(|_| io::Error::other(usage()))?),
            "--keep" => o.keep = Some(PathBuf::from(value(i)?)),
            "--stdin" => o.stdin = Some(PathBuf::from(value(i)?)),
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
    // What the workload writes is not the report: a filter's output
    // would land among its lines.
    let status = Command::new(&command[0])
        .args(&command[1..])
        .env("RR_PROF_DIR", &dir)
        .stdin(super::time::input(o.stdin.as_deref())?)
        .stdout(Stdio::null())
        .status()?;
    let reported = report(&dir, &o)?;
    if !status.success() {
        eprintln!("rr prof: the command failed: {status}");
        return Ok(ExitCode::FAILURE);
    }
    Ok(reported)
}

fn usage() -> &'static str {
    "Usage:\n  rr prof [--top N] [--max N] [--max-copied BYTES] [--max-heap BYTES] [--keep DIR] [--stdin FILE] -- COMMAND [ARGS]\n  rr prof report DIR [--top N] [--max N] [--max-copied BYTES] [--max-heap BYTES]\n\nRuns COMMAND with RR_PROF_DIR set: each process of a program built with\nrr build --prof records its heap allocations, and the bytes it copies\nthrough memcpy and memmove, by stack. Then reports the places in the\nprogram's own code that allocate and copy most, with their callers.\n--max fails when the allocations are above N, --max-copied when the\nbytes copied are above BYTES, --max-heap when the heap held more than\nBYTES at once: budgets for tests. --stdin gives COMMAND a file to read;\nwhat it writes to stdout is dropped.\nBuild with --prof every crate (for line tables) and the final artifact\n(for the runtime); a --prof build is not stripped."
}

/// One frame: the function and where in it.
pub struct Frame {
    pub function: String,
    pub file: String,
    pub line: u32,
}

impl Frame {
    /// The runtime, the allocator and the standard library: not the
    /// program's own code.
    fn plumbing(&self) -> bool {
        let f = self.function.as_str();
        // The runtime's own: by its crate, by its no_mangle names, which
        // line tables give bare, and by its file.
        f.starts_with("rr_prof_rt::")
            || f.starts_with("rr_prof_")
            || self.file.ends_with("rr_prof_rt.rs")
            || matches!(f.trim_start_matches('_'), "memcpy" | "memmove")
            || f.contains("__rg_")
            || f.contains("__rust_")
            || f.contains("rr_prof_anchor")
            || f.contains("GlobalAlloc")
            || ["alloc::", "core::", "<alloc::", "<core::"]
                .iter()
                .any(|p| f.starts_with(p))
            || self.file.replace('\\', "/").contains("/library/alloc/")
            || self.file.replace('\\', "/").contains("/library/core/")
    }

    fn place(&self) -> String {
        if self.file.is_empty() {
            return self.function.clone();
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        let file = Path::new(&self.file)
            .strip_prefix(&cwd)
            .map_or(Path::new(&self.file), |p| p);
        // One separator on every system, as Windows' line tables have theirs.
        let file = file.to_string_lossy().replace('\\', "/");
        format!("{}  {}:{}", self.function, file, self.line)
    }
}

/// A program's line tables, and where `rr_prof_anchor` is in its file: each
/// process image has a load slide of its own.
pub struct Program {
    lines: Lines,
    pub anchor: u64,
}

/// Where a program's functions and lines are: DWARF, in the executable or
/// beside it; or for an MSVC target the PDB its debug directory names,
/// whose addresses are relative to the image (RVAs), as the anchor then is.
enum Lines {
    Dwarf(Box<addr2line::Loader>),
    Pdb(Box<pdb_addr2line::ContextPdbData<'static, 'static, fs::File>>),
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

    /// The top sites, ranked by key, each with its first callers; with
    /// average, the bytes of one count beside them.
    fn print(&self, top: usize, key: fn(&Site) -> u64, average: bool) {
        let mut ranked: Vec<_> = self.sites.iter().collect();
        ranked.sort_by_key(|(_, site)| core::cmp::Reverse(key(site)));
        for (site, s) in ranked.iter().take(top) {
            if average {
                let each = (s.bytes + s.count / 2).checked_div(s.count).unwrap_or(0);
                println!("{:>9} {:>11} {:>12}  {site}", s.count, s.bytes, format!("{each} each"));
            } else {
                println!("{:>9} {:>11}  {site}", s.count, s.bytes);
            }
            let mut callers: Vec<_> = s.callers.iter().filter(|(c, _)| !c.is_empty()).collect();
            callers.sort_by_key(|(_, n)| core::cmp::Reverse(**n));
            for (caller, n) in callers.iter().take(3) {
                println!("{:>9} {:>11}    <- {caller}", n, "");
            }
        }
    }
}

impl Tally {
    /// Says which of the top sites copy a few bytes at a time, often
    /// enough to be much of all the copying: each piece costs a call.
    fn small(&self, top: usize) {
        let mut ranked: Vec<_> = self.sites.iter().collect();
        ranked.sort_by_key(|(_, site)| core::cmp::Reverse(site.count));
        for (site, s) in ranked.iter().take(top) {
            if s.count >= SMALL_MIN && s.count * 10 >= self.count && s.bytes <= s.count * SMALL_BYTES {
                println!(
                    "rr prof: {site} copies {SMALL_BYTES} bytes or fewer at a time, {} times: a call to memcpy for each piece. Copy a run at once: the bytes up to the next one that needs handling, such as the next character to escape, or an indent as one slice",
                    s.count
                );
            }
        }
    }
}

/// The most bytes a copy holds, on average, for its site to count as one
/// that copies piece by piece; and how many times it must copy.
const SMALL_BYTES: u64 = 8;
const SMALL_MIN: u64 = 10_000;

fn report(dir: &Path, o: &Options) -> io::Result<ExitCode> {
    let mut programs: BTreeMap<PathBuf, Option<Program>> = BTreeMap::new();
    let mut allocs = Tally::default();
    let mut copies = Tally::default();
    let (mut images, mut lost, mut peak) = (0u64, 0u64, 0u64);
    for entry in fs::read_dir(dir)? {
        let data = fs::read(entry?.path())?;
        if data.len() < HEADER || &data[..8] != MAGIC {
            continue;
        }
        let word = |at: usize| u64::from_le_bytes(data[at..at + 8].try_into().unwrap_or_default());
        let half = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap_or_default()) as usize;
        let (depth, slots, anchor) = (half(8), half(12), word(16));
        lost += word(24);
        peak = peak.max(word(32));
        let exe = &data[40..HEADER];
        let exe = PathBuf::from(
            String::from_utf8_lossy(&exe[..exe.iter().position(|c| *c == 0).unwrap_or(exe.len())]).into_owned(),
        );
        images += 1;
        let program = programs.entry(exe.clone()).or_insert_with(|| {
            load(&exe, "rr_prof_anchor")
                .inspect_err(|why| println!("rr prof: no line tables to name the program's code: {why}"))
                .ok()
        });
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
    println!("rr prof: the heap held at most {peak} bytes at once");
    if lost > 0 {
        println!("rr prof: {lost} counts on stacks past the table, in neither total");
    }
    allocs.print(o.top, |s| s.count, false);
    println!(
        "rr prof: {} copies through memcpy and memmove, {} bytes",
        copies.count, copies.bytes
    );
    copies.print(o.top, |s| s.bytes, true);
    // A site that copies a few bytes millions of times pays a call for
    // each value, and ranks low by bytes.
    println!("rr prof: the places that copy most often, with the bytes of each copy");
    copies.print(o.top.min(COUNTED_TOP), |s| s.count, true);
    copies.small(o.top.min(COUNTED_TOP));
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
    if let Some(max) = o.max_heap
        && peak > max
    {
        println!("rr prof: the heap held {peak} bytes at once, above the budget of {max}");
        code = ExitCode::FAILURE;
    }
    Ok(code)
}

/// The program's line tables, and the address its symbol table gives
/// the function named anchor, by which the load slide of a process is known.
pub fn load(exe: &Path, anchor: &str) -> Result<Program, String> {
    use object::{Object as _, ObjectSymbol as _};
    let data = fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let file = object::File::parse(&*data).map_err(|e| format!("{}: {e}", exe.display()))?;
    if let Ok(Some(info)) = file.pdb_info() {
        // The PDB the linker named. rustc has it name the file alone
        // (/PDBALTPATH:%_PDB%), which is beside the executable; a full path
        // that is gone means the program has moved, with its PDB beside it.
        let named = PathBuf::from(String::from_utf8_lossy(info.path()).into_owned());
        let beside = exe.with_file_name(named.file_name().unwrap_or(named.as_os_str()));
        let path = if named.is_absolute() && named.is_file() {
            named
        } else {
            beside
        };
        let open = fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let pdb = pdb_addr2line::pdb::PDB::open(open).map_err(|e| format!("{}: {e}", path.display()))?;
        let lines = pdb_addr2line::ContextPdbData::try_from_pdb(pdb).map_err(|e| format!("{}: {e}", path.display()))?;
        let at = pdb_public(&path, anchor)?;
        return Ok(Program {
            lines: Lines::Pdb(Box::new(lines)),
            anchor: u64::from(at),
        });
    }
    let at = file
        .symbols()
        .find(|s| s.name().is_ok_and(|n| n.trim_start_matches('_') == anchor))
        .ok_or_else(|| format!("{}: no symbol {anchor}", exe.display()))?
        .address();
    let loader = addr2line::Loader::new(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    Ok(Program {
        lines: Lines::Dwarf(Box::new(loader)),
        anchor: at,
    })
}

/// The frames at each return address of an image loaded slide bytes off
/// its file's addresses, inlined ones innermost first.
pub fn frames(p: &Program, slide: u64, pcs: &[u64]) -> Vec<Frame> {
    let loader = match &p.lines {
        Lines::Dwarf(loader) => loader,
        Lines::Pdb(lines) => return pdb_frames(lines, slide, pcs),
    };
    let mut out = Vec::new();
    for pc in pcs {
        // A return address is past its call; look at the call.
        let probe = pc.wrapping_sub(slide).wrapping_sub(1);
        let mut found = false;
        if let Ok(mut it) = loader.find_frames(probe) {
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
        if !found && let Some(name) = loader.find_symbol(probe) {
            out.push(Frame {
                function: strip_hash(&addr2line::demangle_auto(name.into(), None)),
                file: String::new(),
                line: 0,
            });
        }
    }
    out
}

/// The RVA of the public symbol anchor in the PDB at path: the linker
/// records every external symbol there, with or without debug
/// information, as a symbol table would.
fn pdb_public(path: &Path, anchor: &str) -> Result<u32, String> {
    use pdb_addr2line::pdb::{self, FallibleIterator as _};
    let failed = |e: pdb::Error| format!("{}: {e}", path.display());
    let open = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut pdb = pdb::PDB::open(open).map_err(failed)?;
    let symbols = pdb.global_symbols().map_err(failed)?;
    let map = pdb.address_map().map_err(failed)?;
    let mut iter = symbols.iter();
    while let Some(symbol) = iter.next().map_err(failed)? {
        if let Ok(pdb::SymbolData::Public(public)) = symbol.parse()
            && public.name.to_string().trim_start_matches('_') == anchor
            && let Some(rva) = public.offset.to_rva(&map)
        {
            return Ok(rva.0);
        }
    }
    Err(format!("{}: no public symbol {anchor}", path.display()))
}

/// A PDB's lookups, with functions named without their argument lists,
/// as DWARF names them.
fn pdb_context<'a>(
    lines: &'a pdb_addr2line::ContextPdbData<'static, 'static, fs::File>,
) -> Result<pdb_addr2line::Context<'a, 'static>, pdb_addr2line::Error> {
    use pdb_addr2line::TypeFormatterFlags as Flags;
    lines.make_context_with_formatter_flags(Flags::default() | Flags::NO_ARGUMENTS)
}

/// frames, from a PDB: each return address less slide is an RVA.
fn pdb_frames(
    lines: &pdb_addr2line::ContextPdbData<'static, 'static, fs::File>,
    slide: u64,
    pcs: &[u64],
) -> Vec<Frame> {
    let mut out = Vec::new();
    let Ok(context) = pdb_context(lines) else {
        return out;
    };
    for pc in pcs {
        // A return address is past its call; look at the call.
        let Ok(probe) = u32::try_from(pc.wrapping_sub(slide).wrapping_sub(1)) else {
            continue;
        };
        if let Ok(Some(found)) = context.find_frames(probe) {
            for f in found.frames {
                // A frame pdb-addr2line could not name, as one of an
                // inlined call may be, says nothing of whose code it is.
                let Some(function) = f.function.as_deref() else {
                    continue;
                };
                out.push(Frame {
                    function: strip_hash(function),
                    file: f.file.map(std::borrow::Cow::into_owned).unwrap_or_default(),
                    line: f.line.unwrap_or(0),
                });
            }
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
