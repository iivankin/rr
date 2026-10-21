use std::fs;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct Scratch {
    pub path: PathBuf,
}

impl Scratch {
    pub fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "rr-check-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            eprintln!("rr: could not remove {}: {error}", self.path.display());
        }
    }
}

pub fn init(args: &[String]) -> io::Result<ExitCode> {
    let mut directory = None;
    let mut library = false;
    let mut kind_set = false;
    for arg in args {
        match arg.as_str() {
            "--lib" | "--bin" if !kind_set => {
                library = arg == "--lib";
                kind_set = true;
            },
            path if !path.starts_with('-') && directory.is_none() => directory = Some(PathBuf::from(path)),
            _ => return Err(io::Error::other("usage: rr init [DIR] [--lib]")),
        }
    }
    let root = directory.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&root)?;
    let name = crate_name(&root.canonicalize()?);
    let files: &[(&str, &str)] = if library { &[("src/lib.rs", LIB)] } else { PROJECT };
    // Refuse before writing anything, so that init never overwrites code
    // or leaves half a project.
    for (path, _) in files {
        if root.join(path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists", root.join(path).display()),
            ));
        }
    }
    for (path, text) in files {
        let file = root.join(path);
        if let Some(dir) = file.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&file)?;
        output.write_all(text.replace("%NAME%", &name).as_bytes())?;
        println!("Created {}", file.display());
    }
    if !library {
        println!("Next: make fmt && make format check lint && make && make test (see AGENTS.md)");
    }
    Ok(ExitCode::SUCCESS)
}

/// The directory's name as a crate name: [a-z0-9_], not starting with a
/// digit.
fn crate_name(dir: &std::path::Path) -> String {
    let base = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut name: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert_str(0, "app_");
    }
    name
}

/// A program as rr projects are laid out: one crate, src/main.rs with
/// its allocator, panic handler and entry, the system in src/sys/, one
/// file for each of macOS, Linux and Windows, a
/// module with its tests, bench and fuzz target beside its code, a
/// Makefile for every check, and the instructions for whoever changes
/// it.
const PROJECT: &[(&str, &str)] = &[
    ("AGENTS.md", include_str!("../../examples/project/AGENTS.md")),
    ("Makefile", include_str!("../../examples/project/Makefile")),
    (".gitignore", include_str!("../../examples/project/gitignore")),
    ("src/main.rs", include_str!("../../examples/project/src/main.rs.in")),
    (
        "src/sys/macos.rs",
        include_str!("../../examples/project/src/sys/macos.rs.in"),
    ),
    (
        "src/sys/linux.rs",
        include_str!("../../examples/project/src/sys/linux.rs.in"),
    ),
    (
        "src/sys/windows.rs",
        include_str!("../../examples/project/src/sys/windows.rs.in"),
    ),
    ("src/greet.rs", include_str!("../../examples/project/src/greet.rs.in")),
];

/// A library crate on its own, for a program to depend on.
const LIB: &str = "#![no_std]\n\npub fn answer() -> u32 {\n    42\n}\n";
