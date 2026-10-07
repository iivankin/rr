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
            _ => return Err(io::Error::other("usage: rr init [DIR] [--lib|--bin]")),
        }
    }
    let root = directory.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&root)?;
    let file = root.join(if library { "lib.rs" } else { "main.rs" });
    // create_new prevents init from overwriting existing source code.
    let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&file)?;
    output.write_all(if library { LIB.as_bytes() } else { BIN.as_bytes() })?;
    println!("Created {}", file.display());
    Ok(ExitCode::SUCCESS)
}

const LIB: &str = "#![no_std]\n\npub fn answer() -> u32 {\n    42\n}\n";

// This minimal native executable uses the platform C runtime for process entry
// and abort, while requiring neither std nor a Rust allocator.
const BIN: &str = "#![no_std]\n#![no_main]\n\n#[link(name = \"c\")]\nunsafe extern \"C\" {\n    fn abort() -> !;\n}\n\n#[unsafe(no_mangle)]\npub extern \"C\" fn main() -> i32 {\n    0\n}\n\n#[panic_handler]\nfn panic(_: &core::panic::PanicInfo<'_>) -> ! {\n    // rr: escape: abort terminates the process on panic; the C runtime provides this symbol.\n    unsafe { abort() }\n}\n";
