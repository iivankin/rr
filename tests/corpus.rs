//! The programs in examples/corpus, written in restricted Rust as rr
//! init lays them out: each stays in rr fmt's style, and passes rr lint
//! with warnings as errors, its tests included, so that a change to rr's
//! rules is tried on code other than the one it was made for. Building
//! and running them needs a distribution's sysroot:
//! scripts/smoke-distribution.py runs their Makefiles there.

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn corpus_programs_pass_rr() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/corpus");
    let mut programs = 0;
    for entry in fs::read_dir(&corpus).unwrap() {
        let root = entry.unwrap().path();
        if !root.join("Makefile").is_file() {
            continue;
        }
        programs += 1;
        let name = root.file_name().unwrap().to_string_lossy().into_owned();
        let format = Command::new(env!("CARGO_BIN_EXE_rr"))
            .current_dir(&root)
            .args(["fmt", "--check", "src/main.rs"])
            .output()
            .unwrap();
        assert!(
            format.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&format.stdout)
        );
        for command in [&["lint", "src/main.rs"][..], &["test", "src/main.rs", "--lint"][..]] {
            let lint = Command::new(env!("CARGO_BIN_EXE_rr"))
                .current_dir(&root)
                .args(command)
                .args(["--crate-name", &name, "-Dwarnings"])
                .env_remove("CLIPPY_ARGS")
                .output()
                .unwrap();
            assert!(
                lint.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&lint.stderr)
            );
        }
    }
    assert!(programs >= 2, "examples/corpus holds {programs} programs");
}
