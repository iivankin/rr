use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rr-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn rr(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rr"))
            .current_dir(&self.0)
            .args(args)
            .env_remove("CLIPPY_ARGS")
            .output()
            .unwrap()
    }
    fn files(&self) -> Vec<String> {
        let mut files: Vec<_> = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_owned())
            .collect();
        files.sort();
        files
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn success(output: &Output) {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn init_lays_out_a_project_that_passes_lint() {
    let project = Project::new();
    success(&project.rr(&["init", "demo-app"]));
    let root = project.0.join("demo-app");
    for file in [
        "AGENTS.md",
        "Makefile",
        ".gitignore",
        "src/main.rs",
        "src/sys/macos.rs",
        "src/sys/linux.rs",
        "src/sys/windows.rs",
        "src/greet.rs",
    ] {
        assert!(root.join(file).is_file(), "{file}");
    }
    assert!(!root.join("Cargo.toml").exists());
    assert!(!root.join("src/lib.rs").exists());
    let main = fs::read_to_string(root.join("src/main.rs")).unwrap();
    assert!(main.contains("//! demo_app:"), "{main}");
    // Building links alloc, which needs the bundle's panic=abort sysroot:
    // scripts/smoke-distribution.py builds, tests and profiles it there.
    let lint = Command::new(env!("CARGO_BIN_EXE_rr"))
        .current_dir(&root)
        .args(["lint", "src/main.rs", "--crate-name", "demo_app", "-Dwarnings"])
        .env_remove("CLIPPY_ARGS")
        .output()
        .unwrap();
    success(&lint);
    // It is in rr's one style already.
    let format = Command::new(env!("CARGO_BIN_EXE_rr"))
        .current_dir(&root)
        .args(["fmt", "--check", "src/main.rs"])
        .output()
        .unwrap();
    success(&format);
    // A second init writes nothing.
    let original = fs::read(root.join("src/main.rs")).unwrap();
    assert!(!project.rr(&["init", "demo-app"]).status.success());
    assert_eq!(fs::read(root.join("src/main.rs")).unwrap(), original);
}

#[test]
fn prof_keeps_symbols_and_reports_an_empty_run() {
    let project = Project::new();
    fs::write(project.0.join("lib.rs"), "#![no_std]\npub fn value() -> u8 { 1 }").unwrap();
    // A stripped --prof build could not be read back.
    let stripped = project.rr(&["build", "--prof", "lib.rs", "-Cstrip=symbols", "-o", "libx.rlib"]);
    assert!(!stripped.status.success());
    assert!(String::from_utf8_lossy(&stripped.stderr).contains("drop -C strip"));
    // A command with no --prof program in it allocates nothing rr prof sees.
    let report = project.rr(&["prof", "--max", "0", "--", "/usr/bin/true"]);
    success(&report);
    assert!(String::from_utf8_lossy(&report.stdout).contains("rr prof: 0 allocations"));
}

#[test]
fn explicit_prebuilt_dependencies_and_local_modules_work() {
    let project = Project::new();
    success(&project.rr(&["init", "dep", "--lib"]));
    success(&project.rr(&["build", "dep/src/lib.rs", "--crate-name", "dep", "-o", "libdep.rlib"]));
    fs::write(project.0.join("local.rs"), "pub fn local() -> u32 { 1 }").unwrap();
    fs::write(
        project.0.join("lib.rs"),
        "#![no_std]\nmod local;\npub fn value() -> u32 { dep::answer() + local::local() }",
    )
    .unwrap();
    success(&project.rr(&["build", "lib.rs", "--extern", "dep=libdep.rlib", "-o", "libapp.rlib"]));
    assert!(project.0.join("libapp.rlib").is_file());
}

#[test]
fn rustc_argument_files_work_and_cannot_disable_rules() {
    let project = Project::new();
    fs::write(project.0.join("lib.rs"), "pub fn value() -> u8 { 1 }").unwrap();
    fs::write(
        project.0.join("flags"),
        "--edition=2024\n--crate-type=rlib\n--cap-lints=allow\n-Arr\nlib.rs\n",
    )
    .unwrap();
    let output = project.rr(&["check", "@flags"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rr-no-std"));
    assert_eq!(project.files(), ["flags", "lib.rs"]);
    assert!(!project.rr(&["--rustc", "lib.rs"]).status.success());
}

#[test]
fn cargo_environment_cannot_disable_rr() {
    let project = Project::new();
    fs::write(project.0.join("lib.rs"), "pub fn value() -> u8 { 1 }").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rr"))
        .current_dir(&project.0)
        .args(["check", "lib.rs"])
        .env("CLIPPY_ARGS", "--no-deps__CLIPPY_HACKERY__-Arr__CLIPPY_HACKERY__")
        .env_remove("CARGO_PRIMARY_PACKAGE")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rr-no-std"));
}

#[test]
fn fuz_initialization_preserves_the_harness_and_creates_no_manifest() {
    let project = Project::new();
    success(&project.rr(&["fuz", "init"]));
    assert_eq!(project.files(), ["artifacts", "corpus", "fuz.rs"]);
    let original = fs::read(project.0.join("fuz.rs")).unwrap();
    success(&project.rr(&["check", "fuz.rs"]));
    success(&project.rr(&["lint", "fuz.rs", "-Dwarnings"]));
    assert!(!project.rr(&["fuz", "init"]).status.success());
    assert_eq!(fs::read(project.0.join("fuz.rs")).unwrap(), original);
    assert_eq!(project.files(), ["artifacts", "corpus", "fuz.rs"]);
}

#[test]
fn fuz_cannot_override_native_output_through_an_argument_file() {
    let project = Project::new();
    success(&project.rr(&["fuz", "init"]));
    fs::write(project.0.join("flags"), "-o\nkeep-me\n").unwrap();
    let output = project.rr(&["fuz", "fuz.rs", "@flags", "--", "-runs=1"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported flag: -o"));
    assert!(!project.0.join("keep-me").exists());
}
