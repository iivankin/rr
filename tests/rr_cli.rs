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
fn init_check_lint_and_build_native_binary_without_manifest() {
    let project = Project::new();
    success(&project.rr(&["init"]));
    assert_eq!(project.files(), ["main.rs"]);
    success(&project.rr(&["check", "main.rs"]));
    success(&project.rr(&["lint", "main.rs", "-Dwarnings", "-Wclippy::cargo"]));
    assert_eq!(project.files(), ["main.rs"]);
    success(&project.rr(&["main.rs", "-O", "-o", "app"]));
    assert!(Command::new(project.0.join("app")).status().unwrap().success());
    let original = fs::read(project.0.join("main.rs")).unwrap();
    assert!(!project.rr(&["init"]).status.success());
    assert_eq!(fs::read(project.0.join("main.rs")).unwrap(), original);
}

#[test]
fn explicit_prebuilt_dependencies_and_local_modules_work() {
    let project = Project::new();
    success(&project.rr(&["init", "--lib"]));
    success(&project.rr(&["build", "lib.rs", "--crate-name", "dep", "-o", "libdep.rlib"]));
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
