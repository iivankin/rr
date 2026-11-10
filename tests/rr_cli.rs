use std::fmt::Write as _;
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
        "rust-toolchain.toml",
        "src/main.rs",
        "src/sys/unix.rs",
        "src/sys/windows.rs",
        "src/greet.rs",
    ] {
        assert!(root.join(file).is_file(), "{file}");
    }
    assert!(!root.join("Cargo.toml").exists());
    assert!(!root.join("src/lib.rs").exists());
    let main = fs::read_to_string(root.join("src/main.rs")).unwrap();
    assert!(main.contains("//! demo_app:"), "{main}");
    // scripts/smoke-distribution.py builds, tests and profiles it with the
    // toolchain. The entry rr fuz adds for several targets keeps rr's rules.
    let greet = root.join("src/greet.rs");
    let mut source = fs::read_to_string(&greet).unwrap();
    source.push_str(
        "\n/// Two names.\n#[cfg(fuzzing)]\npub fn fuzz_two(input: &[u8]) {\n    let mut out = Vec::new();\n    assert!(greet(&mut out, input));\n    assert!(greet(&mut out, input));\n}\n",
    );
    fs::write(&greet, source).unwrap();
    let harness = Command::new(env!("CARGO_BIN_EXE_rr"))
        .current_dir(&root)
        .args([
            "check",
            "src/main.rs",
            "--crate-name",
            "demo_app",
            "--cfg",
            "fuzzing",
            "--rr-harness=fuzz:greet::fuzz_greet,greet::fuzz_two",
        ])
        .output()
        .unwrap();
    success(&harness);
    // Its fuzz targets keep the rules too.
    for cfg in [&[][..], &["--cfg", "fuzzing"][..]] {
        let lint = Command::new(env!("CARGO_BIN_EXE_rr"))
            .current_dir(&root)
            .args(["lint", "src/main.rs", "--crate-name", "demo_app", "-Dwarnings"])
            .args(cfg)
            .env_remove("CLIPPY_ARGS")
            .output()
            .unwrap();
        success(&lint);
    }
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
fn test_builds_its_runtime_against_the_sysroot_the_crate_names() {
    // A sysroot with no standard library in it: the runtime, built
    // against the crate's, fails first, and the crate is never compiled
    // against another.
    let project = Project::new();
    fs::write(project.0.join("lib.rs"), "#![no_std]\npub fn value() -> u8 { 1 }").unwrap();
    let empty = project.0.join("empty");
    fs::create_dir(&empty).unwrap();
    let checked = project.rr(&["test", "lib.rs", "--check", "--sysroot", empty.to_str().unwrap()]);
    assert!(!checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stderr).contains("could not build the rr test runtime"));
}

#[test]
fn time_reports_the_fastest_run_and_fails_above_a_budget() {
    let project = Project::new();
    let rr = env!("CARGO_BIN_EXE_rr");
    let timed = project.rr(&["time", "--runs", "3", "--", rr, "--version"]);
    success(&timed);
    assert!(String::from_utf8_lossy(&timed.stdout).contains("rr time: 3 runs, the fastest"));
    // No run takes no time at all.
    let over = project.rr(&["time", "--max-ms", "0", "--", rr, "--version"]);
    assert!(!over.status.success());
    assert!(String::from_utf8_lossy(&over.stdout).contains("above the budget of 0 ms"));
}

#[test]
fn rustc_builds_and_rr_checks_against_a_prebuilt_dependency() {
    let project = Project::new();
    success(&project.rr(&["init", "dep", "--lib"]));
    // rustc of the same toolchain, which rustup picks for the test as it
    // picked it for cargo.
    let rustc = Command::new("rustc")
        .current_dir(&project.0)
        .args([
            "--edition=2024",
            "dep/src/lib.rs",
            "--crate-name",
            "dep",
            "--crate-type=rlib",
        ])
        .args(["-Cpanic=abort", "-o", "libdep.rlib"])
        .output()
        .unwrap();
    success(&rustc);
    fs::write(project.0.join("local.rs"), "pub fn local() -> u32 { 1 }").unwrap();
    fs::write(
        project.0.join("lib.rs"),
        "#![no_std]\nmod local;\npub fn value() -> u32 { dep::answer() + local::local() }",
    )
    .unwrap();
    success(&project.rr(&["check", "lib.rs", "--extern", "dep=libdep.rlib"]));
    // rr checks; it builds no program.
    let build = project.rr(&["build", "lib.rs", "--extern", "dep=libdep.rlib", "-o", "libapp.rlib"]);
    assert!(!build.status.success());
    assert!(String::from_utf8_lossy(&build.stderr).contains("build it with rustc"));
    assert!(!project.0.join("libapp.rlib").exists());
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
fn fuz_cannot_override_native_output_through_an_argument_file() {
    let project = Project::new();
    success(&project.rr(&["init", "demo"]));
    let root = project.0.join("demo");
    fs::write(root.join("flags"), "-o\nkeep-me\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rr"))
        .current_dir(&root)
        .args([
            "fuz",
            "src/main.rs",
            "--target",
            "greet::fuzz_greet",
            "@flags",
            "--",
            "-runs=1",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported flag: -o"));
    assert!(!root.join("keep-me").exists());
    // A file of its own is no fuzz target: rr fuzzes a crate's functions.
    let file = project.rr(&["fuz", "fuz.rs", "--", "-runs=1"]);
    assert!(!file.status.success());
    assert!(String::from_utf8_lossy(&file.stderr).contains("--target PATH"));
}

#[test]
fn add_copies_a_component_and_what_it_needs_and_keeps_changed_code() {
    let project = Project::new();
    let registry = project.0.join("registry");
    fs::create_dir_all(&registry).unwrap();
    fs::write(
        registry.join("hash.rs"),
        "//! Hashes.\n\n// rr: checked(0.0.1)\n\npub fn hash() {}\n\nmod sys {\n    pub fn fast() {}\n}\n",
    )
    .unwrap();
    fs::write(registry.join("tls.rs"), "// rr: needs(hash)\npub fn tls() {}\n").unwrap();
    fs::create_dir(project.0.join("src")).unwrap();
    fs::write(project.0.join("src/main.rs"), "mod greet;\n").unwrap();

    // Each component in its own file under src/base/, declared in
    // base/mod.rs, its header replaced by what added it; the root is told
    // to declare base.
    let output = project.rr(&["add", "registry/tls.rs"]);
    success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hash = format!(
        "//! Hashes.\n\n// rr: added(hash, rr {})\n\npub fn hash() {{}}\n\nmod sys {{\n    pub fn fast() {{}}\n}}\n",
        rr_version()
    );
    assert_eq!(fs::read_to_string(project.0.join("src/base/hash.rs")).unwrap(), hash);
    assert_eq!(
        fs::read_to_string(project.0.join("src/base/tls.rs")).unwrap(),
        format!("// rr: added(tls, rr {})\npub fn tls() {{}}\n", rr_version())
    );
    let base = fs::read_to_string(project.0.join("src/base/mod.rs")).unwrap();
    assert!(base.contains("pub mod hash;\npub mod tls;\n"), "{base}");
    assert!(stdout.contains("Declare `mod base;`"), "{stdout}");
    assert!(stdout.contains("rr add: hash, tls"), "{stdout}");

    // Again, with base declared: nothing changes, nothing to declare. A
    // file the project changed stops the add, before anything is
    // written, until --overwrite.
    fs::write(project.0.join("src/main.rs"), "mod base;\nmod greet;\n").unwrap();
    let output = project.rr(&["add", "registry/tls.rs"]);
    success(&output);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Declare"));
    assert_eq!(fs::read_to_string(project.0.join("src/base/mod.rs")).unwrap(), base);
    fs::write(project.0.join("src/base/hash.rs"), "pub fn mine() {}\n").unwrap();
    fs::remove_file(project.0.join("src/base/tls.rs")).unwrap();
    let output = project.rr(&["add", "registry/tls.rs"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--overwrite"));
    assert!(!project.0.join("src/base/tls.rs").exists());
    success(&project.rr(&["add", "--overwrite", "registry/tls.rs"]));
    assert_eq!(fs::read_to_string(project.0.join("src/base/hash.rs")).unwrap(), hash);

    // A component that needs a newer rr, brings a file not its own, or
    // was added by rr 0.5 as a directory, is refused.
    fs::write(registry.join("new.rs"), "// rr: checked(99.0.0)\n").unwrap();
    let output = project.rr(&["add", "registry/new.rs"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs rr 99.0.0"));
    fs::write(registry.join("out.rs"), "// rr: file(../evil.rs)\n").unwrap();
    let output = project.rr(&["add", "registry/out.rs"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a file of out's own"));
    assert!(!project.0.join("src/base/out.rs").exists());
    fs::create_dir_all(project.0.join("src/base/old")).unwrap();
    fs::write(project.0.join("src/base/old/mod.rs"), "").unwrap();
    fs::write(registry.join("old.rs"), "pub fn old() {}\n").unwrap();
    let output = project.rr(&["add", "registry/old.rs"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("one file now"));
}

fn rr_version() -> String {
    let rr_cli = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/rr_cli.rs")).unwrap();
    let line = rr_cli.lines().find(|l| l.starts_with("pub const VERSION")).unwrap();
    line.split('"').nth(1).unwrap().to_owned()
}

#[test]
fn add_cuts_what_its_options_leave_out_and_adds_what_they_need() {
    let project = Project::new();
    let registry = project.0.join("registry");
    fs::create_dir_all(&registry).unwrap();
    for name in ["system", "builtin"] {
        fs::write(registry.join(format!("{name}.rs")), format!("pub fn {name}() {{}}\n")).unwrap();
    }
    fs::write(registry.join("tls-vectors.txt"), "vectors\n").unwrap();
    fs::write(
        registry.join("tls.rs"),
        "//! TLS.\n\
         // rr: option(roots, one): Which roots?\n\
         // rr: choice(roots = system, default, needs(system)): the system's\n\
         // rr: choice(roots = builtin, needs(builtin)): its own\n\
         // rr: choice(roots = none): the caller's\n\
         // rr: option(os, many): Which systems?\n\
         // rr: choice(os = linux, default)\n\
         // rr: choice(os = macos, default)\n\
         // rr: choice(os = windows)\n\
         // rr: option(tests, one): Tests?\n\
         // rr: choice(tests = yes, default)\n\
         // rr: choice(tests = no)\n\
         // rr: file(tls-vectors.txt, tests = yes)\n\
         \n\
         pub fn tls() {}\n\
         \n\
         // rr: section(os = linux macos)\n\
         fn unix() {}\n\
         \n\
         // rr: section(os = macos)\n\
         fn macos() {}\n\
         // rr: end(os = macos)\n\
         // rr: end(os = linux macos)\n\
         \n\
         // rr: section(os = windows)\n\
         fn windows() {}\n\
         // rr: end(os = windows)\n\
         \n\
         // rr: unless(os = windows)\n\
         #[cfg(windows)]\n\
         compile_error!(\"no windows\");\n\
         // rr: end(os = windows)\n\
         \n\
         // rr: section(tests = yes)\n\
         mod tests {}\n\
         // rr: end(tests = yes)\n",
    )
    .unwrap();
    // Without a terminal the defaults are taken, and the way to choose
    // said; what they leave out is cut, with the blank line before it.
    let output = project.rr(&["add", "registry/tls.rs"]);
    success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--option roots=VALUE"), "{stdout}");
    assert!(stdout.contains("--option os=A,B"), "{stdout}");
    assert!(
        stdout.contains("rr add: system, tls (roots=system os=linux,macos tests=yes)"),
        "{stdout}"
    );
    assert!(project.0.join("src/base/system.rs").is_file());
    assert!(!project.0.join("src/base/builtin.rs").exists());
    assert_eq!(
        fs::read_to_string(project.0.join("src/base/tls-vectors.txt")).unwrap(),
        "vectors\n"
    );
    assert_eq!(
        fs::read_to_string(project.0.join("src/base/tls.rs")).unwrap(),
        format!(
            "//! TLS.\n// rr: added(tls, rr {}; roots = system; os = linux macos; tests = yes)\n\n\
             pub fn tls() {{}}\n\nfn unix() {{}}\n\nfn macos() {{}}\n\n\
             #[cfg(windows)]\ncompile_error!(\"no windows\");\n\nmod tests {{}}\n",
            rr_version()
        )
    );

    let project2 = Project::new();
    fs::create_dir_all(project2.0.join("registry")).unwrap();
    for entry in fs::read_dir(&registry).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), project2.0.join("registry").join(entry.file_name())).unwrap();
    }
    let output = project2.rr(&[
        "add",
        "--option",
        "roots=builtin",
        "--option",
        "os=windows",
        "--option",
        "tests=no",
        "registry/tls.rs",
    ]);
    success(&output);
    assert!(project2.0.join("src/base/builtin.rs").is_file());
    assert!(!project2.0.join("src/base/tls-vectors.txt").exists());
    assert_eq!(
        fs::read_to_string(project2.0.join("src/base/tls.rs")).unwrap(),
        format!(
            "//! TLS.\n// rr: added(tls, rr {}; roots = builtin; os = windows; tests = no)\n\n\
             pub fn tls() {{}}\n\nfn windows() {{}}\n",
            rr_version()
        )
    );
    let output = project2.rr(&["add", "--option", "roots=other", "registry/tls.rs"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("one of system, builtin, none"));
    let output = project2.rr(&["add", "--option", "roots=system,none", "registry/tls.rs"]);
    assert!(!output.status.success());

    // A mark that is not closed, or names what the header does not ask,
    // is refused.
    fs::write(registry.join("bad.rs"), "// rr: section(os = linux)\nfn f() {}\n").unwrap();
    let output = project.rr(&["add", "registry/bad.rs"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("not an option"));
    fs::write(registry.join("bad.rs"), "fn f() {}\n// rr: needs(system)\n").unwrap();
    let output = project.rr(&["add", "registry/bad.rs"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("belongs in the header"));
    fs::write(registry.join("bad.rs"), "// rr: need(system)\nfn f() {}\n").unwrap();
    let output = project.rr(&["add", "registry/bad.rs"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not one of"));
}

#[test]
fn add_lists_a_registrys_components_with_what_they_need_and_ask() {
    let project = Project::new();
    let index = env!("CARGO_MANIFEST_DIR").to_owned() + "/registry/index.json";
    let output = project.rr(&["add", "--list", &index]);
    success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // What the index says of each component, as the list prints it; the
    // index changes with the registry, the form does not.
    let json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&index).unwrap()).unwrap();
    let strings = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    };
    let components = json["components"].as_array().unwrap();
    assert!(components.iter().any(|component| component["name"] == "tls"));
    for component in components {
        let mut expected = format!(
            "{}  {}\n",
            component["name"].as_str().unwrap(),
            component["description"].as_str().unwrap()
        );
        let needs = strings(&component["dependencies"]);
        if !needs.is_empty() {
            writeln!(expected, "    needs: {}", needs.join(", ")).unwrap();
        }
        for option in component["options"].as_array().into_iter().flatten() {
            writeln!(
                expected,
                "    asks: --option {}={} (default {})",
                option["name"].as_str().unwrap(),
                strings(&option["choices"]).join("|"),
                option["default"].as_str().unwrap()
            )
            .unwrap();
        }
        assert!(stdout.contains(&expected), "{expected}\nin\n{stdout}");
    }
}
