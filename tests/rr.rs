use std::fs;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn compile(source: &str, extra: &[&str]) -> Output {
    let root = std::env::temp_dir().join(format!(
        "rr-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let file = root.join("lib.rs");
    fs::write(&file, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rr"))
        .args([
            "check",
            "--crate-name",
            "rr_fixture",
            "--crate-type=lib",
            "--edition=2024",
            "-A",
            "clippy::all",
        ])
        .arg(&file)
        .args(extra)
        .output()
        .unwrap();
    fs::remove_dir_all(&root).unwrap();
    output
}

fn rejected(source: &str, rule: &str) {
    let output = compile(source, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {source}");
    assert!(stderr.contains(&rule.replace('_', "-")), "expected {rule}:\n{stderr}");
}

fn accepted(source: &str) {
    let output = compile(source, &[]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn requires_no_std_and_rejects_std_aliases() {
    rejected("pub fn value() -> u8 { 1 }", "rr_no_std");
    rejected("#![no_std]\nextern crate std as system;", "rr_no_std");
}

#[test]
fn ordinary_traits_lifetimes_and_core_assertions_work() {
    accepted(
        "#![no_std]\npub trait Read { fn read(&self) -> u8; }\npub fn same<'a>(v: &'a u8) -> &'a u8 { ::core::assert!(*v > 0); v }",
    );
}

#[test]
fn rejects_generic_definitions_and_impl_trait() {
    for source in [
        "pub fn id<T>(v: T) -> T { v }",
        "pub struct Buffer<const N: usize>([u8; N]);",
        "pub fn id(v: impl Copy) {}",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "rr_no_generics");
    }
}

#[test]
fn rejects_complex_traits_and_dyn() {
    for source in [
        "pub trait Read { type Value; }",
        "pub trait Read: Copy {}",
        "pub trait Read where Self: Copy {}",
        "pub fn read(v: &dyn core::fmt::Debug) {}",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "rr_simple_traits");
    }
}

#[test]
fn rejects_async_functions_blocks_closures_and_await() {
    for source in [
        "pub async fn run() {}",
        "pub fn run() { let _ = async {}; }",
        "pub fn run() { let _ = async || {}; }",
        "pub async fn run() { async {}.await; }",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "rr_no_generics");
    }
}

#[test]
fn rejects_macro_definitions_calls_and_derives() {
    for source in [
        "macro_rules! noop { () => {} }",
        "pub fn run() { let _ = core::concat!(\"a\", \"b\"); }",
        "#[derive(Clone)] pub struct Data;",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "rr_no_macros");
    }
}

#[test]
fn cloning_copy_values_and_ufcs_still_need_reasons() {
    rejected(
        "#![no_std]\npub fn copy(v: u8) -> u8 { v.clone() }",
        "rr_unexplained_escape",
    );
    rejected(
        "#![no_std]\npub fn copy(v: &u8) -> u8 { Clone::clone(v) }",
        "rr_unexplained_escape",
    );
    accepted(
        "#![no_std]\npub fn copy(v: u8) -> u8 {\n // rr: escape: the interface deliberately exercises Clone for this scalar.\n v.clone()\n}",
    );
}

#[test]
fn strings_vectors_and_owning_conversions_need_reasons() {
    for body in ["s.clone()", "s.as_str().to_owned()", "s.as_bytes().to_vec(); s.clone()"] {
        rejected(
            &format!(
                "#![no_std]\nextern crate alloc;\nuse alloc::borrow::ToOwned;\npub fn copy(s: &alloc::string::String) -> alloc::string::String {{ {body} }}"
            ),
            "rr_unexplained_escape",
        );
    }
}

#[test]
fn collects_and_shared_ownership_need_reasons() {
    for source in [
        "pub fn copy(v: &[u8]) -> alloc::vec::Vec<u8> { v.iter().copied().collect() }",
        "pub fn shared() { let _ = alloc::rc::Rc::new(1); }",
        "pub fn shared() { let _ = alloc::sync::Arc::new(1); }",
        "pub fn shared() { let _ = core::cell::RefCell::new(1); }",
    ] {
        rejected(
            &format!("#![no_std]\nextern crate alloc;\n{source}"),
            "rr_unexplained_escape",
        );
    }
}

#[test]
fn leaks_forgetting_and_unsafe_need_reasons() {
    rejected(
        "#![no_std]\nextern crate alloc;\npub fn leak(v: alloc::boxed::Box<u8>) { alloc::boxed::Box::leak(v); }",
        "rr_unexplained_escape",
    );
    rejected(
        "#![no_std]\npub fn forget(v: u8) { core::mem::forget(v); }",
        "rr_unexplained_escape",
    );
    rejected(
        "#![no_std]\npub fn read(v: *const u8) -> u8 { unsafe { *v } }",
        "rr_unexplained_escape",
    );
}

#[test]
fn unrelated_method_names_do_not_trigger() {
    accepted(
        "#![no_std]\npub struct Fake;\nimpl Fake { pub fn clone(&self) -> u8 { 1 } }\npub fn get(v: &Fake) -> u8 { v.clone() }",
    );
}

#[test]
fn accepts_trailing_block_and_multiline_statement_comments() {
    for source in [
        "let b = v.clone(); // rr: escape: the interface needs an owned snapshot.\n b",
        "/* rr: escape: the interface needs an owned snapshot. */\n v.clone()",
        "// rr: escape: the interface needs an owned snapshot.\n let b =\n v.clone();\n b",
        "let b =\n // rr: escape: the interface needs an owned snapshot.\n v.clone();\n b",
    ] {
        accepted(&format!("#![no_std]\npub fn copy(v: u8) -> u8 {{\n{source}\n}}"));
    }
}

#[test]
fn comment_must_be_real_nonempty_and_adjacent() {
    for source in [
        "let _ = \"// rr: escape: a fake reason\";\n v.clone()",
        "// rr: escape:\n v.clone()",
        "// rr: escape: a distant reason\n let _ = 1;\n v.clone()",
        "let _ = 1; // rr: escape: applies to the previous statement\n v.clone()",
        "let _ = r#\"\n// rr: escape: still inside a string\n\"#;\n v.clone()",
    ] {
        rejected(
            &format!("#![no_std]\npub fn copy(v: u8) -> u8 {{\n{source}\n}}"),
            "rr_unexplained_escape",
        );
    }
}

#[test]
fn rules_cannot_be_lowered_to_allow() {
    for flags in [
        vec!["-A", "rr", "--cap-lints=allow"],
        vec!["--force-warn=rr"],
        vec!["--force-warn=rr-no-std"],
    ] {
        let output = compile("pub fn value() -> u8 { 1 }", &flags);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("rr-no-std"));
    }
}

#[test]
fn nested_macros_and_conditional_derives_are_rejected() {
    rejected(
        "#![no_std]\npub fn run(v: u8) { assert!(core::matches!(v, 1)); }",
        "rr_no_macros",
    );
    rejected(
        "#![no_std]\n#[cfg_attr(all(), derive(Clone))] pub struct Data;",
        "rr_no_macros",
    );
}

#[test]
fn nested_release_assertions_and_escape_calls_are_checked() {
    rejected(
        "#![no_std]\npub fn run(v: u8) { debug_assert!(core::matches!(v, 1)); }",
        "rr_no_macros",
    );
    rejected(
        "#![no_std]\npub fn run(v: u8) { assert!(v.clone() > 0); }",
        "rr_unexplained_escape",
    );
}

#[test]
fn unsafe_contracts_and_runtime_borrowing_need_reasons() {
    rejected("#![no_std]\npub unsafe fn raw() {}", "rr_unexplained_escape");
    rejected(
        "#![no_std]\npub struct Data; unsafe impl Send for Data {}",
        "rr_unexplained_escape",
    );
    rejected(
        "#![no_std]\npub fn change(v: &core::cell::RefCell<u8>) { *v.borrow_mut() = 1; }",
        "rr_unexplained_escape",
    );
    accepted(
        "#![no_std]\n// rr: escape: callers must follow the documented raw interface contract.\npub unsafe fn raw() {}",
    );
}

#[test]
fn explicit_std_from_extern_flags_is_rejected() {
    let output = compile(
        "#![no_std]\npub fn clock() { let _ = std::time::Instant::now(); }",
        &["--extern", "std"],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rr-no-std"));
}
