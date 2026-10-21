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
fn no_std_compiler_builtins_work() {
    accepted(
        r#"#![no_std]
pub fn builtins() -> &'static str {
    assert!(cfg!(any(unix, windows)));
    let _ = option_env!("RR_OPTIONAL_TEST_VAR");
    let _ = env!("PATH");
    let _ = (file!(), line!(), column!(), module_path!());
    let _ = core::format_args!("value={}", 42);
    let _ = stringify!(Option<u8>);
    concat!("restricted", " rust")
}"#,
    );
}

#[test]
fn no_std_compiler_attribute_builtins_work() {
    accepted(
        r"#![no_std]
#![feature(alloc_error_handler)]
#[alloc_error_handler]
fn oom(_: core::alloc::Layout) -> ! { loop {} }
use core::alloc::{GlobalAlloc, Layout};
struct Heap;
// rr: escape(unsafe): this test allocator always fails allocation and owns no memory.
unsafe impl GlobalAlloc for Heap {
    // rr: escape(unsafe): valid layouts always receive the documented null allocation result.
    unsafe fn alloc(&self, _: Layout) -> *mut u8 { core::ptr::null_mut() }
    // rr: escape(unsafe): no pointer can be allocated by this allocator, so valid deallocations never occur.
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}
#[global_allocator]
static HEAP: Heap = Heap;
",
    );
}

#[test]
fn include_builtins_work_without_bypassing_language_rules() {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rr-builtins");
    accepted(&format!(
        r##"#![no_std]
include!(r#"{}"#);
pub const TEXT: &str = include_str!(r#"{}"#);
pub const BYTES: &[u8] = include_bytes!(r#"{}"#);
"##,
        fixtures.join("ordinary.rs").display(),
        fixtures.join("data.txt").display(),
        fixtures.join("data.txt").display()
    ));
    for (file, rule) in [
        ("generic.rs", "rr_no_generics"),
        ("async.rs", "rr_no_generics"),
        ("dyn.rs", "rr_simple_traits"),
    ] {
        rejected(
            &format!("#![no_std]\ninclude!(r#\"{}\"#);", fixtures.join(file).display()),
            rule,
        );
    }
}

#[test]
fn alloc_library_macros_and_derive_stay_forbidden() {
    rejected(
        "#![no_std]\nuse core::matches as concat; pub fn value() -> bool { concat!(1, 1) }",
        "rr_no_macros",
    );
    rejected(
        "#![no_std]\nextern crate alloc; pub fn run() { let _ = alloc::vec![1u8]; }",
        "rr_no_macros",
    );
    rejected(
        "#![no_std]\nextern crate alloc; pub fn run() { let _ = alloc::format!(\"value={}\", 1); }",
        "rr_no_macros",
    );
    rejected(
        "#![no_std]\n#[derive(Copy, Clone)] pub struct Data(u8);",
        "rr_no_macros",
    );
}

#[test]
fn included_ownership_escape_requires_a_comment() {
    let fixture = |name: &str| {
        format!(
            "#![no_std]\ninclude!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/tests/fixtures/rr-builtins/\", \"{name}\"));"
        )
    };
    for name in ["clone.rs", "unsafe.rs", "unsafe_impl.rs"] {
        rejected(&fixture(name), "rr_unexplained_escape");
    }
    accepted(&fixture("explained.rs"));
}

#[test]
fn external_macro_cannot_impersonate_a_builtin() {
    let root = std::env::temp_dir().join(format!("rr-macro-origin-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("dep.rs"),
        "#![no_std]\n#[macro_export] macro_rules! concat { () => { 42u8 }; }",
    )
    .unwrap();
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .args([
            "--crate-name=macro_dep",
            "--crate-type=rlib",
            "--edition=2024",
            "-Cpanic=abort",
        ])
        .arg(root.join("dep.rs"))
        .arg("-o")
        .arg(root.join("libmacro_dep.rlib"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let external = format!("macro_dep={}", root.join("libmacro_dep.rlib").display());
    let output = compile(
        "#![no_std]\nuse macro_dep::concat; pub fn value() -> u8 { concat!() }",
        &["--extern", &external],
    );
    fs::remove_dir_all(root).unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rr-no-macros"));
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
        "pub fn run() { let _ = core::matches!(1, 1); }",
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
        "#![no_std]\npub fn copy(v: u8) -> u8 {\n // rr: escape(copy): the interface deliberately exercises Clone for this scalar.\n v.clone()\n}",
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
        "#![no_std]\npub struct Fake(u8);\nimpl Fake { pub fn clone(&self) -> u8 { self.0 } }\npub fn get(v: &Fake) -> u8 { v.clone() }",
    );
}

#[test]
fn accepts_trailing_block_and_multiline_statement_comments() {
    for source in [
        "let b = v.clone(); // rr: escape(copy): the interface needs an owned snapshot.\n b",
        "/* rr: escape(copy): the interface needs an owned snapshot. */\n v.clone()",
        "// rr: escape(copy): the interface needs an owned snapshot.\n let b =\n v.clone();\n b",
        "let b =\n // rr: escape(copy): the interface needs an owned snapshot.\n v.clone();\n b",
        "let b = match v {\n 0 => 0,\n // rr: escape(copy): the interface needs an owned snapshot.\n _ => v.clone(),\n };\n b",
    ] {
        accepted(&format!("#![no_std]\npub fn copy(v: u8) -> u8 {{\n{source}\n}}"));
    }
}

#[test]
fn comment_must_be_real_nonempty_and_adjacent() {
    for source in [
        "let _ = \"// rr: escape(copy): a fake reason\";\n v.clone()",
        "// rr: escape(copy):\n v.clone()",
        "// rr: escape(copy): a distant reason\n let _ = 1;\n v.clone()",
        "let _ = 1; // rr: escape(copy): applies to the previous statement\n v.clone()",
        "let _ = r#\"\n// rr: escape(copy): still inside a string\n\"#;\n v.clone()",
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
        "#![no_std]\n// rr: escape(unsafe): callers must follow the documented raw interface contract.\npub unsafe fn raw() {}",
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

fn alloc_fixture(body: &str) -> String {
    format!(
        "#![no_std]\nextern crate alloc;\nuse alloc::borrow::Cow;\nuse alloc::string::{{String, ToString}};\nuse alloc::vec::Vec;\n{body}"
    )
}

#[test]
fn conversions_of_borrowed_data_need_reasons() {
    for source in [
        "pub fn copy(v: &[u8]) -> Vec<u8> { Vec::from(v) }",
        "pub fn copy(v: &[u8]) -> Vec<u8> { v.into() }",
        "pub fn copy(v: &str) -> String { String::from(v) }",
        "pub fn copy(v: &str) -> String { v.to_string() }",
        "pub fn copy(v: Cow<'_, [u8]>) -> Vec<u8> { v.into_owned() }",
        "pub fn copy(v: &mut Cow<'_, [u8]>) { v.to_mut().push(1); }",
    ] {
        rejected(&alloc_fixture(source), "rr_unexplained_escape");
    }
}

#[test]
fn building_from_fixed_data_and_moving_need_no_reason() {
    accepted(&alloc_fixture(
        "const NAME: &[u8] = b\"accord\";\n\
         pub fn make(n: u8) -> (Vec<u8>, String, Vec<u8>, Vec<u8>) {\n\
         let a = Vec::from([n, 1]);\n\
         let b = String::from(\"text\");\n\
         let mut c = Vec::new();\n\
         c.extend_from_slice(NAME);\n\
         let mut d = Vec::new();\n\
         d.extend_from_slice(b\"one\");\n\
         (a, b, c, d)\n}\n\
         pub fn moved(v: Vec<u8>) -> Vec<u8> { let w: Vec<u8> = v.into(); w }\n\
         pub fn number(v: u32) -> String { v.to_string() }",
    ));
}

#[test]
fn a_fresh_buffer_filled_with_one_copy_needs_a_reason() {
    for body in [
        "let mut v = Vec::new();\n v.extend_from_slice(s);\n v",
        "let mut v = Vec::with_capacity(s.len());\n v.extend(s.iter().copied());\n v",
        "let mut v = Vec::new();\n for b in s { v.push(*b); }\n v",
        "let mut v = Vec::new();\n if s.len() > 1 { v.extend_from_slice(s); }\n v",
    ] {
        rejected(
            &alloc_fixture(&format!("pub fn copy(s: &[u8]) -> Vec<u8> {{\n {body}\n}}")),
            "rr_unexplained_escape",
        );
    }
    rejected(
        &alloc_fixture("pub fn copy(s: &str) -> String {\n let mut t = String::new();\n t.push_str(s);\n t\n}"),
        "rr_unexplained_escape",
    );
}

#[test]
fn a_built_buffer_or_explained_copy_is_accepted() {
    for body in [
        // Several writes build something new.
        "let mut v = Vec::new();\n v.extend_from_slice(s);\n v.push(b'\\n');\n v",
        "let mut v = Vec::new();\n for p in [s, s] { v.extend_from_slice(p); }\n v.push(0);\n v",
        "let mut v = Vec::new();\n let mut i = 0;\n while i < s.len() { v.extend_from_slice(&s[i..=i]); i += 1; }\n v",
        // Transforming items is not copying them.
        "let mut v = Vec::new();\n v.extend(s.iter().map(|b| b + 1));\n v",
        "let mut v = Vec::new();\n for b in s { v.push(b + 1); }\n v",
        // A buffer that is lent out may be written by its borrower.
        "let mut v = Vec::new();\n v.extend_from_slice(s);\n fill(&mut v);\n v",
        "// rr: escape(copy): the caller keeps the bytes after the source is reused.\n let mut v = Vec::new();\n v.extend_from_slice(s);\n v",
        "let mut v = Vec::new();\n // rr: escape(copy): the caller keeps the bytes after the source is reused.\n v.extend_from_slice(s);\n v",
    ] {
        accepted(&alloc_fixture(&format!(
            "fn fill(v: &mut Vec<u8>) {{ v.push(1); }}\npub fn build(s: &[u8]) -> Vec<u8> {{\n {body}\n}}"
        )));
    }
}

#[test]
fn calling_a_copy_helper_needs_a_reason() {
    let helper = "fn dup(s: &[u8]) -> Vec<u8> {\n // rr: escape(copy): helper under test.\n s.to_vec()\n}\n";
    rejected(
        &alloc_fixture(&format!("{helper}pub fn run(s: &[u8]) -> Vec<u8> {{ dup(s) }}")),
        "rr_unexplained_escape",
    );
    accepted(&alloc_fixture(&format!(
        "{helper}pub fn run(s: &[u8]) -> Vec<u8> {{\n // rr: escape(copy): the result outlives s.\n dup(s)\n}}"
    )));
    // A function that does more than copy is not a helper.
    accepted(&alloc_fixture(
        "fn upper(s: &[u8]) -> Vec<u8> {\n let mut v = Vec::new();\n for b in s { v.push(b.to_ascii_uppercase()); }\n v\n}\n\
         pub fn run(s: &[u8]) -> Vec<u8> { upper(s) }",
    ));
}

#[test]
fn shared_mutable_state_needs_reasons() {
    for source in [
        "pub static COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);",
        "pub static mut COUNT: u32 = 0;",
        "pub fn cell() -> core::cell::Cell<u8> { core::cell::Cell::new(1) }",
        "pub fn cell() -> core::cell::UnsafeCell<u8> { core::cell::UnsafeCell::new(1) }",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "rr_unexplained_escape");
    }
    accepted(
        "#![no_std]\npub static TABLE: [u8; 2] = [1, 2];\n\
         /// The descriptor the signal handler writes to.\n\
         // rr: escape(shared): a signal handler cannot be passed state.\n\
         pub static FD: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);",
    );
}

#[test]
fn a_reason_may_continue_on_following_comment_lines() {
    accepted(
        "#![no_std]\npub fn copy(v: u8) -> u8 {\n // rr: escape(copy): the interface needs an owned\n // snapshot, kept past the source.\n v.clone()\n}",
    );
    for source in [
        "// rr: escape(copy): a reason\n\n // then a blank line\n v.clone()",
        "// rr: escape(copy): a reason\n let _ = 1;\n // more\n v.clone()",
    ] {
        rejected(
            &format!("#![no_std]\npub fn copy(v: u8) -> u8 {{\n{source}\n}}"),
            "rr_unexplained_escape",
        );
    }
}

#[test]
fn write_macros_and_rr_attributes_are_allowed() {
    accepted(
        "#![no_std]\nuse core::fmt::Write;\npub fn put(w: &mut impl_free::W) -> core::fmt::Result { write!(w, \"{}\", 1)?; writeln!(w) }\n\
         mod impl_free { pub struct W; impl core::fmt::Write for W { fn write_str(&mut self, _: &str) -> core::fmt::Result { Ok(()) } } }\n\
         #[rr::hot]\npub fn hot(v: &mut u8) { *v += 1; }",
    );
}

#[test]
fn a_buffer_made_on_every_turn_of_a_loop_needs_a_reason() {
    rejected(
        &alloc_fixture(
            "pub fn n(xs: &[&[u8]]) -> usize {\n let mut n = 0;\n for x in xs {\n let mut t = Vec::new();\n t.extend_from_slice(x);\n t.push(0);\n n += t.len();\n }\n n\n}",
        ),
        "rr_unexplained_escape",
    );
    // Moved out of the turn, or made once and cleared, it is fine.
    accepted(&alloc_fixture(
        "pub fn keep(xs: &[&[u8]]) -> Vec<Vec<u8>> {\n let mut all = Vec::new();\n for x in xs {\n let mut t = Vec::new();\n t.extend_from_slice(x);\n t.push(0);\n all.push(t);\n }\n all\n}\n\
         pub fn reuse(xs: &[&[u8]]) -> usize {\n let mut n = 0;\n let mut t = Vec::new();\n for x in xs {\n t.clear();\n t.extend_from_slice(x);\n n += t.len();\n }\n n\n}",
    ));
}

#[test]
fn a_buffer_lent_to_a_function_that_copies_it_should_move() {
    let callee = "pub struct P { url: Vec<u8> }\nfn open(url: &[u8]) -> P {\n let mut p = P { url: Vec::new() };\n // rr: escape(copy): P keeps the url.\n p.url.extend_from_slice(url);\n p\n}\n";
    rejected(
        &alloc_fixture(&format!(
            "{callee}pub fn f() -> P {{\n let mut u = Vec::new();\n u.extend_from_slice(b\"x\");\n u.push(1);\n open(&u)\n}}"
        )),
        "rr_unexplained_escape",
    );
    // Still used after the call: the callee's copy is the only way.
    accepted(&alloc_fixture(&format!(
        "{callee}pub fn f() -> (P, usize) {{\n let mut u = Vec::new();\n u.extend_from_slice(b\"x\");\n u.push(1);\n let p = open(&u);\n (p, u.len())\n}}"
    )));
}

#[test]
fn a_hot_mark_behind_cfg_attr_counts_and_rr_sets_the_cfg() {
    rejected(
        &alloc_fixture(
            "#[cfg_attr(rr, rr::hot)]\npub fn hot(x: &[u8]) -> Vec<u8> { let mut v = Vec::with_capacity(x.len()); v.push(1); v }",
        ),
        "rr_hot_path",
    );
    accepted("#![no_std]\n#[cfg(rr)]\npub fn only_under_rr() {}\npub fn call() { only_under_rr() }");
}

#[test]
fn a_hot_path_makes_no_new_buffer() {
    let helper = "fn helper(x: &[u8]) -> usize {\n let mut v = Vec::new();\n v.extend_from_slice(x);\n v.push(1);\n v.len()\n}\n";
    rejected(
        &alloc_fixture(&format!(
            "{helper}#[rr::hot]\npub fn hot(x: &[u8]) -> usize {{ helper(x) }}"
        )),
        "rr_hot_path",
    );
    rejected(
        &alloc_fixture(
            "#[rr::hot]\npub fn hot(x: &[u8]) -> Vec<u8> { let mut v = Vec::with_capacity(x.len()); v.push(1); v }",
        ),
        "rr_hot_path",
    );
    // Writing into the caller's buffer, or a birth with a reason.
    accepted(&alloc_fixture(
        "#[rr::hot]\npub fn hot(out: &mut Vec<u8>, x: &[u8]) -> Result<(), Vec<u8>> {\n out.extend_from_slice(b\"ok\");\n if x.is_empty() {\n // rr: escape(alloc): an error, off the hot path's common case.\n return Err(Vec::from(&b\"empty\"[..]));\n }\n Ok(())\n}",
    ));
}

#[test]
fn a_hot_path_copies_nothing_it_holds() {
    for body in [
        "out.extend_from_slice(x);",
        "for i in 0..x.len() {\n out[i] = x[i];\n }",
        "for &b in x {\n out.push(b);\n }",
        "out.iter_mut().zip(x).for_each(|(d, s)| *d = *s);",
        "helper(out, x);",
    ] {
        rejected(
            &alloc_fixture(&format!(
                "fn helper(out: &mut Vec<u8>, x: &[u8]) {{ out.extend_from_slice(x); }}\n\
                 #[rr::hot]\npub fn hot(out: &mut Vec<u8>, x: &[u8]) {{\n {body}\n}}"
            )),
            "rr_hot_path",
        );
    }
    // Writing what is built here, filling an array on the stack, a copy
    // with a reason, and a cold call.
    accepted(&alloc_fixture(
        "fn helper(out: &mut Vec<u8>, x: &[u8]) { out.extend_from_slice(x); }\n\
         #[rr::hot]\npub fn hot(out: &mut Vec<u8>, x: &[u8], n: u32) -> u8 {\n\
         out.extend_from_slice(&n.to_be_bytes());\n out.extend_from_slice(b\"\\r\\n\");\n\
         for &b in x {\n out.push(b ^ 0x20);\n }\n\
         let mut block = [0u8; 4];\n block.copy_from_slice(x);\n\
         // rr: escape(copy): the frame must outlive the read buffer.\n out.extend_from_slice(x);\n\
         if x.is_empty() {\n // rr: escape(cold): an error, off the common case.\n helper(out, x);\n }\n\
         block[0]\n}",
    ));
}

#[test]
fn a_hot_path_shifts_no_buffer_tail() {
    for body in ["out.remove(0);", "out.insert(0, 1);", "out.drain(..1);"] {
        rejected(
            &alloc_fixture(&format!("#[rr::hot]\npub fn hot(out: &mut Vec<u8>) {{\n {body}\n}}")),
            "rr_hot_path",
        );
    }
    // Taking from the end, or all of it, moves nothing.
    accepted(&alloc_fixture(
        "#[rr::hot]\npub fn hot(out: &mut Vec<u8>) -> usize {\n out.pop();\n out.drain(1..).count() + out.drain(..).count()\n}",
    ));
}

#[test]
fn an_if_chain_over_one_value_is_a_match() {
    rejected(
        "#![no_std]\npub fn f(x: u8) -> u8 {\n if x == 1 {\n 10\n } else if x == 2 {\n 20\n } else {\n 0\n }\n}",
        "rr_match_chain",
    );
    rejected(
        "#![no_std]\npub fn f(x: u8) -> u8 {\n if x == 1 {\n 10\n } else {\n 0\n }\n}\npub fn g(x: &mut u8) {\n if *x == 1 {\n *x = 0;\n } else if *x > 2 {\n *x = 1;\n }\n}",
        "clippy::else_if_without_else",
    );
    accepted(
        "#![no_std]\npub fn f(x: u8, y: u8) -> u8 {\n if x == 1 {\n 10\n } else if y == 2 {\n 20\n } else {\n 0\n }\n}\npub fn g(x: u8) -> u8 {\n match x {\n 1 => 10,\n 2 => 20,\n _ => 0,\n }\n}",
    );
}

#[test]
fn a_variadic_c_function_is_declared_with_its_dots() {
    rejected(
        "#![no_std]\n// rr: escape(unsafe): the C library.\nunsafe extern \"C\" {\n pub fn open(path: *const u8, flags: i32, mode: i32) -> i32;\n}",
        "rr_variadic",
    );
    accepted(
        "#![no_std]\n// rr: escape(unsafe): the C library.\nunsafe extern \"C\" {\n pub fn open(path: *const u8, flags: i32, ...) -> i32;\n pub fn close(fd: i32) -> i32;\n}",
    );
}

#[test]
fn a_condition_states_what_holds() {
    rejected(
        "#![no_std]\npub fn f(a: bool) -> u8 { if !a { 1 } else { 2 } }",
        "clippy::if_not_else",
    );
    accepted("#![no_std]\npub fn f(a: bool) -> u8 { if a { 2 } else { 1 } }");
}

#[test]
fn a_hot_path_moves_no_large_value() {
    let types = "pub struct Big { pub a: [u64; 64] }\npub struct S { pub cur: Big, pub prev: Big }\nfn sum(b: &Big) -> u64 { b.a[0] }\n";
    rejected(
        &format!(
            "#![no_std]\n{types}#[rr::hot]\npub fn step(s: &mut S) -> u64 {{\n let keep = s.prev.a;\n s.cur.a = keep;\n sum(&s.cur)\n}}"
        ),
        "rr_hot_path",
    );
    // Lent, written in place, or built where it ends up.
    accepted(&format!(
        "#![no_std]\n{types}#[rr::hot]\npub fn step(s: &mut S, x: u64) -> u64 {{\n s.cur.a[0] = x;\n s.prev.a = [x; 64];\n sum(&s.prev) + sum(&s.cur)\n}}"
    ));
}

#[test]
fn a_field_that_grows_is_held_to_a_limit() {
    let types = "pub struct Q { pub items: Vec<u8> }\n";
    rejected(
        &alloc_fixture(&format!("{types}pub fn add(q: &mut Q, b: u8) {{ q.items.push(b); }}")),
        "rr_unbounded",
    );
    // A limit on its length, a clear where a cycle starts over, a reason
    // at the field, and a value built here.
    for body in [
        "pub fn add(q: &mut Q, b: u8) -> bool {\n if q.items.len() >= 64 {\n return false;\n }\n q.items.push(b);\n true\n}",
        "pub fn add(q: &mut Q, b: u8) { q.items.push(b); }\npub fn reset(q: &mut Q) { q.items.clear(); }",
        "pub fn make(b: u8) -> Q {\n let mut q = Q { items: Vec::new() };\n q.items.push(b);\n q\n}",
    ] {
        accepted(&alloc_fixture(&format!("{types}{body}")));
    }
    accepted(&alloc_fixture(
        "pub struct Q {\n // rr: escape(bound): one byte per key the user pressed, cleared by its reader.\n pub items: Vec<u8>,\n}\npub fn add(q: &mut Q, b: u8) { q.items.push(b); }",
    ));
}

#[test]
fn a_hot_path_shows_the_bound_of_each_loop() {
    for body in [
        "let mut n = x;\n loop {\n if n == 0 {\n break;\n }\n n /= 2;\n }",
        "let mut n = x;\n while n != x / 2 {\n n -= 1;\n }",
    ] {
        rejected(
            &format!("#![no_std]\n#[rr::hot]\npub fn hot(x: u32) {{\n {body}\n}}"),
            "rr_hot_path",
        );
    }
    for body in [
        "for _ in 0..x {}",
        "let mut n = 0;\n while n < 8 {\n n += 1;\n }",
        "let mut n = x;\n // rr: escape(loop): n halves each turn: 32 turns at most.\n loop {\n if n == 0 {\n break;\n }\n n /= 2;\n }",
    ] {
        accepted(&format!("#![no_std]\n#[rr::hot]\npub fn hot(x: u32) {{\n {body}\n}}"));
    }
}

#[test]
fn panics_and_swallowed_errors_need_reasons_in_every_command() {
    for source in [
        "pub fn f(v: Option<u8>) -> u8 { v.unwrap() }",
        "pub fn f(v: Result<u8, u8>) -> u8 { v.expect(\"a value\") }",
        "pub fn f() -> u8 { panic!(\"no\") }",
        "pub fn f(v: Result<u8, u8>) -> Result<u8, ()> { v.map_err(|_| ()) }",
        "#[must_use]\nfn g() -> u8 { 1 }\npub fn f() { let _ = g(); }",
        "pub enum E { A, B, C }\npub fn f(e: E) -> u8 { match e { E::A => 1, _ => 2 } }",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "clippy::");
    }
    accepted(
        "#![no_std]\npub fn f(v: Option<u8>) -> u8 {\n // rr: escape(panic): the caller has checked it is Some.\n v.unwrap()\n}\n\
         pub enum E { A, B, C }\npub fn g(e: &E) -> u8 {\n match e {\n E::A => 1,\n // rr: escape(wildcard): every other kind counts the same.\n _ => 2,\n }\n}",
    );
    // An allow does not lower them.
    rejected(
        "#![no_std]\n#[allow(clippy::unwrap_used)]\npub fn f(v: Option<u8>) -> u8 { v.unwrap() }",
        "clippy::",
    );
}

#[test]
fn recursion_needs_a_reason() {
    rejected(
        "#![no_std]\npub fn f(n: u8) -> u8 { if n == 0 { 0 } else { f(n - 1) } }",
        "rr_no_recursion",
    );
    rejected(
        "#![no_std]\npub fn a(n: u8) -> u8 { if n == 0 { 0 } else { b(n - 1) } }\nfn b(n: u8) -> u8 { a(n) }",
        "rr_no_recursion",
    );
    accepted(
        "#![no_std]\npub fn f(n: u8) -> u8 {\n if n == 0 {\n return 0;\n }\n // rr: escape(recursion): n is at most 4, so is the depth.\n f(n - 1)\n}\npub fn g(n: u8) -> u8 { n + 1 }\npub fn h(n: u8) -> u8 { g(g(n)) }",
    );
}

#[test]
fn calls_not_written_as_calls_are_in_the_call_graph() {
    for source in [
        // An operator, an index, a deref and a for loop.
        "pub struct N(pub u8);\nimpl core::ops::Add for N { type Output = N; fn add(self, o: N) -> N { N(self.0) + o } }",
        "pub struct S(pub [u8; 4]);\nimpl core::ops::Index<usize> for S { type Output = u8; fn index(&self, i: usize) -> &u8 { &self[i] } }",
        "pub struct S(pub u8);\nimpl core::ops::Deref for S { type Target = u8; fn deref(&self) -> &u8 { &**self } }",
        "pub struct I(pub u8);\nimpl Iterator for I { type Item = u8; fn next(&mut self) -> Option<u8> { for x in I(self.0) { return Some(x); } None } }",
        // A destructor, run by a drop here or by a function of core.
        "pub struct S(pub u8);\nimpl Drop for S { fn drop(&mut self) { f(self.0) } }\npub fn f(n: u8) { let _s = S(n); }",
        "pub struct S(pub u8);\nimpl Drop for S { fn drop(&mut self) { f(self.0) } }\npub fn f(n: u8) { core::mem::drop(S(n)) }",
        // A function pointer, from a static, and a function handed on.
        "pub struct P { pub go: fn(u8) -> u8 }\npub static PS: [P; 1] = [P { go: a }];\nfn a(n: u8) -> u8 { run(n) }\npub fn run(n: u8) -> u8 { (PS[0].go)(n) }",
        "pub fn f(v: Option<u8>) -> Option<u8> { v.map(g) }\nfn g(x: u8) -> u8 { f(Some(x)).unwrap_or(0) }",
        // A type that owns itself.
        "extern crate alloc;\npub struct Node { pub next: Option<alloc::boxed::Box<Node>> }",
        // Foreign code given a pointer, alone or in a struct.
        "// rr: escape(unsafe): a C library that calls back.\nunsafe extern \"C\" {\n // rr: escape(unsafe): it calls f.\n safe fn each(f: extern \"C\" fn(u8) -> u8);\n}\n\
         extern \"C\" fn cb(n: u8) -> u8 { run(); n }\npub fn run() { each(cb) }",
        "#[repr(C)]\npub struct O { pub cb: extern \"C\" fn(u8) -> u8 }\n// rr: escape(unsafe): a C library that calls back.\nunsafe extern \"C\" {\n // rr: escape(unsafe): it calls o.cb.\n safe fn walk(o: &O);\n}\n\
         extern \"C\" fn cb(n: u8) -> u8 { run(); n }\npub fn run() { walk(&O { cb }) }",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "rr_no_recursion");
    }
    accepted(
        "#![no_std]\npub fn g(a: fn(u8) -> u8) -> u8 { a(1) }\npub fn h(n: u8) -> u8 { n }\npub fn k() -> u8 { g(h) }\n\
         pub fn c(n: u8) -> u8 { let f = |m: u8| h(m); f(n) }\npub struct L<'a> { pub up: Option<&'a L<'a>> }",
    );
    // Foreign code given nothing calls nothing back.
    accepted(
        "#![no_std]\n// rr: escape(unsafe): a C library.\nunsafe extern \"C\" {\n // rr: escape(unsafe): it writes one byte.\n safe fn put(b: u8);\n}\n\
         extern \"C\" fn cb(n: u8) -> u8 { put(n); n }\npub fn take() -> extern \"C\" fn(u8) -> u8 { cb }",
    );
    // A cold call's reason answers only a birth beyond the call.
    rejected(
        "#![no_std]\nfn g(n: u8) -> u8 { n }\n#[rr::hot]\npub fn f(n: u8) -> u8 {\n // rr: escape(cold): an error, off the common case.\n g(n)\n}",
        "rr_unused_escape",
    );
    accepted(&alloc_fixture(
        "fn g(n: u8) -> usize { let mut v = Vec::with_capacity(4); v.push(n); v.len() }\n\
         #[rr::hot]\npub fn f(n: u8) -> usize {\n // rr: escape(cold): an error, off the common case.\n g(n)\n}",
    ));
    // The hot path follows a function pointer and a destructor.
    rejected(
        &alloc_fixture(
            "fn g(n: u8) -> usize { let mut v = Vec::with_capacity(4); v.push(n); v.len() }\n\
             #[rr::hot]\npub fn hot(a: fn(u8) -> usize) -> usize { a(1) }\npub fn take() -> usize { hot(g) }",
        ),
        "rr_hot_path",
    );
    rejected(
        &alloc_fixture(
            "pub struct S;\nimpl Drop for S { fn drop(&mut self) { let mut v = Vec::with_capacity(4); v.push(1u8); } }\n\
             #[rr::hot]\npub fn hot() { let _s = S; }",
        ),
        "rr_hot_path",
    );
}

#[test]
fn lossy_casts_dropped_results_and_owned_parameters_need_reasons() {
    for source in [
        "pub fn f(v: i64) -> u16 { v as u16 }",
        "pub fn f(v: i32) -> u32 { v as u32 }",
        "pub fn f(v: u32) -> i32 { v as i32 }",
        "#[must_use]\nfn g() -> u8 { 1 }\npub fn f() { g(); }",
        "extern crate alloc;\npub fn f(v: alloc::vec::Vec<u8>) -> usize { v.len() }",
    ] {
        rejected(&format!("#![no_std]\n{source}"), "");
    }
    accepted(
        "#![no_std]\npub fn f(v: i64) -> Option<u16> { u16::try_from(v).ok() }\n\
         pub fn g(v: u8) -> u32 { u32::from(v) }\n\
         pub fn h(v: i64) -> u16 {\n // rr: escape(cast): the caller keeps v in 0..1000.\n v as u16\n}",
    );
}

#[test]
fn a_reason_answers_only_the_kinds_it_names() {
    // A reason for the unsafe call does not cover the cast on its line.
    rejected(
        "#![no_std]\n// rr: escape(unsafe): the test's own declarations.\nunsafe extern \"C\" { fn take(n: u32); }\npub fn f(n: u64) {\n // rr: escape(unsafe): take accepts any value.\n unsafe { take(n as u32) }\n}",
        "cast_possible_truncation",
    );
    accepted(
        "#![no_std]\n// rr: escape(unsafe): the test's own declarations.\nunsafe extern \"C\" { fn take(n: u32); }\npub fn f(n: u64) {\n // rr: escape(unsafe, cast): take accepts any value, and n is a count below 2^32.\n unsafe { take(n as u32) }\n}",
    );
    // The old form names no kind.
    rejected(
        "#![no_std]\npub fn copy(v: u8) -> u8 {\n // rr: escape: an owned snapshot.\n v.clone()\n}",
        "rr_unexplained_escape",
    );
    // A comment inside a statement that spans lines answers its own line only.
    rejected(
        "#![no_std]\n// rr: escape(unsafe): the test's own declarations.\nunsafe extern \"C\" { fn two(a: u8, b: u8); }\npub fn f(a: u8) {\n unsafe {\n two(\n // rr: escape(unsafe): a reason for something else.\n a,\n 1,\n )\n }\n}",
        "rr_unexplained_escape",
    );
}

#[test]
fn a_reason_that_answers_nothing_is_rejected() {
    for body in [
        // Nothing beside it.
        "pub fn f() -> u8 {\n // rr: escape(copy): an owned snapshot.\n 1\n}",
        // A kind of the list that the code no longer needs.
        "// rr: escape(unsafe): the test's own declarations.\nunsafe extern \"C\" { fn take(n: u32); }\npub fn f(n: u32) {\n // rr: escape(unsafe, cast): take accepts any value.\n unsafe { take(n) }\n}",
        // A kind rr does not know.
        "// rr: escape(unsafe): the test's own declarations.\nunsafe extern \"C\" { fn take(n: u32); }\npub fn f(n: u32) {\n // rr: escape(unsafe, frob): take accepts any value.\n unsafe { take(n) }\n}",
        // The old form names none.
        "pub fn f() -> u8 {\n // rr: escape: an owned snapshot.\n 1\n}",
        // Trailing an item.
        "pub static N: u8 = 1; // rr: escape(shared): read by a signal handler.",
    ] {
        rejected(&format!("#![no_std]\n{body}"), "rr_unused_escape");
    }
    // Code that cfg leaves out is not looked at.
    accepted(
        "#![no_std]\n// rr: escape(unsafe): not built here.\n#[cfg(any())]\npub fn g() {}\n\
         #[cfg(any())]\nmod m {\n pub fn h() -> u8 {\n  // rr: escape(copy): not built here.\n  1\n }\n}",
    );
}

#[test]
fn a_field_filled_with_one_copy_needs_a_reason() {
    let record = "pub struct P { url: Vec<u8>, n: Vec<u8> }\n";
    rejected(
        &alloc_fixture(&format!(
            "{record}pub fn open(url: &[u8]) -> P {{\n let mut p = P {{ url: Vec::new(), n: Vec::new() }};\n p.url.extend_from_slice(url);\n p\n}}"
        )),
        "rr_unexplained_escape",
    );
    // Written again, or through the whole record, it is built, not copied.
    accepted(&alloc_fixture(&format!(
        "{record}fn fill(p: &mut P) {{ if p.url.len() < 64 {{ p.url.push(0); }} }}\n\
         pub fn open(url: &[u8]) -> P {{\n let mut p = P {{ url: Vec::new(), n: Vec::new() }};\n p.url.extend_from_slice(url);\n p.url.push(b'/');\n p\n}}\n\
         pub fn other(url: &[u8]) -> P {{\n let mut p = P {{ url: Vec::new(), n: Vec::new() }};\n p.url.extend_from_slice(url);\n fill(&mut p);\n p\n}}"
    )));
}

#[test]
fn rewrites_take_no_reason_and_flags_are_variants() {
    // Always rewritable, so no reason answers it: &raw const x.
    rejected(
        "#![no_std]\npub fn f(x: u8) -> usize {\n // rr: escape(cast): an address.\n let p = &x as *const u8;\n p as usize\n}",
        "borrow_as_ptr",
    );
    rejected(
        "#![no_std]\n// rr: escape(unsafe): the test's own declarations.\nunsafe extern \"C\" { fn a(); fn b(); }\npub fn f() {\n // rr: escape(unsafe): both are safe to call.\n unsafe { a(); b() }\n}",
        "multiple_unsafe_ops_per_block",
    );
    let flags =
        "pub struct S { a: bool, b: bool, c: bool, d: bool }\npub fn f(s: &S) -> bool { s.a && s.b && s.c && s.d }";
    rejected(&format!("#![no_std]\n{flags}"), "struct_excessive_bools");
    accepted(&format!(
        "#![no_std]\n// rr: escape(bools): four independent switches of a test.\n{flags}"
    ));
}

#[test]
fn unsafe_attributes_and_global_assembly_need_reasons() {
    for body in [
        "#[unsafe(no_mangle)]\npub extern \"C\" fn malloc(n: usize) -> usize { n }",
        "#[unsafe(export_name = \"free\")]\npub extern \"C\" fn f() {}",
        "#[unsafe(link_section = \"__DATA,__rr\")]\npub static X: u8 = 0;",
        "core::arch::global_asm!(\".globl rr_x\", \"rr_x: ret\");",
    ] {
        rejected(&format!("#![no_std]\n{body}"), "rr_unexplained_escape");
    }
    accepted(
        "#![no_std]\n// rr: escape(unsafe): no other symbol of the program is named rr_f.\n#[unsafe(no_mangle)]\npub extern \"C\" fn rr_f() {}",
    );
    // The entry of a no_main program is what the symbol is for.
    accepted("#![no_std]\n#![no_main]\n#[unsafe(no_mangle)]\npub extern \"C\" fn main() -> i32 { 0 }");
    rejected(
        "#![no_std]\n#![no_main]\n#[unsafe(no_mangle)]\npub extern \"C\" fn main() -> i32 { 0 }\n#[unsafe(no_mangle)]\npub extern \"C\" fn other() {}",
        "rr_unexplained_escape",
    );
}

#[test]
fn leaks_atomics_large_copies_and_provenance_casts_are_checked() {
    for body in [
        "pub fn f(v: Vec<u8>) -> &'static mut [u8] { v.leak() }",
        "pub fn f(v: String) -> &'static mut str { v.leak() }",
        "pub fn f(v: alloc::boxed::Box<u8>) -> *mut u8 { alloc::boxed::Box::into_raw(v) }",
        "pub fn f(v: Vec<u8>) -> core::mem::ManuallyDrop<Vec<u8>> { core::mem::ManuallyDrop::new(v) }",
        "pub struct S { n: core::sync::atomic::AtomicUsize }\npub fn f() -> S { S { n: core::sync::atomic::AtomicUsize::new(0) } }",
        "pub struct B { b: [u8; 65] }\nimpl Clone for B { fn clone(&self) -> B { *self } }\nimpl Copy for B {}",
    ] {
        rejected(&alloc_fixture(body), "rr_unexplained_escape");
    }
    accepted(&alloc_fixture(
        "pub struct B { b: [u8; 64] }\nimpl Clone for B { fn clone(&self) -> B { *self } }\nimpl Copy for B {}\n\
         pub struct C { c: [u8; 65] }\nimpl Clone for C { fn clone(&self) -> C { *self } }\n\
         // rr: escape(copy): a block of the cipher is a value.\nimpl Copy for C {}",
    ));
    rejected(
        "#![no_std]\npub fn f(x: &u8) -> usize { x as *const u8 as usize }",
        "implicit_provenance_casts",
    );
    rejected(
        "#![no_std]\npub fn f(a: usize) -> *const u8 { a as *const u8 }",
        "implicit_provenance_casts",
    );
    accepted("#![no_std]\npub fn f(x: &u8) -> usize { core::ptr::from_ref(x).addr() }");
}

#[test]
fn foreign_declarations_need_reasons() {
    // The block vouches for its signatures.
    rejected(
        "#![no_std]\nunsafe extern \"C\" {\n fn free(p: *mut u8);\n}",
        "rr_unexplained_escape",
    );
    // A safe item is used with no unsafe block: free(p); free(p) would pass.
    for item in [
        "pub safe fn free(p: *mut u8);",
        "#[link_name = \"free\"]\n pub safe fn harmless(p: *mut u8);",
        "pub safe static X: u8;",
    ] {
        rejected(
            &format!("#![no_std]\n// rr: escape(unsafe): libc.\nunsafe extern \"C\" {{\n {item}\n}}"),
            "rr_unexplained_escape",
        );
    }
    accepted(
        "#![no_std]\n// rr: escape(unsafe): libc.\nunsafe extern \"C\" {\n // rr: escape(unsafe): abs reads only its argument.\n pub safe fn abs(x: i32) -> i32;\n}\npub fn f(x: i32) -> i32 { abs(x) }",
    );
}

#[test]
fn checks_for_undefined_behavior_cannot_be_allowed() {
    for (lint, body) in [
        (
            "invalid_reference_casting",
            "pub fn f(x: &u8) {\n // rr: escape(unsafe): demo.\n unsafe { *(x as *const u8).cast_mut() = 1 }\n}",
        ),
        (
            "dangling_pointers_from_temporaries",
            "extern crate alloc;\npub fn f() -> *const u8 { alloc::vec::Vec::<u8>::new().as_ptr() }",
        ),
        (
            "static_mut_refs",
            "// rr: escape(shared): demo.\nstatic mut X: u8 = 0;\npub fn f() -> &'static u8 {\n // rr: escape(unsafe): demo.\n unsafe { &X }\n}",
        ),
        (
            "unsafe_op_in_unsafe_fn",
            "// rr: escape(unsafe): demo.\nunsafe extern \"C\" {\n fn free(p: *mut u8);\n}\n// rr: escape(unsafe): p is live.\npub unsafe fn f(p: *mut u8) { free(p) }",
        ),
    ] {
        rejected(&format!("#![no_std]\n#![allow({lint})]\n{body}"), "E0453");
    }
}
