//! What rr test, rr bench and rr fuz --target do to the crate before
//! expansion: the program's own `main` steps aside, kept under another
//! name and no longer the C entry, so that what it calls is still used;
//! and the entry of the run comes in its place. For tests and benches that is a `main` that hands
//! its arguments to the test runtime and calls the harness that rustc
//! makes of the `#[test]` and `#[bench]` items; for fuzzing it is
//! libFuzzer's `LLVMFuzzerTestOneInput`, which hands each input to the
//! function the run names. The code it adds is ordinary source, with its
//! reasons, so that rr's rules read it as they read the rest; the
//! entry's `#[unsafe(no_mangle)]` needs none, as a program's does not.

use rustc_ast::{self as ast, attr};
use rustc_parse::lexer::StripTokens;
use rustc_parse::parser::{AllowConstBlockItems, ForceCollect};
use rustc_session::Session;
use rustc_span::{FileName, Symbol, sym};
use std::sync::OnceLock;

/// The run a crate is built for.
pub enum Harness {
    /// rr test and rr bench: the harness of the `#[test]` and `#[bench]`
    /// items.
    Test,
    /// rr fuz --target: libFuzzer's entry, calling this path.
    Fuzz(String),
}

/// Set once, by `--rr-harness`, before the compiler runs.
static HARNESS: OnceLock<Harness> = OnceLock::new();

/// Take the driver's internal `--rr-harness=test|fuzz:PATH` out of args,
/// as rr test, rr bench and rr fuz --target pass it; an error names a
/// harness that is not one.
pub fn take(args: &mut Vec<String>) -> Result<(), String> {
    let Some(i) = args.iter().position(|arg| arg.starts_with("--rr-harness=")) else {
        return Ok(());
    };
    let arg = args.remove(i);
    let harness = match arg.trim_start_matches("--rr-harness=") {
        "test" => Harness::Test,
        other => match other.strip_prefix("fuzz:") {
            Some(path) => Harness::Fuzz(path.to_owned()),
            None => return Err(format!("unknown harness `{other}`")),
        },
    };
    let _ = HARNESS.set(harness);
    Ok(())
}

const TEST_ENTRY: &str = r#"
#[unsafe(no_mangle)]
extern "C" fn main(argc: i32, argv: *const *const core::ffi::c_char) -> i32 {
    test::start(argc, argv);
    __rr_test_main();
    0
}
"#;

fn fuzz_entry(target: &str) -> String {
    format!(
        r#"
#[unsafe(no_mangle)]
extern "C" fn LLVMFuzzerTestOneInput(pointer: *const u8, size: usize) -> i32 {{
    if size == 0 {{
        crate::{target}(&[]);
        return 0;
    }}
    // rr: escape(unsafe): libFuzzer guarantees size readable bytes at pointer for the call.
    let input = unsafe {{ core::slice::from_raw_parts(pointer, size) }};
    crate::{target}(input);
    0
}}
"#
    )
}

/// Whether item is the program's entry: a function named main at the
/// crate root.
fn is_entry(item: &ast::Item) -> bool {
    matches!(&item.kind, ast::ItemKind::Fn(f) if f.ident.name.as_str() == "main")
}

/// The program's entry aside in krate, the run's in.
pub fn apply(sess: &Session, krate: &mut ast::Crate) {
    let Some(harness) = HARNESS.get() else { return };
    for item in krate.items.iter_mut().filter(|item| is_entry(item)) {
        item.attrs.retain(|attr| !attr.has_name(sym::no_mangle));
        item.attrs.push(attr::mk_attr_nested_word(
            &sess.psess.attr_id_generator,
            ast::AttrStyle::Outer,
            sym::allow,
            sym::dead_code,
            item.span,
        ));
        if let ast::ItemKind::Fn(f) = &mut item.kind {
            f.ident.name = Symbol::intern("__rr_program_main");
        }
    }
    let source = match harness {
        Harness::Test => TEST_ENTRY.to_owned(),
        Harness::Fuzz(target) => fuzz_entry(target),
    };
    let name = FileName::Custom("rr harness".to_owned());
    let mut parser = match rustc_parse::new_parser_from_source_str(&sess.psess, name, source, StripTokens::Nothing) {
        Ok(parser) => parser,
        Err(errors) => {
            for e in errors {
                e.emit();
            }
            return;
        },
    };
    match parser.parse_item(ForceCollect::No, AllowConstBlockItems::DoesNotMatter) {
        Ok(Some(item)) => krate.items.push(item),
        Ok(None) => {},
        Err(e) => {
            e.emit();
        },
    }
}
