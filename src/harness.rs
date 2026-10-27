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
use std::fmt::Write as _;
use std::sync::OnceLock;

/// The run a crate is built for.
pub enum Harness {
    /// rr test and rr bench: the harness of the `#[test]` and `#[bench]`
    /// items.
    Test,
    /// rr fuz --target: libFuzzer's entry, calling these paths; with more
    /// than one, `--rr-target=N` on the run's command line picks the Nth.
    Fuzz(Vec<String>),
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
            Some(paths) => Harness::Fuzz(paths.split(',').map(str::to_owned).collect()),
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

/// The entry for several targets: libFuzzer's initialization reads the
/// `--rr-target=N` that rr fuz passes (libFuzzer ignores flags that start
/// with `--`), and each input goes to the Nth target.
fn fuzz_entries(targets: &[String]) -> String {
    let mut arms = String::new();
    for (i, target) in targets.iter().enumerate() {
        // Writing to a String does not fail.
        let _ = writeln!(arms, "        {i} => crate::{target}(input),");
    }
    format!(
        r#"
// rr: escape(shared): the target this run fuzzes, chosen once before the first input.
static RR_FUZZ_TARGET: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[unsafe(no_mangle)]
extern "C" fn LLVMFuzzerInitialize(argc: *mut i32, argv: *mut *mut *const u8) -> i32 {{
    const FLAG: &[u8] = b"--rr-target=";
    // The symbolizer is called by name, which the linker does not see:
    // a use here keeps it in the program.
    core::hint::black_box(__sanitizer_symbolize_pc as extern "C" fn(*const u8, *const u8, *mut u8, usize));
    core::hint::black_box(
        __sanitizer_get_module_and_offset_for_pc as extern "C" fn(*const u8, *mut u8, usize, *mut usize) -> i32,
    );
    // rr: escape(unsafe): libFuzzer passes main's argc.
    let count = unsafe {{ *argc }};
    // rr: escape(unsafe): libFuzzer passes main's argv.
    let list = unsafe {{ *argv }};
    for i in 0..usize::try_from(count).unwrap_or(0) {{
        // rr: escape(unsafe): argv holds argc pointers, and i < argc.
        let place = unsafe {{ list.add(i) }};
        // rr: escape(unsafe): each of them points to a C string.
        let arg = unsafe {{ *place }};
        let mut matched = 0;
        let mut target = 0usize;
        // The flag is its name and a few digits.
        for k in 0..32 {{
            // rr: escape(unsafe): arg is a C string, and no byte past its NUL is read.
            let at = unsafe {{ arg.add(k) }};
            // rr: escape(unsafe): at is within the string or at its NUL.
            let byte = unsafe {{ *at }};
            if byte == 0 {{
                break;
            }}
            if matched < FLAG.len() {{
                if FLAG.get(matched) != Some(&byte) {{
                    break;
                }}
                matched += 1;
            }} else if byte.is_ascii_digit() {{
                target = target.saturating_mul(10).saturating_add(usize::from(byte - b'0'));
            }} else {{
                break;
            }}
        }}
        if matched == FLAG.len() {{
            RR_FUZZ_TARGET.store(target, core::sync::atomic::Ordering::Relaxed);
        }}
    }}
    0
}}

/// libFuzzer prints coverage by function once it can name a PC: rr fuz
/// names each by its distance from LLVMFuzzerTestOneInput, `rr+HEX`, which
/// is the same in every run of the binary, and finds the function itself.
#[unsafe(no_mangle)]
extern "C" fn __sanitizer_symbolize_pc(pc: *const u8, _format: *const u8, out: *mut u8, size: usize) {{
    let anchor = (LLVMFuzzerTestOneInput as extern "C" fn(*const u8, usize) -> i32 as *const u8).addr();
    let mut offset = pc.addr().wrapping_sub(anchor);
    let mut text = [0u8; 24];
    let mut at = text.len();
    for _ in 0..16 {{
        at -= 1;
        if let Some(digit) = text.get_mut(at) {{
            *digit = b"0123456789abcdef".get(offset & 15).copied().unwrap_or(b'0');
        }}
        offset >>= 4;
        if offset == 0 {{
            break;
        }}
    }}
    for &c in b"x0+rr".iter() {{
        at -= 1;
        if let Some(byte) = text.get_mut(at) {{
            *byte = c;
        }}
    }}
    let name = text.get(at..).unwrap_or_default();
    if size <= name.len() {{
        return;
    }}
    // rr: escape(unsafe): libFuzzer gives size writable bytes at out, more than the name and its NUL.
    unsafe {{ core::ptr::copy_nonoverlapping(name.as_ptr(), out, name.len()) }};
    // rr: escape(unsafe): the NUL goes just past the name, within size.
    let end = unsafe {{ out.add(name.len()) }};
    // rr: escape(unsafe): end is within the buffer.
    unsafe {{ end.write(0) }};
}}

#[unsafe(no_mangle)]
extern "C" fn __sanitizer_get_module_and_offset_for_pc(pc: *const u8, module: *mut u8, size: usize, offset: *mut usize) -> i32 {{
    if size < 3 {{
        return 0;
    }}
    // rr: escape(unsafe): libFuzzer gives size writable bytes at module, at least three.
    unsafe {{ core::ptr::copy_nonoverlapping(b"rr\0".as_ptr(), module, 3) }};
    // rr: escape(unsafe): offset is libFuzzer's, to write.
    unsafe {{ offset.write(pc.addr()) }};
    1
}}

#[unsafe(no_mangle)]
extern "C" fn LLVMFuzzerTestOneInput(pointer: *const u8, size: usize) -> i32 {{
    let input: &[u8] = if size == 0 {{
        &[]
    }} else {{
        // rr: escape(unsafe): libFuzzer guarantees size readable bytes at pointer for the call.
        unsafe {{ core::slice::from_raw_parts(pointer, size) }}
    }};
    match RR_FUZZ_TARGET.load(core::sync::atomic::Ordering::Relaxed) {{
{arms}        _ => {{}}
    }}
    0
}}
"#
    )
}

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
        Harness::Fuzz(targets) => match targets.as_slice() {
            [target] => fuzz_entry(target),
            _ => fuzz_entries(targets),
        },
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
    loop {
        match parser.parse_item(ForceCollect::No, AllowConstBlockItems::DoesNotMatter) {
            Ok(Some(item)) => krate.items.push(item),
            Ok(None) => return,
            Err(e) => {
                e.emit();
                return;
            },
        }
    }
}
