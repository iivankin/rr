//! Restricted Rust rules, enabled by rr.

use rustc_lint::{LintId, LintStore};
use rustc_middle::ty::TyCtxt;
use rustc_session::declare_lint;

mod allocs;
mod bounds;
mod builtins;
mod calls;
mod chains;
mod comments;
mod copies;
mod copyflow;
mod derives;
mod disguises;
mod duplicates;
mod escape_hatches;
mod expanded;
mod ffi;
mod inbounds;
mod macros;
mod recursion;
mod stale;
mod syntax;

declare_lint! { pub RR_NO_STD, Deny, "rr requires a no_std crate without explicit std imports" }
declare_lint! { pub RR_NO_GENERICS, Deny, "rr forbids user-defined type and const generics, impl Trait and async fn" }
declare_lint! { pub RR_NO_MACROS, Deny, "rr forbids macro definitions, derives and calls except no_std compiler builtins and core panic/assert macros" }
declare_lint! { pub RR_SIMPLE_TRAITS, Deny, "rr forbids associated types, supertraits and where clauses" }
declare_lint! { pub RR_UNEXPLAINED_ESCAPE, Deny, "rr requires a reason for ownership and borrow-checker escape hatches" }
declare_lint! { pub RR_NO_RECURSION, Deny, "rr forbids recursion, direct or through other functions, without a reason" }
declare_lint! { pub RR_UNUSED_ESCAPE, Deny, "rr forbids a reason that answers no operation" }
declare_lint! { pub RR_HOT_PATH, Deny, "rr forbids new buffers, copies, large moves and loops without a stated bound on a path marked #[rr::hot] without a reason" }
declare_lint! { pub RR_MATCH_CHAIN, Deny, "rr requires a match for an if chain that compares one value with constants" }
declare_lint! { pub RR_VARIADIC, Deny, "rr forbids declaring a variadic C library function with a fixed list of arguments" }
declare_lint! { pub RR_C_SIGNATURE, Deny, "rr requires a C function declared with C's types: pointers, not references" }
declare_lint! { pub RR_DUPLICATE, Deny, "rr forbids a function body that repeats another's without a reason" }
declare_lint! { pub RR_UNUSED_DERIVE, Deny, "rr forbids a derived trait that nothing in the program uses" }
declare_lint! { pub RR_UNBOUNDED, Deny, "rr forbids a collection kept in a field growing with nothing that holds it to a limit" }

/// The kinds of rr's own rules a reason names.
const RULE_KINDS: &[&str] = &[
    "unsafe",
    "copy",
    "shared",
    "leak",
    "alloc",
    "cold",
    "bound",
    "loop",
    "recursion",
    "sentinel",
    "tag",
    "duplicate",
    "dyn",
];

/// Clippy lints rr enforces as its own: forbidden in every rr command,
/// and answered, like rr's rules, by an adjacent `// rr: escape(kind):` reason
/// naming the kind paired with each lint here. A lint without a kind is a
/// rewrite that is always possible, and no reason answers it.
pub const CLIPPY: &[(&str, Option<&str>)] = &[
    ("unwrap_used", Some("panic")),
    ("expect_used", Some("panic")),
    ("panic", Some("panic")),
    ("unreachable", Some("panic")),
    ("todo", Some("panic")),
    ("unimplemented", Some("panic")),
    ("unwrap_in_result", Some("panic")),
    ("string_slice", Some("panic")),
    // An index or a slice that may be out of bounds panics as unwrap does:
    // `get` says what happens when it is.
    ("indexing_slicing", Some("panic")),
    ("unchecked_time_subtraction", Some("panic")),
    ("let_underscore_must_use", Some("discard")),
    ("map_err_ignore", Some("discard")),
    ("wildcard_enum_match_arm", Some("wildcard")),
    ("cast_possible_truncation", Some("cast")),
    ("cast_sign_loss", Some("cast")),
    ("cast_possible_wrap", Some("cast")),
    ("cast_ptr_alignment", Some("cast")),
    ("needless_pass_by_value", Some("move")),
    ("large_stack_arrays", Some("stack")),
    ("infinite_loop", Some("loop")),
    ("struct_excessive_bools", Some("bools")),
    ("fn_params_excessive_bools", Some("bools")),
    ("multiple_unsafe_ops_per_block", None),
    ("borrow_as_ptr", None),
    ("ptr_as_ptr", None),
    ("ptr_cast_constness", None),
    ("as_ptr_cast_mut", None),
    ("fn_to_numeric_cast", None),
    ("transmute_ptr_to_ptr", None),
    ("trivially_copy_pass_by_ref", None),
    ("ref_option", None),
    ("if_not_else", None),
    ("else_if_without_else", None),
    ("comparison_chain", None),
    // State and copies: a collection written and never read, a clone or
    // a collect thrown away, a buffer replaced rather than reused.
    ("collection_is_never_read", None),
    ("redundant_clone", None),
    ("needless_collect", None),
    ("assigning_clones", None),
    ("format_push_string", None),
    ("unnecessary_box_returns", None),
    ("linkedlist", None),
    ("read_zero_byte_vec", None),
    // Correctness: evaluation order, typos in formulas, silenced errors,
    // bytes on the wire in the host's order, overflow, off-by-one.
    ("mixed_read_write_in_expression", None),
    ("suspicious_operation_groupings", None),
    ("unused_result_ok", None),
    ("host_endian_bytes", None),
    ("checked_conversions", None),
    ("manual_midpoint", None),
    ("float_cmp", None),
    ("range_minus_one", None),
    ("range_plus_one", None),
    ("precedence_bits", None),
    ("decimal_bitwise_operands", None),
    ("let_underscore_untyped", None),
    // Simple signatures and types.
    ("unnecessary_wraps", None),
    ("option_option", None),
    ("unused_self", None),
    ("or_fun_call", None),
    ("needless_pass_by_ref_mut", Some("move")),
    // Stack frames.
    ("large_stack_frames", Some("stack")),
    // An allow says why, as a reason does: silencing a lint is a decision.
    ("allow_attributes_without_reason", None),
    // Logic that is always true or false, or not what it seems.
    ("invalid_upcast_comparisons", None),
    ("suspicious_xor_used_as_pow", None),
    ("fallible_impl_from", None),
    ("maybe_infinite_iter", None),
    ("match_wild_err_arm", None),
    ("overly_complex_bool_expr", None),
    ("needless_bitwise_bool", None),
    ("same_functions_in_if_condition", None),
    ("nonminimal_bool", None),
    ("lossy_float_literal", None),
    ("while_float", None),
    ("empty_drop", None),
    ("trailing_empty_array", None),
    ("literal_string_with_formatting_args", None),
    ("mut_mut", None),
    // Copies and allocations anywhere, not only on a hot path.
    ("implicit_clone", None),
    ("inefficient_to_string", None),
    ("cloned_instead_of_copied", None),
    ("string_add", None),
    ("string_add_assign", None),
    ("clear_with_drain", None),
    ("iter_with_drain", None),
    ("unnecessary_struct_initialization", None),
    ("set_contains_or_insert", None),
    ("naive_bytecount", None),
    ("stable_sort_primitive", None),
    // What a cast or an import names, said.
    ("as_underscore", None),
    ("as_pointer_underscore", None),
    ("alloc_instead_of_core", None),
    ("non_ascii_literal", None),
    // unsafe and the system: layouts, volatile, unions, ABI, pointers.
    ("transmute_undefined_repr", None),
    ("uninhabited_references", None),
    ("volatile_composites", None),
    ("default_union_representation", None),
    ("no_mangle_with_rust_abi", None),
    ("ref_as_ptr", None),
    ("same_length_and_capacity", None),
    ("ptr_offset_by_literal", None),
    ("fn_to_numeric_cast_any", Some("cast")),
    // Allocations.
    ("format_collect", None),
    ("with_capacity_zero", None),
    // One way to write each thing, and each name one meaning.
    ("match_same_arms", None),
    ("items_after_statements", None),
    ("manual_let_else", None),
    ("needless_continue", None),
    ("shadow_unrelated", None),
];

/// The kind a reason names, if rr knows it.
fn kind(name: &str) -> Option<&'static str> {
    RULE_KINDS
        .iter()
        .copied()
        .chain(CLIPPY.iter().filter_map(|&(_, kind)| kind))
        .find(|&kind| kind == name)
}

/// Every kind rr knows, for a diagnostic.
fn kinds() -> String {
    let mut all: Vec<&str> = RULE_KINDS.to_vec();
    for kind in CLIPPY.iter().filter_map(|&(_, kind)| kind) {
        if !all.contains(&kind) {
            all.push(kind);
        }
    }
    all.join(", ")
}

/// After analysis: reasons left over, which answer nothing.
pub fn unused_reasons(tcx: TyCtxt<'_>) {
    stale::check(tcx);
}

/// Compiler lints rr forbids: a `must_use` result dropped as a statement
/// (`let _ =` with a reason is how to drop one on purpose); integers cast
/// to pointers or pointers to integers, which lose provenance (`addr`,
/// `with_addr` and `expose_provenance` say what is meant); an unsafe
/// operation in an unsafe fn outside an unsafe block, which no reason
/// covers; and the compiler's checks for undefined behavior and certain
/// panics, which `#![allow]` could otherwise turn off.
pub const RUSTC: &[&str] = &[
    "unused_must_use",
    "implicit_provenance_casts",
    "invalid_reference_casting",
    "dangling_pointers_from_temporaries",
    "dangling_pointers_from_locals",
    "static_mut_refs",
    "invalid_value",
    "invalid_null_arguments",
    "mutable_transmutes",
    "useless_ptr_null_checks",
    "invalid_from_utf8_unchecked",
    "ptr_to_integer_transmute_in_consts",
    "invalid_atomic_ordering",
    "deref_nullptr",
    "uninhabited_static",
    "unsafe_op_in_unsafe_fn",
    "missing_unsafe_on_extern",
    "unsafe_attr_outside_unsafe",
    "arithmetic_overflow",
    "unconditional_panic",
];

/// What answers a Clippy emission of lint at span: a reason naming the
/// kind rr gives the lint.
fn clippy_escape(
    sess: &rustc_session::Session,
    lint: &'static rustc_lint::Lint,
    span: rustc_span::Span,
) -> clippy_utils::diagnostics::Escaped {
    use clippy_utils::diagnostics::Escaped;
    let name = lint.name_lower();
    let Some(&(_, Some(kind))) = CLIPPY.iter().find(|(l, _)| name == format!("clippy::{l}")) else {
        return Escaped::No;
    };
    match comments::escape_for(sess, span, span, kind) {
        comments::Escape::Named => Escaped::Yes,
        comments::Escape::Unnamed(comment) => Escaped::Unnamed(comment, kind),
        comments::Escape::Missing => Escaped::No,
    }
}

/// Clippy lints that ask the opposite of rr's style: a nested condition is
/// a branch of its own, as each branch is a case to handle, and an `else
/// if` chain is an `else` holding an `if`; a zeroed `Vec` is made by
/// `resize`, as `vec!` is a macro. They stay off.
pub const CLIPPY_OFF: &[&str] = &["collapsible_if", "collapsible_else_if", "slow_vector_initialization"];

/// Inside a test, a panic is how the test fails: `panic!`, `unwrap`,
/// `expect` and indexing there end the test's child, not the program. A
/// fuzz target under `cfg(fuzzing)` is a test the fuzzer runs.
pub fn adjust_conf(conf: &mut clippy_config::Conf) {
    conf.allow_panic_in_tests = true;
    conf.allow_unwrap_in_tests = true;
    conf.allow_expect_in_tests = true;
    conf.allow_indexing_slicing_in_tests = true;
}

/// rr's Clippy lints: forbidden whatever the command line asks, and their
/// reasons heard.
pub fn force_clippy(opts: &mut rustc_session::config::Options) {
    opts.lint_opts.retain(|(name, _)| {
        let name = name.replace('-', "_");
        !CLIPPY.iter().any(|(l, _)| name == format!("clippy::{l}")) && !RUSTC.contains(&name.as_str())
    });
    for (l, _) in CLIPPY {
        opts.lint_opts.push((format!("clippy::{l}"), rustc_lint::Level::Forbid));
    }
    for l in RUSTC {
        opts.lint_opts.push(((*l).to_owned(), rustc_lint::Level::Forbid));
    }
    for l in CLIPPY_OFF {
        opts.lint_opts.push((format!("clippy::{l}"), rustc_lint::Level::Allow));
    }
    let _ = clippy_utils::diagnostics::ESCAPE.set(clippy_escape);
}

pub fn register(store: &mut LintStore) {
    let lints = &[
        RR_NO_STD,
        RR_NO_GENERICS,
        RR_NO_MACROS,
        RR_SIMPLE_TRAITS,
        RR_UNEXPLAINED_ESCAPE,
        RR_HOT_PATH,
        RR_UNBOUNDED,
        RR_MATCH_CHAIN,
        RR_VARIADIC,
        RR_C_SIGNATURE,
        RR_DUPLICATE,
        RR_UNUSED_DERIVE,
        RR_NO_RECURSION,
        RR_UNUSED_ESCAPE,
    ];
    store.register_lints(lints);
    store.register_group(true, "rr", None, lints.iter().map(|lint| LintId::of(lint)).collect());
    store.register_pre_expansion_lint_pass(Box::new(|| Box::new(syntax::RestrictedSyntax::default())));
    store.register_late_lint_pass(Box::new(|_| Box::new(escape_hatches::EscapeHatches)));
    store.register_late_lint_pass(Box::new(|_| Box::new(allocs::Allocs::default())));
    store.register_late_lint_pass(Box::new(|_| Box::new(bounds::Bounds::default())));
    store.register_late_lint_pass(Box::new(|_| Box::new(chains::Chains)));
    store.register_late_lint_pass(Box::new(|_| Box::new(ffi::Ffi)));
    store.register_late_lint_pass(Box::new(|_| Box::<disguises::Disguises>::default()));
    store.register_late_lint_pass(Box::new(|_| Box::new(duplicates::Duplicates)));
    store.register_late_lint_pass(Box::new(|_| Box::new(derives::Derives::default())));
    store.register_late_lint_pass(Box::new(|_| Box::new(recursion::Recursion)));
    store.register_late_lint_pass(Box::new(|_| Box::new(builtins::BuiltinOrigins::default())));
    store.register_late_lint_pass(Box::new(|_| Box::new(expanded::ExpandedSyntax)));
}
