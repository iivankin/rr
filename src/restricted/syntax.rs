use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_then};
use rustc_ast::ast;
use rustc_ast::visit::{AssocCtxt, FnCtxt, FnKind};
use rustc_data_structures::fx::{FxBuildHasher, FxHashSet};
use rustc_feature::is_builtin_attr_name;
use rustc_lint::{EarlyContext, EarlyLintPass, LintContext as _};
use rustc_session::impl_lint_pass;
use rustc_span::symbol::{kw, sym};
use rustc_span::{BytePos, Span, Symbol};
use std::sync::Mutex;

use super::{RR_NO_GENERICS, RR_NO_MACROS, RR_NO_STD, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE};

/// The entries of a `#![no_main]` program: C's main, and libFuzzer's for
/// a harness of rr fuz.
const ENTRIES: &[&str] = &[
    "main",
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    // The symbolizer libFuzzer asks for, which rr fuz's harness gives.
    "__sanitizer_symbolize_pc",
    "__sanitizer_get_module_and_offset_for_pc",
];

#[derive(Default)]
pub struct RestrictedSyntax {
    /// The crate is `#![no_main]`: its entry is a function of its own.
    no_main: bool,
    /// `#[unsafe(no_mangle)]` on that entry, a symbol the program must define
    /// under its C name and nothing else defines: no reason.
    entry: Option<ast::AttrId>,
    /// Where `impl Trait` is allowed: a function's parameter that is `impl
    /// Fn`, `FnMut` or `FnOnce`, a closure handed in, which the function
    /// calls; and the whole return type of a free function or an inherent
    /// method that is `impl Iterator<Item = T>`.
    allowed: FxHashSet<BytePos>,
    /// Whether the item whose generics come next may have `const N:
    /// usize`: a function, a struct, an impl or a method of one.
    consts: bool,
}
impl_lint_pass!(RestrictedSyntax => [RR_NO_STD, RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE]);

/// Where this pass reported something, for the pass after expansion,
/// which sees the same code again and what include! brought in besides.
static REPORTED: Mutex<FxHashSet<BytePos>> = Mutex::new(FxHashSet::with_hasher(FxBuildHasher));

/// Whether the pass before expansion reported something at span.
pub fn reported(span: Span) -> bool {
    REPORTED.lock().is_ok_and(|seen| seen.contains(&span.lo()))
}

/// What to write instead of a library macro: the ones programs reach
/// for first, then the rule.
fn instead_of(name: &str) -> &'static str {
    match name {
        "vec" => {
            "build a vector from an array, `Vec::from([a, b, c])`, or with `Vec::new()` and `resize(n, x)` for n copies"
        },
        "format" => {
            "write into a String the code holds with `write!(s, ...)` (`core::fmt::Write`), or into the output it goes \
             to; an error is a variant of its enum, formatted where it is shown"
        },
        "println" | "print" | "eprintln" | "eprint" | "dbg" => {
            "rr has no std: output goes through `sys::stdout` and `sys::stderr`, with `write!` into a buffer the code \
             holds"
        },
        _ => "only no_std compiler builtins and core panic/assert macros are allowed",
    }
}

fn report(
    cx: &EarlyContext<'_>,
    lint: &'static rustc_lint::Lint,
    span: Span,
    message: &'static str,
    help: &'static str,
) {
    if !span.from_expansion() {
        if let Ok(mut seen) = REPORTED.lock() {
            seen.insert(span.lo());
        }
        span_lint_and_help(cx, lint, span, message, None, help);
    }
}

impl EarlyLintPass for RestrictedSyntax {
    fn check_crate(&mut self, cx: &EarlyContext<'_>, krate: &ast::Crate) {
        self.no_main = krate.attrs.iter().any(|attr| attr.has_name(sym::no_main));
        for attr in krate.attrs.iter().filter(|attr| attr.has_name(sym::feature)) {
            for item in attr.meta_item_list().unwrap_or_default() {
                if item.name().is_some_and(|name| CONST_FEATURES.contains(&name.as_str())) {
                    report(
                        cx,
                        RR_NO_GENERICS,
                        item.span(),
                        "this feature makes a const parameter more than a number, and is forbidden by rr",
                        "a const parameter is `const N: usize`, given as a number or another such parameter",
                    );
                }
            }
        }
        if !krate.attrs.iter().any(|attr| attr.has_name(sym::no_std)) {
            report(
                cx,
                RR_NO_STD,
                krate.spans.inner_span,
                "rr requires #![no_std]",
                "add #![no_std] at the crate root",
            );
        }
    }

    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &ast::Item) {
        self.consts = matches!(
            item.kind,
            ast::ItemKind::Fn(_) | ast::ItemKind::Struct(..) | ast::ItemKind::Impl(_)
        );
        if self.no_main
            && let ast::ItemKind::Fn(f) = &item.kind
            && ENTRIES.contains(&f.ident.name.as_str())
        {
            self.entry = item
                .attrs
                .iter()
                .find(|attr| attr.has_name(sym::no_mangle))
                .map(|attr| attr.id);
        }
        match &item.kind {
            ast::ItemKind::ExternCrate(original, ident) if original.unwrap_or(ident.name) == sym::std => {
                report(
                    cx,
                    RR_NO_STD,
                    item.span,
                    "explicit std imports are forbidden by rr",
                    "use core or alloc instead",
                );
            },
            ast::ItemKind::Trait(trait_) if !trait_.bounds.is_empty() => {
                report(
                    cx,
                    RR_SIMPLE_TRAITS,
                    item.span,
                    "supertraits are forbidden by rr",
                    "use a trait without supertrait bounds",
                );
            },
            ast::ItemKind::Impl(implementation) => {
                if let Some(trait_) = &implementation.of_trait
                    && let ast::Safety::Unsafe(span) = trait_.safety
                {
                    require_unsafe_reason(cx, item.span.with_hi(span.hi()), "unsafe impl");
                }
            },
            ast::ItemKind::ForeignMod(foreign) => {
                // The block vouches for every signature in it.
                if let ast::Safety::Unsafe(_) = foreign.safety {
                    require_unsafe_reason(
                        cx,
                        item.span.with_hi(foreign.extern_span.hi()),
                        "an unsafe extern block",
                    );
                }
                // A safe item is called or read with no unsafe block, so its
                // own reason says why any use is sound.
                for foreign_item in &foreign.items {
                    let (safety, operation) = match &foreign_item.kind {
                        ast::ForeignItemKind::Fn(f) => (f.sig.header.safety, "a safe foreign function"),
                        ast::ForeignItemKind::Static(s) => (s.safety, "a safe foreign static"),
                        ast::ForeignItemKind::TyAlias(_) | ast::ForeignItemKind::MacCall(_) => continue,
                    };
                    if let ast::Safety::Safe(_) = safety {
                        require_unsafe_reason(cx, foreign_item.span, operation);
                    }
                }
            },
            ast::ItemKind::TraitAlias(_) => {
                report(
                    cx,
                    RR_SIMPLE_TRAITS,
                    item.span,
                    "trait aliases are forbidden by rr",
                    "use a simple trait directly",
                );
            },
            ast::ItemKind::MacroDef(..) => {
                report(
                    cx,
                    RR_NO_MACROS,
                    item.span,
                    "macro definitions are forbidden by rr",
                    "write ordinary functions or concrete types",
                );
            },
            _ => {},
        }
    }

    fn check_impl_item(&mut self, _: &EarlyContext<'_>, _: &ast::AssocItem) {
        self.consts = true;
    }

    fn check_generics(&mut self, cx: &EarlyContext<'_>, generics: &ast::Generics) {
        for param in &generics.params {
            match &param.kind {
                ast::GenericParamKind::Lifetime => {},
                ast::GenericParamKind::Const { ty, default: None, .. } if self.consts && usize_path(ty) => {},
                ast::GenericParamKind::Const { .. } => report(
                    cx,
                    RR_NO_GENERICS,
                    param.span(),
                    "a const parameter other than `const N: usize` of a function, a struct or an impl is forbidden by rr",
                    "write `const N: usize`, without a default, on a function, a struct, an impl or a method of one; \
                     not on a trait, an enum or a type alias",
                ),
                ast::GenericParamKind::Type { .. } => report(
                    cx,
                    RR_NO_GENERICS,
                    param.span(),
                    "type parameters are forbidden by rr",
                    "use concrete types: for a set of types the crate knows, an enum with a variant for each \
                     (a slice or a reader, a string or standard output); for code that must call what the caller \
                     brings, `&mut dyn` of a trait of the crate; lifetime parameters and `const N: usize` are allowed",
                ),
            }
        }
        if !generics.where_clause.is_empty() {
            report(
                cx,
                RR_SIMPLE_TRAITS,
                generics.where_clause.span,
                "where clauses are forbidden by rr",
                "use concrete types and simple trait signatures",
            );
        }
    }

    fn check_ty(&mut self, cx: &EarlyContext<'_>, ty: &ast::Ty) {
        // dyn is checked after resolution, which knows whose trait it is.
        if let ast::TyKind::ImplTrait(..) = ty.kind
            && !self.allowed.contains(&ty.span.lo())
        {
            report(
                cx,
                RR_NO_GENERICS,
                ty.span,
                "impl Trait is forbidden by rr",
                "use a concrete type, an enum of the types the crate knows, or `&mut dyn` of a trait of the crate; \
                 a parameter may be `impl Fn`, `impl FnMut` or `impl FnOnce`, and a function or an inherent \
                 method may return `impl Iterator<Item = T>`",
            );
        }
    }

    fn check_expr(&mut self, cx: &EarlyContext<'_>, expr: &ast::Expr) {
        let span = match &expr.kind {
            ast::ExprKind::Await(_, span)
            | ast::ExprKind::Gen(_, _, ast::GenBlockKind::Async | ast::GenBlockKind::AsyncGen, span) => Some(*span),
            ast::ExprKind::Closure(closure) => closure
                .coroutine_kind
                .filter(|kind| {
                    matches!(
                        kind,
                        ast::CoroutineKind::Async { .. } | ast::CoroutineKind::AsyncGen { .. }
                    )
                })
                .map(ast::CoroutineKind::span),
            _ => None,
        };
        if let Some(span) = span {
            report(
                cx,
                RR_NO_GENERICS,
                span,
                "async/await is forbidden by rr",
                "use synchronous code with concrete types",
            );
        }
    }

    fn check_fn(&mut self, cx: &EarlyContext<'_>, kind: FnKind<'_>, span: Span, _: ast::NodeId) {
        if let FnKind::Fn(ctxt, _, f) = kind {
            // An iterator returned: the compiler knows its type, and so do
            // rr's checks, which run after it is revealed. Not in a trait,
            // where it would be an associated type.
            if matches!(ctxt, FnCtxt::Free | FnCtxt::Assoc(AssocCtxt::Impl { of_trait: false }))
                && let ast::FnRetTy::Ty(output) = &f.sig.decl.output
                && let ast::TyKind::ImplTrait(_, bounds) = &output.kind
                && iterator_bounds(bounds)
            {
                self.allowed.insert(output.span.lo());
            }
            let mut takes = None;
            for param in &f.sig.decl.inputs {
                if let ast::TyKind::ImplTrait(_, bounds) = &param.ty.kind
                    && closure_bounds(bounds)
                {
                    self.allowed.insert(param.ty.span.lo());
                    takes = Some(param.ty.span);
                }
            }
            // The compiler copies such a function for each closure it is
            // given: a long one multiplies the work of the build.
            if let (Some(param), Some(body)) = (takes, &f.body) {
                let map = cx.sess().source_map();
                let lines = map.lookup_char_pos(body.span.hi()).line - map.lookup_char_pos(body.span.lo()).line + 1;
                if lines > CLOSURE_FN_LINES_MAX {
                    report(
                        cx,
                        RR_NO_GENERICS,
                        param,
                        "a function of more than 30 lines that takes a closure is compiled again for every closure",
                        "keep the part around the closure short, and call the rest from it as an ordinary function",
                    );
                }
            }
        }
        if let Some(header) = kind.header()
            && let ast::Safety::Unsafe(keyword) = header.safety
        {
            require_unsafe_reason(cx, span.with_hi(keyword.hi()), "unsafe fn");
        }
        if let Some(header) = kind.header()
            && let Some(ast::CoroutineKind::Async { span, .. } | ast::CoroutineKind::AsyncGen { span, .. }) =
                header.coroutine_kind
        {
            report(
                cx,
                RR_NO_GENERICS,
                span,
                "async fn is forbidden by rr",
                "use an ordinary function with a concrete return type",
            );
        }
    }

    fn check_trait_item(&mut self, cx: &EarlyContext<'_>, item: &ast::AssocItem) {
        self.consts = false;
        if matches!(item.kind, ast::AssocItemKind::Type(_)) {
            report(
                cx,
                RR_SIMPLE_TRAITS,
                item.span,
                "associated types are forbidden by rr",
                "use concrete types in trait methods",
            );
        }
    }

    fn check_mac(&mut self, cx: &EarlyContext<'_>, mac: &ast::MacCall) {
        super::macros::check_arguments(cx, &mac.args.tokens);
        // Assembly outside any function, which no unsafe block marks.
        if mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident.name.as_str() == "global_asm")
        {
            require_unsafe_reason(cx, mac.span(), "global assembly");
        }
        if !allowed_macro_path(&mac.path) {
            let name = mac.path.segments.last().map_or("", |s| s.ident.name.as_str());
            report(
                cx,
                RR_NO_MACROS,
                mac.span(),
                "macro calls are forbidden by rr",
                instead_of(name),
            );
        }
    }

    fn check_attribute(&mut self, cx: &EarlyContext<'_>, attr: &ast::Attribute) {
        if attr.is_doc_comment() {
            return;
        }
        // #[unsafe(no_mangle)], #[unsafe(export_name)], #[unsafe(link_section)]:
        // a symbol can stand in for another, such as malloc.
        if let ast::AttrKind::Normal(normal) = &attr.kind
            && let ast::Safety::Unsafe(_) = normal.item.unsafety
            && self.entry != Some(attr.id)
        {
            require_unsafe_reason(cx, attr.span, "an unsafe attribute");
        }
        let path = attr.path();
        let Some(&first) = path.first() else { return };
        // A misspelt mark would mark nothing, and its check would not run.
        if first.as_str() == "rr" && !matches!(path.as_slice(), [_, name] if RR_ATTRIBUTES.contains(&name.as_str())) {
            report(
                cx,
                RR_NO_MACROS,
                attr.span,
                "rr knows no such attribute",
                "rr's attributes are #[rr::hot], #[rr::poll] and #[rr::blocking]",
            );
        }
        let conditional_forbidden = attr.has_name(sym::cfg_attr)
            && attr
                .meta_item_list()
                .is_some_and(|items| items.iter().skip(1).any(forbidden_meta));
        let derive = attr.has_name(sym::derive);
        let forbidden = conditional_forbidden
            || (derive && !attr.meta_item_list().is_some_and(|items| allowed_derives(&items)))
            || attr.has_name(sym::derive_const)
            || attr.is_proc_macro_attr()
            || (!derive
                && !is_builtin_attr_name(first)
                && !allowed_builtin_attribute(&path)
                && !matches!(first.as_str(), "clippy" | "rustfmt" | "rr"));
        if forbidden {
            report(
                cx,
                RR_NO_MACROS,
                attr.span,
                "derive and procedural macro attributes are forbidden by rr",
                "write the implementation explicitly",
            );
        }
    }
}

/// rr's own attributes: a hot path's root, an event loop's handler, and
/// a function that blocks.
const RR_ATTRIBUTES: &[&str] = &["hot", "poll", "blocking"];

/// The most lines of a function that takes a closure: the compiler copies
/// it for each closure it is given.
const CLOSURE_FN_LINES_MAX: usize = 30;

/// Whether the bounds of an `impl Trait` say only that it is a closure:
/// one of `Fn(..)`, `FnMut(..)` or `FnOnce(..)`, lifetimes, and `Send` or
/// `Sync`, which say it may go to another thread and run nothing.
fn closure_bounds(bounds: &[ast::GenericBound]) -> bool {
    let mut closures = 0;
    for bound in bounds {
        match bound {
            ast::GenericBound::Trait(poly) => {
                let Some(last) = poly.trait_ref.path.segments.last() else {
                    return false;
                };
                if last.args.is_none() && matches!(last.ident.name.as_str(), "Send" | "Sync") {
                    continue;
                }
                let parenthesized = matches!(last.args.as_deref(), Some(ast::GenericArgs::Parenthesized(_)));
                if !parenthesized || !matches!(last.ident.name.as_str(), "Fn" | "FnMut" | "FnOnce") {
                    return false;
                }
                closures += 1;
            },
            ast::GenericBound::Outlives(_) => {},
            ast::GenericBound::Use(..) => return false,
        }
    }
    closures == 1
}

/// The traits an iterator returned as `impl Trait` may name besides
/// `Iterator<Item = T>`: they add `next_back` and `len`, which the
/// compiler resolves on the type it reveals as it does `next`, and no type
/// of their own.
pub(super) const ITERATOR_EXTRAS: &[&str] = &["DoubleEndedIterator", "ExactSizeIterator"];

/// Whether the bounds of a returned `impl Trait` say only that it is an
/// iterator: one `Iterator<Item = T>`, perhaps `DoubleEndedIterator` and
/// `ExactSizeIterator`, lifetimes and `use<..>` of lifetimes. The type of
/// the items is checked as any type is.
fn iterator_bounds(bounds: &[ast::GenericBound]) -> bool {
    let mut iterators = 0;
    for bound in bounds {
        match bound {
            ast::GenericBound::Trait(poly) => {
                if !poly.bound_generic_params.is_empty() || poly.modifiers != ast::TraitBoundModifiers::NONE {
                    return false;
                }
                let Some(last) = poly.trait_ref.path.segments.last() else {
                    return false;
                };
                let name = last.ident.name.as_str();
                match last.args.as_deref() {
                    None if ITERATOR_EXTRAS.contains(&name) => {},
                    Some(ast::GenericArgs::AngleBracketed(args)) if name == "Iterator" && item_only(args) => {
                        iterators += 1;
                    },
                    _ => return false,
                }
            },
            ast::GenericBound::Outlives(_) => {},
            ast::GenericBound::Use(args, _) => {
                if !args
                    .iter()
                    .all(|arg| matches!(arg, ast::PreciseCapturingArg::Lifetime(_)))
                {
                    return false;
                }
            },
        }
    }
    iterators == 1
}

/// Whether the arguments of `Iterator<..>` are `Item = T` alone.
fn item_only(args: &ast::AngleBracketedArgs) -> bool {
    let [ast::AngleBracketedArg::Constraint(c)] = args.args.as_slice() else {
        return false;
    };
    c.ident.name.as_str() == "Item"
        && c.gen_args.is_none()
        && matches!(
            c.kind,
            ast::AssocItemConstraintKind::Equality { term: ast::Term::Ty(_) }
        )
}

/// Whether ty is `usize`, by its name or its path in core.
fn usize_path(ty: &ast::Ty) -> bool {
    let ast::TyKind::Path(None, path) = &ty.kind else {
        return false;
    };
    let names: Vec<&str> = path
        .segments
        .iter()
        .filter(|segment| segment.ident.name != kw::PathRoot && segment.args.is_none())
        .map(|segment| segment.ident.name.as_str())
        .collect();
    names.len() == path.segments.iter().filter(|s| s.ident.name != kw::PathRoot).count()
        && matches!(names.as_slice(), ["usize"] | ["core", "primitive", "usize"])
}

/// The compiler's features that would let a const parameter be more than
/// a number: a computed one, one of a type of the crate, a generic constant.
const CONST_FEATURES: &[&str] = &[
    "generic_const_exprs",
    "adt_const_params",
    "unsized_const_params",
    "generic_const_items",
    "min_generic_const_args",
    "generic_const_parameter_types",
    "generic_arg_infer",
];

fn allowed_macro_path(path: &ast::Path) -> bool {
    let names: Vec<_> = path
        .segments
        .iter()
        .filter(|segment| segment.ident.name != kw::PathRoot)
        .map(|segment| segment.ident.name.as_str())
        .collect();
    allowed_macro_names(&names)
}

pub(super) fn allowed_macro_names(names: &[&str]) -> bool {
    let macro_name = match names {
        [name] | ["core", name] | ["core", "arch", name @ ("asm" | "global_asm" | "naked_asm")] => *name,
        ["core", "pat", "pattern_type"] => "pattern_type",
        ["core", "marker", "direct_const_arg"] => "direct_const_arg",
        ["core", "view", "view_type"] => "view_type",
        ["core", "iter", "iter"] => "iter",
        _ => return false,
    };
    super::builtins::is_builtin(macro_name)
        || matches!(
            macro_name,
            "panic"
                | "unreachable"
                | "unimplemented"
                | "todo"
                | "assert"
                | "assert_eq"
                | "assert_ne"
                | "debug_assert"
                | "debug_assert_eq"
                | "debug_assert_ne"
                // Formatting into a core::fmt::Write: sugar for write_fmt.
                | "write"
                | "writeln"
                // A pattern test: sugar for a match that answers true or false.
                | "matches"
        )
}

fn forbidden_meta(inner: &ast::MetaItemInner) -> bool {
    let Some(meta) = inner.meta_item() else { return false };
    let Some(first) = meta.path.segments.first().map(|segment| segment.ident.name) else {
        return false;
    };
    if first == sym::cfg_attr {
        return meta
            .meta_item_list()
            .is_some_and(|items| items.iter().skip(1).any(forbidden_meta));
    }
    if first == sym::derive {
        return !meta.meta_item_list().is_some_and(allowed_derives);
    }
    matches!(
        first.as_str(),
        "derive_const" | "proc_macro" | "proc_macro_attribute" | "proc_macro_derive"
    ) || (!is_builtin_attr_name(first)
        && !allowed_builtin_attribute(&meta.path.segments.iter().map(|s| s.ident.name).collect::<Vec<_>>())
        && !matches!(first.as_str(), "clippy" | "rustfmt" | "rr"))
        || (first.as_str() == "rr"
            && !matches!(meta.path.segments.as_slice(), [_, name] if RR_ATTRIBUTES.contains(&name.ident.name.as_str())))
}

/// The compiler's own derives that ordinary syntax needs on a type of the
/// program: copying it (`Copy`, and `Clone`, which `Copy` requires), `==`
/// and a constant of it in a pattern (`PartialEq`, `Eq`), `<` and sorting
/// (`PartialOrd`, `Ord`), and unwrap, `{:?}` and `assert_eq!` (`Debug`). rr
/// allows these, and no other derive: `Hash` serves the hash maps of std,
/// and a constructor says what `Default` would.
pub(super) const DERIVES: &[&str] = &["Clone", "Copy", "Debug", "PartialEq", "Eq", "PartialOrd", "Ord"];

/// Whether every item of a `derive(..)` list is one of the compiler's own
/// derives, by its name or its path in core.
fn allowed_derives(items: &[ast::MetaItemInner]) -> bool {
    items.iter().all(|item| {
        item.meta_item().is_some_and(|meta| {
            meta.is_word()
                && match meta.path.segments.as_slice() {
                    [name] => DERIVES.contains(&name.ident.name.as_str()),
                    [root, .., name] => root.ident.name == sym::core && DERIVES.contains(&name.ident.name.as_str()),
                    [] => false,
                }
        })
    })
}

fn require_unsafe_reason(cx: &EarlyContext<'_>, span: Span, operation: &'static str) {
    if !span.from_expansion() && !super::comments::has_escape_reason(cx, span, span, "unsafe") {
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            span,
            format!("{operation} needs a safety justification"),
            |diag| {
                diag.help("keep it behind a safe function in the one module that talks to the system, and say in the reason what makes it sound");
                super::comments::note(diag, cx.sess(), span, span, "unsafe");
            },
        );
    }
}

fn allowed_builtin_attribute(path: &[Symbol]) -> bool {
    let name = match path {
        [name] => *name,
        [root, name] if *root == sym::core => *name,
        [root, module, name] if *root == sym::core && module.as_str() == "autodiff" => *name,
        _ => return false,
    };
    super::builtins::is_builtin_attribute(name.as_str())
}
