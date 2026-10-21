use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_then};
use rustc_ast::ast;
use rustc_ast::visit::FnKind;
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
const ENTRIES: &[&str] = &["main", "LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize"];

#[derive(Default)]
pub struct RestrictedSyntax {
    /// The crate is `#![no_main]`: its entry is a function of its own.
    no_main: bool,
    /// `#[unsafe(no_mangle)]` on that entry, a symbol the program must define
    /// under its C name and nothing else defines: no reason.
    entry: Option<ast::AttrId>,
}
impl_lint_pass!(RestrictedSyntax => [RR_NO_STD, RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE]);

/// Where this pass reported something, for the pass after expansion,
/// which sees the same code again and what include! brought in besides.
static REPORTED: Mutex<FxHashSet<BytePos>> = Mutex::new(FxHashSet::with_hasher(FxBuildHasher));

/// Whether the pass before expansion reported something at span.
pub fn reported(span: Span) -> bool {
    REPORTED.lock().is_ok_and(|seen| seen.contains(&span.lo()))
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

    fn check_generics(&mut self, cx: &EarlyContext<'_>, generics: &ast::Generics) {
        for param in &generics.params {
            if !matches!(param.kind, ast::GenericParamKind::Lifetime) {
                report(
                    cx,
                    RR_NO_GENERICS,
                    param.span(),
                    "type and const parameters are forbidden by rr",
                    "use concrete types; lifetime parameters are allowed",
                );
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
        match ty.kind {
            ast::TyKind::ImplTrait(..) => report(
                cx,
                RR_NO_GENERICS,
                ty.span,
                "impl Trait is forbidden by rr",
                "use a concrete type",
            ),
            ast::TyKind::TraitObject(..) => report(
                cx,
                RR_SIMPLE_TRAITS,
                ty.span,
                "dyn Trait is forbidden by rr",
                "use a concrete type or an ordinary trait implementation",
            ),
            _ => {},
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
            report(
                cx,
                RR_NO_MACROS,
                mac.span(),
                "macro calls are forbidden by rr",
                "only no_std compiler builtins and core panic/assert macros are allowed",
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
        let conditional_forbidden = attr.has_name(sym::cfg_attr)
            && attr
                .meta_item_list()
                .is_some_and(|items| items.iter().skip(1).any(forbidden_meta));
        let forbidden = conditional_forbidden
            || attr.has_name(sym::derive)
            || attr.has_name(sym::derive_const)
            || attr.is_proc_macro_attr()
            || (!is_builtin_attr_name(first)
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
    matches!(
        first.as_str(),
        "derive" | "derive_const" | "proc_macro" | "proc_macro_attribute" | "proc_macro_derive"
    ) || (!is_builtin_attr_name(first)
        && !allowed_builtin_attribute(&meta.path.segments.iter().map(|s| s.ident.name).collect::<Vec<_>>())
        && !matches!(first.as_str(), "clippy" | "rustfmt" | "rr"))
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
