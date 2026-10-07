use clippy_utils::diagnostics::span_lint_and_help;
use rustc_ast::ast;
use rustc_ast::visit::FnKind;
use rustc_feature::is_builtin_attr_name;
use rustc_lint::{EarlyContext, EarlyLintPass};
use rustc_session::impl_lint_pass;
use rustc_span::Span;
use rustc_span::symbol::{kw, sym};

use super::{RR_NO_GENERICS, RR_NO_MACROS, RR_NO_STD, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE};

pub struct RestrictedSyntax;
impl_lint_pass!(RestrictedSyntax => [RR_NO_STD, RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE]);

fn report(
    cx: &EarlyContext<'_>,
    lint: &'static rustc_lint::Lint,
    span: Span,
    message: &'static str,
    help: &'static str,
) {
    if !span.from_expansion() {
        span_lint_and_help(cx, lint, span, message, None, help);
    }
}

impl EarlyLintPass for RestrictedSyntax {
    fn check_crate(&mut self, cx: &EarlyContext<'_>, krate: &ast::Crate) {
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
        if !allowed_macro_path(&mac.path) {
            report(
                cx,
                RR_NO_MACROS,
                mac.span(),
                "macro calls are forbidden by rr",
                "only core panic/assert macros are allowed",
            );
        }
    }

    fn check_attribute(&mut self, cx: &EarlyContext<'_>, attr: &ast::Attribute) {
        if attr.is_doc_comment() {
            return;
        }
        let path = attr.path();
        let Some(&first) = path.first() else { return };
        let conditional_forbidden = attr.has_name(sym::cfg_attr)
            && attr
                .meta_item_list()
                .is_some_and(|items| items.iter().skip(1).any(forbidden_meta));
        let forbidden = conditional_forbidden
            || attr.has_name(sym::derive)
            || attr.is_proc_macro_attr()
            || (!is_builtin_attr_name(first) && !matches!(first.as_str(), "clippy" | "rustfmt"));
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
        [name] | ["core", name] => *name,
        _ => return false,
    };
    matches!(
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
        "derive" | "proc_macro" | "proc_macro_attribute" | "proc_macro_derive"
    ) || (!is_builtin_attr_name(first) && !matches!(first.as_str(), "clippy" | "rustfmt"))
}

fn require_unsafe_reason(cx: &EarlyContext<'_>, span: Span, operation: &'static str) {
    if !span.from_expansion() && !super::comments::has_escape_reason(cx, span, span) {
        span_lint_and_help(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            span,
            format!("{operation} needs a safety justification"),
            None,
            "add an adjacent `// rr: escape: <reason>` explaining the unsafe contract",
        );
    }
}
