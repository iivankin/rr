//! Check language restrictions after builtin macros have expanded (notably include!).

use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_then};
use rustc_hir::{self as hir, AmbigArg};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_session::impl_lint_pass;
use rustc_span::Span;
use rustc_span::def_id::LocalDefId;

use super::{RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE};

pub struct ExpandedSyntax;
impl_lint_pass!(ExpandedSyntax => [RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE]);

fn reject(cx: &LateContext<'_>, lint: &'static rustc_lint::Lint, span: Span, feature: &str) {
    // What the check before expansion has reported already; this one is
    // for what macros bring in, such as include!.
    if super::syntax::reported(span) || !super::builtins::is_user_code(span) {
        return;
    }
    span_lint_and_help(
        cx,
        lint,
        span,
        format!("{feature} is forbidden by rr after macro expansion"),
        None,
        "use concrete types and simple traits, including in included source",
    );
}

impl<'tcx> LateLintPass<'tcx> for ExpandedSyntax {
    fn check_generics(&mut self, cx: &LateContext<'tcx>, generics: &'tcx hir::Generics<'tcx>) {
        for param in generics.params {
            if !matches!(param.kind, hir::GenericParamKind::Lifetime { .. }) {
                reject(cx, RR_NO_GENERICS, param.span, "type/const generic parameters");
            }
        }
        if generics.has_where_clause_predicates {
            reject(cx, RR_SIMPLE_TRAITS, generics.where_clause_span, "where clauses");
        }
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::Item<'tcx>) {
        match item.kind {
            hir::ItemKind::Trait { bounds, .. } if !bounds.is_empty() => {
                reject(cx, RR_SIMPLE_TRAITS, item.span, "supertraits");
            },
            hir::ItemKind::Impl(implementation)
                if implementation
                    .of_trait
                    .is_some_and(|header| header.safety == hir::Safety::Unsafe) =>
            {
                require_included_unsafe_reason(cx, item.span);
            },
            hir::ItemKind::TraitAlias(..) => reject(cx, RR_SIMPLE_TRAITS, item.span, "trait aliases"),
            hir::ItemKind::Macro(..) => reject(cx, RR_NO_MACROS, item.span, "macro definitions"),
            _ => {},
        }
    }

    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: hir::intravisit::FnKind<'tcx>,
        _: &'tcx hir::FnDecl<'tcx>,
        _: &'tcx hir::Body<'tcx>,
        span: Span,
        _: LocalDefId,
    ) {
        if kind
            .header()
            .is_some_and(|header| header.safety == hir::HeaderSafety::Normal(hir::Safety::Unsafe))
        {
            require_included_unsafe_reason(cx, span);
        }
    }

    fn check_trait_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::TraitItem<'tcx>) {
        if matches!(item.kind, hir::TraitItemKind::Type(..)) {
            reject(cx, RR_SIMPLE_TRAITS, item.span, "associated types");
        }
    }

    fn check_ty(&mut self, cx: &LateContext<'tcx>, ty: &'tcx hir::Ty<'tcx, AmbigArg>) {
        match ty.kind {
            hir::TyKind::TraitObject(..) => reject(cx, RR_SIMPLE_TRAITS, ty.span, "dyn Trait"),
            hir::TyKind::OpaqueDef(..) => reject(cx, RR_NO_GENERICS, ty.span, "impl Trait"),
            _ => {},
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx hir::Expr<'tcx>) {
        if let hir::ExprKind::Closure(closure) = expr.kind
            && matches!(
                closure.kind,
                hir::ClosureKind::Coroutine(hir::CoroutineKind::Desugared(
                    hir::CoroutineDesugaring::Async | hir::CoroutineDesugaring::AsyncGen,
                    _
                )) | hir::ClosureKind::CoroutineClosure(
                    hir::CoroutineDesugaring::Async | hir::CoroutineDesugaring::AsyncGen
                )
            )
        {
            reject(cx, RR_NO_GENERICS, expr.span, "async/await");
        }
    }
}

fn require_included_unsafe_reason(cx: &LateContext<'_>, span: Span) {
    if super::builtins::is_user_code(span) && !super::comments::has_escape_reason(cx, span, span, "unsafe") {
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            span,
            "unsafe declaration in included source needs a safety justification",
            |diag| super::comments::note(diag, cx.sess(), span, span, "unsafe"),
        );
    }
}
