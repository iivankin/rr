use clippy_utils::diagnostics::span_lint_and_then;
use clippy_utils::res::MaybeDef as _;
use clippy_utils::visitors::is_local_used;
use rustc_hir::{Closure, Expr, ExprKind, PatKind};
use rustc_lint::LateContext;
use rustc_span::sym;

use super::MAP_ERR_IGNORE;

pub(super) fn check(cx: &LateContext<'_>, e: &Expr<'_>, arg: &Expr<'_>) {
    if let Some(method_id) = cx.typeck_results().type_dependent_def_id(e.hir_id)
        && let Some(impl_id) = cx.tcx.impl_of_assoc(method_id)
        && cx
            .tcx
            .type_of(impl_id)
            .instantiate_identity()
            .skip_norm_wip()
            .is_diag_item(cx, sym::Result)
        && let ExprKind::Closure(&Closure {
            body, fn_decl_span, ..
        }) = arg.kind
        && let closure_body = cx.tcx.hir_body(body)
        && let [param] = closure_body.params
        // `_`, or a name the closure never reads, which drops the error as
        // well; so does a `move` closure.
        && match param.pat.kind {
            PatKind::Wild => true,
            PatKind::Binding(_, id, ..) => !is_local_used(cx, closure_body.value, id),
            _ => false,
        }
    {
        // span the area of the closure capture and warn that the
        // original error will be thrown away
        #[expect(clippy::collapsible_span_lint_calls, reason = "rust-clippy#7797")]
        span_lint_and_then(
            cx,
            MAP_ERR_IGNORE,
            fn_decl_span,
            "this `map_err` closure discards the original error",
            |diag| {
                diag.help("keep the original error in the new one, or convert it with a From impl and `?`");
            },
        );
    }
}
