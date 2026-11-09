//! An outcome a caller may drop unseen: a function that changes something
//! and says how it went in a bool, an integer or an Option, without
//! `#[must_use]`. rustc reports a dropped Result, whose type is `must_use`,
//! but not `if !set.insert(x)` written as `set.insert(x);`, a count of
//! bytes written that is never compared with what was meant, or a `pop`
//! whose value is lost. A function changes something when it takes `&mut`
//! (itself or a parameter), when it calls foreign code, and when it is a
//! foreign function: C says how a call went in what it returns. With
//! `#[must_use]`, dropping it is rustc's `unused_must_use`, which rr
//! forbids, and `let _ =` takes an `escape(discard)` reason. No reason
//! answers this rule: the attribute is always possible.

use clippy_utils::diagnostics::span_lint_and_help;
use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::LocalDefId;
use rustc_hir::{self as hir, ExprKind, find_attr};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{self, Ty};
use rustc_session::impl_lint_pass;
use rustc_span::{Span, sym};

use super::RR_MUST_USE;

pub struct Outcomes;

impl_lint_pass!(Outcomes => [RR_MUST_USE]);

impl<'tcx> LateLintPass<'tcx> for Outcomes {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::Item<'tcx>) {
        if let hir::ItemKind::Fn { sig, body, ident, .. } = item.kind {
            check(cx, item.owner_id.def_id, ident.span, &sig, Some(body));
        }
    }

    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::ImplItem<'tcx>) {
        // A trait's method takes the attribute where the trait declares it.
        if let hir::ImplItemKind::Fn(sig, body) = item.kind
            && cx.tcx.trait_impl_of_assoc(item.owner_id.to_def_id()).is_none()
        {
            check(cx, item.owner_id.def_id, item.ident.span, &sig, Some(body));
        }
    }

    fn check_trait_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::TraitItem<'tcx>) {
        if let hir::TraitItemKind::Fn(sig, trait_fn) = item.kind {
            let body = match trait_fn {
                hir::TraitFn::Provided(body) => Some(body),
                hir::TraitFn::Required(_) => None,
            };
            check(cx, item.owner_id.def_id, item.ident.span, &sig, body);
        }
    }

    fn check_foreign_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::ForeignItem<'tcx>) {
        if let hir::ForeignItemKind::Fn(..) = item.kind {
            let def = item.owner_id.def_id;
            if let Some(what) = outcome(cx, def)
                && unmarked(cx, def, item.span)
            {
                report(cx, item.ident.span, def, what, "is a C function");
            }
        }
    }
}

fn check(cx: &LateContext<'_>, def: LocalDefId, span: Span, sig: &hir::FnSig<'_>, body: Option<hir::BodyId>) {
    // A function C calls, such as the program's entry or a callback,
    // returns to C.
    if !sig.header.abi.is_rustic_abi() || clippy_utils::is_in_test(cx.tcx, cx.tcx.local_def_id_to_hir_id(def)) {
        return;
    }
    let Some(what) = outcome(cx, def) else { return };
    if !unmarked(cx, def, span) {
        return;
    }
    let inputs = cx.tcx.fn_sig(def).instantiate_identity().skip_binder().inputs();
    let lent = inputs
        .iter()
        .any(|t| matches!(t.kind(), ty::Ref(_, _, hir::Mutability::Mut)));
    let why = if lent {
        "takes `&mut`, so it changes something"
    } else if body.is_some_and(|body| calls_foreign(cx, body)) {
        "calls foreign code, so it changes something"
    } else {
        return;
    };
    report(cx, span, def, what, why);
}

/// What def returns that says how it went: a bool, an integer or an
/// Option.
fn outcome(cx: &LateContext<'_>, def: LocalDefId) -> Option<&'static str> {
    let output: Ty<'_> = cx.tcx.fn_sig(def).instantiate_identity().skip_binder().output();
    match output.kind() {
        ty::Bool => Some("a bool"),
        ty::Int(_) | ty::Uint(_) => Some("an integer"),
        ty::Adt(adt, _) if cx.tcx.is_diagnostic_item(sym::Option, adt.did()) => Some("an Option"),
        _ => None,
    }
}

/// Whether def, the program's own, has no `#[must_use]`.
fn unmarked(cx: &LateContext<'_>, def: LocalDefId, span: Span) -> bool {
    super::builtins::is_user_code(span) && !find_attr!(cx.tcx, def, MustUse { .. })
}

/// Whether the body calls a foreign function.
fn calls_foreign(cx: &LateContext<'_>, body: hir::BodyId) -> bool {
    let tcx = cx.tcx;
    let typeck = tcx.typeck_body(body);
    for_each_expr(tcx, tcx.hir_body(body).value, |e| {
        if let ExprKind::Call(callee, _) = e.kind
            && let ExprKind::Path(ref path) = callee.kind
            && let Res::Def(DefKind::Fn, def) = typeck.qpath_res(path, callee.hir_id)
            && tcx.is_foreign_item(def)
        {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .is_some()
}

fn report(cx: &LateContext<'_>, span: Span, def: LocalDefId, what: &str, why: &str) {
    span_lint_and_help(
        cx,
        RR_MUST_USE,
        span,
        format!(
            "{} {why}, and returns {what}, which a caller may drop unseen: rustc reports a dropped Result, not this",
            super::calls::name(cx.tcx, def)
        ),
        None,
        "add `#[must_use]`, so that dropping the outcome is an error and `let _ =` takes an `escape(discard)` reason; \
         or return a Result",
    );
}
