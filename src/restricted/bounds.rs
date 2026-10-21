//! A collection a value keeps grows with no limit unless something holds
//! it to one. Each field that a push, extend or insert grows must be held
//! somewhere in the crate: its `len()` compared with a limit, or a
//! `clear()` or `truncate()` that starts it over; otherwise a reason that
//! says what bounds it, at the field's declaration or at a growth. A
//! field of a value this function owns and builds is not looked at: it
//! grows once, as the value is made. A field that grows on every event
//! and is never held is a leak that takes hours to show.

use clippy_utils::diagnostics::span_lint_hir_and_then;
use clippy_utils::res::MaybeResPath as _;
use rustc_data_structures::fx::FxHashSet;
use rustc_hir::{BinOpKind, Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::ty::{self, Ty};
use rustc_session::impl_lint_pass;
use rustc_span::def_id::DefId;
use rustc_span::{Span, Symbol};

use super::RR_UNBOUNDED;
use super::allocs::{reason, statement};
use super::comments::{has_escape_reason, note};
use super::copies::std_def;

/// A field: the type that has it and its name.
type Field = (DefId, Symbol);

#[derive(Default)]
pub struct Bounds {
    /// Each place a field grows.
    grows: Vec<(Field, HirId, Span, String)>,
    /// The fields something holds.
    held: FxHashSet<Field>,
}

impl_lint_pass!(Bounds => [RR_UNBOUNDED]);

/// The methods that make a collection longer.
const GROW: &[&str] = &[
    "push",
    "push_back",
    "push_front",
    "push_str",
    "insert",
    "insert_str",
    "extend",
    "extend_from_slice",
    "extend_from_within",
    "append",
    "resize",
];

/// Collections of the standard library whose length a value can grow.
fn growable(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    let ty::Adt(adt, _) = ty.peel_refs().kind() else {
        return false;
    };
    let path = cx.tcx.def_path_str(adt.did());
    matches!(
        path.as_str(),
        "alloc::vec::Vec" | "alloc::string::String" | "alloc::collections::vec_deque::VecDeque"
    ) || path.starts_with("alloc::collections::b")
}

/// The field e names, past borrows and derefs.
fn field(cx: &LateContext<'_>, e: &Expr<'_>) -> Option<Field> {
    let ExprKind::Field(base, name) = peel(e).kind else {
        return None;
    };
    match cx.typeck_results().expr_ty_adjusted(base).peel_refs().kind() {
        ty::Adt(adt, _) => Some((adt.did(), name.name)),
        _ => None,
    }
}

impl<'tcx> LateLintPass<'tcx> for Bounds {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>) {
        match e.kind {
            // A comparison of a field's length holds it.
            ExprKind::Binary(op, l, r)
                if matches!(
                    op.node,
                    BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge | BinOpKind::Eq | BinOpKind::Ne
                ) =>
            {
                for side in [l, r] {
                    if let Some(f) = length_of(cx, side) {
                        self.held.insert(f);
                    }
                }
            },
            ExprKind::MethodCall(segment, receiver, ..) => {
                let name = segment.ident.as_str();
                let Some(f) = field(cx, receiver) else { return };
                if matches!(name, "clear" | "truncate") {
                    self.held.insert(f);
                    return;
                }
                if !GROW.contains(&name)
                    || built_here(cx, receiver)
                    || !super::builtins::is_user_code(e.span)
                    || !cx
                        .typeck_results()
                        .type_dependent_def_id(e.hir_id)
                        .is_some_and(|def| std_def(cx, def))
                    || !growable(cx, cx.typeck_results().expr_ty(peel(receiver)))
                {
                    return;
                }
                let what = cx
                    .sess()
                    .source_map()
                    .span_to_snippet(peel(receiver).span)
                    .unwrap_or_else(|_| "this collection".to_owned());
                self.grows.push((f, e.hir_id, e.span, what));
            },
            _ => {},
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (f, id, span, what) in &self.grows {
            if self.held.contains(f) || declared(cx, *f) || reason(cx, *id, *span, "bound") {
                continue;
            }
            span_lint_hir_and_then(
                cx,
                RR_UNBOUNDED,
                *id,
                *span,
                format!(
                    "`{what}` grows here, and nothing in the crate holds `{}` to a limit",
                    f.1
                ),
                |diag| {
                    diag.help(
                        "compare its len() with a limit where it grows, or clear() it where a cycle starts over; or say at the field what bounds it",
                    );
                    note(diag, cx.sess(), statement(cx, *id, *span), *span, "bound");
                },
            );
        }
    }
}

/// Whether the field's declaration has a reason that says what bounds it.
fn declared(cx: &LateContext<'_>, (adt, name): Field) -> bool {
    let Some(field) = cx.tcx.adt_def(adt).all_fields().find(|f| f.name == name) else {
        return false;
    };
    if !field.did.is_local() {
        return false;
    }
    let span = cx.tcx.def_span(field.did);
    has_escape_reason(cx, span, span, "bound")
}

/// Whether the field e names is of a value bound in this function and
/// owned by it, which it is building.
fn built_here(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    let mut e = peel(e);
    while let ExprKind::Field(base, _) = e.kind {
        e = base;
    }
    e.res_local_id().is_some() && !matches!(cx.typeck_results().expr_ty(e).kind(), ty::Ref(..) | ty::RawPtr(..))
}

/// The field whose `len()` e takes, as in `x.f.len() + n`.
fn length_of(cx: &LateContext<'_>, e: &Expr<'_>) -> Option<Field> {
    match peel(e).kind {
        ExprKind::MethodCall(s, r, [], _) if s.ident.as_str() == "len" => field(cx, r),
        ExprKind::Binary(_, l, r) => length_of(cx, l).or_else(|| length_of(cx, r)),
        _ => None,
    }
}

/// e without the borrows and derefs around it.
fn peel<'a>(mut e: &'a Expr<'a>) -> &'a Expr<'a> {
    loop {
        e = match e.kind {
            ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(rustc_hir::UnOp::Deref, inner) => inner,
            _ => return e,
        };
    }
}
