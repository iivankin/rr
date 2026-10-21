//! An `if` chain that compares one value with constants is a `match`: the
//! value is read once, each case is a pattern, and the compiler checks
//! that the cases do not overlap.

use clippy_utils::SpanlessEq;
use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::{BinOpKind, Expr, ExprKind, Node};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_session::impl_lint_pass;
use rustc_span::SyntaxContext;

use super::RR_MATCH_CHAIN;

pub struct Chains;

impl_lint_pass!(Chains => [RR_MATCH_CHAIN]);

impl<'tcx> LateLintPass<'tcx> for Chains {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>) {
        if !super::builtins::is_user_code(e.span) || continues(cx, e) {
            return;
        }
        // The value each condition of the chain compares, in turn.
        let mut subject: Option<&Expr<'_>> = None;
        let mut cases = 0;
        let mut at = e;
        while let ExprKind::If(cond, _, other) = at.kind {
            let Some(value) = compared(cx, cond) else {
                return;
            };
            if let Some(s) = subject
                && !SpanlessEq::new(cx).eq_expr(SyntaxContext::root(), s, value)
            {
                return;
            }
            subject = Some(value);
            cases += 1;
            match other {
                Some(next) if matches!(next.kind, ExprKind::If(..)) => at = next,
                Some(block) => match only_if(block) {
                    Some(next) => at = next,
                    None => break,
                },
                None => break,
            }
        }
        let Some(subject) = subject else { return };
        if cases < 2 {
            return;
        }
        let what = cx
            .sess()
            .source_map()
            .span_to_snippet(subject.span)
            .unwrap_or_else(|_| "the value".to_owned());
        span_lint_and_help(
            cx,
            RR_MATCH_CHAIN,
            e.span,
            format!("this chain compares `{what}` with one value after another"),
            None,
            format!("make it a match on `{what}`, a pattern for each value"),
        );
    }
}

/// Whether e is the `else` of an `if` that is part of the same chain.
fn continues(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    let mut child = e.hir_id;
    for (id, node) in cx.tcx.hir_parent_iter(e.hir_id) {
        match node {
            Node::Expr(Expr {
                kind: ExprKind::If(_, _, Some(other)),
                ..
            }) if other.hir_id == child => return true,
            // An `else` block holding only this `if`.
            Node::Block(block) if block.stmts.is_empty() && block.expr.is_some_and(|x| x.hir_id == child) => {
                child = id;
            },
            Node::Expr(Expr {
                kind: ExprKind::Block(..),
                ..
            }) => child = id,
            _ => return false,
        }
    }
    false
}

/// The `if` an `else` block holds and nothing else.
fn only_if<'a>(e: &'a Expr<'a>) -> Option<&'a Expr<'a>> {
    let ExprKind::Block(block, _) = e.kind else {
        return None;
    };
    match (block.stmts, block.expr) {
        ([], Some(inner)) if matches!(inner.kind, ExprKind::If(..)) => Some(inner),
        _ => None,
    }
}

/// What cond compares for equality with a constant: `x == A`, `A == x`.
fn compared<'a>(cx: &LateContext<'_>, cond: &'a Expr<'a>) -> Option<&'a Expr<'a>> {
    let cond = match cond.kind {
        ExprKind::DropTemps(inner) => inner,
        _ => cond,
    };
    let ExprKind::Binary(op, l, r) = cond.kind else {
        return None;
    };
    if op.node != BinOpKind::Eq {
        return None;
    }
    match (constant(cx, l), constant(cx, r)) {
        (false, true) => Some(l),
        (true, false) => Some(r),
        _ => None,
    }
}

/// A literal, a constant or a unit variant, possibly borrowed or
/// dereferenced: what a pattern can name.
fn constant(cx: &LateContext<'_>, mut e: &Expr<'_>) -> bool {
    loop {
        e = match e.kind {
            ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(rustc_hir::UnOp::Deref, inner) => inner,
            ExprKind::Lit(_) => return true,
            ExprKind::Path(ref path) => {
                return matches!(
                    cx.qpath_res(path, e.hir_id),
                    Res::Def(
                        DefKind::Const { .. }
                            | DefKind::AssocConst { .. }
                            | DefKind::Ctor(_, rustc_hir::def::CtorKind::Const),
                        _
                    )
                );
            },
            _ => return false,
        };
    }
}
