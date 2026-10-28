//! A function whose body repeats another's, token for token and on values
//! of the same types: one function, called from both places, says it once,
//! and a fix made to one copy reaches the other. Bodies are compared as
//! written, without comments and spacing, with the type of each
//! expression: `Self { memo: Memo::new() }` of two types, or
//! `self.workspace.abort()` on two workspaces, spells two things the same
//! way, and one function for both would need a trait to say it. A short
//! body, a few statements, is not looked at. A constant of the same name,
//! type and value defined twice is one fact in two places as well: one
//! changes and the other does not.

use clippy_utils::diagnostics::span_lint_hir_and_then;
use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_data_structures::fx::FxIndexMap;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::LocalDefId;
use rustc_hir::{ExprKind, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::mir::ConstValue;
use rustc_middle::ty::{self, Ty};
use rustc_session::impl_lint_pass;
use rustc_span::Symbol;

use super::RR_DUPLICATE;
use super::calls::name;
use super::comments::{has_escape_reason, note};

pub struct Duplicates;

impl_lint_pass!(Duplicates => [RR_DUPLICATE]);

/// The fewest statements of a body, counted in every block written in it,
/// that rr compares: a shorter one, such as a constructor or a getter,
/// says too little to be a copy.
const STATEMENTS_MIN: usize = 4;

impl<'tcx> LateLintPass<'tcx> for Duplicates {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let mut bodies: FxIndexMap<(String, Vec<Ty<'tcx>>), Vec<LocalDefId>> = FxIndexMap::default();
        for owner in cx.tcx.hir_body_owners() {
            if !matches!(cx.tcx.def_kind(owner), DefKind::Fn | DefKind::AssocFn) {
                continue;
            }
            let body = cx.tcx.hir_body_owned_by(owner);
            let span = body.value.span;
            if !super::builtins::is_user_code(span) {
                continue;
            }
            let Ok(text) = cx.sess().source_map().span_to_snippet(span) else {
                continue;
            };
            let typeck = cx.tcx.typeck(owner);
            let mut statements = 0;
            let mut types = Vec::new();
            for_each_expr(cx.tcx, body.value, |e| {
                // A block the compiler wrote, as a `for` loop's, is not counted.
                if let ExprKind::Block(block, _) = e.kind
                    && !block.span.from_expansion()
                {
                    statements += block.stmts.len() + usize::from(block.expr.is_some());
                }
                // A closure's type is its own, in whichever body it is.
                if let Some(ty) = typeck.expr_ty_opt(e)
                    && !ty
                        .walk()
                        .any(|arg| matches!(arg.as_type().map(Ty::kind), Some(ty::Closure(..))))
                {
                    // Each function's lifetimes are its own.
                    types.push(cx.tcx.erase_and_anonymize_regions(ty));
                }
                ControlFlow::<()>::Continue(())
            });
            if statements >= STATEMENTS_MIN {
                bodies.entry((normalize(&text), types)).or_default().push(owner);
            }
        }
        for owners in bodies.values() {
            let Some((&first, rest)) = owners.split_first() else {
                continue;
            };
            for &copy in rest {
                let span = cx.tcx.def_span(copy);
                if has_escape_reason(cx, span, span, "duplicate") {
                    continue;
                }
                span_lint_hir_and_then(
                    cx,
                    RR_DUPLICATE,
                    cx.tcx.local_def_id_to_hir_id(copy),
                    span,
                    format!(
                        "the body of {} repeats {}, token for token and type for type",
                        name(cx.tcx, copy),
                        name(cx.tcx, first)
                    ),
                    |diag| {
                        diag.span_note(cx.tcx.def_span(first), "the same body is here");
                        diag.help(
                            "keep one function and call it from both places; a closure parameter can take what differs",
                        );
                        note(diag, cx.sess(), span, span, "duplicate");
                    },
                );
            }
        }
        constants(cx);
    }
}

/// Each constant defined again with the same name, type and value.
fn constants(cx: &LateContext<'_>) {
    let tcx = cx.tcx;
    let mut seen: FxIndexMap<(Symbol, Ty<'_>, ConstValue), LocalDefId> = FxIndexMap::default();
    for id in tcx.hir_free_items() {
        let item = tcx.hir_item(id);
        let ItemKind::Const(ident, ..) = item.kind else {
            continue;
        };
        if !super::builtins::is_user_code(item.span) {
            continue;
        }
        let def = item.owner_id.def_id;
        // A number, a bool or a char: a value compared as it is.
        let Ok(value @ ConstValue::Scalar(_)) = tcx.const_eval_poly(def.to_def_id()) else {
            continue;
        };
        let ty = tcx.type_of(def).instantiate_identity().skip_norm_wip();
        let first = *seen.entry((ident.name, ty, value)).or_insert(def);
        if first == def || has_escape_reason(cx, item.span, item.span, "duplicate") {
            continue;
        }
        span_lint_hir_and_then(
            cx,
            RR_DUPLICATE,
            item.hir_id(),
            item.span,
            format!("`{}` is defined again, with the same value", ident.name),
            |diag| {
                diag.span_note(tcx.def_span(first), "it is defined here");
                diag.help("define it once and use it from both places: one fact in two places drifts apart");
                note(diag, cx.sess(), item.span, item.span, "duplicate");
            },
        );
    }
}

/// The text without comments, with each run of spacing one space.
fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut space = false;
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
                space = true;
            },
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut last = ' ';
                for next in chars.by_ref() {
                    if last == '*' && next == '/' {
                        break;
                    }
                    last = next;
                }
                space = true;
            },
            c if c.is_whitespace() => space = true,
            c => {
                if space && !out.is_empty() {
                    out.push(' ');
                }
                space = false;
                out.push(c);
            },
        }
    }
    out
}
