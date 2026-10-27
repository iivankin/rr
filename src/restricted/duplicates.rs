//! A function whose body repeats another's, token for token: one function,
//! called from both places, says it once, and a fix made to one copy
//! reaches the other. Bodies are compared as written, without comments
//! and spacing; a short body, a few tokens, is not looked at.

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_data_structures::fx::FxIndexMap;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::LocalDefId;
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_session::impl_lint_pass;

use super::RR_DUPLICATE;
use super::calls::name;
use super::comments::{has_escape_reason, note};

pub struct Duplicates;

impl_lint_pass!(Duplicates => [RR_DUPLICATE]);

/// The fewest characters of a body, as normalized, that rr compares: a
/// shorter one, such as a getter, says too little to be a copy.
const BODY_MIN: usize = 60;

impl<'tcx> LateLintPass<'tcx> for Duplicates {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let mut bodies: FxIndexMap<String, Vec<LocalDefId>> = FxIndexMap::default();
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
            let tokens = normalize(&text);
            if tokens.len() >= BODY_MIN {
                bodies.entry(tokens).or_default().push(owner);
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
                        "the body of {} repeats {}, token for token",
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
