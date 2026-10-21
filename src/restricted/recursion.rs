//! Recursion, direct or through other functions: the depth of the stack
//! then depends on the input. Each call that closes a cycle of the
//! crate's call graph needs a reason, such as a bound on the depth; the
//! graph holds the calls that are not written as calls too (see calls).
//! So does a type that owns another value of itself: its drop glue
//! recurses as deep as the data goes.

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::LocalDefId;
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::ty;
use rustc_session::impl_lint_pass;
use rustc_span::{BytePos, Pos as _, Span};
use std::collections::hash_map::Entry;

use super::RR_NO_RECURSION;
use super::allocs::{reason, statement};
use super::calls::{Graph, name, owns};
use super::comments::{has_escape_reason, note};

pub struct Recursion;

impl_lint_pass!(Recursion => [RR_NO_RECURSION]);

impl<'tcx> LateLintPass<'tcx> for Recursion {
    fn check_crate(&mut self, cx: &LateContext<'tcx>) {
        let graph = Graph::new(cx);
        let component = components(&graph);
        let mut reported = FxHashSet::default();
        for &owner in &graph.fns {
            for call in graph.from(owner) {
                let cycle = call.to == owner
                    || component
                        .get(&owner)
                        .is_some_and(|c| component.get(&call.to) == Some(c));
                if !cycle
                    || !super::builtins::is_user_code(call.span)
                    || reason(cx, call.id, call.span, "recursion")
                    || !reported.insert((call.id, call.span))
                {
                    continue;
                }
                let from = name(cx.tcx, owner);
                let message = if call.to == owner {
                    format!("{from} {}", call.verb("itself"))
                } else {
                    format!(
                        "{from} {}, which leads back to {from}",
                        call.verb(&name(cx.tcx, call.to))
                    )
                };
                span_lint_hir_and_then(cx, RR_NO_RECURSION, call.id, call.span, message, |diag| {
                    diag.help("make it a loop with an explicit stack, or say in the reason what bounds the depth");
                    note(
                        diag,
                        cx.sess(),
                        statement(cx, call.id, call.span),
                        call.span,
                        "recursion",
                    );
                });
            }
        }
        recursive_types(cx);
    }
}

/// A type that owns a value of itself, through a Box, an Option, a Vec or
/// any other owner: dropping it drops the next one inside, as deep as the
/// data goes.
fn recursive_types(cx: &LateContext<'_>) {
    let tcx = cx.tcx;
    for def in tcx.hir_crate_items(()).definitions() {
        if !matches!(tcx.def_kind(def), DefKind::Struct | DefKind::Enum | DefKind::Union) {
            continue;
        }
        let adt = tcx.adt_def(def);
        let args = ty::GenericArgs::identity_for_item(tcx, def);
        let env = ty::TypingEnv::post_analysis(tcx, def);
        let mut again = false;
        for field in adt.all_fields() {
            owns(tcx, env, field.ty(tcx, args).skip_norm_wip(), &mut |t| {
                again |= matches!(t.kind(), ty::Adt(inner, _) if inner.did() == adt.did());
            });
        }
        let span = tcx.def_span(def);
        if !again || !super::builtins::is_user_code(span) {
            continue;
        }
        let item = with_attributes(cx, tcx.hir_span(tcx.local_def_id_to_hir_id(def)));
        if has_escape_reason(cx, item, span, "recursion") {
            continue;
        }
        let id = tcx.local_def_id_to_hir_id(def);
        let what = tcx.item_name(def.to_def_id());
        span_lint_hir_and_then(
            cx,
            RR_NO_RECURSION,
            id,
            span,
            format!("`{what}` owns another `{what}`, so dropping it recurses as deep as the data goes"),
            |diag| {
                diag.help("keep the values in one flat collection and link them by index, or give the type a Drop that takes the inner values out in a loop and say so in the reason");
                note(diag, cx.sess(), item, span, "recursion");
            },
        );
    }
}

/// span, from the attribute lines above it: a reason may stand above them.
fn with_attributes(cx: &LateContext<'_>, span: Span) -> Span {
    let source_map = cx.sess().source_map();
    let file = source_map.lookup_source_file(span.lo());
    let Some(source) = &file.src else { return span };
    let mut start = (span.lo() - file.start_pos).to_usize();
    start = source[..start].rfind('\n').map_or(0, |pos| pos + 1);
    while start > 0 {
        let above = source[..start - 1].rfind('\n').map_or(0, |pos| pos + 1);
        if !source[above..start].trim_start().starts_with("#[") {
            break;
        }
        start = above;
    }
    span.with_lo(file.start_pos + BytePos::from_usize(start))
}

/// The strongly connected component of each function that is in a cycle
/// of two or more, by Tarjan's algorithm, kept iterative.
fn components(graph: &Graph) -> FxHashMap<LocalDefId, usize> {
    let mut index: FxHashMap<LocalDefId, usize> = FxHashMap::default();
    let mut low: FxHashMap<LocalDefId, usize> = FxHashMap::default();
    let mut on_stack = FxHashSet::default();
    let mut stack = Vec::new();
    let mut out = FxHashMap::default();
    let mut next = 0;
    let mut found = 0;
    let edges = |v: LocalDefId| graph.from(v);
    for &root in &graph.fns {
        if index.contains_key(&root) {
            continue;
        }
        // Each frame: a function and how many of its calls are looked at.
        let mut work = vec![(root, 0usize)];
        index.insert(root, next);
        low.insert(root, next);
        next += 1;
        stack.push(root);
        on_stack.insert(root);
        while let Some(&mut (v, ref mut at)) = work.last_mut() {
            if let Some(call) = edges(v).get(*at) {
                *at += 1;
                let w = call.to;
                match index.entry(w) {
                    Entry::Vacant(slot) => {
                        slot.insert(next);
                        low.insert(w, next);
                        next += 1;
                        stack.push(w);
                        on_stack.insert(w);
                        work.push((w, 0));
                    },
                    Entry::Occupied(seen) => {
                        if on_stack.contains(&w) {
                            let lw = *seen.get();
                            if let Some(l) = low.get_mut(&v) {
                                *l = (*l).min(lw);
                            }
                        }
                    },
                }
                continue;
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                let lv = low[&v];
                if let Some(lp) = low.get_mut(&parent) {
                    *lp = (*lp).min(lv);
                }
            }
            if low[&v] == index[&v] {
                let mut members = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack.remove(&w);
                    members.push(w);
                    if w == v {
                        break;
                    }
                }
                if members.len() > 1 {
                    for m in members {
                        out.insert(m, found);
                    }
                    found += 1;
                }
            }
        }
    }
    out
}
