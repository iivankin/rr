//! A call that blocks, on a path that runs on an event loop: one slow
//! lookup stalls every connection the loop serves. `#[rr::poll]` marks a
//! function a poll loop runs for an event; rr follows the call graph from
//! there, as it does from `#[rr::hot]`, and reports a call to a C function
//! that always blocks, which rr knows by name, and a call to a function of
//! the crate marked `#[rr::blocking]`, such as a lookup that waits for its
//! answer. Whether a read, a write, an accept or a connect blocks depends
//! on how its descriptor was opened, which rr cannot see: those are not
//! looked at. A `// rr: escape(block): <reason>` at the call answers it.

use clippy_utils::diagnostics::span_lint_hir_and_then;
use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_session::impl_lint_pass;
use rustc_span::Symbol;

use super::RR_BLOCKING;
use super::allocs::{reason, statement};
use super::calls::{Call, Graph, name};
use super::comments::note;

pub struct Blocking;

impl_lint_pass!(Blocking => [RR_BLOCKING]);

/// The C library's and the systems' functions that block whatever their
/// arguments: they sleep, wait for another thread or process, or ask the
/// network and wait for its answer.
const BLOCKING: &[&str] = &[
    "sleep",
    "usleep",
    "nanosleep",
    "clock_nanosleep",
    "pause",
    "sigsuspend",
    "sigwait",
    "sigwaitinfo",
    "getaddrinfo",
    "getnameinfo",
    "gethostbyname",
    "gethostbyname2",
    "gethostbyname_r",
    "gethostbyaddr",
    "res_query",
    "res_search",
    "res_nquery",
    "res_nsearch",
    "pthread_join",
    "pthread_cond_wait",
    "sem_wait",
    "wait",
    "system",
    "popen",
    "pclose",
    // Windows.
    "Sleep",
    "SleepEx",
    "GetAddrInfoW",
    "GetAddrInfoA",
    "GetNameInfoW",
    // A chain built or checked by the system, which may fetch what it
    // lacks from the network: macOS's and Windows'.
    "SecTrustEvaluateWithError",
    "SecTrustEvaluate",
    "CertGetCertificateChain",
];

impl<'tcx> LateLintPass<'tcx> for Blocking {
    fn check_crate(&mut self, cx: &LateContext<'tcx>) {
        let tcx = cx.tcx;
        let poll = [Symbol::intern("rr"), Symbol::intern("poll")];
        let roots: Vec<LocalDefId> = tcx
            .hir_body_owners()
            .filter(|&owner| marked(cx, owner.to_def_id(), &poll))
            .collect();
        if roots.is_empty() {
            return;
        }
        let graph = Graph::new(cx);
        let mut reported = FxHashSet::default();
        for root in roots {
            walk(cx, &graph, root, &mut reported);
        }
    }
}

/// Whether def has the attribute at path.
fn marked(cx: &LateContext<'_>, def: DefId, path: &[Symbol]) -> bool {
    def.as_local().is_some_and(|local| {
        cx.tcx
            .hir_attrs(cx.tcx.local_def_id_to_hir_id(local))
            .iter()
            .any(|attr| attr.path_matches(path))
    })
}

/// Every blocking call on the path from root, which a poll loop runs.
fn walk(cx: &LateContext<'_>, graph: &Graph, root: LocalDefId, reported: &mut FxHashSet<rustc_hir::HirId>) {
    let tcx = cx.tcx;
    let blocking = [Symbol::intern("rr"), Symbol::intern("blocking")];
    let mut via: FxHashMap<LocalDefId, (LocalDefId, &Call)> = FxHashMap::default();
    let mut seen = FxHashSet::default();
    let mut todo = vec![root];
    while let Some(owner) = todo.pop() {
        if !seen.insert(owner) {
            continue;
        }
        for call in graph.from(owner) {
            // A blocking function is reported where it is called, and
            // what it calls is its own business.
            if !marked(cx, call.to.to_def_id(), &blocking) {
                via.entry(call.to).or_insert((owner, call));
                todo.push(call.to);
            }
        }
        let Some(body) = tcx.hir_maybe_body_owned_by(owner) else {
            continue;
        };
        let typeck = tcx.typeck(owner);
        for_each_expr(tcx, body.value, |e: &Expr<'_>| {
            let callee = match e.kind {
                ExprKind::Call(f, _) => match f.kind {
                    ExprKind::Path(ref path) => match typeck.qpath_res(path, f.hir_id) {
                        Res::Def(DefKind::Fn | DefKind::AssocFn, def) => Some(def),
                        _ => None,
                    },
                    _ => None,
                },
                ExprKind::MethodCall(..) => typeck.type_dependent_def_id(e.hir_id),
                _ => None,
            };
            let Some(def) = callee else {
                return ControlFlow::<()>::Continue(());
            };
            let what = if tcx.is_foreign_item(def) && BLOCKING.contains(&tcx.item_name(def).as_str()) {
                format!("`{}` blocks whatever it is given", tcx.item_name(def))
            } else if let Some(local) = def.as_local()
                && marked(cx, def, &blocking)
            {
                format!("{} is marked `#[rr::blocking]`", name(tcx, local))
            } else {
                return ControlFlow::Continue(());
            };
            if !super::builtins::is_user_code(e.span)
                || reason(cx, e.hir_id, e.span, "block")
                || !reported.insert(e.hir_id)
            {
                return ControlFlow::Continue(());
            }
            let mut chain = Vec::new();
            let mut at = owner;
            while at != root
                && let Some(&(caller, call)) = via.get(&at)
                && chain.len() < 16
            {
                chain.push(call);
                at = caller;
            }
            span_lint_hir_and_then(
                cx,
                RR_BLOCKING,
                e.hir_id,
                e.span,
                format!("{what}, on a path an event loop runs"),
                |diag| {
                    diag.note(format!("reached from `#[rr::poll]` {}", name(tcx, root)));
                    for call in chain.iter().rev() {
                        diag.span_note(call.span, call.through(&name(tcx, call.to)));
                    }
                    diag.help(
                        "start it and take its answer when the loop is told it is ready, or run it on a thread \
                         and wake the loop when it is done; while it blocks, every other event waits",
                    );
                    note(diag, cx.sess(), statement(cx, e.hir_id, e.span), e.span, "block");
                },
            );
            ControlFlow::Continue(())
        });
    }
}
