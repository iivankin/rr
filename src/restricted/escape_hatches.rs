use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::{BlockCheckMode, Expr, ExprKind, Node, UnsafeSource};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{self, Ty};
use rustc_session::impl_lint_pass;
use rustc_span::Span;
use rustc_span::def_id::DefId;

use super::comments::has_escape_reason;
use super::{RR_NO_STD, RR_UNEXPLAINED_ESCAPE};

pub struct EscapeHatches;
impl_lint_pass!(EscapeHatches => [RR_NO_STD, RR_UNEXPLAINED_ESCAPE]);

impl<'tcx> LateLintPass<'tcx> for EscapeHatches {
    fn check_path(&mut self, cx: &LateContext<'tcx>, path: &rustc_hir::Path<'tcx>, _: rustc_hir::HirId) {
        if path.span.from_expansion() {
            return;
        }
        let std_path = path
            .segments
            .first()
            .is_some_and(|segment| segment.ident.name.as_str() == "std")
            || path
                .res
                .opt_def_id()
                .is_some_and(|id| cx.tcx.crate_name(id.krate).as_str() == "std");
        if std_path {
            span_lint_and_help(
                cx,
                RR_NO_STD,
                path.span,
                "std paths are forbidden by rr",
                None,
                "use core or alloc instead",
            );
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() {
            return;
        }
        let Some(operation) = escape_operation(cx, expr) else {
            return;
        };
        if has_escape_reason(cx, statement_span(cx, expr), expr.span) {
            return;
        }
        span_lint_and_help(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            expr.span,
            format!("{operation} needs an ownership justification"),
            None,
            "add an adjacent `// rr: escape: <reason>` explaining the cost or risk and why ordinary borrowing/ownership is insufficient",
        );
    }
}

fn statement_span(cx: &LateContext<'_>, expr: &Expr<'_>) -> Span {
    for (_, node) in cx.tcx.hir_parent_iter(expr.hir_id) {
        match node {
            Node::Stmt(stmt) => return stmt.span,
            Node::LetStmt(local) => return local.span,
            Node::Block(_) | Node::Item(_) | Node::ImplItem(_) | Node::TraitItem(_) => break,
            _ => {},
        }
    }
    expr.span
}

fn escape_operation<'tcx>(cx: &LateContext<'tcx>, expr: &Expr<'tcx>) -> Option<&'static str> {
    if let ExprKind::Block(block, _) = expr.kind
        && matches!(block.rules, BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided))
    {
        return Some("an unsafe block");
    }
    let def_id = match expr.kind {
        ExprKind::MethodCall(_, _, _, _) => cx.typeck_results().type_dependent_def_id(expr.hir_id),
        ExprKind::Call(callee, _) if let ExprKind::Path(ref path) = callee.kind => {
            cx.typeck_results().qpath_res(path, callee.hir_id).opt_def_id()
        },
        _ => None,
    }?;
    let name = cx.tcx.item_name(def_id);
    let trait_id = cx.tcx.trait_of_assoc(def_id);
    if matches!(name.as_str(), "clone" | "clone_from")
        && trait_id.is_some()
        && trait_id == cx.tcx.lang_items().clone_trait()
    {
        return Some("Clone copying (which may allocate or increment a reference count)");
    }
    if !is_standard_definition(cx, def_id) {
        return None;
    }
    match name.as_str() {
        "to_owned" | "clone_into" => Some("conversion to owned data"),
        "to_vec" => Some("copying a slice into a Vec"),
        "borrow" | "borrow_mut" | "try_borrow" | "try_borrow_mut"
            if cx.tcx.def_path_str(def_id).contains("RefCell") =>
        {
            Some("runtime-checked borrowing through RefCell")
        },
        "cloned" => Some("cloning iterator elements"),
        "collect" if owned_collection(cx, cx.typeck_results().expr_ty(expr)) => {
            Some("materializing an owned collection")
        },
        "leak" if cx.tcx.def_path_str(def_id).contains("boxed") => {
            Some("Box::leak (extending a lifetime by leaking storage)")
        },
        "forget" => Some("mem::forget (skipping destruction)"),
        "transmute" | "transmute_copy" | "transmute_unchecked" => Some("transmute (bypassing type/lifetime checks)"),
        _ => match owner_kind(cx, cx.typeck_results().expr_ty(expr)) {
            Some("Rc" | "Arc") => Some("creating or acquiring shared ownership (Rc/Arc)"),
            Some("RefCell") => Some("creating interior mutability (RefCell)"),
            _ => None,
        },
    }
}

// Match resolved compiler definitions, not spelling. An unrelated user method
// named `clone`, `collect` or `forget` is not evidence of these operations.
fn is_standard_definition(cx: &LateContext<'_>, def_id: DefId) -> bool {
    matches!(cx.tcx.crate_name(def_id.krate).as_str(), "core" | "alloc" | "std")
}

fn owner_kind<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> Option<&'static str> {
    let ty::Adt(adt, _) = ty.kind() else { return None };
    match cx.tcx.def_path_str(adt.did()).as_str() {
        "alloc::rc::Rc" => Some("Rc"),
        "alloc::sync::Arc" => Some("Arc"),
        "core::cell::RefCell" => Some("RefCell"),
        _ => None,
    }
}

fn owned_collection<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> bool {
    let ty::Adt(adt, _) = ty.kind() else { return false };
    matches!(
        cx.tcx.def_path_str(adt.did()).as_str(),
        "alloc::string::String"
            | "alloc::vec::Vec"
            | "alloc::collections::btree::map::BTreeMap"
            | "alloc::collections::btree::set::BTreeSet"
            | "alloc::collections::vec_deque::VecDeque"
            | "alloc::collections::linked_list::LinkedList"
            | "alloc::collections::binary_heap::BinaryHeap"
            | "std::collections::hash::map::HashMap"
            | "std::collections::hash::set::HashSet"
    )
}
