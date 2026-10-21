use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_then};
use rustc_hir::{BlockCheckMode, Expr, ExprKind, Item, ItemKind, LetStmt, Mutability, Node, UnsafeSource};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::ty::{self, Ty};
use rustc_session::impl_lint_pass;
use rustc_span::Span;
use rustc_span::def_id::DefId;

use super::comments::{has_escape_reason, note};
use super::{RR_NO_STD, RR_UNEXPLAINED_ESCAPE, copies};

pub struct EscapeHatches;
impl_lint_pass!(EscapeHatches => [RR_NO_STD, RR_UNEXPLAINED_ESCAPE]);

impl<'tcx> LateLintPass<'tcx> for EscapeHatches {
    fn check_path(&mut self, cx: &LateContext<'tcx>, path: &rustc_hir::Path<'tcx>, _: rustc_hir::HirId) {
        if !super::builtins::is_user_code(path.span) {
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
        if !super::builtins::is_user_code(expr.span) {
            return;
        }
        let Some((kind, operation)) = escape_operation(cx, expr) else {
            return;
        };
        let statement = statement_span(cx, expr.hir_id, expr.span);
        if has_escape_reason(cx, statement, expr.span, kind) {
            return;
        }
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            expr.span,
            format!("{operation} needs an ownership justification"),
            |diag| {
                diag.help(match kind {
                    "copy" => "borrow it where it is, or move it if its owner is done with it; a copy is for two owners that must both live on",
                    "shared" => "own it in one place and lend it with & or &mut",
                    "leak" => "let it drop; leak only what must live as long as the process",
                    _ => "say in the reason what makes it sound",
                });
                note(diag, cx.sess(), statement, expr.span, kind);
            },
        );
    }

    fn check_local(&mut self, cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) {
        if !super::builtins::is_user_code(local.span) {
            return;
        }
        for (copy, operation) in copies::filled_once(cx, local) {
            let let_statement = statement_span(cx, local.pat.hir_id, local.span);
            let copy_statement = statement_span(cx, copy.hir_id, copy.span);
            if has_escape_reason(cx, let_statement, local.span, "copy")
                || has_escape_reason(cx, copy_statement, copy.span, "copy")
            {
                continue;
            }
            span_lint_and_then(
                cx,
                RR_UNEXPLAINED_ESCAPE,
                copy.span,
                format!("{operation} needs an ownership justification"),
                |diag| {
                    diag.span_note(local.span, "the buffer is made here; borrow or move the data instead");
                    note(diag, cx.sess(), let_statement, local.span, "copy");
                },
            );
        }
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if !super::builtins::is_user_code(item.span) {
            return;
        }
        if let ItemKind::Impl(implementation) = &item.kind {
            large_copy(cx, item, implementation);
            return;
        }
        let ItemKind::Static(mutability, ..) = item.kind else {
            return;
        };
        let ty = cx.tcx.type_of(item.owner_id).instantiate_identity().skip_norm_wip();
        let operation = if mutability == Mutability::Mut {
            "static mut (global mutable state)"
        } else if !ty.is_freeze(cx.tcx, cx.typing_env()) {
            "a static with interior mutability, such as an atomic (global mutable state)"
        } else {
            return;
        };
        if has_escape_reason(cx, item.span, item.span, "shared") {
            return;
        }
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            item.span,
            format!("{operation} needs an ownership justification"),
            |diag| {
                diag.help("pass the state by reference instead, unless something outside the call tree must reach it, such as a signal handler");
                note(diag, cx.sess(), item.span, item.span, "shared");
            },
        );
    }
}

fn statement_span(cx: &LateContext<'_>, id: rustc_hir::HirId, span: Span) -> Span {
    for (_, node) in cx.tcx.hir_parent_iter(id) {
        match node {
            Node::Stmt(stmt) => return stmt.span,
            Node::LetStmt(local) => return local.span,
            Node::Block(_) | Node::Item(_) | Node::ImplItem(_) | Node::TraitItem(_) => break,
            _ => {},
        }
    }
    span
}

/// Larger than this, a Copy type is copied whole, silently, at every use.
const COPY_MAX: u64 = 64;

/// `impl Copy` for a type larger than `COPY_MAX` bytes: each move of it
/// becomes a copy that no `clone()` shows.
fn large_copy<'tcx>(cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>, implementation: &'tcx rustc_hir::Impl<'tcx>) {
    let Some(header) = implementation.of_trait else { return };
    if header.trait_ref.trait_def_id() != cx.tcx.lang_items().copy_trait() {
        return;
    }
    let ty = cx.tcx.type_of(item.owner_id).instantiate_identity().skip_norm_wip();
    let Ok(layout) = cx.tcx.layout_of(cx.typing_env().as_query_input(ty)) else {
        return;
    };
    let size = layout.size.bytes();
    if size <= COPY_MAX || has_escape_reason(cx, item.span, item.span, "copy") {
        return;
    }
    span_lint_and_then(
        cx,
        RR_UNEXPLAINED_ESCAPE,
        item.span,
        format!("Copy on a type of {size} bytes copies it whole at every use; this needs an ownership justification"),
        |diag| {
            diag.help(format!("keep it a moved value, or Copy only up to {COPY_MAX} bytes"));
            note(diag, cx.sess(), item.span, item.span, "copy");
        },
    );
}

fn escape_operation<'tcx>(cx: &LateContext<'tcx>, expr: &Expr<'tcx>) -> Option<(&'static str, &'static str)> {
    if let ExprKind::Block(block, _) = expr.kind
        && matches!(block.rules, BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided))
    {
        return Some(("unsafe", "an unsafe block"));
    }
    let def_id = match expr.kind {
        ExprKind::MethodCall(_, _, _, _) => cx.typeck_results().type_dependent_def_id(expr.hir_id),
        ExprKind::Call(callee, _) if let ExprKind::Path(ref path) = callee.kind => {
            cx.typeck_results().qpath_res(path, callee.hir_id).opt_def_id()
        },
        _ => None,
    }?;
    if copies::copy_helper(cx, def_id) {
        return Some(("copy", "a call to a function that only returns a copy of its argument"));
    }
    let name = cx.tcx.item_name(def_id);
    let trait_id = cx.tcx.trait_of_assoc(def_id);
    if matches!(name.as_str(), "clone" | "clone_from")
        && trait_id.is_some()
        && trait_id == cx.tcx.lang_items().clone_trait()
    {
        return Some((
            "copy",
            "Clone copying (which may allocate or increment a reference count)",
        ));
    }
    if !is_standard_definition(cx, def_id) {
        return None;
    }
    if let Some(operation) = copies::conversion(cx, expr, def_id) {
        return Some(("copy", operation));
    }
    match name.as_str() {
        "to_owned" | "clone_into" => Some(("copy", "conversion to owned data")),
        "to_vec" => Some(("copy", "copying a slice into a Vec")),
        "borrow" | "borrow_mut" | "try_borrow" | "try_borrow_mut"
            if cx.tcx.def_path_str(def_id).contains("RefCell") =>
        {
            Some(("shared", "runtime-checked borrowing through RefCell"))
        },
        "cloned" => Some(("copy", "cloning iterator elements")),
        "collect" if owned_collection(cx, cx.typeck_results().expr_ty(expr)) => {
            Some(("copy", "materializing an owned collection"))
        },
        "leak" => Some(("leak", "leak (extending a lifetime by leaking storage)")),
        "into_raw" | "into_raw_parts" | "into_non_null" => Some((
            "leak",
            "into_raw (ownership handed to a raw pointer, which nothing frees)",
        )),
        "forget" => Some(("leak", "mem::forget (skipping destruction)")),
        "transmute" | "transmute_copy" | "transmute_unchecked" => {
            Some(("unsafe", "transmute (bypassing type/lifetime checks)"))
        },
        _ => match owner_kind(cx, cx.typeck_results().expr_ty(expr)) {
            Some("Rc" | "Arc") => Some(("shared", "creating or acquiring shared ownership (Rc/Arc)")),
            Some("RefCell") => Some(("shared", "creating interior mutability (RefCell)")),
            Some("Cell") => Some(("shared", "creating interior mutability (Cell, UnsafeCell or OnceCell)")),
            Some("Atomic") => Some(("shared", "creating interior mutability (an atomic)")),
            Some("ManuallyDrop") => Some(("leak", "ManuallyDrop (skipping destruction)")),
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
        "core::cell::Cell" | "core::cell::UnsafeCell" | "core::cell::OnceCell" | "core::cell::LazyCell" => Some("Cell"),
        "core::mem::ManuallyDrop" => Some("ManuallyDrop"),
        path if path.starts_with("core::sync::atomic::Atomic") => Some("Atomic"),
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
