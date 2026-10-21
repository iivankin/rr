//! Allocations and copies a design can avoid: a buffer made again on every
//! turn of a loop, a caller's buffer copied by a callee when it could have
//! been moved, and any new buffer or copy on a path marked `#[rr::hot]`,
//! where a loop must show its bound too.

use clippy_utils::diagnostics::{span_lint_and_then, span_lint_hir_and_then};
use clippy_utils::get_parent_expr;
use clippy_utils::res::MaybeResPath as _;
use clippy_utils::usage::local_used_after_expr;
use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::LocalDefId;
use rustc_hir::{BorrowKind, Expr, ExprKind, HirId, LetStmt, LoopSource, Mutability, Node, PatKind, StmtKind, UnOp};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::ty::{self, TypeckResults};
use rustc_session::impl_lint_pass;
use rustc_span::def_id::DefId;
use rustc_span::{Span, Symbol};

use super::calls::{Call, Graph, name};
use super::comments::{has_escape_reason, note};
use super::copies::{copy, fresh, of_param, owned_container, params, std_def, takes_mut_self};
use super::{RR_HOT_PATH, RR_UNEXPLAINED_ESCAPE};

#[derive(Default)]
pub struct Allocs {
    /// Births already reported, so that two hot paths through one function
    /// report it once.
    reported: FxHashSet<HirId>,
}

impl_lint_pass!(Allocs => [RR_UNEXPLAINED_ESCAPE, RR_HOT_PATH]);

impl<'tcx> LateLintPass<'tcx> for Allocs {
    fn check_local(&mut self, cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) {
        if !super::builtins::is_user_code(local.span) {
            return;
        }
        let Some(write) = loop_buffer(cx, local) else { return };
        if reason(cx, local.hir_id, local.span, "alloc") || reason(cx, write.hir_id, write.span, "alloc") {
            return;
        }
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            local.span,
            "a buffer made again on every turn of the loop needs an ownership justification",
            |diag| {
                diag.help("make it once before the loop and clear() it at the top of each turn");
                note(
                    diag,
                    cx.sess(),
                    statement(cx, local.hir_id, local.span),
                    local.span,
                    "alloc",
                );
            },
        );
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if !super::builtins::is_user_code(expr.span) {
            return;
        }
        let Some((arg, name)) = copied_argument(cx, expr) else {
            return;
        };
        if reason(cx, expr.hir_id, expr.span, "copy") {
            return;
        }
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            arg.span,
            format!(
                "`{name}` copies this buffer, which is not used after the call; this needs an ownership justification"
            ),
            |diag| {
                diag.help("take the parameter by value and move the buffer in");
                note(
                    diag,
                    cx.sess(),
                    statement(cx, expr.hir_id, expr.span),
                    expr.span,
                    "copy",
                );
            },
        );
    }

    fn check_crate(&mut self, cx: &LateContext<'tcx>) {
        let hot = Symbol::intern("hot");
        let rr = Symbol::intern("rr");
        let mut graph = None;
        for owner in cx.tcx.hir_body_owners() {
            let id = cx.tcx.local_def_id_to_hir_id(owner);
            if cx.tcx.hir_attrs(id).iter().any(|attr| attr.path_matches(&[rr, hot])) {
                let graph = graph.get_or_insert_with(|| Graph::new(cx));
                self.hot(cx, graph, owner);
            }
        }
    }
}

/// The statement that holds the expression at id.
pub(super) fn statement(cx: &LateContext<'_>, id: HirId, span: Span) -> Span {
    cx.tcx
        .hir_parent_iter(id)
        .find_map(|(_, node)| match node {
            Node::Stmt(stmt) => Some(stmt.span),
            Node::LetStmt(local) => Some(local.span),
            _ => None,
        })
        .unwrap_or(span)
}

/// Whether there is an adjacent reason naming kind, without using it.
fn peek(cx: &LateContext<'_>, id: HirId, span: Span, kind: &'static str) -> bool {
    super::comments::peek(cx.sess(), statement(cx, id, span), span, kind)
}

/// An adjacent reason naming kind for the statement or expression at id.
pub(super) fn reason(cx: &LateContext<'_>, id: HirId, span: Span, kind: &'static str) -> bool {
    has_escape_reason(cx, statement(cx, id, span), span, kind)
}

/// A fresh buffer bound inside a loop, written there and never moved out
/// of the turn: the write, to point at.
fn loop_buffer<'tcx>(cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) -> Option<&'tcx Expr<'tcx>> {
    let PatKind::Binding(_, id, _, None) = local.pat.kind else {
        return None;
    };
    if !fresh(cx, local.init?) {
        return None;
    }
    let mut in_loop = false;
    for (_, node) in cx.tcx.hir_parent_iter(local.hir_id) {
        match node {
            Node::Expr(Expr {
                kind: ExprKind::Loop(..),
                ..
            }) => {
                in_loop = true;
                break;
            },
            Node::Expr(Expr {
                kind: ExprKind::Closure(..),
                ..
            })
            | Node::Item(_)
            | Node::ImplItem(_) => break,
            _ => {},
        }
    }
    if !in_loop {
        return None;
    }
    let Node::Stmt(stmt) = cx.tcx.parent_hir_node(local.hir_id) else {
        return None;
    };
    let Node::Block(block) = cx.tcx.parent_hir_node(stmt.hir_id) else {
        return None;
    };
    let mut write = None;
    let mut moved = false;
    let mut visit = |e: &'tcx Expr<'tcx>| {
        if e.span.lo() < local.span.hi() || e.res_local_id() != Some(id) {
            return ControlFlow::<()>::Continue(());
        }
        match get_parent_expr(cx, e).map(|p| (p, &p.kind)) {
            Some((p, ExprKind::MethodCall(_, receiver, ..))) if receiver.hir_id == e.hir_id => {
                match cx.typeck_results().type_dependent_def_id(p.hir_id) {
                    Some(m) if takes_mut_self(cx, m) => write = write.or(Some(p)),
                    Some(m) if takes_self_by_value(cx, m) => moved = true,
                    _ => {},
                }
            },
            Some((p, ExprKind::AddrOf(BorrowKind::Ref, Mutability::Mut, _))) => write = write.or(Some(p)),
            Some((
                _,
                ExprKind::AddrOf(..) | ExprKind::Index(..) | ExprKind::Field(..) | ExprKind::Unary(UnOp::Deref, _),
            )) => {},
            _ => moved = true,
        }
        ControlFlow::Continue(())
    };
    for stmt in block.stmts {
        for_each_expr(cx.tcx, stmt, &mut visit);
    }
    if let Some(tail) = block.expr {
        for_each_expr(cx.tcx, tail, &mut visit);
    }
    if moved { None } else { write }
}

fn takes_self_by_value(cx: &LateContext<'_>, def_id: DefId) -> bool {
    let sig = cx.tcx.fn_sig(def_id).instantiate_identity().skip_binder();
    sig.inputs().first().is_some_and(|ty| !matches!(ty.kind(), ty::Ref(..)))
}

/// A call that lends a local owned buffer to a local function which copies
/// that parameter, when the caller does not use the buffer afterwards: the
/// argument and the function's name.
fn copied_argument<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) -> Option<(&'tcx Expr<'tcx>, String)> {
    let (def_id, args, skip) = match expr.kind {
        ExprKind::Call(f, args) if let ExprKind::Path(ref path) = f.kind => {
            (cx.typeck_results().qpath_res(path, f.hir_id).opt_def_id()?, args, 0)
        },
        ExprKind::MethodCall(_, _, args, _) => (cx.typeck_results().type_dependent_def_id(expr.hir_id)?, args, 1),
        _ => return None,
    };
    let local = def_id.as_local()?;
    if !matches!(cx.tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
        return None;
    }
    let body = cx.tcx.hir_maybe_body_owned_by(local)?;
    let ids = params(body);
    for (i, arg) in args.iter().enumerate() {
        let Some(buffer) = lent_buffer(cx, arg) else { continue };
        if local_used_after_expr(cx, buffer, expr) {
            continue;
        }
        let Some(param) = body.params.get(i + skip) else {
            continue;
        };
        let mut bound = Vec::new();
        param.pat.each_binding(|_, id, _, _| bound.push(id));
        if bound.iter().all(|id| ids.contains(id)) && copies_param_anywhere(cx, local, &bound) {
            return Some((arg, cx.tcx.item_name(def_id).to_string()));
        }
    }
    None
}

/// The local whose owned String or Vec the argument lends whole: `&v`,
/// `&v[..]`, `v.as_slice()`, `v.as_bytes()`, `&*v`.
fn lent_buffer(cx: &LateContext<'_>, arg: &Expr<'_>) -> Option<HirId> {
    let mut e = arg;
    let mut lent = false;
    loop {
        e = match e.kind {
            ExprKind::AddrOf(BorrowKind::Ref, _, inner) | ExprKind::Unary(UnOp::Deref, inner) => {
                lent = true;
                inner
            },
            ExprKind::Index(inner, range, _) if is_full_range(cx, range) => {
                lent = true;
                inner
            },
            ExprKind::MethodCall(segment, receiver, [], _)
                if matches!(segment.ident.as_str(), "as_slice" | "as_bytes" | "as_str" | "as_ref") =>
            {
                lent = true;
                receiver
            },
            _ => break,
        };
    }
    let id = e.res_local_id()?;
    (lent && owned_container(cx, cx.typeck_results().expr_ty(e))).then_some(id)
}

fn is_full_range(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    matches!(cx.typeck_results().expr_ty(e).kind(), ty::Adt(adt, _) if cx.tcx.def_path_str(adt.did()) == "core::ops::RangeFull")
}

/// Whether the body of local makes a new owned value out of one of the
/// parameter bindings: a named copy of the whole of it, or a fresh buffer
/// (or a field of a fresh struct) whose only write copies it. Appending
/// it to a buffer that lives on, such as an output or a queue, is not
/// such a copy: no move could replace it.
fn copies_param_anywhere(cx: &LateContext<'_>, local: LocalDefId, bound: &[HirId]) -> bool {
    let Some(body) = cx.tcx.hir_maybe_body_owned_by(local) else {
        return false;
    };
    let typeck = cx.tcx.typeck(local);
    let mut fresh_locals = FxHashSet::default();
    let mut writes: FxHashMap<(HirId, Option<Symbol>), (u32, bool)> = FxHashMap::default();
    let named = for_each_expr(cx.tcx, body.value, |e| {
        if let ExprKind::Let(..) = e.kind {
            return ControlFlow::Continue(());
        }
        if whole_copy(cx, typeck, e).is_some_and(|source| of_param(source, bound)) {
            return ControlFlow::Break(());
        }
        if let ExprKind::MethodCall(segment, receiver, args, _) = e.kind
            && let Some(key) = place(receiver)
            && typeck
                .type_dependent_def_id(e.hir_id)
                .is_some_and(|m| takes_mut_self(cx, m))
        {
            let copy = matches!(segment.ident.as_str(), "extend_from_slice" | "extend" | "push_str")
                && args.first().is_some_and(|arg| of_param(arg, bound));
            let w = writes.entry(key).or_default();
            w.0 += 1;
            w.1 |= copy;
        }
        ControlFlow::Continue(())
    })
    .is_some();
    if named {
        return true;
    }
    // The lets that bind a fresh buffer or a struct built here.
    for_each_expr(cx.tcx, body.value, |e| {
        if let ExprKind::Block(block, _) = e.kind {
            for stmt in block.stmts {
                if let StmtKind::Let(l) = stmt.kind
                    && let PatKind::Binding(_, id, _, None) = l.pat.kind
                    && l.init.is_some_and(|init| {
                        matches!(init.kind, ExprKind::Struct(..))
                            || (matches!(init.kind, ExprKind::Call(..)) && owned_container(cx, typeck.expr_ty(init)))
                    })
                {
                    fresh_locals.insert(id);
                }
            }
        }
        ControlFlow::<()>::Continue(())
    });
    // Whether any place qualifies: the order of the visit does not matter.
    #[allow(rustc::potential_query_instability)]
    let found = writes
        .iter()
        .any(|((id, _), (count, copy))| *count == 1 && *copy && fresh_locals.contains(id));
    found
}

/// The local, or the field of a local, a method call writes to.
fn place(receiver: &Expr<'_>) -> Option<(HirId, Option<Symbol>)> {
    match receiver.kind {
        ExprKind::Field(base, field) => base.res_local_id().map(|id| (id, Some(field.name))),
        _ => receiver.res_local_id().map(|id| (id, None)),
    }
}

/// The source of a named copy of a whole value at e: `to_vec`, `to_owned`,
/// `clone`, `into`, `into_owned`, `collect`, or `From`.
fn whole_copy<'tcx>(
    cx: &LateContext<'tcx>,
    typeck: &TypeckResults<'tcx>,
    e: &'tcx Expr<'tcx>,
) -> Option<&'tcx Expr<'tcx>> {
    match e.kind {
        ExprKind::MethodCall(segment, receiver, [], _) => {
            let def = typeck.type_dependent_def_id(e.hir_id)?;
            (std_def(cx, def)
                && matches!(
                    segment.ident.as_str(),
                    "to_vec" | "to_owned" | "to_string" | "clone" | "into" | "into_owned" | "collect"
                ))
            .then_some(receiver)
        },
        ExprKind::Call(f, [arg]) if let ExprKind::Path(ref path) = f.kind => {
            let def = typeck.qpath_res(path, f.hir_id).opt_def_id()?;
            (std_def(cx, def) && cx.tcx.item_name(def).as_str() == "from").then_some(arg)
        },
        _ => None,
    }
}

/// What at e makes a new buffer, by name, for a hot path. A fresh buffer
/// counts only once something writes to it: `Vec::new()` alone is free.
fn birth<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &'tcx Expr<'tcx>) -> Option<&'static str> {
    let owned = || owned_container(cx, typeck.expr_ty(e));
    match e.kind {
        ExprKind::Call(f, _) if let ExprKind::Path(ref path) = f.kind => {
            let def = typeck.qpath_res(path, f.hir_id).opt_def_id()?;
            if !std_def(cx, def) {
                return None;
            }
            let path = cx.tcx.def_path_str(def);
            match cx.tcx.item_name(def).as_str() {
                "with_capacity" if owned() => Some("a buffer allocated with_capacity"),
                "new" if path.contains("boxed::Box") || path.contains("rc::Rc") || path.contains("sync::Arc") => {
                    Some("a new Box, Rc or Arc")
                },
                "new" if owned() && written_fresh(cx, typeck, e) => Some("a new buffer, written here"),
                "from" if owned() => Some("an owned value made from another"),
                "format" => Some("formatting into a new String"),
                _ => None,
            }
        },
        ExprKind::MethodCall(segment, ..) => {
            let def = typeck.type_dependent_def_id(e.hir_id)?;
            if !std_def(cx, def) {
                return None;
            }
            match segment.ident.as_str() {
                "to_vec" | "to_owned" | "to_string" | "into_owned" => Some("a copy into a new buffer"),
                "clone" | "collect" | "into" if owned() => Some("a new owned collection"),
                _ => None,
            }
        },
        _ => None,
    }
}

/// Whether the fresh buffer e is bound by a `let` and written afterwards.
fn written_fresh<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &'tcx Expr<'tcx>) -> bool {
    let Node::LetStmt(local) = cx.tcx.parent_hir_node(e.hir_id) else {
        return false;
    };
    let PatKind::Binding(_, id, _, _) = local.pat.kind else {
        return false;
    };
    let Node::Stmt(stmt) = cx.tcx.parent_hir_node(local.hir_id) else {
        return false;
    };
    let Node::Block(block) = cx.tcx.parent_hir_node(stmt.hir_id) else {
        return false;
    };
    let after = local.span.hi();
    block
        .stmts
        .iter()
        .filter_map(|s| match s.kind {
            StmtKind::Expr(x) | StmtKind::Semi(x) => Some(x),
            StmtKind::Let(l) => l.init,
            StmtKind::Item(_) => None,
        })
        .chain(block.expr)
        .any(|x| {
            for_each_expr(cx.tcx, x, |u| {
                if u.span.lo() < after || u.res_local_id() != Some(id) {
                    return ControlFlow::Continue(());
                }
                let writes = match cx.tcx.parent_hir_node(u.hir_id) {
                    Node::Expr(p) => match p.kind {
                        ExprKind::MethodCall(_, r, ..) if r.hir_id == u.hir_id => typeck
                            .type_dependent_def_id(p.hir_id)
                            .is_some_and(|m| takes_mut_self(cx, m)),
                        ExprKind::AddrOf(BorrowKind::Ref, Mutability::Mut, _) => true,
                        _ => false,
                    },
                    _ => false,
                };
                if writes {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .is_some()
        })
}

/// Whether a loop shows its bound: a `for`, which walks what it is given,
/// or a `while let` that takes from a collection until it is empty. A
/// `loop` or another `while` runs as long as its body says.
fn stated(block: &rustc_hir::Block<'_>, source: LoopSource) -> bool {
    match source {
        LoopSource::ForLoop => true,
        LoopSource::Loop => false,
        LoopSource::While => block
            .expr
            .is_some_and(|e| matches!(e.kind, ExprKind::If(cond, ..) if bounds(cond))),
    }
}

/// Whether a `while` condition shows a bound: a part of it puts a count
/// in order against a limit (`i < n`), compares with a length or a
/// constant, waits for a collection to empty, or takes from one until it
/// is empty.
fn bounds(cond: &Expr<'_>) -> bool {
    // A length, or a limit fixed in the program.
    let length = |e: &Expr<'_>| match e.kind {
        ExprKind::MethodCall(m, _, [], _) => m.ident.as_str() == "len",
        ExprKind::Lit(_) => true,
        ExprKind::Path(rustc_hir::QPath::Resolved(_, path)) => matches!(
            path.res,
            rustc_hir::def::Res::Def(DefKind::Const { .. } | DefKind::AssocConst { .. }, _)
        ),
        _ => false,
    };
    match cond.kind {
        ExprKind::Binary(op, l, r) if op.node == rustc_hir::BinOpKind::And => bounds(l) || bounds(r),
        // A count against a limit: an order, whatever the limit is.
        ExprKind::Binary(op, ..)
            if matches!(
                op.node,
                rustc_hir::BinOpKind::Lt
                    | rustc_hir::BinOpKind::Le
                    | rustc_hir::BinOpKind::Gt
                    | rustc_hir::BinOpKind::Ge
            ) =>
        {
            true
        },
        ExprKind::Binary(op, l, r) if op.node.is_comparison() => length(l) || length(r),
        ExprKind::Unary(UnOp::Not, inner) => {
            matches!(inner.kind, ExprKind::MethodCall(m, _, [], _) if m.ident.as_str() == "is_empty")
        },
        ExprKind::Let(l) => matches!(l.init.kind, ExprKind::MethodCall(m, ..)
            if matches!(m.ident.as_str(), "next" | "pop" | "pop_front" | "pop_back")),
        ExprKind::DropTemps(inner) => bounds(inner),
        _ => false,
    }
}

/// What at e a hot path forbids, with the kind of reason that allows it.
fn waste<'tcx>(
    cx: &LateContext<'tcx>,
    typeck: &TypeckResults<'tcx>,
    e: &'tcx Expr<'tcx>,
) -> Option<(String, &'static str)> {
    if !super::builtins::is_user_code(e.span) {
        return None;
    }
    if let ExprKind::Loop(block, _, source, _) = e.kind
        && !stated(block, source)
    {
        return Some(("a loop with no stated bound".to_owned(), "loop"));
    }
    if let Some(size) = large_move(cx, typeck, e) {
        return Some((format!("a move of {size} bytes, which is a memcpy,"), "move"));
    }
    birth(cx, typeck, e)
        .map(|what| (what.to_owned(), "alloc"))
        .or_else(|| copy(cx, typeck, e).map(|what| (what.to_owned(), "copy")))
}

/// Whether a new buffer is made by copying data, as `to_vec` makes it: a
/// reason of either kind, alloc or copy, answers it.
fn also_copy(what: &str) -> bool {
    what.starts_with("a copy")
}

/// The most bytes a hot path moves at once without a reason: past about
/// this, a move is a call to memcpy rather than a few loads and stores.
const MOVE_MAX: u64 = 256;

/// The size of the value e, when e reads a large one out of memory, a
/// variable, a field, an element or what a reference points to, and the
/// expression around it takes it by value: a `let`, an assignment, an
/// argument or a field of a value being built. Building a value in place
/// and lending one move nothing.
fn large_move<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &'tcx Expr<'tcx>) -> Option<u64> {
    let place = match e.kind {
        ExprKind::Path(ref path) => matches!(typeck.qpath_res(path, e.hir_id), rustc_hir::def::Res::Local(_)),
        ExprKind::Field(..) | ExprKind::Index(..) | ExprKind::Unary(UnOp::Deref, _) => true,
        _ => false,
    };
    if !place || !typeck.expr_adjustments(e).is_empty() {
        return None;
    }
    let taken = match cx.tcx.parent_hir_node(e.hir_id) {
        Node::LetStmt(local) => local.init.is_some_and(|init| init.hir_id == e.hir_id),
        Node::ExprField(_) => true,
        Node::Expr(parent) => match parent.kind {
            ExprKind::Assign(_, rhs, _) => rhs.hir_id == e.hir_id,
            ExprKind::Call(_, args) => args.iter().any(|a| a.hir_id == e.hir_id),
            ExprKind::MethodCall(_, _, args, _) => args.iter().any(|a| a.hir_id == e.hir_id),
            _ => false,
        },
        _ => false,
    };
    if !taken {
        return None;
    }
    let ty = typeck.expr_ty(e);
    let env = ty::TypingEnv::post_analysis(cx.tcx, typeck.hir_owner.def_id);
    let size = cx.tcx.layout_of(env.as_query_input(ty)).ok()?.size.bytes();
    (size > MOVE_MAX).then_some(size)
}

impl Allocs {
    /// Every new buffer and copy on the path from the hot function root:
    /// its body and the bodies of the local functions it reaches, as the
    /// call graph has them. One with an adjacent reason is allowed. A call
    /// with a `cold` reason is off the path, such as an error or once per
    /// item, and the callee is not followed from there; such a reason
    /// answers something only when what the path forbids, without its own
    /// reason, lies beyond the call.
    fn hot<'g>(&mut self, cx: &LateContext<'_>, graph: &'g Graph, root: LocalDefId) {
        // How each function was reached: its caller and the call.
        let mut via: FxHashMap<LocalDefId, (LocalDefId, &Call)> = FxHashMap::default();
        let mut cold: Vec<&'g Call> = Vec::new();
        let mut seen = FxHashSet::default();
        let mut todo = vec![root];
        let root_name = name(cx.tcx, root);
        while let Some(owner) = todo.pop() {
            if !seen.insert(owner) {
                continue;
            }
            for call in graph.from(owner) {
                if peek(cx, call.id, call.span, "cold") {
                    cold.push(call);
                } else {
                    via.entry(call.to).or_insert((owner, call));
                    todo.push(call.to);
                }
            }
            let Some(body) = cx.tcx.hir_maybe_body_owned_by(owner) else {
                continue;
            };
            let typeck = cx.tcx.typeck(owner);
            for_each_expr(cx.tcx, body.value, |e| {
                if let Some((what, kind)) = waste(cx, typeck, e)
                    && !reason(cx, e.hir_id, e.span, kind)
                    && !(also_copy(&what) && reason(cx, e.hir_id, e.span, "copy"))
                    && self.reported.insert(e.hir_id)
                {
                    // The calls from the root down to here, outermost first.
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
                        RR_HOT_PATH,
                        e.hir_id,
                        e.span,
                        format!("{what} on a hot path"),
                        |diag| {
                            diag.note(format!("reached from `#[rr::hot]` {root_name}"));
                            for call in chain.iter().rev() {
                                diag.span_note(call.span, call.through(&name(cx.tcx, call.to)));
                            }
                            match kind {
                                "alloc" => diag.help("reuse a buffer that lives outside the path"),
                                "move" => diag.help("lend it by reference, or build it where it ends up through &mut"),
                                _ if what.starts_with("a shift") => diag.help("take from the end, keep a read offset that moves instead of the data, or use a VecDeque when both ends change"),
                                "loop" => diag.help("bound it: walk what it reads with for, or count its turns against a limit; or say in a reason what bounds it, such as the bytes of one event"),
                                _ => diag.help("lend the data where it is, or write it once where it ends up"),
                            };
                            diag.help("a branch off the path, such as an error, takes a `// rr: escape(cold): <reason>` at a call above: rr does not follow a call marked cold, so mark only one that is rare");
                            note(diag, cx.sess(), statement(cx, e.hir_id, e.span), e.span, kind);
                        },
                    );
                }
                ControlFlow::<()>::Continue(())
            });
        }
        let mut wasted = FxHashMap::default();
        for call in cold {
            if waste_beyond(cx, graph, call.to, &mut wasted) {
                reason(cx, call.id, call.span, "cold");
            }
        }
    }
}

/// Whether what a hot path forbids, without its own reason, is reachable
/// from f through calls that are not cold; wasted caches whether each
/// body holds it.
fn waste_beyond(cx: &LateContext<'_>, graph: &Graph, f: LocalDefId, wasted: &mut FxHashMap<LocalDefId, bool>) -> bool {
    let mut seen = FxHashSet::default();
    let mut todo = vec![f];
    while let Some(owner) = todo.pop() {
        if !seen.insert(owner) {
            continue;
        }
        let here = *wasted.entry(owner).or_insert_with(|| {
            let Some(body) = cx.tcx.hir_maybe_body_owned_by(owner) else {
                return false;
            };
            let typeck = cx.tcx.typeck(owner);
            for_each_expr(cx.tcx, body.value, |e| {
                if let Some((what, kind)) = waste(cx, typeck, e)
                    && !peek(cx, e.hir_id, e.span, kind)
                    && !(also_copy(&what) && peek(cx, e.hir_id, e.span, "copy"))
                {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .is_some()
        });
        if here {
            return true;
        }
        todo.extend(
            graph
                .from(owner)
                .iter()
                .filter(|call| !peek(cx, call.id, call.span, "cold"))
                .map(|call| call.to),
        );
    }
    false
}
