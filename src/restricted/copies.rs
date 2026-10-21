//! Copies that the named escape operations do not cover: the same copy of
//! borrowed data spelled as a conversion, as a fresh buffer filled once, or
//! hidden behind a local function that does nothing else.

use clippy_utils::get_parent_expr;
use clippy_utils::higher::ForLoop;
use clippy_utils::res::MaybeResPath as _;
use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::{BorrowKind, Expr, ExprKind, HirId, LetStmt, Mutability, Node, PatKind, StmtKind, UnOp};
use rustc_lint::LateContext;
use rustc_middle::ty::{self, Ty, TypeckResults, TypingEnv};
use rustc_span::def_id::DefId;
use rustc_span::{Span, Symbol};

/// Owned standard containers that a copy can produce.
pub fn owned_container(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    let ty::Adt(adt, _) = ty.kind() else { return false };
    matches!(
        cx.tcx.def_path_str(adt.did()).as_str(),
        "alloc::string::String" | "alloc::vec::Vec" | "alloc::boxed::Box" | "alloc::collections::vec_deque::VecDeque"
    )
}

pub(super) fn std_def(cx: &LateContext<'_>, def_id: DefId) -> bool {
    matches!(cx.tcx.crate_name(def_id.krate).as_str(), "core" | "alloc" | "std")
}

fn trait_path(cx: &LateContext<'_>, def_id: DefId) -> String {
    cx.tcx
        .trait_of_assoc(def_id)
        .map(|id| cx.tcx.def_path_str(id))
        .unwrap_or_default()
}

pub(super) fn callee(cx: &LateContext<'_>, expr: &Expr<'_>) -> Option<DefId> {
    match expr.kind {
        ExprKind::MethodCall(..) => cx.typeck_results().type_dependent_def_id(expr.hir_id),
        ExprKind::Call(callee, _) if let ExprKind::Path(ref path) = callee.kind => {
            cx.typeck_results().qpath_res(path, callee.hir_id).opt_def_id()
        },
        _ => None,
    }
}

/// Data fixed in the program: a literal or a constant, possibly viewed
/// through a borrow, a slice of it or a byte view. Copying it is building,
/// not duplicating something the program owns.
pub(super) fn fixed(typeck: &TypeckResults<'_>, mut e: &Expr<'_>) -> bool {
    loop {
        e = match e.kind {
            ExprKind::Lit(_) => return true,
            ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(UnOp::Deref, inner) | ExprKind::Index(inner, _, _) => inner,
            ExprKind::MethodCall(segment, receiver, [], _)
                if matches!(segment.ident.as_str(), "as_bytes" | "as_slice" | "as_ref" | "as_str") =>
            {
                receiver
            },
            ExprKind::Path(ref path) => {
                return matches!(
                    typeck.qpath_res(path, e.hir_id),
                    Res::Def(
                        DefKind::Const { .. }
                            | DefKind::AssocConst { .. }
                            | DefKind::Static {
                                mutability: Mutability::Not,
                                ..
                            },
                        _
                    )
                );
            },
            _ => return false,
        };
    }
}

fn is_ref(typeck: &TypeckResults<'_>, e: &Expr<'_>) -> bool {
    matches!(typeck.expr_ty_adjusted(e).kind(), ty::Ref(..))
}

/// A conversion of borrowed data into an owned container: `From`/`Into` from
/// a reference, `Cow::into_owned`/`to_mut` and `ToString` on a string.
pub fn conversion<'tcx>(cx: &LateContext<'tcx>, expr: &Expr<'tcx>, def_id: DefId) -> Option<&'static str> {
    let name = cx.tcx.item_name(def_id);
    let owned = || owned_container(cx, cx.typeck_results().expr_ty(expr));
    match (name.as_str(), &expr.kind) {
        ("into_owned" | "to_mut", ExprKind::MethodCall(_, receiver, ..))
            if cx.tcx.def_path_str(def_id).contains("Cow") && !fixed(cx.typeck_results(), receiver) =>
        {
            Some("Cow::into_owned/to_mut (copying data that may be borrowed)")
        },
        ("from", ExprKind::Call(_, [arg]))
            if trait_path(cx, def_id) == "core::convert::From"
                && owned()
                && is_ref(cx.typeck_results(), arg)
                && !fixed(cx.typeck_results(), arg) =>
        {
            Some("From converting borrowed data into an owned copy")
        },
        ("into", ExprKind::MethodCall(_, receiver, ..))
            if trait_path(cx, def_id) == "core::convert::Into"
                && owned()
                && is_ref(cx.typeck_results(), receiver)
                && !fixed(cx.typeck_results(), receiver) =>
        {
            Some("Into converting borrowed data into an owned copy")
        },
        ("to_string", ExprKind::MethodCall(_, receiver, ..))
            if trait_path(cx, def_id) == "alloc::string::ToString"
                && is_text(cx, cx.typeck_results().expr_ty(receiver).peel_refs())
                && !fixed(cx.typeck_results(), receiver) =>
        {
            Some("ToString copying a string")
        },
        _ => None,
    }
}

/// str or String.
fn is_text(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    match ty.kind() {
        ty::Str => true,
        ty::Adt(adt, _) => cx.tcx.def_path_str(adt.did()) == "alloc::string::String",
        _ => false,
    }
}

/// `Vec::new`, `String::with_capacity` and the like: an empty owned buffer.
pub(super) fn fresh(cx: &LateContext<'_>, init: &Expr<'_>) -> bool {
    matches!(init.kind, ExprKind::Call(..))
        && callee(cx, init)
            .is_some_and(|id| std_def(cx, id) && matches!(cx.tcx.item_name(id).as_str(), "new" | "with_capacity"))
        && owned_container(cx, cx.typeck_results().expr_ty(init))
}

/// What a use of a buffer does to it.
enum Use {
    /// All of the borrowed data in the argument, at once.
    Copy,
    /// An element of a borrowed collection, in a loop over it.
    Element,
    /// Anything else that writes to it.
    Write,
}

/// An argument that hands over existing data as it is: a reference, or an
/// iterator that only walks one and copies or clones its items.
fn borrowed_source(typeck: &TypeckResults<'_>, mut e: &Expr<'_>) -> bool {
    loop {
        if is_ref(typeck, e) {
            return !fixed(typeck, e);
        }
        match e.kind {
            ExprKind::MethodCall(segment, receiver, [], _)
                if matches!(segment.ident.as_str(), "iter" | "into_iter" | "copied" | "cloned") =>
            {
                e = receiver;
            },
            _ => return false,
        }
    }
}

pub(super) fn takes_mut_self(cx: &LateContext<'_>, def_id: DefId) -> bool {
    let sig = cx.tcx.fn_sig(def_id).instantiate_identity().skip_binder();
    sig.inputs()
        .first()
        .is_some_and(|ty| matches!(ty.kind(), ty::Ref(_, _, Mutability::Mut)))
}

/// Whether e runs in a loop inside the block `stop`: a copy there
/// gathers many pieces, which builds something new.
pub(super) fn in_loop(cx: &LateContext<'_>, e: &Expr<'_>, stop: HirId) -> bool {
    for (id, node) in cx.tcx.hir_parent_iter(e.hir_id) {
        if id == stop {
            return false;
        }
        if let Node::Expr(Expr {
            kind: ExprKind::Loop(..),
            ..
        }) = node
        {
            return true;
        }
    }
    false
}

/// A push of a `for` loop's own element, when the loop walks a borrowed
/// collection.
fn element_push<'tcx>(cx: &LateContext<'tcx>, push: &'tcx Expr<'tcx>, arg: &'tcx Expr<'tcx>, stop: HirId) -> bool {
    let mut value = arg;
    while let ExprKind::Unary(UnOp::Deref, inner) = value.kind {
        value = inner;
    }
    let Some(local) = value.res_local_id() else {
        return false;
    };
    for (id, node) in cx.tcx.hir_parent_iter(push.hir_id) {
        if id == stop {
            return false;
        }
        if let Node::Expr(e) = node
            && let Some(l) = ForLoop::hir(e)
        {
            let mut bound = false;
            l.pat.each_binding(|_, hir_id, _, _| bound |= hir_id == local);
            return bound && borrowed_source(cx.typeck_results(), l.arg);
        }
    }
    false
}

/// Every write to the buffer bound at `local`, or to its field `field`
/// when the binding is a struct, from the end of its `let` to the end of
/// the block. A write to the struct as a whole may write the field.
fn uses<'tcx>(
    cx: &LateContext<'tcx>,
    local: HirId,
    field: Option<Symbol>,
    block: &'tcx rustc_hir::Block<'tcx>,
    after: Span,
) -> Vec<(&'tcx Expr<'tcx>, Use)> {
    let mut found = Vec::new();
    let mut visit = |e: &'tcx Expr<'tcx>| {
        if e.span.lo() < after.hi() || e.res_local_id() != Some(local) {
            return ControlFlow::<()>::Continue(());
        }
        let (buffer, whole) = match (field, get_parent_expr(cx, e)) {
            (None, _) => (e, false),
            (Some(name), Some(parent)) if matches!(parent.kind, ExprKind::Field(_, ident) if ident.name == name) => {
                (parent, false)
            },
            (Some(_), _) => (e, true),
        };
        if let Some((write, kind)) = written(cx, buffer, block) {
            found.push((write, if whole { Use::Write } else { kind }));
        }
        ControlFlow::Continue(())
    };
    for stmt in block.stmts {
        for_each_expr(cx.tcx, stmt, &mut visit);
    }
    if let Some(tail) = block.expr {
        for_each_expr(cx.tcx, tail, &mut visit);
    }
    found
}

/// What the expression around a buffer does to it, if it writes it.
fn written<'tcx>(
    cx: &LateContext<'tcx>,
    e: &'tcx Expr<'tcx>,
    block: &'tcx rustc_hir::Block<'tcx>,
) -> Option<(&'tcx Expr<'tcx>, Use)> {
    let parent = get_parent_expr(cx, e)?;
    match parent.kind {
        ExprKind::MethodCall(segment, receiver, args, _) if receiver.hir_id == e.hir_id => {
            let Some(id) = cx.typeck_results().type_dependent_def_id(parent.hir_id) else {
                return Some((parent, Use::Write));
            };
            if !takes_mut_self(cx, id) || matches!(segment.ident.as_str(), "reserve" | "reserve_exact") {
                return None;
            }
            let kind = match (segment.ident.as_str(), args) {
                ("extend_from_slice" | "extend" | "push_str", [arg])
                    if std_def(cx, id)
                        && borrowed_source(cx.typeck_results(), arg)
                        && !in_loop(cx, parent, block.hir_id) =>
                {
                    Use::Copy
                },
                ("push", [arg]) if std_def(cx, id) && element_push(cx, parent, arg, block.hir_id) => Use::Element,
                _ => Use::Write,
            };
            Some((parent, kind))
        },
        ExprKind::AddrOf(BorrowKind::Ref, Mutability::Mut, _) => Some((parent, Use::Write)),
        ExprKind::Assign(lhs, ..) | ExprKind::AssignOp(_, lhs, _) if lhs.hir_id == e.hir_id => {
            Some((parent, Use::Write))
        },
        _ => None,
    }
}

/// Each fresh buffer whose only write copies borrowed data into it, whole
/// or element by element: the binding itself, or a field of a struct it
/// is built as. The expression that copies, and what it is.
pub fn filled_once<'tcx>(cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) -> Vec<(&'tcx Expr<'tcx>, &'static str)> {
    let mut out = Vec::new();
    let PatKind::Binding(_, id, _, None) = local.pat.kind else {
        return out;
    };
    let Some(init) = local.init else { return out };
    let Node::Stmt(stmt) = cx.tcx.parent_hir_node(local.hir_id) else {
        return out;
    };
    let Node::Block(block) = cx.tcx.parent_hir_node(stmt.hir_id) else {
        return out;
    };
    let buffers: Vec<Option<Symbol>> = match init.kind {
        ExprKind::Struct(_, fields, _) => fields
            .iter()
            .filter(|f| fresh(cx, f.expr))
            .map(|f| Some(f.ident.name))
            .collect(),
        _ if fresh(cx, init) => vec![None],
        _ => Vec::new(),
    };
    for field in buffers {
        match uses(cx, id, field, block, local.span).as_slice() {
            [(e, Use::Copy)] => out.push((*e, "a fresh buffer filled with one copy of borrowed data")),
            [(e, Use::Element)] => out.push((*e, "a fresh collection rebuilt element by element")),
            _ => {},
        }
    }
    out
}

/// The parameters' bindings of a local function's body.
pub(super) fn params(body: &rustc_hir::Body<'_>) -> Vec<HirId> {
    let mut ids = Vec::new();
    for param in body.params {
        param.pat.each_binding(|_, id, _, _| ids.push(id));
    }
    ids
}

/// An expression that is a parameter, seen through borrows, slices, byte
/// views and iterator adapters that keep its items as they are.
pub(super) fn of_param(e: &Expr<'_>, params: &[HirId]) -> bool {
    let mut e = e;
    loop {
        e = match e.kind {
            ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(UnOp::Deref, inner) | ExprKind::Index(inner, _, _) => inner,
            ExprKind::MethodCall(segment, receiver, [], _)
                if matches!(
                    segment.ident.as_str(),
                    "as_bytes" | "as_slice" | "as_ref" | "as_str" | "iter" | "into_iter" | "copied" | "cloned"
                ) =>
            {
                receiver
            },
            _ => return e.res_local_id().is_some_and(|id| params.contains(&id)),
        };
    }
}

/// Whether the expression copies a parameter: a named copy, a conversion,
/// or a collect of its items.
fn copies_param<'tcx>(cx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>, params: &[HirId]) -> bool {
    let typeck = cx.tcx.typeck(e.hir_id.owner.def_id);
    let def_id = match e.kind {
        ExprKind::MethodCall(..) => typeck.type_dependent_def_id(e.hir_id),
        ExprKind::Call(f, _) if let ExprKind::Path(ref path) = f.kind => typeck.qpath_res(path, f.hir_id).opt_def_id(),
        _ => None,
    };
    let Some(def_id) = def_id else { return false };
    if !std_def(cx, def_id) {
        return false;
    }
    let name = cx.tcx.item_name(def_id);
    match e.kind {
        ExprKind::MethodCall(_, receiver, [], _) => {
            matches!(
                name.as_str(),
                "clone" | "to_vec" | "to_owned" | "to_string" | "into" | "into_owned" | "collect"
            ) && of_param(receiver, params)
        },
        ExprKind::Call(_, [arg]) => name.as_str() == "from" && of_param(arg, params),
        _ => false,
    }
}

/// A local function whose body does nothing but return a copy of one of
/// its parameters: `{ p.to_vec() }`, `{ Vec::from(p) }`, or a fresh buffer
/// filled once from it and returned.
pub fn copy_helper(cx: &LateContext<'_>, def_id: DefId) -> bool {
    let Some(local) = def_id.as_local() else { return false };
    if !matches!(cx.tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
        return false;
    }
    let Some(body) = cx.tcx.hir_maybe_body_owned_by(local) else {
        return false;
    };
    let params = params(body);
    let ExprKind::Block(block, _) = body.value.kind else {
        return false;
    };
    let Some(tail) = block.expr else { return false };
    match block.stmts {
        [] => copies_param(cx, tail, &params),
        [first, second] => {
            let (StmtKind::Let(l), StmtKind::Semi(fill)) = (&first.kind, &second.kind) else {
                return false;
            };
            let PatKind::Binding(_, id, _, None) = l.pat.kind else {
                return false;
            };
            let typeck = cx.tcx.typeck(local);
            l.init.is_some_and(|init| {
                matches!(init.kind, ExprKind::Call(..)) && owned_container(cx, typeck.expr_ty(init))
            }) && tail.res_local_id() == Some(id)
                && matches!(
                    fill.kind,
                    ExprKind::MethodCall(segment, receiver, [arg], _)
                        if matches!(segment.ident.as_str(), "extend_from_slice" | "extend" | "push_str")
                            && receiver.res_local_id() == Some(id)
                            && of_param(arg, &params)
                )
        },
        _ => false,
    }
}

/// What at e copies data the program holds into other memory it holds,
/// by name, for a hot path: a buffer filled from another, a copy within
/// one or between pointers, a clone, or one element at a time in a loop or
/// a closure. Writing what is built here, such as a literal, a constant or
/// the bytes of a number, is not a copy, nor is filling an array on the
/// stack, which builds a value.
pub(super) fn copy<'tcx>(
    cx: &LateContext<'tcx>,
    typeck: &TypeckResults<'tcx>,
    e: &'tcx Expr<'tcx>,
) -> Option<&'static str> {
    match e.kind {
        ExprKind::MethodCall(segment, receiver, args, _) => {
            let def = typeck.type_dependent_def_id(e.hir_id)?;
            if !std_def(cx, def) {
                return None;
            }
            let into = held(typeck, receiver);
            match (segment.ident.as_str(), args) {
                (
                    "copy_from_slice" | "clone_from_slice" | "extend_from_slice" | "push_str" | "clone_from"
                    | "write_str",
                    [arg],
                )
                | ("insert_str", [_, arg])
                    if into && held(typeck, arg) =>
                {
                    Some("a copy into another buffer")
                },
                ("extend" | "append", [arg]) if into && borrowed_source(typeck, arg) => {
                    Some("a copy into another buffer")
                },
                ("copy_within" | "extend_from_within", _) if into => Some("a copy within a buffer"),
                // Taking out or putting in anywhere but the end moves the
                // rest of the buffer: in a loop, the work goes quadratic.
                ("remove", [_]) | ("insert" | "insert_str", [_, _]) if into && shifts(cx, typeck.expr_ty(receiver)) => {
                    Some("a shift of a buffer's tail")
                },
                ("drain", [range]) if into && shifts(cx, typeck.expr_ty(receiver)) && cut(cx, range) => {
                    Some("a shift of a buffer's tail")
                },
                ("copy_from" | "copy_from_nonoverlapping", [arg, _]) if held(typeck, arg) => {
                    Some("a copy between pointers")
                },
                ("copy_to" | "copy_to_nonoverlapping", _) if into => Some("a copy between pointers"),
                ("clone", []) if cloned(cx, typeck, e) => Some("a clone"),
                ("push" | "push_back" | "push_front" | "insert", [.., arg])
                    if into && repeated(cx, e) && loaded(cx, typeck, arg) =>
                {
                    Some("a copy one element at a time")
                },
                _ => None,
            }
        },
        ExprKind::Call(f, [source, ..]) if let ExprKind::Path(ref path) = f.kind => {
            let def = typeck.qpath_res(path, f.hir_id).opt_def_id()?;
            (std_def(cx, def)
                && matches!(cx.tcx.item_name(def).as_str(), "copy" | "copy_nonoverlapping")
                && held(typeck, source))
            .then_some("a copy between pointers")
        },
        ExprKind::Assign(place, value, _)
            if in_memory(place) && held(typeck, place) && repeated(cx, e) && loaded(cx, typeck, value) =>
        {
            Some("a copy one element at a time")
        },
        _ => None,
    }
}

/// Whether e is memory the program holds, viewed through a borrow, a
/// field, a slice or a method that lends a part: what a reference points
/// to, or a buffer, by either way of an `if` or a `match`. A literal, a
/// constant, a number or an array on the stack, and a value a call has
/// just made, are built here.
fn held(typeck: &TypeckResults<'_>, mut e: &Expr<'_>) -> bool {
    loop {
        e = match e.kind {
            ExprKind::AddrOf(_, _, inner)
            | ExprKind::Index(inner, ..)
            | ExprKind::Field(inner, _)
            | ExprKind::Unary(UnOp::Deref, inner) => inner,
            ExprKind::MethodCall(_, receiver, ..) if matches!(typeck.expr_ty(e).kind(), ty::Ref(..)) => receiver,
            ExprKind::Block(block, _) => match block.expr {
                Some(tail) => tail,
                None => return false,
            },
            // Either way may be held.
            ExprKind::If(_, then, Some(other)) => return held(typeck, then) || held(typeck, other),
            ExprKind::Match(_, arms, _) => return arms.iter().any(|arm| held(typeck, arm.body)),
            ExprKind::Path(ref path) => {
                let ty = typeck.expr_ty(e);
                return matches!(typeck.qpath_res(path, e.hir_id), Res::Local(_))
                    && !matches!(ty.kind(), ty::Array(..))
                    && !ty.is_scalar();
            },
            _ => return false,
        };
    }
}

/// A Vec or String: one block, whose tail moves when a part before it
/// is taken out or put in.
fn shifts(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    let ty::Adt(adt, _) = ty.peel_refs().kind() else {
        return false;
    };
    matches!(
        cx.tcx.def_path_str(adt.did()).as_str(),
        "alloc::vec::Vec" | "alloc::string::String"
    )
}

/// Whether a drain of range leaves a tail to move: it ends before the end.
fn cut(cx: &LateContext<'_>, range: &Expr<'_>) -> bool {
    clippy_utils::higher::Range::hir(cx, range).is_none_or(|r| r.end.is_some())
}

/// Whether the clone at e copies: not of a Copy value, which is free,
/// nor of a shared pointer, which only counts, nor of an owned container,
/// which a hot path already sees as a new buffer.
fn cloned<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &Expr<'_>) -> bool {
    let ty = typeck.expr_ty(e);
    let env = TypingEnv::post_analysis(cx.tcx, typeck.hir_owner.def_id);
    let shared = matches!(ty.kind(), ty::Adt(adt, _)
        if matches!(cx.tcx.def_path_str(adt.did()).as_str(), "alloc::rc::Rc" | "alloc::sync::Arc"));
    !shared && !owned_container(cx, ty) && !cx.tcx.type_is_copy_modulo_regions(env, ty)
}

/// Whether e runs again and again: in a loop, or in a closure, which code
/// that takes one calls per item.
fn repeated(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    for (_, node) in cx.tcx.hir_parent_iter(e.hir_id) {
        match node {
            Node::Expr(Expr {
                kind: ExprKind::Loop(..) | ExprKind::Closure(..),
                ..
            }) => return true,
            Node::Item(_) | Node::ImplItem(_) | Node::TraitItem(_) => return false,
            _ => {},
        }
    }
    false
}

/// A place in memory rather than a local: an element, or what a reference
/// points to, or a field of either.
fn in_memory(mut place: &Expr<'_>) -> bool {
    loop {
        place = match place.kind {
            ExprKind::Field(base, _) => base,
            ExprKind::Index(..) | ExprKind::Unary(UnOp::Deref, _) => return true,
            _ => return false,
        };
    }
}

/// Whether e is a value read as it is from memory the program holds: an
/// element, what a reference points to, a field of either, or a binding
/// of one.
fn loaded(cx: &LateContext<'_>, typeck: &TypeckResults<'_>, mut e: &Expr<'_>) -> bool {
    loop {
        e = match e.kind {
            ExprKind::Field(base, _) => base,
            ExprKind::Index(base, ..) => return held(typeck, base),
            ExprKind::Unary(UnOp::Deref, inner) => {
                return matches!(typeck.expr_ty(inner).kind(), ty::Ref(..) | ty::RawPtr(..)) && held(typeck, inner);
            },
            ExprKind::Path(_) => return e.res_local_id().is_some_and(|id| element(cx, typeck, id)),
            _ => return false,
        };
    }
}

/// Whether the binding at id holds a value read from memory: bound
/// through a `&` pattern, as `for &b in` and `Some(&b)` are, bound by a
/// `for` over copied items of borrowed data, or let to such a value.
fn element(cx: &LateContext<'_>, typeck: &TypeckResults<'_>, id: HirId) -> bool {
    let mut parents = cx.tcx.hir_parent_iter(id);
    let outer = loop {
        match parents.next() {
            Some((_, Node::Pat(pat))) if matches!(pat.kind, PatKind::Ref(..)) => return true,
            Some((_, Node::Pat(_))) => {},
            Some((_, node)) => break node,
            None => return false,
        }
    };
    if let Node::LetStmt(local) = outer
        && let Some(init) = local.init
    {
        return loaded(cx, typeck, init);
    }
    for (_, node) in cx.tcx.hir_parent_iter(id) {
        if let Node::Expr(e) = node
            && let Some(l) = ForLoop::hir(e)
        {
            let mut bound = false;
            l.pat.each_binding(|_, hir_id, _, _| bound |= hir_id == id);
            return bound
                && matches!(l.arg.kind, ExprKind::MethodCall(segment, receiver, [], _)
                    if matches!(segment.ident.as_str(), "copied" | "cloned" | "bytes")
                        && borrowed_source(typeck, receiver));
        }
    }
    false
}
