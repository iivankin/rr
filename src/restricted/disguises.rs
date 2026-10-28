//! Operations rr asks a reason for, written in a form the rule for them
//! does not see: a truncating cast as a byte of a number's bytes, a
//! `must_use` value dropped into a binding never read, an error's cause
//! thrown away by `ok()`, a magic number standing for none, an integer
//! saying which kind a value is, a large value built on the stack and
//! copied into a Box, a bug reported as bad input (`get(..).ok_or(..)`
//! with an index computed from the slice's own length), and unsafe code
//! outside the module that talks to the system.

use clippy_utils::diagnostics::span_lint_and_then;
use clippy_utils::is_must_use_func_call;
use clippy_utils::res::MaybeResPath as _;
use clippy_utils::ty::opt_must_use_path;
use clippy_utils::visitors::{for_each_expr, is_local_used};
use core::ops::ControlFlow;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::{
    BinOpKind, BlockCheckMode, Expr, ExprKind, FieldDef, FnSig, HirId, Item, ItemKind, LetStmt, Node, PatKind, QPath,
    Safety, UnsafeSource,
};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::ty::{self, Ty, TypeckResults};
use rustc_session::impl_lint_pass;
use rustc_span::Span;

use super::RR_UNEXPLAINED_ESCAPE;
use super::allocs::{reason, statement};
use super::comments::note;

#[derive(Default)]
pub struct Disguises {
    /// The locals of the function last looked into.
    locals: super::inbounds::Locals,
}

impl_lint_pass!(Disguises => [RR_UNEXPLAINED_ESCAPE]);

/// The most bytes `Box::new` takes without a reason: past this, building
/// the value on the stack and copying it into the heap is a memcpy.
const BOX_MAX: u64 = 256;

/// Report what at span needs a reason of kind, unless an adjacent one
/// gives it.
fn ask(cx: &LateContext<'_>, id: HirId, span: Span, kind: &'static str, what: String, help: &'static str) {
    if reason(cx, id, span, kind) {
        return;
    }
    span_lint_and_then(cx, RR_UNEXPLAINED_ESCAPE, span, what, |diag| {
        diag.help(help);
        note(diag, cx.sess(), statement(cx, id, span), span, kind);
    });
}

impl<'tcx> LateLintPass<'tcx> for Disguises {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>) {
        if !super::builtins::is_user_code(e.span) {
            return;
        }
        let typeck = cx.typeck_results();
        if let Some(what) = byte_cast(cx, typeck, e) {
            ask(
                cx,
                e.hir_id,
                e.span,
                "cast",
                what,
                "use try_from and say what happens when it does not fit, or say in a reason why only these bits matter",
            );
        }
        if let ExprKind::MethodCall(segment, receiver, ..) = e.kind
            && matches!(segment.ident.as_str(), "ok_or" | "ok_or_else")
            && let ExprKind::MethodCall(ok, inner, [], _) = receiver.kind
            && ok.ident.as_str() == "ok"
            && is_result(cx, typeck.expr_ty(inner))
        {
            ask(
                cx,
                e.hir_id,
                e.span,
                "discard",
                "`ok().ok_or(..)` throws away the error's cause".to_owned(),
                "use map_err, which keeps it, or say in a reason why the cause does not matter",
            );
        }
        ok_unwrap(cx, typeck, e);
        if let Some(slice) = self.locals.own_index(cx, e) {
            ask(
                cx,
                e.hir_id,
                e.span,
                "panic",
                format!(
                    "the index into `{slice}` is computed from its own length: out of bounds, it is a bug, which `ok_or` reports as bad input"
                ),
                "index it, and say in a reason why the index is below the length; a bug stops the program where it is",
            );
        }
        if let Some(what) = sentinel(cx, typeck, e) {
            ask(
                cx,
                e.hir_id,
                e.span,
                "sentinel",
                what,
                "an Option says there is none, and the compiler checks that each use handles it",
            );
        }
        if let ExprKind::Call(f, [arg]) = e.kind
            && let ExprKind::Path(ref path) = f.kind
            && let Res::Def(DefKind::AssocFn, def) = typeck.qpath_res(path, f.hir_id)
            && cx.tcx.item_name(def).as_str() == "new"
            && cx.tcx.def_path_str(def).starts_with("alloc::boxed::Box")
            && let Some(size) = size(cx, typeck, arg)
            && size > BOX_MAX
        {
            ask(
                cx,
                e.hir_id,
                e.span,
                "move",
                format!("`Box::new` of {size} bytes builds the value on the stack and copies it into the heap"),
                "box its large parts where they are made, or say in a reason why this copy is rare",
            );
        }
        if let ExprKind::Block(block, _) = e.kind
            && let BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided) = block.rules
            && !in_sys(cx, e.hir_id)
            && !in_entry(cx, e.hir_id)
        {
            outside_sys(cx, e.span, "an unsafe block");
        }
        if let Some(arm) = impossible_error_arm(typeck, e) {
            span_lint_and_then(
                cx,
                RR_UNEXPLAINED_ESCAPE,
                arm,
                "this arm cannot run: the arms above cover every value the match can take",
                |diag| {
                    diag.help("an arm that cannot run is a bug if it does, not bad input: write `_ => unreachable!()` with a `// rr: escape(panic): <why>`");
                },
            );
        }
        if let Some(arms) = numbered_dispatch(cx, e) {
            ask(
                cx,
                e.hir_id,
                arms,
                "tag",
                "a match over numbers taken from a list of numbers is a table of kinds by number".to_owned(),
                "an enum names each kind, and a match on it covers every one",
            );
        }
    }

    fn check_local(&mut self, cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) {
        let PatKind::Binding(_, id, ident, None) = local.pat.kind else {
            return;
        };
        let Some(init) = local.init else { return };
        let name = ident.name.as_str();
        if !name.starts_with('_') || name == "_" || !super::builtins::is_user_code(local.span) {
            return;
        }
        let ty = cx.typeck_results().expr_ty(init);
        // A guard held to the end of its scope is what a binding is for.
        let dropped = is_result(cx, ty)
            || ((opt_must_use_path(cx, ty).is_some() || is_must_use_func_call(cx, init))
                && !ty.needs_drop(cx.tcx, cx.typing_env()));
        let Node::Block(block) = cx.tcx.parent_hir_node(cx.tcx.parent_hir_id(local.hir_id)) else {
            return;
        };
        if dropped && !is_local_used(cx, block, id) {
            ask(
                cx,
                local.hir_id,
                local.span,
                "discard",
                format!("a must_use value bound to `{name}`, which nothing reads, is dropped"),
                "handle it, or drop it with `let _ =` and say in a reason why",
            );
        }
    }

    fn check_field_def(&mut self, cx: &LateContext<'tcx>, field: &'tcx FieldDef<'tcx>) {
        let name = field.ident.name.as_str();
        let tag = matches!(name, "kind" | "tag" | "mode" | "variant" | "type_" | "typ")
            || name.ends_with("_kind")
            || name.ends_with("_tag");
        let ty = cx.tcx.type_of(field.def_id).instantiate_identity().skip_norm_wip();
        if tag && ty.is_integral() && super::builtins::is_user_code(field.span) {
            ask(
                cx,
                field.hir_id,
                field.span,
                "tag",
                format!("`{name}` is an integer that says which kind a value is"),
                "an enum names each kind and carries the data only that kind has; a match on it covers every one",
            );
        }
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if !super::builtins::is_user_code(item.span) || in_sys(cx, item.hir_id()) {
            return;
        }
        let what = match item.kind {
            ItemKind::Fn {
                sig: FnSig { header, .. },
                ..
            } if header.is_unsafe() => "an unsafe fn",
            ItemKind::Impl(implementation)
                if implementation
                    .of_trait
                    .is_some_and(|t| matches!(t.safety, Safety::Unsafe)) =>
            {
                "an unsafe impl"
            },
            ItemKind::ForeignMod { .. } => "a foreign block",
            _ => return,
        };
        outside_sys(cx, item.span, what);
    }
}

/// `ok().unwrap()` and `ok().expect(..)` on a Result: the error is thrown
/// away before the failure could name it; `ok().unwrap_or(..)` and the
/// like: the Result's own says the same, shorter.
fn ok_unwrap<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &Expr<'_>) {
    if let ExprKind::MethodCall(segment, receiver, ..) = e.kind
        && matches!(
            segment.ident.as_str(),
            "unwrap" | "expect" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default"
        )
        && let ExprKind::MethodCall(ok, inner, [], _) = receiver.kind
        && ok.ident.as_str() == "ok"
        && is_result(cx, typeck.expr_ty(inner))
    {
        let fallback = segment.ident.as_str().starts_with("unwrap_or");
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            e.span,
            if fallback {
                format!(
                    "`ok().{}()` makes the Result an Option only to throw its error away",
                    segment.ident
                )
            } else {
                format!(
                    "`ok().{}()` throws the error away, and a failure cannot say which it was",
                    segment.ident
                )
            },
            |diag| {
                if fallback {
                    diag.help("call it on the Result itself, where the error it replaces is in sight");
                } else {
                    diag.help("call it on the Result itself; for tests, give the error type Debug with `#[cfg_attr(test, derive(Debug))]`");
                }
            },
        );
    }
}

fn outside_sys(cx: &LateContext<'_>, span: Span, what: &str) {
    span_lint_and_then(
        cx,
        RR_UNEXPLAINED_ESCAPE,
        span,
        format!("{what} outside the `sys` module"),
        |diag| {
            diag.help("unsafe code and the operating system stay in a `sys` module, behind safe functions the rest of the program calls");
        },
    );
}

/// Whether the code at id is in a module named `sys`, or one inside it.
fn in_sys(cx: &LateContext<'_>, id: HirId) -> bool {
    let module = cx.tcx.parent_module(id).to_def_id();
    cx.tcx
        .def_path(module)
        .data
        .iter()
        .any(|segment| segment.data.get_opt_name().is_some_and(|name| name.as_str() == "sys"))
}

/// Whether the code at id is in the C entry of a `#![no_main]` program,
/// whose arguments the system hands over as raw pointers.
fn in_entry(cx: &LateContext<'_>, id: HirId) -> bool {
    let owner = cx.tcx.hir_enclosing_body_owner(id);
    matches!(cx.tcx.hir_node_by_def_id(owner), Node::Item(Item { kind: ItemKind::Fn { sig, .. }, .. })
        if !sig.header.abi.is_rustic_abi())
        && matches!(
            cx.tcx.item_name(owner.to_def_id()).as_str(),
            // rr test and rr fuz keep the program's main under this name.
            "main"
                | "__rr_program_main"
                | "LLVMFuzzerTestOneInput"
                | "LLVMFuzzerInitialize"
                | "__sanitizer_symbolize_pc"
                | "__sanitizer_get_module_and_offset_for_pc"
        )
}

fn is_result(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    matches!(ty.kind(), ty::Adt(adt, _) if cx.tcx.is_diagnostic_item(rustc_span::sym::Result, adt.did()))
}

/// The size of the value e, when it is known.
fn size<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &Expr<'_>) -> Option<u64> {
    let ty = typeck.expr_ty(e);
    let env = ty::TypingEnv::post_analysis(cx.tcx, typeck.hir_owner.def_id);
    Some(cx.tcx.layout_of(env.as_query_input(ty)).ok()?.size.bytes())
}

/// The integer whose bytes e takes, `x.to_le_bytes()` and the like, and
/// its width in bytes.
fn number_bytes<'tcx>(typeck: &TypeckResults<'tcx>, e: &Expr<'_>) -> Option<Ty<'tcx>> {
    match e.kind {
        ExprKind::MethodCall(segment, receiver, [], _)
            if matches!(segment.ident.as_str(), "to_le_bytes" | "to_be_bytes" | "to_ne_bytes") =>
        {
            let ty = typeck.expr_ty(receiver).peel_refs();
            ty.is_integral().then_some(ty)
        },
        _ => None,
    }
}

fn width<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> Option<u64> {
    ty.is_integral().then(|| ty.primitive_size(cx.tcx).bytes())
}

/// A truncating or sign-changing cast written as bytes: one byte of a
/// wider number's bytes, `x.to_le_bytes()[0]`; a number made from some of
/// a wider one's bytes; or one made from all the bytes of a number of the
/// other sign, `i32::from_le_bytes(u.to_le_bytes())`.
fn byte_cast<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &Expr<'_>) -> Option<String> {
    match e.kind {
        ExprKind::Index(base, index, _) if matches!(index.kind, ExprKind::Lit(_)) => {
            let from = number_bytes(typeck, base)?;
            (width(cx, from)? > 1 && !is_whole_from_bytes(cx, e))
                .then(|| format!("a byte of the bytes of a `{from}` is a truncating cast to `u8`"))
        },
        ExprKind::Call(f, [arg]) if let ExprKind::Path(ref path) = f.kind => {
            let def = typeck.qpath_res(path, f.hir_id).opt_def_id()?;
            if !matches!(
                cx.tcx.item_name(def).as_str(),
                "from_le_bytes" | "from_be_bytes" | "from_ne_bytes"
            ) {
                return None;
            }
            let to = typeck.expr_ty(e);
            if !to.is_integral() {
                return None;
            }
            match arg.kind {
                _ if let Some(from) = number_bytes(typeck, arg) => (from != to && width(cx, from) == width(cx, to))
                    .then(|| format!("a `{to}` made from the bytes of a `{from}` is a cast that changes the sign")),
                ExprKind::Array(parts) => {
                    let from = parts.iter().find_map(|part| match part.kind {
                        ExprKind::Index(base, ..) => number_bytes(typeck, base),
                        _ => None,
                    })?;
                    (width(cx, from)? > width(cx, to)?)
                        .then(|| format!("a `{to}` made from some of the bytes of a `{from}` is a truncating cast"))
                },
                _ => None,
            }
        },
        _ => None,
    }
}

/// Whether the byte at e is one of a list that `from_*_bytes` rebuilds
/// into a number, which that call answers for.
fn is_whole_from_bytes(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    matches!(
        cx.tcx.parent_hir_node(e.hir_id),
        Node::Expr(Expr {
            kind: ExprKind::Array(..),
            ..
        })
    )
}

/// A value standing for none, compared with or chosen as the default of
/// an Option: `x == u32::MAX`, `map_or(u32::MAX, ..)`,
/// `unwrap_or(u32::MAX)`.
fn sentinel<'tcx>(cx: &LateContext<'tcx>, typeck: &TypeckResults<'tcx>, e: &Expr<'_>) -> Option<String> {
    let extreme = |x: &Expr<'_>| match x.kind {
        ExprKind::Path(ref path @ QPath::TypeRelative(..)) => {
            let Res::Def(DefKind::AssocConst { .. }, def) = typeck.qpath_res(path, x.hir_id) else {
                return None;
            };
            let name = cx.tcx.item_name(def);
            (typeck.expr_ty(x).is_integral() && matches!(name.as_str(), "MAX" | "MIN"))
                .then(|| format!("{}::{name}", typeck.expr_ty(x)))
        },
        _ => None,
    };
    match e.kind {
        ExprKind::Binary(op, l, r) if matches!(op.node, BinOpKind::Eq | BinOpKind::Ne) => {
            let value = extreme(l).or_else(|| extreme(r))?;
            Some(format!("`{value}` stands for none here"))
        },
        // On a Result, as from try_from, the default clamps what does not
        // fit; on an Option it stands for the None.
        ExprKind::MethodCall(segment, receiver, [default, ..], _)
            if matches!(segment.ident.as_str(), "map_or" | "unwrap_or")
                && matches!(typeck.expr_ty(receiver).peel_refs().kind(),
                    ty::Adt(adt, _) if cx.tcx.is_diagnostic_item(rustc_span::sym::Option, adt.did())) =>
        {
            let value = extreme(default)?;
            Some(format!("`{value}` stands for none here"))
        },
        _ => None,
    }
}

/// The values a match on `x & MASK` or `x % N`, with x unsigned and
/// the mask or divisor a literal, can take: `0..=MASK` or `0..N`.
fn masked_values(typeck: &TypeckResults<'_>, scrutinee: &Expr<'_>) -> Option<u128> {
    let ExprKind::Binary(op, l, r) = scrutinee.kind else {
        return None;
    };
    let literal = |x: &Expr<'_>| match x.kind {
        ExprKind::Lit(lit) => match lit.node {
            rustc_ast::LitKind::Int(n, _) => Some(n.get()),
            _ => None,
        },
        _ => None,
    };
    if !matches!(typeck.expr_ty(l).kind(), ty::Uint(_)) {
        return None;
    }
    let count = match op.node {
        BinOpKind::BitAnd => {
            let mask = literal(r).or_else(|| literal(l))?;
            (mask & (mask + 1) == 0).then_some(mask + 1)?
        },
        BinOpKind::Rem => literal(r)?,
        _ => return None,
    };
    (count <= 256).then_some(count)
}

/// A catch-all arm that returns an error, in a match whose other arms
/// cover every value its masked scrutinee can take: a bug spelled as bad
/// input.
fn impossible_error_arm(typeck: &TypeckResults<'_>, e: &Expr<'_>) -> Option<Span> {
    let ExprKind::Match(scrutinee, arms, rustc_hir::MatchSource::Normal) = e.kind else {
        return None;
    };
    let count = masked_values(typeck, scrutinee)?;
    let mut covered = 0u128;
    let mut catch_all = None;
    for arm in arms {
        if arm.guard.is_some() {
            return None;
        }
        let mut values = Vec::new();
        let mut wild = false;
        arm.pat.walk_always(|pat| match pat.kind {
            PatKind::Wild | PatKind::Binding(..) => wild = true,
            PatKind::Expr(lit) => {
                if let rustc_hir::PatExprKind::Lit { lit, negated: false } = lit.kind
                    && let rustc_ast::LitKind::Int(n, _) = lit.node
                {
                    values.push(n.get());
                }
            },
            _ => {},
        });
        if wild {
            catch_all = Some(arm);
        } else {
            covered += u128::try_from(values.iter().filter(|&&n| n < count).count()).ok()?;
        }
    }
    let arm = catch_all?;
    let error = |x: &Expr<'_>| {
        let x = match x.kind {
            ExprKind::Ret(Some(inner)) => inner,
            _ => x,
        };
        matches!(x.kind, ExprKind::Call(f, _) if matches!(f.kind,
            ExprKind::Path(QPath::Resolved(_, path)) if path.segments.last().is_some_and(|s| s.ident.as_str() == "Err")))
    };
    let body = match arm.body.kind {
        ExprKind::Block(block, _) if block.stmts.is_empty() => block.expr?,
        _ => arm.body,
    };
    (covered >= count && error(body)).then_some(arm.span)
}

/// The arms of a match, in a `for` over a list of integer literals, on
/// the item it takes: a dispatch table keyed by number.
fn numbered_dispatch<'tcx>(cx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>) -> Option<Span> {
    let for_loop = clippy_utils::higher::ForLoop::hir(e)?;
    let mut list = for_loop.arg;
    while let ExprKind::AddrOf(_, _, inner) | ExprKind::MethodCall(_, inner, [], _) = list.kind {
        list = inner;
    }
    let ExprKind::Array(items) = list.kind else {
        return None;
    };
    if items.len() < 2 || !items.iter().all(|item| matches!(item.kind, ExprKind::Lit(_))) {
        return None;
    }
    let PatKind::Binding(_, id, ..) = for_loop.pat.kind else {
        return None;
    };
    let mut found = None;
    for_each_expr(cx.tcx, for_loop.body, |x| {
        if let ExprKind::Match(scrutinee, ..) = x.kind
            && scrutinee.res_local_id() == Some(id)
        {
            found = Some(x.span);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
    found
}
