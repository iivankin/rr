//! Check language restrictions after builtin macros have expanded (notably include!).

use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_then};
use rustc_hir::{self as hir, AmbigArg};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_session::impl_lint_pass;
use rustc_span::Span;
use rustc_span::def_id::LocalDefId;

use super::{RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE};

pub struct ExpandedSyntax;
impl_lint_pass!(ExpandedSyntax => [RR_NO_GENERICS, RR_NO_MACROS, RR_SIMPLE_TRAITS, RR_UNEXPLAINED_ESCAPE]);

fn reject(cx: &LateContext<'_>, lint: &'static rustc_lint::Lint, span: Span, feature: &str) {
    // What the check before expansion has reported already; this one is
    // for what macros bring in, such as include!.
    if super::syntax::reported(span) || !super::builtins::is_user_code(span) {
        return;
    }
    span_lint_and_help(
        cx,
        lint,
        span,
        format!("{feature} is forbidden by rr after macro expansion"),
        None,
        "use concrete types and simple traits, including in included source",
    );
}

impl<'tcx> LateLintPass<'tcx> for ExpandedSyntax {
    fn check_generics(&mut self, cx: &LateContext<'tcx>, generics: &'tcx hir::Generics<'tcx>) {
        for param in generics.params {
            match param.kind {
                hir::GenericParamKind::Lifetime { .. } => {},
                // An `impl Fn` parameter: a closure handed in.
                hir::GenericParamKind::Type { synthetic: true, .. } if closure_param(cx, generics, param) => {},
                _ => reject(cx, RR_NO_GENERICS, param.span, "type/const generic parameters"),
            }
        }
        if generics.has_where_clause_predicates {
            reject(cx, RR_SIMPLE_TRAITS, generics.where_clause_span, "where clauses");
        }
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::Item<'tcx>) {
        match item.kind {
            hir::ItemKind::Trait { bounds, .. } if !bounds.is_empty() => {
                reject(cx, RR_SIMPLE_TRAITS, item.span, "supertraits");
            },
            hir::ItemKind::Impl(implementation)
                if implementation
                    .of_trait
                    .is_some_and(|header| header.safety == hir::Safety::Unsafe) =>
            {
                require_included_unsafe_reason(cx, item.span);
            },
            hir::ItemKind::TraitAlias(..) => reject(cx, RR_SIMPLE_TRAITS, item.span, "trait aliases"),
            hir::ItemKind::Macro(..) => reject(cx, RR_NO_MACROS, item.span, "macro definitions"),
            _ => {},
        }
    }

    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: hir::intravisit::FnKind<'tcx>,
        _: &'tcx hir::FnDecl<'tcx>,
        _: &'tcx hir::Body<'tcx>,
        span: Span,
        _: LocalDefId,
    ) {
        if kind
            .header()
            .is_some_and(|header| header.safety == hir::HeaderSafety::Normal(hir::Safety::Unsafe))
        {
            require_included_unsafe_reason(cx, span);
        }
    }

    fn check_trait_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx hir::TraitItem<'tcx>) {
        if matches!(item.kind, hir::TraitItemKind::Type(..)) {
            reject(cx, RR_SIMPLE_TRAITS, item.span, "associated types");
        }
    }

    fn check_ty(&mut self, cx: &LateContext<'tcx>, ty: &'tcx hir::Ty<'tcx, AmbigArg>) {
        match ty.kind {
            hir::TyKind::TraitObject(bounds, ..) => {
                // A trait of the crate: every implementation is here, and
                // the call graph follows a call through dyn to each. `Send`
                // and `Sync` run nothing: the compiler checks them.
                if !bounds.iter().all(|bound| {
                    bound
                        .trait_ref
                        .trait_def_id()
                        .is_some_and(|id| id.is_local() || cx.tcx.trait_is_auto(id))
                }) && super::builtins::is_user_code(ty.span)
                {
                    span_lint_and_help(
                        cx,
                        RR_SIMPLE_TRAITS,
                        ty.span,
                        "dyn of a trait from another crate is forbidden by rr",
                        None,
                        "dyn may name a trait of this crate, whose implementations rr sees; pass a closure as `impl Fn` instead",
                    );
                }
            },
            hir::TyKind::OpaqueDef(opaque) if !returned_iterator(cx, ty.hir_id, opaque) => {
                reject(cx, RR_NO_GENERICS, ty.span, "impl Trait");
            },
            _ => {},
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx hir::Expr<'tcx>) {
        if let hir::ExprKind::Closure(closure) = expr.kind
            && matches!(
                closure.kind,
                hir::ClosureKind::Coroutine(hir::CoroutineKind::Desugared(
                    hir::CoroutineDesugaring::Async | hir::CoroutineDesugaring::AsyncGen,
                    _
                )) | hir::ClosureKind::CoroutineClosure(
                    hir::CoroutineDesugaring::Async | hir::CoroutineDesugaring::AsyncGen
                )
            )
        {
            reject(cx, RR_NO_GENERICS, expr.span, "async/await");
        }
    }
}

/// Whether the synthetic parameter of an `impl Trait` argument is bound
/// by one of the closure traits, and otherwise only by `Send` and `Sync`,
/// the compiler's marks that it may go to another thread, which run
/// nothing.
fn closure_param(cx: &LateContext<'_>, generics: &hir::Generics<'_>, param: &hir::GenericParam<'_>) -> bool {
    let items = cx.tcx.lang_items();
    let closures = [items.fn_trait(), items.fn_mut_trait(), items.fn_once_trait()];
    let mut count = 0;
    for bound in generics
        .bounds_for_param(param.def_id)
        .flat_map(|predicate| predicate.bounds)
    {
        let hir::GenericBound::Trait(poly) = bound else {
            continue;
        };
        match poly.trait_ref.trait_def_id() {
            Some(id) if cx.tcx.trait_is_auto(id) => {},
            id @ Some(_) if closures.contains(&id) => count += 1,
            _ => return false,
        }
    }
    count == 1
}

/// Whether an opaque type is the whole return type of a function or an
/// inherent method, not of a trait's, bound by core's `Iterator<Item = T>`
/// alone, perhaps with `DoubleEndedIterator`, `ExactSizeIterator`,
/// lifetimes and `use<..>` of lifetimes. MIR after analysis has the type
/// it hides, so the call graph and the hot path follow what it runs.
fn returned_iterator(cx: &LateContext<'_>, id: hir::HirId, opaque: &hir::OpaqueTy<'_>) -> bool {
    let hir::OpaqueTyOrigin::FnReturn {
        parent,
        in_trait_or_impl: None,
    } = opaque.origin
    else {
        return false;
    };
    let whole = cx
        .tcx
        .hir_fn_decl_by_hir_id(cx.tcx.local_def_id_to_hir_id(parent))
        .is_some_and(|decl| matches!(decl.output, hir::FnRetTy::Return(out) if out.hir_id == id));
    if !whole {
        return false;
    }
    let iterator = cx.tcx.get_diagnostic_item(rustc_span::sym::Iterator);
    let mut iterators = 0;
    for bound in opaque.bounds {
        match bound {
            hir::GenericBound::Trait(poly) => {
                let Some(def) = poly.trait_ref.trait_def_id() else {
                    return false;
                };
                if !poly.bound_generic_params.is_empty() {
                    return false;
                }
                let args = poly.trait_ref.path.segments.last().map(hir::PathSegment::args);
                let bare = args.is_none_or(|a| a.args.is_empty() && a.constraints.is_empty());
                let path = cx.tcx.def_path_str(def);
                if Some(def) == iterator
                    && let Some(args) = args
                    && args.args.is_empty()
                    && let [item] = args.constraints
                    && item.ident.name.as_str() == "Item"
                    && matches!(
                        item.kind,
                        hir::AssocItemConstraintKind::Equality { term: hir::Term::Ty(_) }
                    )
                {
                    iterators += 1;
                } else if !(bare
                    && path
                        .strip_prefix("core::iter::")
                        .is_some_and(|name| super::syntax::ITERATOR_EXTRAS.contains(&name)))
                {
                    return false;
                }
            },
            hir::GenericBound::Outlives(_) => {},
            hir::GenericBound::Use(args, _) => {
                if !args
                    .iter()
                    .all(|arg| matches!(arg, hir::PreciseCapturingArgKind::Lifetime(_)))
                {
                    return false;
                }
            },
        }
    }
    iterators == 1
}

fn require_included_unsafe_reason(cx: &LateContext<'_>, span: Span) {
    if super::builtins::is_user_code(span) && !super::comments::has_escape_reason(cx, span, span, "unsafe") {
        span_lint_and_then(
            cx,
            RR_UNEXPLAINED_ESCAPE,
            span,
            "unsafe declaration in included source needs a safety justification",
            |diag| super::comments::note(diag, cx.sess(), span, span, "unsafe"),
        );
    }
}
