//! A derive the program never uses is code written for nothing, and the
//! easy habit of an agent: derive everything, in case. Each derived trait
//! of a type must be used somewhere: a call of its method (an operator
//! `==` or `<` is one), a function that requires it of the type (`sort`
//! requires `Ord`, `unwrap` requires the error's `Debug`, `{:?}` requires
//! `Debug`), a copy of a value for `Copy`, a constant of the type in a
//! pattern for `PartialEq`, or a trait that has it as its supertrait or a
//! derive of a type that holds it. What only tests use is derived under
//! `cfg_attr(test, ..)`, and stays out of the program.

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::{BinOpKind, Expr, ExprKind, ItemKind, Node, Pat, PatExprKind, PatKind, QPath, UnOp};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_session::impl_lint_pass;
use rustc_span::hygiene::{ExpnKind, MacroKind};
use rustc_span::{Span, sym};

use super::RR_UNUSED_DERIVE;

#[derive(Default)]
pub struct Derives {
    /// What the program uses outside derived impls.
    used: FxHashSet<Use>,
    /// What the methods of each derived impl use, which counts once the
    /// impl itself is used.
    within: FxHashMap<LocalDefId, FxHashSet<Use>>,
}

impl_lint_pass!(Derives => [RR_UNUSED_DERIVE]);

/// A trait of a type: the type's definition and the trait's.
type Use = (DefId, DefId);

/// A derived impl: what it implements for whom, where it was derived, and
/// the trait's name.
struct Derived {
    of: Use,
    id: LocalDefId,
    span: Span,
    name: String,
}

impl<'tcx> LateLintPass<'tcx> for Derives {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>) {
        let tcx = cx.tcx;
        let traits = Traits::new(tcx);
        let owner = tcx.hir_enclosing_body_owner(e.hir_id);
        let set = match tcx.opt_local_parent(owner) {
            Some(parent) if derived_impl(cx, parent) => self.within.entry(parent).or_default(),
            _ => &mut self.used,
        };
        let mut used = Used {
            tcx,
            traits: &traits,
            set,
        };
        let typeck = cx.typeck_results();
        match e.kind {
            ExprKind::Binary(op, l, _) => {
                let operator = match op.node {
                    BinOpKind::Eq | BinOpKind::Ne => traits.partial_eq,
                    BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge => traits.partial_ord,
                    _ => None,
                };
                if let Some(operator) = operator {
                    used.mark(typeck.expr_ty(l).peel_refs(), operator);
                }
            },
            ExprKind::MethodCall(..) => {
                if let Some(def) = typeck.type_dependent_def_id(e.hir_id) {
                    used.call(def, typeck.node_args(e.hir_id));
                }
            },
            ExprKind::Call(f, _) => {
                if let ExprKind::Path(ref path) = f.kind
                    && let Res::Def(DefKind::Fn | DefKind::AssocFn, def) = typeck.qpath_res(path, f.hir_id)
                {
                    used.call(def, typeck.node_args(f.hir_id));
                }
            },
            _ => {},
        }
        // A value read out of a place by value is a copy, for a Copy type.
        if let Some(copy) = traits.copy
            && read_by_value(cx, e)
        {
            used.mark(typeck.expr_ty(e), copy);
        }
    }

    fn check_pat(&mut self, cx: &LateContext<'tcx>, pat: &'tcx Pat<'tcx>) {
        // A constant of a type of the crate in a pattern compares with it,
        // and needs its PartialEq derived.
        if let PatKind::Expr(expr) = pat.kind
            && let PatExprKind::Path(QPath::Resolved(_, path)) = expr.kind
            && let Res::Def(DefKind::Const { .. } | DefKind::AssocConst { .. }, def) = path.res
            && let Some(partial_eq) = cx.tcx.lang_items().eq_trait()
        {
            let traits = Traits::new(cx.tcx);
            let ty = cx.tcx.type_of(def).instantiate_identity().skip_norm_wip();
            Used {
                tcx: cx.tcx,
                traits: &traits,
                set: &mut self.used,
            }
            .mark(ty, partial_eq);
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let tcx = cx.tcx;
        let derived = derived_impls(cx);
        let traits = Traits::new(tcx);
        let mut done: FxHashSet<LocalDefId> = FxHashSet::default();
        // A derived impl that is used makes what its methods use used, and
        // a used Copy or Eq the same trait of its fields.
        loop {
            let before = self.used.len() + done.len();
            for d in &derived {
                if done.contains(&d.id) || !self.used.contains(&d.of) {
                    continue;
                }
                done.insert(d.id);
                let inner = self.within.remove(&d.id).unwrap_or_default();
                let mut used = Used {
                    tcx,
                    traits: &traits,
                    set: &mut self.used,
                };
                #[allow(rustc::potential_query_instability, reason = "the set is merged whole")]
                for (adt, trait_) in inner {
                    if let Some(local) = adt.as_local() {
                        used.mark(tcx.type_of(local).instantiate_identity().skip_norm_wip(), trait_);
                    }
                }
                used.fields(d.of);
            }
            if self.used.len() + done.len() == before {
                break;
            }
        }
        for d in &derived {
            // A derive writes markers beside the trait it names, such as
            // StructuralPartialEq: the trait it names is what is used.
            if self.used.contains(&d.of) || !traits.derivable(d.of.1) {
                continue;
            }
            // A library's exported type may be used by another crate.
            if let Some(local) = d.of.0.as_local()
                && cx.effective_visibilities.is_exported(local)
                && !tcx
                    .crate_types()
                    .contains(&rustc_session::config::CrateType::Executable)
            {
                continue;
            }
            span_lint_hir_and_then(
                cx,
                RR_UNUSED_DERIVE,
                tcx.local_def_id_to_hir_id(d.id),
                d.span,
                format!(
                    "`{}` is derived for `{}`, and nothing uses it",
                    d.name,
                    tcx.item_name(d.of.0)
                ),
                |diag| {
                    diag.help("remove it; if only tests use it, derive it under `#[cfg_attr(test, derive(..))]`, which keeps it out of the program");
                },
            );
        }
    }
}

/// Whether def is an impl a derive wrote.
fn derived_impl(cx: &LateContext<'_>, def: LocalDefId) -> bool {
    cx.tcx.def_kind(def) == DefKind::Impl { of_trait: true }
        && matches!(
            cx.tcx.def_span(def).ctxt().outer_expn_data().kind,
            ExpnKind::Macro(MacroKind::Derive, _)
        )
}

/// Whether e is a place read by value: a local, a field, an element or
/// what a reference points to, taken whole rather than lent or written.
fn read_by_value(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    let place = match e.kind {
        ExprKind::Path(QPath::Resolved(_, path)) => matches!(
            path.res,
            Res::Local(_) | Res::Def(DefKind::Static { .. } | DefKind::Const { .. }, _)
        ),
        ExprKind::Field(..) | ExprKind::Index(..) | ExprKind::Unary(UnOp::Deref, _) => true,
        _ => false,
    };
    if !place || !cx.typeck_results().expr_adjustments(e).is_empty() {
        return false;
    }
    match cx.tcx.parent_hir_node(e.hir_id) {
        Node::Expr(parent) => match parent.kind {
            ExprKind::AddrOf(..) | ExprKind::Field(..) | ExprKind::Index(..) => false,
            ExprKind::Assign(lhs, ..) | ExprKind::AssignOp(_, lhs, _) => lhs.hir_id != e.hir_id,
            ExprKind::MethodCall(_, receiver, ..) => receiver.hir_id != e.hir_id,
            _ => true,
        },
        Node::LetStmt(_) | Node::ExprField(_) => true,
        _ => false,
    }
}

/// The impls of the crate that a derive wrote, with where it was written.
fn derived_impls(cx: &LateContext<'_>) -> Vec<Derived> {
    let tcx = cx.tcx;
    let mut out = Vec::new();
    for id in tcx.hir_free_items() {
        let item = tcx.hir_item(id);
        let ItemKind::Impl(implementation) = item.kind else {
            continue;
        };
        if implementation.of_trait.is_none() || !item.span.from_expansion() {
            continue;
        }
        let data = item.span.ctxt().outer_expn_data();
        let ExpnKind::Macro(MacroKind::Derive, name) = data.kind else {
            continue;
        };
        if !super::builtins::is_user_code(data.call_site) {
            continue;
        }
        let trait_ref = tcx.impl_trait_ref(item.owner_id).instantiate_identity().skip_norm_wip();
        let ty::Adt(adt, _) = tcx.type_of(item.owner_id).instantiate_identity().skip_norm_wip().kind() else {
            continue;
        };
        out.push(Derived {
            of: (adt.did(), trait_ref.def_id),
            id: item.owner_id.def_id,
            span: data.call_site,
            name: name.to_string(),
        });
    }
    out
}

/// The traits rr lets a program derive, and what each implies.
struct Traits {
    copy: Option<DefId>,
    clone: Option<DefId>,
    partial_eq: Option<DefId>,
    eq: Option<DefId>,
    partial_ord: Option<DefId>,
    ord: Option<DefId>,
    debug: Option<DefId>,
}

impl Traits {
    fn new(tcx: TyCtxt<'_>) -> Self {
        let items = tcx.lang_items();
        Self {
            copy: items.copy_trait(),
            clone: items.clone_trait(),
            partial_eq: items.eq_trait(),
            eq: tcx.get_diagnostic_item(sym::Eq),
            partial_ord: items.partial_ord_trait(),
            ord: tcx.get_diagnostic_item(sym::Ord),
            debug: tcx.get_diagnostic_item(sym::Debug),
        }
    }

    /// The traits that using trait on a type uses as well: its supertraits.
    fn implied(&self, trait_: DefId) -> Vec<DefId> {
        let of = |t: Option<DefId>| t == Some(trait_);
        let list = if of(self.copy) {
            vec![self.clone]
        } else if of(self.ord) {
            vec![self.partial_ord, self.eq, self.partial_eq]
        } else if of(self.partial_ord) || of(self.eq) {
            vec![self.partial_eq]
        } else {
            vec![]
        };
        list.into_iter().flatten().collect()
    }

    /// Whether trait is one that rr lets a program derive.
    fn derivable(&self, trait_: DefId) -> bool {
        [
            self.copy,
            self.clone,
            self.partial_eq,
            self.eq,
            self.partial_ord,
            self.ord,
            self.debug,
        ]
        .contains(&Some(trait_))
    }

    /// Whether a derived trait of a type needs the same trait of the types
    /// its fields hold, with no call that shows it: Copy and Eq.
    fn of_fields(&self, trait_: DefId) -> bool {
        Some(trait_) == self.copy || Some(trait_) == self.eq
    }
}

struct Used<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    traits: &'a Traits,
    set: &'a mut FxHashSet<Use>,
}

impl<'tcx> Used<'_, 'tcx> {
    /// trait used on each type of the crate that ty holds, by value: not
    /// through a reference, which uses the reference's own.
    fn mark(&mut self, ty: Ty<'tcx>, trait_: DefId) {
        let mut todo = vec![ty];
        while let Some(ty) = todo.pop() {
            match *ty.kind() {
                ty::Adt(adt, args) => {
                    if adt.did().is_local() && self.set.insert((adt.did(), trait_)) {
                        for implied in self.traits.implied(trait_) {
                            self.set.insert((adt.did(), implied));
                        }
                    }
                    todo.extend(args.types());
                },
                ty::Tuple(tys) => todo.extend(tys),
                ty::Array(t, _) | ty::Slice(t) => todo.push(t),
                _ => {},
            }
        }
    }

    /// For a derive of Copy or Eq that is used: the same trait of the types
    /// its fields hold.
    fn fields(&mut self, (adt, trait_): Use) {
        if !self.traits.of_fields(trait_) {
            return;
        }
        let tcx = self.tcx;
        let def = tcx.adt_def(adt);
        for field in def.all_fields() {
            let ty = tcx.type_of(field.did).instantiate_identity().skip_norm_wip();
            self.mark(ty, trait_);
        }
    }

    /// A call of def with args: the trait method it resolves to, and what
    /// def requires of the types it is given.
    fn call(&mut self, def: DefId, args: ty::GenericArgsRef<'tcx>) {
        let tcx = self.tcx;
        if let Some(trait_) = tcx.trait_of_assoc(def)
            && let Some(self_ty) = args.types().next()
        {
            self.mark(self_ty, trait_);
        }
        // What typeck recorded for the call covers all of def's parameters,
        // or the call is not one of those this looks into.
        if args.len() != tcx.generics_of(def).count() {
            return;
        }
        let clauses = tcx.clauses_of(def).instantiate(tcx, args);
        for clause in clauses.clauses {
            if let Some(predicate) = clause.skip_norm_wip().as_trait_clause() {
                let predicate = predicate.skip_binder();
                self.mark(predicate.self_ty(), predicate.def_id());
            }
        }
    }
}
