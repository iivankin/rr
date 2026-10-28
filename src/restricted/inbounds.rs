//! An index a function computed from the length of the slice it indexes,
//! and from nothing it was given or read: `ids.get(ids.len() - 1)`, the
//! counter of a loop over `0..ids.len()`, the index `enumerate` gives. Out
//! of bounds, it is a bug in the function, not bad input, and
//! `get(..).ok_or(Error)` reports the bug as bad input.

use clippy_utils::higher::{ForLoop, Range};
use rustc_data_structures::fx::{FxHashMap, FxIndexMap, FxIndexSet};
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::LocalDefId;
use rustc_hir::intravisit::{Visitor, walk_expr};
use rustc_hir::{BorrowKind, Expr, ExprKind, HirId, LetStmt, MatchSource, Mutability, PatKind, QPath, UnOp};
use rustc_lint::LateContext;
use rustc_middle::hir::nested_filter;
use rustc_middle::ty::{self, TyCtxt};
use rustc_span::{Symbol, sym};

/// A place: a local and the fields under it, `self.items`.
type Place = (HirId, Vec<Symbol>);

/// The places whose lengths a value is computed from; `None` when it is
/// computed from something else as well.
type Lengths = Option<FxIndexSet<Place>>;

/// Methods whose result is computed from their receiver and arguments
/// alone.
const ARITHMETIC: [&str; 20] = [
    "checked_add",
    "checked_sub",
    "checked_mul",
    "checked_div",
    "checked_rem",
    "checked_shl",
    "checked_shr",
    "saturating_add",
    "saturating_sub",
    "saturating_mul",
    "wrapping_add",
    "wrapping_sub",
    "wrapping_mul",
    "min",
    "max",
    "pow",
    "abs_diff",
    "div_ceil",
    "ilog2",
    "unwrap_or",
];

/// The locals of one function, and the lengths each is computed from.
#[derive(Default)]
pub struct Locals {
    owner: Option<LocalDefId>,
    lengths: FxHashMap<HirId, Lengths>,
}

impl Locals {
    /// The slice e indexes, when e is `x.get(i).ok_or(..)` with i
    /// computed from x's length alone.
    pub fn own_index(&mut self, cx: &LateContext<'_>, e: &Expr<'_>) -> Option<Symbol> {
        let ExprKind::MethodCall(segment, mut receiver, ..) = e.kind else {
            return None;
        };
        if !matches!(segment.ident.as_str(), "ok_or" | "ok_or_else") {
            return None;
        }
        if let ExprKind::MethodCall(copied, inner, [], _) = receiver.kind
            && matches!(copied.ident.as_str(), "copied" | "cloned")
        {
            receiver = inner;
        }
        let ExprKind::MethodCall(get, base, [index], _) = receiver.kind else {
            return None;
        };
        let indexed = cx.typeck_results().expr_ty(base).peel_refs();
        let sequence = match indexed.kind() {
            ty::Slice(_) | ty::Array(..) => true,
            ty::Adt(adt, _) => cx.tcx.is_diagnostic_item(sym::Vec, adt.did()),
            _ => false,
        };
        if !sequence || !matches!(get.ident.as_str(), "get" | "get_mut") {
            return None;
        }
        // A range with both ends, `2..len - 4`, is empty and out of bounds
        // when the slice is short: by the input.
        if Range::hir(cx, index).is_some_and(|range| range.start.is_some() && range.end.is_some()) {
            return None;
        }
        let place = place(base)?;
        let root = cx
            .tcx
            .typeck_root_def_id_local(cx.tcx.hir_enclosing_body_owner(e.hir_id));
        if self.owner != Some(root) {
            *self = Self::of(cx, root);
        }
        let name = place.1.last().copied().or_else(|| match cx.tcx.hir_node(place.0) {
            rustc_hir::Node::Pat(pat) => match pat.kind {
                PatKind::Binding(_, _, ident, _) => Some(ident.name),
                _ => None,
            },
            _ => None,
        })?;
        self.expr(cx, index)?.contains(&place).then_some(name)
    }

    /// The lengths each local of the function root is computed from.
    fn of(cx: &LateContext<'_>, root: LocalDefId) -> Self {
        let tcx = cx.tcx;
        let mut sources = Sources {
            tcx,
            of: FxIndexMap::default(),
        };
        sources.visit_body(tcx.hir_body_owned_by(root));
        let mut locals = Self {
            owner: Some(root),
            lengths: sources.of.keys().map(|&id| (id, Some(FxIndexSet::default()))).collect(),
        };
        // Lengths only grow, and None stays: the loop ends.
        loop {
            let mut changed = false;
            for (&id, list) in &sources.of {
                let mut all = Some(FxIndexSet::default());
                for source in list {
                    all = match (all, locals.source(cx, source)) {
                        (Some(mut a), Some(b)) => {
                            a.extend(b);
                            Some(a)
                        },
                        _ => None,
                    };
                }
                if locals.lengths.get(&id) != Some(&all) {
                    locals.lengths.insert(id, all);
                    changed = true;
                }
            }
            if !changed {
                return locals;
            }
        }
    }

    fn source(&self, cx: &LateContext<'_>, source: &Source<'_>) -> Lengths {
        match *source {
            Source::Value(e) => self.expr(cx, e),
            Source::Iterator(e) => self.iterator(cx, e),
            Source::Position(e) => {
                let mut e = e;
                while let ExprKind::MethodCall(_, inner, [], _) = e.kind {
                    e = inner;
                    if let Some(place) = place(e) {
                        return Some(FxIndexSet::from_iter([place]));
                    }
                }
                Some(FxIndexSet::default())
            },
            Source::Unknown => None,
        }
    }

    /// The lengths a counter takes its values from: a range, reversed or
    /// stepped.
    fn iterator(&self, cx: &LateContext<'_>, e: &Expr<'_>) -> Lengths {
        match e.kind {
            ExprKind::MethodCall(segment, inner, [], _) if matches!(segment.ident.as_str(), "rev" | "into_iter") => {
                self.iterator(cx, inner)
            },
            ExprKind::MethodCall(segment, inner, [step], _) if segment.ident.as_str() == "step_by" => {
                union(self.iterator(cx, inner), self.expr(cx, step))
            },
            _ => self.expr(cx, e),
        }
    }

    fn expr(&self, cx: &LateContext<'_>, e: &Expr<'_>) -> Lengths {
        if let Some(range) = Range::hir(cx, e) {
            let start = range.start.map_or(Some(FxIndexSet::default()), |s| self.expr(cx, s));
            let end = range.end.map_or(Some(FxIndexSet::default()), |s| self.expr(cx, s));
            return union(start, end);
        }
        match e.kind {
            ExprKind::Lit(_) | ExprKind::Path(QPath::TypeRelative(..)) => Some(FxIndexSet::default()),
            ExprKind::Path(QPath::Resolved(_, path)) => match path.res {
                Res::Local(id) => self.lengths.get(&id).cloned().flatten(),
                Res::Def(DefKind::Const { .. } | DefKind::AssocConst { .. }, _) => Some(FxIndexSet::default()),
                _ => None,
            },
            ExprKind::Binary(_, l, r) => union(self.expr(cx, l), self.expr(cx, r)),
            ExprKind::Unary(UnOp::Neg | UnOp::Not, x) | ExprKind::Cast(x, _) | ExprKind::DropTemps(x) => {
                self.expr(cx, x)
            },
            ExprKind::Block(block, _) if block.stmts.is_empty() => self.expr(cx, block.expr?),
            ExprKind::MethodCall(segment, receiver, args, _) => match segment.ident.as_str() {
                "len" if args.is_empty() => Some(place(receiver).into_iter().collect()),
                "ok_or" | "ok_or_else" | "unwrap" | "expect" => self.expr(cx, receiver),
                name if ARITHMETIC.contains(&name) => union(self.expr(cx, receiver), self.all(cx, args)),
                _ => None,
            },
            // `usize::from(x)` and `usize::try_from(x)` convert.
            ExprKind::Call(f, args) => {
                let name = match f.kind {
                    ExprKind::Path(QPath::Resolved(_, path)) => path.segments.last().map(|s| s.ident.name),
                    ExprKind::Path(QPath::TypeRelative(_, segment)) => Some(segment.ident.name),
                    _ => None,
                }?;
                if !matches!(name.as_str(), "from" | "try_from") {
                    return None;
                }
                self.all(cx, args)
            },
            // `x?` matches on `Try::branch(x)`.
            ExprKind::Match(scrutinee, _, MatchSource::TryDesugar(_)) => match scrutinee.kind {
                ExprKind::Call(_, [inner]) => self.expr(cx, inner),
                _ => None,
            },
            _ => None,
        }
    }
}

impl Locals {
    fn all(&self, cx: &LateContext<'_>, exprs: &[Expr<'_>]) -> Lengths {
        let mut out = FxIndexSet::default();
        for e in exprs {
            out.extend(self.expr(cx, e)?);
        }
        Some(out)
    }
}

fn union(a: Lengths, b: Lengths) -> Lengths {
    let mut a = a?;
    a.extend(b?);
    Some(a)
}

/// The place e names: a local and its fields, through references and
/// derefs.
fn place(e: &Expr<'_>) -> Option<Place> {
    match e.kind {
        ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(UnOp::Deref, inner) => place(inner),
        ExprKind::MethodCall(segment, inner, [], _)
            if matches!(
                segment.ident.as_str(),
                "as_slice" | "as_mut_slice" | "as_ref" | "as_mut"
            ) =>
        {
            place(inner)
        },
        ExprKind::Path(QPath::Resolved(_, path)) => match path.res {
            Res::Local(id) => Some((id, Vec::new())),
            _ => None,
        },
        ExprKind::Field(inner, ident) => {
            let (id, mut fields) = place(inner)?;
            fields.push(ident.name);
            Some((id, fields))
        },
        _ => None,
    }
}

/// Where a local's value comes from.
enum Source<'tcx> {
    Value(&'tcx Expr<'tcx>),
    /// Each item of an iterator.
    Iterator(&'tcx Expr<'tcx>),
    /// The position `enumerate` gives, in what it enumerates.
    Position(&'tcx Expr<'tcx>),
    /// Something rr does not follow: lent mutably, or set elsewhere.
    Unknown,
}

/// Each local a function binds by name, with each value it takes.
struct Sources<'tcx> {
    tcx: TyCtxt<'tcx>,
    of: FxIndexMap<HirId, Vec<Source<'tcx>>>,
}

impl<'tcx> Sources<'tcx> {
    fn add(&mut self, e: &Expr<'_>, source: Source<'tcx>) {
        if let ExprKind::Path(QPath::Resolved(_, path)) = e.kind
            && let Res::Local(id) = path.res
            && let Some(list) = self.of.get_mut(&id)
        {
            list.push(source);
        }
    }
}

impl<'tcx> Visitor<'tcx> for Sources<'tcx> {
    type NestedFilter = nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_local(&mut self, local: &'tcx LetStmt<'tcx>) {
        if let PatKind::Binding(_, id, _, None) = local.pat.kind {
            self.of.insert(id, local.init.into_iter().map(Source::Value).collect());
        }
        rustc_hir::intravisit::walk_local(self, local);
    }

    fn visit_expr(&mut self, e: &'tcx Expr<'tcx>) {
        if let Some(each) = ForLoop::hir(e) {
            match each.pat.kind {
                PatKind::Binding(_, id, _, None) => {
                    self.of.insert(id, vec![Source::Iterator(each.arg)]);
                },
                PatKind::Tuple([position, ..], _)
                    if let PatKind::Binding(_, id, _, None) = position.kind
                        && let ExprKind::MethodCall(segment, inner, [], _) = each.arg.kind
                        && segment.ident.as_str() == "enumerate" =>
                {
                    self.of.insert(id, vec![Source::Position(inner)]);
                },
                _ => {},
            }
        }
        match e.kind {
            ExprKind::Assign(lhs, rhs, _) | ExprKind::AssignOp(_, lhs, rhs) => self.add(lhs, Source::Value(rhs)),
            ExprKind::AddrOf(BorrowKind::Ref | BorrowKind::Raw, Mutability::Mut, inner) => {
                self.add(inner, Source::Unknown);
            },
            _ => {},
        }
        walk_expr(self, e);
    }
}
