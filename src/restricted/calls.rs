//! The crate's call graph, read from MIR, where every call is explicit: an
//! operator, an index, a deref, the `next` of a `for` loop and the
//! destructor run at a drop are calls there like any other, and a call
//! that was inlined is still recorded in the scope it was inlined into. A
//! call through a function pointer may reach every local function whose
//! address is taken with that signature; a call through dyn or a generic
//! parameter, every local body of the method; a call into foreign code,
//! every function whose pointer it is given, alone or within what an
//! argument holds or points to; a function or closure handed
//! to other code may be called by it; and a value moved into a function
//! outside the crate may be dropped there. A closure is part of the
//! function it is written in: what it calls, that function calls.

use clippy_utils::visitors::for_each_expr;
use core::ops::ControlFlow;
use rustc_data_structures::fx::{FxHashMap, FxHashSet, FxIndexMap};
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::intravisit::{Visitor, walk_expr, walk_pat};
use rustc_hir::{Expr, ExprKind, HirId, Node, Pat};
use rustc_lint::LateContext;
use rustc_middle::hir::nested_filter;
use rustc_middle::mir::{Body, Operand, SourceScope, TerminatorKind};
use rustc_middle::ty::adjustment::{Adjust, PointerCoercion};
use rustc_middle::ty::{self, FnSig, Instance, InstanceKind, Ty, TyCtxt, TypingEnv};
use rustc_span::Span;

/// How a function reaches another.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// A call written as one.
    Call,
    /// An operator, an index, a deref or a `for` loop.
    Implicit,
    /// The destructor of a value dropped here.
    Drop,
    /// Through a function pointer, dyn or a generic parameter.
    Indirect,
    /// Handed to other code, which may call it.
    Handed,
    /// Called back from foreign code.
    Foreign,
}

/// One way a function of the crate reaches another.
pub struct Call {
    pub to: LocalDefId,
    pub span: Span,
    pub id: HirId,
    pub how: How,
}

impl Call {
    /// What the call does, from its caller, with to named as given.
    pub fn verb(&self, to: &str) -> String {
        match self.how {
            How::Call => format!("calls {to}"),
            How::Implicit => format!("calls {to} implicitly, through an operator, index, deref or `for`"),
            How::Drop => format!("runs {to} when this value is dropped"),
            How::Indirect => format!("may call {to} through this indirect call"),
            How::Handed => format!("hands {to} to code that may call it"),
            How::Foreign => format!("calls foreign code here that may call back {to}"),
        }
    }

    /// For a path of calls, how this step goes on to to.
    pub fn through(&self, to: &str) -> String {
        match self.how {
            How::Call => format!("through this call to {to}"),
            How::Implicit => format!("through this implicit call to {to}"),
            How::Drop => format!("through the drop of this value, which runs {to}"),
            How::Indirect => format!("through this indirect call, which may reach {to}"),
            How::Handed => format!("through {to}, handed here to code that may call it"),
            How::Foreign => format!("through this foreign call, which may call {to} back"),
        }
    }
}

/// A function of the crate by name, in backticks.
pub fn name(tcx: TyCtxt<'_>, def: LocalDefId) -> String {
    let def = def.to_def_id();
    if tcx.def_kind(def) == DefKind::AssocFn {
        format!("`{}`", tcx.def_path_str(def))
    } else {
        format!("`{}`", tcx.item_name(def))
    }
}

pub struct Graph {
    calls: FxIndexMap<LocalDefId, Vec<Call>>,
    /// The functions with a body, in the crate's order.
    pub fns: Vec<LocalDefId>,
}

impl Graph {
    pub fn new(cx: &LateContext<'_>) -> Self {
        let tcx = cx.tcx;
        let owners: Vec<LocalDefId> = tcx.hir_body_owners().collect();
        let bodies: Vec<LocalDefId> = owners
            .iter()
            .copied()
            .filter(|&o| tcx.hir_body_owner_kind(o).is_fn_or_closure())
            .collect();
        let mut build = Build {
            tcx,
            calls: FxIndexMap::default(),
            seen: FxHashSet::default(),
            pointers: FxHashMap::default(),
            bodies: FxHashMap::default(),
            drops: Vec::new(),
            owned: FxHashMap::default(),
            spans: FxHashMap::default(),
        };
        let drop_trait = tcx.lang_items().drop_trait();
        for &f in &bodies {
            if let Some(item) = tcx.trait_item_of(f) {
                build.bodies.entry(item).or_default().push(f);
                if tcx.trait_of_assoc(item) == drop_trait {
                    build.drops.push(f);
                }
            } else if tcx.def_kind(f) == DefKind::AssocFn && tcx.trait_of_assoc(f.to_def_id()).is_some() {
                // A trait's own default body.
                build.bodies.entry(f.to_def_id()).or_default().push(f);
            }
        }
        for &owner in &owners {
            build.mentions(owner);
        }
        for &f in &bodies {
            build.mir(f);
        }
        for calls in build.calls.values_mut() {
            let direct: FxHashSet<LocalDefId> = calls.iter().filter(|c| c.how != How::Handed).map(|c| c.to).collect();
            calls.retain(|c| c.how != How::Handed || !direct.contains(&c.to));
        }
        let fns = bodies
            .into_iter()
            .filter(|&f| !tcx.is_closure_like(f.to_def_id()))
            .collect();
        Self {
            calls: build.calls,
            fns,
        }
    }

    pub fn from(&self, f: LocalDefId) -> &[Call] {
        self.calls.get(&f).map_or(&[], Vec::as_slice)
    }
}

struct Build<'tcx> {
    tcx: TyCtxt<'tcx>,
    calls: FxIndexMap<LocalDefId, Vec<Call>>,
    /// Calls already recorded: a handed function once per caller, any
    /// other once per place.
    seen: FxHashSet<(LocalDefId, LocalDefId, Option<Span>)>,
    /// Local functions whose address is taken, by the pointer's signature.
    pointers: FxHashMap<FnSig<'tcx>, Vec<LocalDefId>>,
    /// The local bodies of each trait method: the impls' and its default.
    bodies: FxHashMap<DefId, Vec<LocalDefId>>,
    /// Every local `Drop::drop`.
    drops: Vec<LocalDefId>,
    /// The local destructors a value of each type runs when dropped.
    owned: FxHashMap<Ty<'tcx>, Vec<LocalDefId>>,
    /// The expressions and patterns of each body, by span.
    spans: FxHashMap<LocalDefId, FxHashMap<Span, HirId>>,
}

impl<'tcx> Build<'tcx> {
    fn push(&mut self, from: LocalDefId, mut call: Call) {
        let from = self.function(from);
        let to = self.function(call.to);
        if to == from && to != call.to {
            // A closure of its own: its body is from's.
            return;
        }
        call.to = to;
        let at = (call.how != How::Handed).then_some(call.span);
        if self.seen.insert((from, to, at)) {
            self.calls.entry(from).or_default().push(call);
        }
    }

    /// The function whose code f is: itself, or for a closure the
    /// function it is written in.
    fn function(&self, f: LocalDefId) -> LocalDefId {
        self.tcx.typeck_root_def_id(f.to_def_id()).expect_local()
    }

    /// A local function named as a value: turned into a pointer, it joins
    /// what calls through pointers may reach; handed on as itself, as a
    /// closure is, the body it appears in may have it called.
    fn mentions(&mut self, owner: LocalDefId) {
        let tcx = self.tcx;
        let Some(body) = tcx.hir_maybe_body_owned_by(owner) else {
            return;
        };
        let typeck = tcx.typeck(owner);
        let caller = tcx.hir_body_owner_kind(owner).is_fn_or_closure();
        let mut handed = Vec::new();
        for_each_expr(tcx, body.value, |e| {
            let def = match e.kind {
                ExprKind::Closure(closure) => Some(closure.def_id),
                ExprKind::Path(ref path) if !is_callee(tcx, e) => match typeck.qpath_res(path, e.hir_id) {
                    Res::Def(DefKind::Fn | DefKind::AssocFn, def) => def.as_local(),
                    _ => None,
                },
                _ => None,
            };
            let Some(def) = def else {
                return ControlFlow::<()>::Continue(());
            };
            let pointer = typeck.expr_adjustments(e).iter().find_map(|a| match a.kind {
                Adjust::Pointer(PointerCoercion::ReifyFnPointer(_) | PointerCoercion::ClosureFnPointer(_)) => {
                    Some(a.target)
                },
                _ => None,
            });
            match pointer {
                Some(target) => {
                    let sig = erased_sig(tcx, target);
                    self.pointers.entry(sig).or_default().push(def);
                },
                None if caller => handed.push((def, e.span, e.hir_id)),
                None => {},
            }
            ControlFlow::Continue(())
        });
        for (to, span, id) in handed {
            self.push(
                owner,
                Call {
                    to,
                    span,
                    id,
                    how: How::Handed,
                },
            );
        }
    }

    fn mir(&mut self, owner: LocalDefId) {
        let tcx = self.tcx;
        if !tcx.is_mir_available(owner) {
            return;
        }
        let body = tcx.optimized_mir(owner);
        let env = TypingEnv::post_analysis(tcx, owner);
        for data in body.basic_blocks.iter() {
            let term = data.terminator();
            let scope = term.source_info.scope;
            let (from, over) = attribute(body, root(body, scope), owner);
            match &term.kind {
                TerminatorKind::Call { func, args, .. } | TerminatorKind::TailCall { func, args, .. } => {
                    let span = over.unwrap_or(term.source_info.span);
                    let ty = func.ty(body, tcx);
                    let targets = self.targets(env, ty);
                    let foreign = matches!(*ty.kind(), ty::FnDef(def, _) if tcx.is_foreign_item(def));
                    let inside = !targets.is_empty() || ty.is_fn_ptr() || foreign;
                    for (to, how) in targets {
                        let how = if over.is_some() { How::Handed } else { how };
                        self.at(from, body, scope, to, span, how);
                    }
                    // Foreign code may call back what it is given.
                    if foreign {
                        for arg in args {
                            for to in self.given(env, arg.node.ty(body, tcx)) {
                                self.at(from, body, scope, to, span, How::Foreign);
                            }
                        }
                    }
                    // A value moved into a function of another crate.
                    if !inside {
                        for arg in args {
                            if let Operand::Move(place) = &arg.node {
                                let ty = place.ty(body, tcx).ty;
                                for to in self.destructors(env, ty) {
                                    self.at(from, body, scope, to, span, How::Drop);
                                }
                            }
                        }
                    }
                },
                TerminatorKind::Drop { place, .. } => {
                    let span = over.unwrap_or(body.local_decls[place.local].source_info.span);
                    let ty = place.ty(body, tcx).ty;
                    for to in self.destructors(env, ty) {
                        self.at(from, body, scope, to, span, How::Drop);
                    }
                },
                _ => {},
            }
        }
        // Calls the optimizer inlined: each leaves the scope it became.
        for (scope, data) in body.source_scopes.iter_enumerated() {
            let Some((instance, call)) = data.inlined else {
                continue;
            };
            let InstanceKind::Item(def) = instance.def else {
                continue;
            };
            let Some(to) = def.as_local() else { continue };
            let (from, over) = attribute(body, data.inlined_parent_scope, owner);
            let how = if over.is_some() { How::Handed } else { How::Call };
            self.at(from, body, scope, to, over.unwrap_or(call), how);
        }
    }

    /// Record a call at span from from, with the expression there, and a
    /// call that is not written as one marked implicit.
    fn at(&mut self, from: LocalDefId, body: &Body<'tcx>, scope: SourceScope, to: LocalDefId, span: Span, how: How) {
        let tcx = self.tcx;
        let from = self.function(from);
        let id = self.spans(from).get(&span).copied().unwrap_or_else(|| {
            scope
                .lint_root(&body.source_scopes)
                .filter(|id| id.owner.def_id == from)
                .unwrap_or_else(|| tcx.local_def_id_to_hir_id(from))
        });
        let how = match how {
            How::Call
                if !matches!(tcx.hir_node(id), Node::Expr(e)
                    if e.span == span
                        && e.span.desugaring_kind().is_none()
                        && matches!(e.kind, ExprKind::Call(..) | ExprKind::MethodCall(..))) =>
            {
                How::Implicit
            },
            how => how,
        };
        self.push(from, Call { to, span, id, how });
    }

    fn spans(&mut self, f: LocalDefId) -> &FxHashMap<Span, HirId> {
        let tcx = self.tcx;
        self.spans.entry(f).or_insert_with(|| {
            let mut spans = Spans {
                tcx,
                map: FxHashMap::default(),
            };
            if let Some(body) = tcx.hir_maybe_body_owned_by(f) {
                spans.visit_body(body);
            }
            spans.map
        })
    }

    /// The local functions a call to a value of type ty may run, and how.
    fn targets(&self, env: TypingEnv<'tcx>, ty: Ty<'tcx>) -> Vec<(LocalDefId, How)> {
        let tcx = self.tcx;
        match *ty.kind() {
            ty::FnDef(def, args) => {
                if tcx.trait_of_assoc(def).is_none() {
                    return def.as_local().map(|d| (d, How::Call)).into_iter().collect();
                }
                let every = || {
                    self.bodies
                        .get(&def)
                        .map_or(&[][..], Vec::as_slice)
                        .iter()
                        .map(|&d| (d, How::Indirect))
                        .collect()
                };
                match Instance::try_resolve(tcx, env, def, tcx.instantiate_bound_regions_with_erased(args)) {
                    Ok(Some(instance)) => match instance.def {
                        InstanceKind::Item(d) => d.as_local().map(|d| (d, How::Call)).into_iter().collect(),
                        InstanceKind::Virtual(..) => every(),
                        _ => Vec::new(),
                    },
                    Ok(None) => every(),
                    Err(_) => Vec::new(),
                }
            },
            ty::FnPtr(..) => self
                .pointers
                .get(&erased_sig(tcx, ty))
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|&d| (d, How::Indirect))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The local functions a value of type ty may lead to as pointers: in
    /// it, in what it holds and in what it points to.
    fn given(&self, env: TypingEnv<'tcx>, ty: Ty<'tcx>) -> Vec<LocalDefId> {
        let tcx = self.tcx;
        let mut seen = FxHashSet::default();
        let mut todo = vec![tcx.erase_and_anonymize_regions(ty)];
        let mut out = Vec::new();
        while let Some(ty) = todo.pop()
            && seen.len() < 4096
        {
            if !seen.insert(ty) {
                continue;
            }
            match *ty.kind() {
                ty::FnPtr(..) => {
                    out.extend(self.pointers.get(&erased_sig(tcx, ty)).map_or(&[][..], Vec::as_slice));
                },
                ty::Ref(_, t, _) | ty::RawPtr(t, _) | ty::Array(t, _) | ty::Slice(t) => todo.push(t),
                ty::Tuple(tys) => todo.extend(tys),
                ty::Adt(adt, args) => todo.extend(adt.all_fields().map(|field| {
                    let t = tcx.erase_and_anonymize_regions(field.ty(tcx, args).skip_norm_wip());
                    tcx.try_normalize_erasing_regions(env, ty::Unnormalized::new_wip(t))
                        .unwrap_or(t)
                })),
                _ => {},
            }
        }
        out
    }

    /// The local destructors that dropping a value of type ty runs: those
    /// of every type it owns, and every one for a type not known here.
    fn destructors(&mut self, env: TypingEnv<'tcx>, ty: Ty<'tcx>) -> Vec<LocalDefId> {
        if let Some(found) = self.owned.get(&ty) {
            return found.clone();
        }
        let tcx = self.tcx;
        let mut found = FxHashSet::default();
        let mut unknown = false;
        owns(tcx, env, ty, &mut |t| match *t.kind() {
            ty::Adt(adt, _) => {
                if let Some(d) = tcx.adt_destructor(adt.did())
                    && let Some(d) = d.did.as_local()
                {
                    found.insert(d);
                }
            },
            ty::Param(_) | ty::Alias(..) | ty::Dynamic(..) => unknown = true,
            _ => {},
        });
        let out: Vec<LocalDefId> = if unknown {
            self.drops.clone()
        } else {
            self.drops.iter().copied().filter(|d| found.contains(d)).collect()
        };
        self.owned.insert(ty, out.clone());
        out
    }
}

/// Each type a value of type ty owns and drops with it, ty first: the
/// fields of a struct, enum or closure and the element of an array, and
/// for a type of another crate its type arguments as well, such as the
/// element of a Vec. f may see a type twice.
pub fn owns<'tcx>(tcx: TyCtxt<'tcx>, env: TypingEnv<'tcx>, ty: Ty<'tcx>, f: &mut impl FnMut(Ty<'tcx>)) {
    let mut seen = FxHashSet::default();
    let mut todo = vec![tcx.erase_and_anonymize_regions(ty)];
    // A type that nests itself deeper at each level never ends.
    while let Some(ty) = todo.pop()
        && seen.len() < 4096
    {
        if !seen.insert(ty) || !ty.needs_drop(tcx, env) {
            continue;
        }
        f(ty);
        let normal = |t: Ty<'tcx>| {
            let t = tcx.erase_and_anonymize_regions(t);
            tcx.try_normalize_erasing_regions(env, ty::Unnormalized::new_wip(t))
                .unwrap_or(t)
        };
        match *ty.kind() {
            ty::Adt(adt, args) => {
                todo.extend(
                    adt.all_fields()
                        .map(|field| normal(field.ty(tcx, args).skip_norm_wip())),
                );
                if !adt.did().is_local() {
                    todo.extend(args.types());
                }
            },
            ty::Tuple(tys) => todo.extend(tys),
            ty::Array(t, _) | ty::Slice(t) | ty::Pat(t, _) => todo.push(t),
            ty::Closure(_, args) => todo.extend(args.as_closure().upvar_tys()),
            _ => {},
        }
    }
}

/// The innermost scope a call was inlined into, if any, for scope.
fn root(body: &Body<'_>, scope: SourceScope) -> Option<SourceScope> {
    let data = &body.source_scopes[scope];
    if data.inlined.is_some() {
        Some(scope)
    } else {
        data.inlined_parent_scope
    }
}

/// Whose code something in the inlined scope root is: the innermost local
/// function, and when that is not the one inlined there, the call in it
/// through which code of other crates did it.
fn attribute(body: &Body<'_>, root: Option<SourceScope>, owner: LocalDefId) -> (LocalDefId, Option<Span>) {
    let mut over = None;
    let mut at = root;
    while let Some(scope) = at {
        let data = &body.source_scopes[scope];
        let Some((instance, call)) = data.inlined else { break };
        if let InstanceKind::Item(def) = instance.def
            && let Some(local) = def.as_local()
        {
            return (local, over);
        }
        over = Some(call);
        at = data.inlined_parent_scope;
    }
    (owner, over)
}

fn erased_sig<'tcx>(tcx: TyCtxt<'tcx>, ty: Ty<'tcx>) -> FnSig<'tcx> {
    tcx.erase_and_anonymize_regions(tcx.instantiate_bound_regions_with_erased(ty.fn_sig(tcx)))
}

fn is_callee(tcx: TyCtxt<'_>, e: &Expr<'_>) -> bool {
    matches!(tcx.parent_hir_node(e.hir_id), Node::Expr(p)
        if matches!(p.kind, ExprKind::Call(f, _) if f.hir_id == e.hir_id))
}

/// Every expression and pattern of a body by span, the outermost first.
struct Spans<'tcx> {
    tcx: TyCtxt<'tcx>,
    map: FxHashMap<Span, HirId>,
}

impl<'tcx> Visitor<'tcx> for Spans<'tcx> {
    type NestedFilter = nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_expr(&mut self, e: &'tcx Expr<'tcx>) {
        self.map.entry(e.span).or_insert(e.hir_id);
        walk_expr(self, e);
    }

    fn visit_pat(&mut self, p: &'tcx Pat<'tcx>) {
        self.map.entry(p.span).or_insert(p.hir_id);
        walk_pat(self, p);
    }
}
