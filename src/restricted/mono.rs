//! The instantiations of the crate's const-generic code: from functions
//! that are not generic, each call, function value, closure, drop and
//! dyn coercion of their MIR, with the caller's arguments put in, leads to
//! a function with all its arguments known, and so on from there, as the
//! compiler's collector does before codegen. A check that needs a size,
//! which a generic body does not have, takes it from each instantiation;
//! where rr finds none, it says it cannot check rather than skip.

use rustc_data_structures::fx::{FxHashSet, FxIndexMap};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_lint::LintContext as _;
use rustc_middle::mir::visit::{TyContext, Visitor};
use rustc_middle::mir::{CastKind, ConstOperand, Location, Rvalue, Terminator, TerminatorKind};
use rustc_middle::ty::adjustment::PointerCoercion;
use rustc_middle::ty::{
    self, EarlyBinder, GenericArgsRef, Instance, InstanceKind, Ty, TyCtxt, TypeVisitableExt as _, TypingEnv,
};

/// The most instantiations rr follows from one set of roots.
const INSTANCES_MAX: usize = 1 << 16;

/// What the walk found: with which arguments each generic function of
/// the crate runs, closures under the function that writes them, and with
/// which each generic type of the crate is used.
#[derive(Default)]
pub struct Instances<'tcx> {
    pub fns: FxIndexMap<LocalDefId, Vec<GenericArgsRef<'tcx>>>,
    pub adts: FxIndexMap<DefId, Vec<GenericArgsRef<'tcx>>>,
    /// Every instantiation of a generic body, closures' too.
    pub bodies: Vec<Instance<'tcx>>,
    /// The walk stopped at `INSTANCES_MAX`: what it found is not all.
    pub cut: bool,
}

impl<'tcx> Instances<'tcx> {
    /// These, and for a function they lack, its instantiations in all:
    /// what a path reaches through dyn or a function pointer may be made
    /// anywhere in the crate.
    #[must_use]
    pub fn or(mut self, all: &Self) -> Self {
        for (&def, args) in &all.fns {
            self.fns.entry(def).or_insert_with(|| args.clone());
        }
        self.cut |= all.cut;
        self
    }
}

/// Whether def, or what it is in, has a type or const parameter.
pub fn generic(tcx: TyCtxt<'_>, def: DefId) -> bool {
    tcx.generics_of(def).requires_monomorphization(tcx)
}

/// Whether the crate has any const-generic definition: without one, no
/// walk is needed.
pub fn any_generic(tcx: TyCtxt<'_>) -> bool {
    tcx.hir_crate_items(())
        .definitions()
        .any(|def| tcx.def_kind(def).has_generics() && tcx.generics_of(def).own_requires_monomorphization())
}

/// The instantiations reached from roots, the functions that are not
/// generic among them.
pub fn collect<'tcx>(tcx: TyCtxt<'tcx>, roots: impl IntoIterator<Item = LocalDefId>) -> Instances<'tcx> {
    let mut walk = Walk {
        tcx,
        seen: FxHashSet::default(),
        todo: Vec::new(),
        out: Instances::default(),
        instance: None,
    };
    for root in roots {
        if tcx.hir_body_owner_kind(root).is_fn_or_closure()
            && !tcx.is_closure_like(root.to_def_id())
            && !generic(tcx, root.to_def_id())
        {
            walk.push(Instance::mono(tcx, root.to_def_id()));
        }
    }
    while let Some(instance) = walk.todo.pop() {
        if walk.seen.len() >= INSTANCES_MAX {
            walk.out.cut = true;
            break;
        }
        let InstanceKind::Item(def) = instance.def else {
            continue;
        };
        if !tcx.def_kind(def).is_fn_like() || !tcx.is_mir_available(def) {
            continue;
        }
        walk.instance = Some(instance);
        walk.visit_body(tcx.optimized_mir(def));
    }
    walk.out
}

/// The parameters of def with what args gives them, `N = 64`, for a
/// diagnostic.
pub fn describe<'tcx>(tcx: TyCtxt<'tcx>, def: DefId, args: GenericArgsRef<'tcx>) -> String {
    let generics = tcx.generics_of(def);
    let mut out = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if i >= generics.count() {
            break;
        }
        let param = generics.param_at(i, tcx);
        if let ty::GenericParamDefKind::Const { .. } = param.kind {
            out.push(format!("{} = {arg}", param.name));
        }
    }
    out.join(", ")
}

/// The size of ty, the type of something in owner's body, in each
/// instantiation of owner that instances has; Err with what stops rr from
/// knowing it.
pub fn sizes<'tcx>(
    tcx: TyCtxt<'tcx>,
    owner: LocalDefId,
    ty: Ty<'tcx>,
    instances: Option<&Instances<'tcx>>,
) -> Result<Vec<(u64, Option<GenericArgsRef<'tcx>>)>, String> {
    let owner = tcx.typeck_root_def_id(owner.to_def_id());
    if !ty.has_param() {
        let env = TypingEnv::post_analysis(tcx, owner);
        return match tcx.layout_of(env.as_query_input(ty)) {
            Ok(layout) => Ok(vec![(layout.size.bytes(), None)]),
            Err(error) => Err(format!("its layout is not known: {error}")),
        };
    }
    let Some(local) = owner.as_local() else {
        return Err("it is generic code of another crate".to_owned());
    };
    let found = instances.and_then(|i| i.fns.get(&local)).map_or(&[][..], Vec::as_slice);
    if found.is_empty() {
        let cut = if instances.is_some_and(|i| i.cut) {
            format!(", within the {INSTANCES_MAX} instantiations rr follows")
        } else {
            String::new()
        };
        return Err(format!(
            "it depends on the parameters of {}, and nothing rr follows here instantiates it{cut}",
            super::calls::name(tcx, local)
        ));
    }
    let env = TypingEnv::fully_monomorphized();
    let mut out = Vec::new();
    for &args in found {
        let concrete = tcx
            .try_instantiate_and_normalize_erasing_regions(args, env, EarlyBinder::bind(tcx, ty))
            .map_err(|_| format!("it does not normalize with {}", describe(tcx, owner, args)))?;
        let layout = tcx
            .layout_of(env.as_query_input(concrete))
            .map_err(|error| format!("with {}, its layout is not known: {error}", describe(tcx, owner, args)))?;
        out.push((layout.size.bytes(), Some(args)));
    }
    Ok(out)
}

struct Walk<'tcx> {
    tcx: TyCtxt<'tcx>,
    seen: FxHashSet<Instance<'tcx>>,
    todo: Vec<Instance<'tcx>>,
    out: Instances<'tcx>,
    /// The instance whose body is being walked.
    instance: Option<Instance<'tcx>>,
}

impl<'tcx> Walk<'tcx> {
    fn push(&mut self, instance: Instance<'tcx>) {
        let InstanceKind::Item(def) = instance.def else {
            return;
        };
        let Some(local) = def.as_local() else { return };
        if !self.seen.insert(instance) {
            return;
        }
        if generic(self.tcx, def) {
            self.out.bodies.push(instance);
        }
        if !self.tcx.is_closure_like(def) && generic(self.tcx, def) {
            let all = self.out.fns.entry(local).or_default();
            if !all.contains(&instance.args) {
                all.push(instance.args);
            }
        }
        self.todo.push(instance);
    }

    /// ty, of the body being walked, with the instance's arguments.
    fn concrete(&self, ty: Ty<'tcx>) -> Option<Ty<'tcx>> {
        let instance = self.instance?;
        instance
            .try_instantiate_mir_and_normalize_erasing_regions(
                self.tcx,
                TypingEnv::fully_monomorphized(),
                EarlyBinder::bind(self.tcx, ty),
            )
            .ok()
    }

    /// The function a value of FnDef type def with args runs.
    fn resolve(&mut self, def: DefId, args: GenericArgsRef<'tcx>) {
        let tcx = self.tcx;
        if !matches!(tcx.def_kind(def), DefKind::Fn | DefKind::AssocFn) {
            return;
        }
        let args = tcx.erase_and_anonymize_regions(args);
        if let Ok(Some(instance)) = Instance::try_resolve(tcx, TypingEnv::fully_monomorphized(), def, args) {
            self.push(instance);
        }
    }

    /// Every function, closure and generic type of the crate in ty.
    fn mentions(&mut self, ty: Ty<'tcx>) {
        let Some(ty) = self.concrete(ty) else { return };
        for arg in ty.walk() {
            let Some(t) = arg.as_type() else { continue };
            match *t.kind() {
                ty::FnDef(def, args) => self.resolve(def, self.tcx.instantiate_bound_regions_with_erased(args)),
                ty::Closure(def, args) => self.push(Instance::new_raw(def, args)),
                ty::Adt(adt, args) if adt.did().is_local() && generic(self.tcx, adt.did()) => {
                    let all = self.out.adts.entry(adt.did()).or_default();
                    if !all.contains(&args) {
                        all.push(args);
                    }
                    // Its destructor runs where a value of it is dropped.
                    if let Some(drop) = self.tcx.adt_destructor(adt.did()) {
                        self.push(Instance::new_raw(drop.did, args));
                    }
                },
                _ => {},
            }
        }
    }

    /// The methods a coercion of source to dyn of a crate's trait puts in
    /// its table.
    fn vtable(&mut self, source: Ty<'tcx>, target: Ty<'tcx>) {
        let tcx = self.tcx;
        let (Some(source), Some(target)) = (self.concrete(source), self.concrete(target)) else {
            return;
        };
        let pointee = |t: Ty<'tcx>| t.builtin_deref(true).or_else(|| t.boxed_ty());
        let (Some(from), Some(to)) = (pointee(source), pointee(target)) else {
            return;
        };
        let ty::Dynamic(predicates, ..) = *to.kind() else {
            return;
        };
        let Some(trait_) = predicates.principal_def_id() else {
            return;
        };
        for &method in tcx.associated_item_def_ids(trait_) {
            if tcx.def_kind(method) != DefKind::AssocFn {
                continue;
            }
            let args = ty::GenericArgs::for_item(tcx, method, |param, _| {
                if param.index == 0 {
                    from.into()
                } else {
                    tcx.lifetimes.re_erased.into()
                }
            });
            self.resolve(method, args);
        }
    }
}

impl<'tcx> Visitor<'tcx> for Walk<'tcx> {
    fn visit_ty(&mut self, ty: Ty<'tcx>, _: TyContext) {
        self.mentions(ty);
    }

    fn visit_const_operand(&mut self, constant: &ConstOperand<'tcx>, _: Location) {
        self.mentions(constant.const_.ty());
    }

    fn visit_rvalue(&mut self, rvalue: &Rvalue<'tcx>, location: Location) {
        if let Rvalue::Cast(CastKind::PointerCoercion(PointerCoercion::Unsize, _), operand, target) = rvalue
            && let Some(instance) = self.instance
        {
            let body = self.tcx.optimized_mir(instance.def_id());
            self.vtable(operand.ty(body, self.tcx), *target);
        }
        self.super_rvalue(rvalue, location);
    }

    fn visit_terminator(&mut self, terminator: &Terminator<'tcx>, location: Location) {
        if let TerminatorKind::Drop { place, .. } = &terminator.kind
            && let Some(instance) = self.instance
        {
            let body = self.tcx.optimized_mir(instance.def_id());
            if let Some(ty) = self.concrete(place.ty(body, self.tcx).ty) {
                let tcx = self.tcx;
                let mut drops = Vec::new();
                super::calls::owns(tcx, TypingEnv::fully_monomorphized(), ty, &mut |t| {
                    if let ty::Adt(adt, args) = *t.kind()
                        && let Some(drop) = tcx.adt_destructor(adt.did())
                        && drop.did.is_local()
                    {
                        drops.push(Instance::new_raw(drop.did, args));
                    }
                });
                for drop in drops {
                    self.push(drop);
                }
            }
        }
        self.super_terminator(terminator, location);
    }
}

/// The most bytes of one array on the stack, and of a whole frame, as
/// Clippy's large_stack_arrays and large_stack_frames have them by
/// default. Those look at a generic body, where `[u8; N]` has no size, and
/// stop; rr looks at each instantiation.
const ARRAY_MAX: u64 = 16 * 1024;
const FRAME_MAX: u64 = 512_000;

/// Arrays and frames on the stack of each instantiation of the crate's
/// const-generic code, larger than Clippy allows: each takes an
/// `escape(stack)` reason, as those lints do.
pub fn stack<'tcx>(cx: &rustc_lint::LateContext<'tcx>, instances: &Instances<'tcx>) {
    let tcx = cx.tcx;
    let env = TypingEnv::fully_monomorphized();
    let mut reported = FxHashSet::default();
    for &instance in &instances.bodies {
        let def = instance.def_id();
        let Some(local) = def.as_local() else { continue };
        if clippy_utils::is_in_test(tcx, tcx.local_def_id_to_hir_id(local)) {
            continue;
        }
        let body = tcx.optimized_mir(def);
        let with = describe(tcx, tcx.typeck_root_def_id(def), instance.args);
        let mut frame = 0u64;
        for decl in &body.local_decls {
            let Ok(ty) =
                instance.try_instantiate_mir_and_normalize_erasing_regions(tcx, env, EarlyBinder::bind(tcx, decl.ty))
            else {
                continue;
            };
            let Ok(layout) = tcx.layout_of(env.as_query_input(ty)) else {
                continue;
            };
            let size = layout.size.bytes();
            frame = frame.saturating_add(size);
            let span = decl.source_info.span;
            if decl.ty.has_param()
                && matches!(ty.kind(), ty::Array(..))
                && size > ARRAY_MAX
                && super::builtins::is_user_code(span)
                && reported.insert(span)
                && !super::comments::has_escape_reason(cx, span, span, "stack")
            {
                too_large(
                    cx,
                    span,
                    format!("an array of {size} bytes on the stack with {with}"),
                    "keep it in a Box, or in a buffer that lives outside the function",
                );
            }
        }
        let span = tcx.def_ident_span(def).unwrap_or_else(|| tcx.def_span(def));
        if frame > FRAME_MAX
            && super::builtins::is_user_code(span)
            && reported.insert(span)
            && !super::comments::has_escape_reason(cx, span, span, "stack")
        {
            too_large(
                cx,
                span,
                format!("a stack frame of {frame} bytes with {with}"),
                "keep its large values in a Box, or in a buffer that lives outside the function",
            );
        }
    }
}

fn too_large(cx: &rustc_lint::LateContext<'_>, span: rustc_span::Span, what: String, help: &'static str) {
    clippy_utils::diagnostics::span_lint_and_then(
        cx,
        super::RR_UNEXPLAINED_ESCAPE,
        span,
        format!("{what}, which Clippy's stack lints do not see in generic code; this needs a reason"),
        |diag| {
            diag.help(help);
            super::comments::note(diag, cx.sess(), span, span, "stack");
        },
    );
}
