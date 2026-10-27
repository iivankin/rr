//! A copy one element at a time, as MIR has it, whatever the source looks
//! like: in a loop, a value read out of memory the function reaches through
//! a reference or a pointer, stored into such memory or pushed. The value
//! may pass through locals, a destructuring, a struct built field by field
//! (`Item { pos: it.pos, w: it.w }`), an iterator's item, or a local
//! function that returns what it was given (`make(it.pos, it.w)`,
//! `it.copy()`). Arithmetic on it builds a new value, as a literal does. A
//! Copy value of at most 8 bytes moved within one buffer is a permutation,
//! as `swap` makes one.

use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def_id::LocalDefId;
use rustc_middle::mir::{
    AggregateKind, BasicBlock, Body, Local, Operand, Place, ProjectionElem, Rvalue, SourceScope, StatementKind,
    TerminatorKind,
};
use rustc_middle::ty::{self, Instance, InstanceKind, TyCtxt, TypingEnv};
use rustc_span::Span;

/// The most bytes of a Copy element moved within one buffer that are not
/// a copy.
const MOVE_WITHIN_MAX: u64 = 8;

/// What rr knows of each local function: whether what it returns is made
/// of what it was given.
#[derive(Default)]
pub struct Summaries {
    returns_given: FxHashMap<LocalDefId, bool>,
}

impl Summaries {
    fn returns_given(&mut self, tcx: TyCtxt<'_>, f: LocalDefId) -> bool {
        if let Some(&known) = self.returns_given.get(&f) {
            return known;
        }
        // A cycle, which rr forbids without a reason, counts as no.
        self.returns_given.insert(f, false);
        let known = tcx.is_mir_available(f) && {
            let body = tcx.optimized_mir(f);
            let mut flow = Flow::new(tcx, body, f);
            for arg in body.args_iter() {
                flow.tainted.insert(arg);
            }
            flow.run(self, None);
            flow.tainted.contains(&rustc_middle::mir::RETURN_PLACE)
        };
        self.returns_given.insert(f, known);
        known
    }
}

/// The spans in owner's own code of each copy one element at a time.
pub fn element_copies(tcx: TyCtxt<'_>, owner: LocalDefId, summaries: &mut Summaries) -> Vec<Span> {
    if !tcx.is_mir_available(owner) {
        return Vec::new();
    }
    let body = tcx.optimized_mir(owner);
    let looping = cyclic(body);
    let mut flow = Flow::new(tcx, body, owner);
    let mut copies = Vec::new();
    flow.run(summaries, Some((&looping, &mut copies)));
    copies.sort();
    copies.dedup();
    copies
}

/// The blocks that lie on a cycle of the body's control flow: the body of
/// a loop.
fn cyclic(body: &Body<'_>) -> FxHashSet<BasicBlock> {
    let mut out = FxHashSet::default();
    for (start, data) in body.basic_blocks.iter_enumerated() {
        let mut seen = FxHashSet::default();
        let mut todo: Vec<BasicBlock> = data.terminator().successors().collect();
        while let Some(at) = todo.pop() {
            if at == start {
                out.insert(start);
                break;
            }
            if seen.insert(at) {
                todo.extend(body.basic_blocks[at].terminator().successors());
            }
        }
    }
    out
}

/// How a value read out of memory is carried into a place.
enum Carried<'r, 'tcx> {
    /// As it is, from this place.
    From(&'r Place<'tcx>),
    /// Rebuilt field by field.
    Rebuilt,
}

/// Whether a place in memory is an element of a buffer, or the whole of
/// what a reference points to, as an item of `iter_mut` is: not a field of
/// a struct reached through a reference, such as `self.pos`.
fn element(place: &Place<'_>) -> bool {
    place.projection.iter().any(|p| {
        matches!(
            p,
            ProjectionElem::Index(_) | ProjectionElem::ConstantIndex { .. } | ProjectionElem::Subslice { .. }
        )
    }) || matches!(place.projection.last(), Some(ProjectionElem::Deref))
}

struct Flow<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    body: &'a Body<'tcx>,
    env: TypingEnv<'tcx>,
    /// Locals that hold a value read out of memory, or made of such values.
    tainted: FxHashSet<Local>,
    /// Locals that hold a reference into memory: what a function is given
    /// through one, it reads out of memory.
    pointing: FxHashSet<Local>,
    /// For a local that holds a value read out of memory, the local through
    /// which it was read: the buffer it came from.
    origin: FxHashMap<Local, Local>,
}

impl<'a, 'tcx> Flow<'a, 'tcx> {
    fn new(tcx: TyCtxt<'tcx>, body: &'a Body<'tcx>, owner: LocalDefId) -> Self {
        Self {
            tcx,
            body,
            env: TypingEnv::post_analysis(tcx, owner),
            tainted: FxHashSet::default(),
            pointing: FxHashSet::default(),
            origin: FxHashMap::default(),
        }
    }

    /// Spread the taint to a fixed point; with `report`, record each store
    /// of a tainted value into memory in a loop.
    fn run(&mut self, summaries: &mut Summaries, mut report: Option<(&FxHashSet<BasicBlock>, &mut Vec<Span>)>) {
        let body = self.body;
        loop {
            let before = self.tainted.len() + self.pointing.len();
            for (block, data) in body.basic_blocks.iter_enumerated() {
                for statement in &data.statements {
                    let StatementKind::Assign(assign) = &statement.kind else {
                        continue;
                    };
                    let (place, rvalue) = &**assign;
                    if let Rvalue::Ref(_, _, target) | Rvalue::RawPtr(_, target) = rvalue
                        && place.projection.is_empty()
                        && self.place(target)
                    {
                        self.pointing.insert(place.local);
                    }
                    let Some(source) = self.carries(rvalue) else {
                        continue;
                    };
                    if place.projection.iter().any(|p| matches!(p, ProjectionElem::Deref)) {
                        if let Some((looping, copies)) = report.as_mut()
                            && looping.contains(&block)
                            && element(place)
                            && !self.permutation(place, &source)
                        {
                            copies.push(self.written_at(statement.source_info.scope, statement.source_info.span));
                        }
                    } else {
                        self.tainted.insert(place.local);
                        if let Carried::From(source) = source {
                            let from = if source.projection.iter().any(|p| matches!(p, ProjectionElem::Deref)) {
                                Some(source.local)
                            } else {
                                self.origin.get(&source.local).copied()
                            };
                            if let Some(from) = from {
                                self.origin.insert(place.local, from);
                            }
                        }
                    }
                }
                if let TerminatorKind::Call {
                    func,
                    args,
                    destination,
                    ..
                } = &data.terminator().kind
                    && let ty::FnDef(def, fn_args) = *func.ty(body, self.tcx).kind()
                {
                    let fn_args = self.tcx.instantiate_bound_regions_with_erased(fn_args);
                    let given = args.iter().any(|arg| self.operand(&arg.node) || self.lent(&arg.node));
                    if !given {
                        continue;
                    }
                    let name = self.tcx.item_name(def);
                    // A push of a value read out of memory, one at a time.
                    if !def.is_local()
                        && matches!(name.as_str(), "push" | "push_back" | "push_front")
                        && let Some((looping, copies)) = report.as_mut()
                        && looping.contains(&block)
                        && args.get(1).is_some_and(|arg| self.operand(&arg.node))
                    {
                        let info = data.terminator().source_info;
                        copies.push(self.written_at(info.scope, info.span));
                    }
                    // A local function that returns what it was given.
                    if let Ok(Some(instance)) = Instance::try_resolve(self.tcx, self.env, def, fn_args)
                        && let InstanceKind::Item(item) = instance.def
                        && let Some(local) = item.as_local()
                        && summaries.returns_given(self.tcx, local)
                        && destination.projection.is_empty()
                    {
                        self.tainted.insert(destination.local);
                    }
                }
            }
            if self.tainted.len() + self.pointing.len() == before {
                return;
            }
        }
    }

    /// Whether an operand is a value read out of memory, or a tainted local.
    fn operand(&self, operand: &Operand<'tcx>) -> bool {
        match operand {
            Operand::Copy(place) | Operand::Move(place) => self.place(place),
            _ => false,
        }
    }

    /// Whether an operand is a reference into memory.
    fn lent(&self, operand: &Operand<'tcx>) -> bool {
        matches!(operand, Operand::Copy(p) | Operand::Move(p) if self.pointing.contains(&p.local))
    }

    fn place(&self, place: &Place<'tcx>) -> bool {
        self.tainted.contains(&place.local) || place.projection.iter().any(|p| matches!(p, ProjectionElem::Deref))
    }

    /// How an rvalue carries a value read out of memory: `None` when it
    /// builds a new value.
    fn carries<'r>(&self, rvalue: &'r Rvalue<'tcx>) -> Option<Carried<'r, 'tcx>> {
        match rvalue {
            Rvalue::Use(operand, _) if self.operand(operand) => match operand {
                Operand::Copy(place) | Operand::Move(place) => Some(Carried::From(place)),
                Operand::Constant(_) | Operand::RuntimeChecks(_) => None,
            },
            Rvalue::Aggregate(kind, fields)
                if matches!(**kind, AggregateKind::Adt(..) | AggregateKind::Tuple) && !fields.is_empty() =>
            {
                let read = fields.iter().filter(|f| self.operand(f)).count();
                let built = fields.iter().filter(|f| matches!(f, Operand::Constant(_))).count();
                (read > 0 && read + built == fields.len() && read * 2 >= fields.len()).then_some(Carried::Rebuilt)
            },
            _ => None,
        }
    }

    /// Whether a store into place of the value at source moves a small
    /// Copy element within one buffer: a permutation.
    fn permutation(&self, place: &Place<'tcx>, carried: &Carried<'_, 'tcx>) -> bool {
        let Carried::From(source) = carried else {
            return false;
        };
        let from = if source.projection.iter().any(|p| matches!(p, ProjectionElem::Deref)) {
            Some(source.local)
        } else {
            self.origin.get(&source.local).copied()
        };
        if from != Some(place.local) {
            return false;
        }
        let ty = place.ty(self.body, self.tcx).ty;
        self.tcx.type_is_copy_modulo_regions(self.env, ty)
            && self
                .tcx
                .layout_of(self.env.as_query_input(ty))
                .is_ok_and(|layout| layout.size.bytes() <= MOVE_WITHIN_MAX)
    }

    /// Where in the function's own code something at span in scope was
    /// written: the call that inlined it, if it was.
    fn written_at(&self, mut scope: SourceScope, span: Span) -> Span {
        let mut at = span;
        loop {
            let data = &self.body.source_scopes[scope];
            if let Some((_, call)) = data.inlined {
                at = call;
            }
            match data.inlined_parent_scope {
                Some(parent) => scope = parent,
                None => return at,
            }
        }
    }
}
