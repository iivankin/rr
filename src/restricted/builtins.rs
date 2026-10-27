//! Builtins are compiler expanders, not an exception for arbitrary library macros.

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_data_structures::fx::FxHashSet;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::{AmbigArg, Expr, Item, ItemKind, Ty};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_session::impl_lint_pass;
use rustc_span::Span;
use rustc_span::hygiene::{ExpnId, ExpnKind, MacroKind};

use super::RR_NO_MACROS;

// Pinned to register_builtin_macros in Rust 1.99.1. std_panic and the
// proc_macro quote expander are deliberately excluded; of the derives, only
// the compiler's own (syntax::DERIVES) are allowed.
pub(super) fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        "asm"
            | "assert"
            | "cfg"
            | "cfg_select"
            | "column"
            | "compile_error"
            | "concat"
            | "concat_bytes"
            | "const_format_args"
            | "core_panic"
            | "direct_const_arg"
            | "env"
            | "file"
            | "format_args"
            | "format_args_nl"
            | "global_asm"
            | "include"
            | "include_bytes"
            | "include_str"
            | "iter"
            | "line"
            | "log_syntax"
            | "module_path"
            | "naked_asm"
            | "option_env"
            | "pattern_type"
            | "stringify"
            | "trace_macros"
            | "unreachable"
            | "view_type"
    )
}

// From register_attr! in the same compiler. Test/bench require std; offload_kernel
// currently generates an explicit std::unimplemented! stub.
pub(super) fn is_builtin_attribute(name: &str) -> bool {
    matches!(
        name,
        "alloc_error_handler"
            | "test"
            | "bench"
            | "autodiff_forward"
            | "autodiff_reverse"
            | "cfg_accessible"
            | "cfg_eval"
            | "define_opaque"
            | "eii"
            | "eii_declaration"
            | "eii_shared_macro"
            | "global_allocator"
            | "unsafe_eii"
    )
}

#[derive(Default)]
pub struct BuiltinOrigins {
    seen: FxHashSet<ExpnId>,
}

impl_lint_pass!(BuiltinOrigins => [RR_NO_MACROS]);

impl BuiltinOrigins {
    fn check(&mut self, cx: &LateContext<'_>, span: Span) {
        let mut expansion = span.ctxt().outer_expn();
        while expansion != ExpnId::root() {
            let data = expansion.expn_data();
            if !self.seen.insert(expansion) {
                break;
            }
            let forbidden_origin = is_user_code(data.call_site)
                && data.macro_def_id.is_some_and(|id| {
                    cx.tcx.crate_name(id.krate).as_str() != "core" || !allowed_definition(cx.tcx.item_name(id).as_str())
                });
            if matches!(data.kind, ExpnKind::Macro(..)) && forbidden_origin && !written_forbidden(cx, data.call_site) {
                // The early pass validates builtin names; the resolved expansion
                // prevents importing a third-party macro under an allowed name.
                span_lint_and_help(
                    cx,
                    RR_NO_MACROS,
                    data.call_site,
                    "only compiler builtins and core panic/assert macros are allowed",
                    None,
                    "remove the library macro; only compiler builtins and core panic/assert macros are allowed",
                );
            }
            expansion = data.parent;
        }
    }
}

/// Whether the call at span names a macro the early pass already refused
/// by its written path: then it has been reported. What is left here is a
/// macro that hides under an allowed name.
fn written_forbidden(cx: &LateContext<'_>, span: Span) -> bool {
    let Ok(text) = cx.sess().source_map().span_to_snippet(span) else {
        return false;
    };
    let Some((path, _)) = text.split_once('!') else {
        return false;
    };
    let names: Vec<&str> = path
        .split("::")
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    !super::syntax::allowed_macro_names(&names)
}

impl<'tcx> LateLintPass<'tcx> for BuiltinOrigins {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        self.check(cx, expr.span);
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        self.check(cx, item.span);
        let ItemKind::Use(path, _) = item.kind else { return };
        let Some(Res::Def(DefKind::Macro(_), id)) = path.res.macro_ns else {
            return;
        };
        if cx.tcx.crate_name(id.krate).as_str() == "core" && allowed_definition(cx.tcx.item_name(id).as_str()) {
            return;
        }
        span_lint_and_help(
            cx,
            RR_NO_MACROS,
            item.span,
            "importing a library macro is forbidden by rr",
            None,
            "use compiler builtins or core panic/assert macros",
        );
    }

    fn check_ty(&mut self, cx: &LateContext<'tcx>, ty: &'tcx Ty<'tcx, AmbigArg>) {
        self.check(cx, ty.span);
    }
}

fn allowed_definition(name: &str) -> bool {
    super::syntax::allowed_macro_names(&[name])
        || is_builtin_attribute(name)
        // The early pass lets through a derive list only of the compiler's
        // own derives; under another name, one from elsewhere is refused
        // here by the crate that defines it.
        || name == "derive"
        || super::syntax::DERIVES.contains(&name)
}

// include! copies user source into an expansion context; desugarings retain the
// user's call site. Other compiler builtin expansions are implementation code.
pub(super) fn is_user_code(mut span: Span) -> bool {
    while span.from_expansion() {
        let data = span.ctxt().outer_expn_data();
        match data.kind {
            ExpnKind::Macro(MacroKind::Bang, name) if name.as_str() == "include" => return true,
            ExpnKind::Desugaring(_) => span = data.call_site,
            _ => return false,
        }
    }
    true
}
