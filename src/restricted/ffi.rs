//! A C function that takes a variable number of arguments, declared with
//! a fixed list: the call compiles and links, but where the platform
//! passes variadic arguments elsewhere than fixed ones, as arm64 macOS
//! passes them on the stack, the callee reads garbage. The C library's
//! variadic functions are known by name; each needs its `...`.

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::{ForeignItem, ForeignItemKind, TyKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_session::impl_lint_pass;

use super::{RR_C_SIGNATURE, RR_VARIADIC};

pub struct Ffi;

impl_lint_pass!(Ffi => [RR_VARIADIC, RR_C_SIGNATURE]);

/// The C library's functions that take a variable number of arguments.
const VARIADIC: &[&str] = &[
    "open", "openat", "fcntl", "ioctl", "printf", "fprintf", "dprintf", "sprintf", "snprintf", "asprintf", "scanf",
    "fscanf", "sscanf", "syslog", "execl", "execle", "execlp", "sem_open", "mq_open", "semctl", "prctl", "syscall",
    "ptrace",
];

impl<'tcx> LateLintPass<'tcx> for Ffi {
    fn check_foreign_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx ForeignItem<'tcx>) {
        let ForeignItemKind::Fn(sig, ..) = item.kind else {
            return;
        };
        let name = item.ident.name;
        // C has pointers: a reference promises Rust's rules about the
        // memory to code that does not keep them.
        for input in sig.decl.inputs.iter().chain(match sig.decl.output {
            rustc_hir::FnRetTy::Return(ty) => Some(ty),
            rustc_hir::FnRetTy::DefaultReturn(_) => None,
        }) {
            if let TyKind::Ref(..) = input.kind
                && super::builtins::is_user_code(input.span)
            {
                span_lint_and_help(
                    cx,
                    RR_C_SIGNATURE,
                    input.span,
                    format!("`{name}` is declared with a reference, which C does not have"),
                    None,
                    "declare it as its header does, with *const or *mut, and lend the reference with `&raw` at the call",
                );
            }
        }
        if sig.decl.c_variadic() || !VARIADIC.contains(&name.as_str()) || !super::builtins::is_user_code(item.span) {
            return;
        }
        span_lint_and_help(
            cx,
            RR_VARIADIC,
            item.span,
            format!("`{name}` takes a variable number of arguments in C, and this declares a fixed list"),
            None,
            "declare it as its header does, ending in `...`; the arguments after it then go where the platform expects them",
        );
    }
}
