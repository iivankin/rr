//! Restricted Rust rules, enabled by rr.

use rustc_lint::{LintId, LintStore};
use rustc_session::declare_lint;

mod comments;
mod escape_hatches;
mod macros;
mod syntax;

declare_lint! { pub RR_NO_STD, Deny, "rr requires a no_std crate without explicit std imports" }
declare_lint! { pub RR_NO_GENERICS, Deny, "rr forbids user-defined type and const generics, impl Trait and async fn" }
declare_lint! { pub RR_NO_MACROS, Deny, "rr forbids macro definitions, derives and calls except core panic/assert macros" }
declare_lint! { pub RR_SIMPLE_TRAITS, Deny, "rr forbids associated types, supertraits and where clauses" }
declare_lint! { pub RR_UNEXPLAINED_ESCAPE, Deny, "rr requires a reason for ownership and borrow-checker escape hatches" }

pub fn register(store: &mut LintStore) {
    let lints = &[
        RR_NO_STD,
        RR_NO_GENERICS,
        RR_NO_MACROS,
        RR_SIMPLE_TRAITS,
        RR_UNEXPLAINED_ESCAPE,
    ];
    store.register_lints(lints);
    store.register_group(true, "rr", None, lints.iter().map(|lint| LintId::of(lint)).collect());
    store.register_pre_expansion_lint_pass(Box::new(|| Box::new(syntax::RestrictedSyntax)));
    store.register_late_lint_pass(Box::new(|_| Box::new(escape_hatches::EscapeHatches)));
}
