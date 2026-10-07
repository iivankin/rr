#![feature(rustc_private)]
#![warn(rust_2018_idioms, unused_lifetimes, rustc::internal)]

extern crate rustc_ast;
extern crate rustc_driver;
extern crate rustc_feature;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_lexer;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

#[path = "../driver_core.rs"]
mod driver_core;

#[path = "../rr_cli.rs"]
mod rr_cli;

fn main() -> std::process::ExitCode {
    rr_cli::main()
}
