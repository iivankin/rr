#![feature(rustc_private)]
#![warn(rust_2018_idioms, unused_lifetimes, rustc::internal)]

extern crate rustc_ast;
extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_feature;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_lexer;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_parse;
extern crate rustc_session;
extern crate rustc_span;
extern crate rustc_symbol_mangling;

mod driver_core;

fn main() -> std::process::ExitCode {
    let dcx = rustc_session::EarlyDiagCtxt::new(rustc_session::config::ErrorOutputType::default());
    driver_core::run(rustc_driver::args::raw_args(&dcx), false, false)
}
