#[path = "restricted/mod.rs"]
mod restricted;

#[path = "harness.rs"]
mod harness;

// Override the C allocator in the same way that the `rustc` binary would do.
rustc_driver::override_c_allocator_in_binary!();

use clippy_utils::sym;
use declare_clippy_lint::LintListBuilder;
use rustc_interface::interface;
use rustc_middle::ty::{Instance, SymbolName, TyCtxt};
use rustc_session::config::ErrorOutputType;
use rustc_session::{EarlyDiagCtxt, Session};
use rustc_span::symbol::Symbol;

use std::env;
use std::fs::read_to_string;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

/// If a command-line option matches `find_arg`, then apply the predicate `pred` on its value. If
/// true, then return it. The parameter is assumed to be either `--arg=value` or `--arg value`.
fn arg_value(args: &[String], find_arg: &str, pred: impl Fn(&str) -> bool) -> bool {
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        let mut arg = arg.splitn(2, '=');
        if arg.next() != Some(find_arg) {
            continue;
        }

        match arg.next().or_else(|| args.next()) {
            Some(v) if pred(v) => return true,
            _ => {},
        }
    }
    false
}

/// Returns true if this is `arg` or `arg=...`, otherwise returns false.
fn is_arg(argument: &str, key: &str) -> bool {
    argument
        .strip_prefix(key)
        .is_some_and(|s| s.is_empty() || s.starts_with('='))
}

#[test]
fn test_arg_value() {
    use std::ops::Not as _;

    let args = &["--bar=bar", "--foobar", "123", "--foo"].map(String::from);

    assert!(arg_value(&[], "--foobar", |_| true).not());
    assert!(arg_value(args, "--bar", |_| false).not());
    assert!(arg_value(args, "--bar", |_| true));
    assert!(arg_value(args, "--bar", |p| p == "bar"));
    assert!(arg_value(args, "--bar", |p| p == "foo").not());
    assert!(arg_value(args, "--foobar", |p| p == "foo").not());
    assert!(arg_value(args, "--foobar", |p| p == "123"));
    assert!(arg_value(args, "--foobar", |p| p.contains("12")));
    assert!(arg_value(args, "--foo", |_| true).not());
}

#[test]
fn test_has_arg() {
    assert!(is_arg("--foo=bar", "--foo"));
    assert!(is_arg("--baz", "--baz"));
    assert!(is_arg("-vV", "-vV"));

    assert!(
        ["--=bar", "--barr", "-bar", "bar"]
            .iter()
            .all(|arg| !is_arg(arg, "--bar"))
    );
}

fn track_clippy_args(sess: &Session, args_env_var: Option<&str>) {
    sess.env_depinfo
        .borrow_mut()
        .insert((sym::CLIPPY_ARGS, args_env_var.map(Symbol::intern)));
}

/// Track files that may be accessed at runtime in `file_depinfo` so that cargo will re-run clippy
/// when any of them are modified
fn track_files(sess: &Session) {
    let mut file_depinfo = sess.file_depinfo.borrow_mut();

    // Used by `clippy::cargo` lints and to determine the MSRV. `cargo clippy` executes `clippy-driver`
    // with the current directory set to `CARGO_MANIFEST_DIR` so a relative path is fine
    if Path::new("Cargo.toml").exists() {
        file_depinfo.insert(sym::Cargo_toml);
    }

    // `clippy.toml` will be automatically tracked as it's loaded with `sess.source_map().load_file()`

    // During development track the `clippy-driver` executable so that cargo will re-run clippy whenever
    // it is rebuilt
    if cfg!(debug_assertions)
        && let Ok(current_exe) = env::current_exe()
        && let Some(current_exe) = current_exe.to_str()
    {
        file_depinfo.insert(Symbol::intern(current_exe));
    }
}

struct DefaultCallbacks;
impl rustc_driver::Callbacks for DefaultCallbacks {}

/// This is different from `DefaultCallbacks` that it will inform Cargo to track the value of
/// `CLIPPY_ARGS` environment variable.
struct RustcCallbacks {
    clippy_args_var: Option<String>,
}

impl rustc_driver::Callbacks for RustcCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        let clippy_args_var = self.clippy_args_var.take();
        config.track_state = Some(Box::new(move |sess| {
            track_clippy_args(sess, clippy_args_var.as_deref());
        }));
        config.extra_symbols = sym::EXTRA_SYMBOLS.into();
    }
}

struct ClippyCallbacks {
    clippy_args_var: Option<String>,
    restricted: bool,
    /// `rr build --prof`: see `profiled_symbol_name`.
    prof: bool,
}

type SymbolNameQuery = for<'tcx> fn(TyCtxt<'tcx>, Instance<'tcx>) -> SymbolName<'tcx>;

static SYMBOL_NAME: std::sync::OnceLock<SymbolNameQuery> = std::sync::OnceLock::new();

/// rr prof's renaming. The allocator functions `#[global_allocator]`
/// defines in the program become `__rg_*`; rr prof's runtime defines its
/// `rr_prof_rust_*` as the `__rust_*` the program calls, which count each
/// call and hand it on. (A function named `__rust_alloc` would make the
/// runtime a second global allocator to the compiler.)
fn profiled_symbol_name<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> SymbolName<'tcx> {
    let name = SYMBOL_NAME
        .get()
        .map_or(SymbolName::new(tcx, ""), |query| query(tcx, instance));
    let def = instance.def_id();
    let item = tcx.opt_item_name(def);
    for method in ["alloc", "dealloc", "realloc", "alloc_zeroed"] {
        let rust = rustc_symbol_mangling::mangle_internal_symbol(tcx, &format!("__rust_{method}"));
        // The runtime's functions keep their new names wherever they are
        // named, as a Windows link names upstream exports; the program's
        // allocator is renamed only where it is defined.
        if name.name == rust && def.is_local() {
            return SymbolName::new(
                tcx,
                &rustc_symbol_mangling::mangle_internal_symbol(tcx, &format!("__rg_{method}")),
            );
        }
        if item.is_some_and(|n| n.as_str() == format!("rr_prof_rust_{method}"))
            && tcx.crate_name(def.krate).as_str() == "rr_prof_rt"
        {
            return SymbolName::new(tcx, &rust);
        }
    }
    name
}

/// Plain rustc with rr prof's renaming: how rr builds the runtime.
struct ProfCallbacks;

impl rustc_driver::Callbacks for ProfCallbacks {
    fn config(&mut self, config: &mut interface::Config) {
        config.override_queries = Some(override_symbol_name);
    }
}

fn override_symbol_name(_: &Session, providers: &mut rustc_middle::util::Providers) {
    let _ = SYMBOL_NAME.set(providers.queries.symbol_name);
    providers.queries.symbol_name = profiled_symbol_name;
}

impl rustc_driver::Callbacks for ClippyCallbacks {
    #[expect(rustc::bad_opt_access, reason = "necessary in clippy driver to set `mir_opt_level`")]
    fn config(&mut self, config: &mut interface::Config) {
        let previous = config.register_lints.take();
        let restricted = self.restricted;
        if self.prof {
            config.override_queries = Some(override_symbol_name);
        }
        if restricted {
            // rr rules are requirements, even with --cap-lints=allow or -A warnings.
            config.opts.lint_cap = None;
            // ForceWarn has priority over Forbid in rustc. Remove that override
            // only for required rr rules; other compiler/Clippy lints retain it.
            self::restricted::force_clippy(&mut config.opts);
            config.opts.lint_opts.retain(|(name, level)| {
                *level != rustc_lint::Level::ForceWarn
                    || !(name == "rr" || name == "warnings" || name.starts_with("rr_"))
            });
        }
        let clippy_args_var = self.clippy_args_var.take();
        config.track_state = Some(Box::new(move |sess| {
            track_clippy_args(sess, clippy_args_var.as_deref());
            if !restricted {
                track_files(sess);
            }

            // Trigger a rebuild if CLIPPY_CONF_DIR changes. The value must be a valid string so
            // changes between dirs that are invalid UTF-8 will not trigger rebuilds
            sess.env_depinfo.borrow_mut().insert((
                sym::CLIPPY_CONF_DIR,
                env::var("CLIPPY_CONF_DIR").ok().map(|dir| Symbol::intern(&dir)),
            ));
        }));
        config.register_lints = Some(Box::new(move |sess, lint_store| {
            // technically we're ~guaranteed that this is none but might as well call anything that
            // is there already. Certainly it can't hurt.
            if let Some(previous) = &previous {
                (previous)(sess, lint_store);
            }

            let mut list_builder = LintListBuilder::default();
            list_builder.insert(clippy_lints::declared_lints::LINTS);
            list_builder.register(lint_store);

            let conf = if restricted {
                clippy_config::Conf::load_adjusted(sess, self::restricted::adjust_conf)
            } else {
                clippy_config::Conf::load(sess)
            };
            clippy_lints::register_lint_passes(lint_store, conf, !restricted);
            if restricted {
                self::restricted::register(lint_store);
            }

            #[cfg(feature = "internal")]
            clippy_lints_internal::register_lints(lint_store);
        }));
        config.extra_symbols = sym::EXTRA_SYMBOLS.into();

        // FIXME: #4825; This is required, because Clippy lints that are based on MIR have to be
        // run on the unoptimized MIR. On the other hand this results in some false negatives. If
        // MIR passes can be enabled / disabled separately, we should figure out, what passes to
        // use for Clippy.
        config.opts.unstable_opts.mir_opt_level = Some(0);
        config.opts.unstable_opts.mir_enable_passes =
            vec![("CheckNull".to_owned(), false), ("CheckAlignment".to_owned(), false)];

        // Disable flattening and inlining of format_args!(), so the HIR matches with the AST.
        config.opts.unstable_opts.flatten_format_args = false;
    }

    fn after_crate_root_parsing(
        &mut self,
        compiler: &interface::Compiler,
        krate: &mut rustc_ast::Crate,
    ) -> rustc_driver::Compilation {
        self::harness::apply(&compiler.sess, krate);
        rustc_driver::Compilation::Continue
    }

    fn after_analysis(&mut self, _: &interface::Compiler, tcx: TyCtxt<'_>) -> rustc_driver::Compilation {
        // Every rule has heard its reasons by now: what is left answers nothing.
        if self.restricted {
            self::restricted::unused_reasons(tcx);
        }
        rustc_driver::Compilation::Continue
    }
}

fn display_help() -> ExitCode {
    if writeln!(&mut anstream::stdout().lock(), "{}", help_message()).is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

const BUG_REPORT_URL: &str = "https://github.com/rust-lang/rust-clippy/issues/new?template=ice.yml";

pub fn run(mut orig_args: Vec<String>, restricted: bool, prof: bool) -> ExitCode {
    let early_dcx = EarlyDiagCtxt::new(ErrorOutputType::default());

    rustc_driver::init_rustc_env_logger(&early_dcx);

    rustc_driver::install_ice_hook(BUG_REPORT_URL, |dcx| {
        // FIXME: this macro calls unwrap internally but is called in a panicking context!  It's not
        // as simple as moving the call from the hook to main, because `install_ice_hook` doesn't
        // accept a generic closure.
        let version_info = rustc_tools_util::get_version_info!();
        dcx.handle().note(format!("Clippy version: {version_info}"));
    });

    rustc_driver::catch_with_exit_code(move || {
        fn has_sysroot_arg(args: &[String]) -> bool {
            // https://doc.rust-lang.org/rustc/command-line-arguments.html#path-load-command-line-flags-from-a-path
            // Beside checking for existence of `--sysroot` on the command line, we need to
            // check for the arg files that are prefixed with @ as well to be consistent with rustc
            args.iter().any(|arg| {
                if let Some(arg_file_path) = arg.strip_prefix('@')
                    && let Ok(arg_file) = read_to_string(arg_file_path)
                {
                    arg_file.lines().any(|arg| is_arg(arg, "--sysroot"))
                } else {
                    is_arg(arg, "--sysroot")
                }
            })
        }

        if let Err(error) = harness::take(&mut orig_args) {
            early_dcx.early_fatal(error);
        }

        let sys_root_env = std::env::var("SYSROOT").ok();
        let pass_sysroot_env_if_given = |args: &mut Vec<String>, sys_root_env| {
            if let Some(sys_root) = sys_root_env
                && !has_sysroot_arg(args)
            {
                args.extend(["--sysroot".to_string(), sys_root]);
            }
        };

        // make "clippy-driver --rustc" work like a subcommand that passes further args to "rustc"
        // for example `clippy-driver --rustc --version` will print the rustc version that clippy-driver
        // uses
        if !restricted && let Some(pos) = orig_args.iter().position(|arg| arg == "--rustc") {
            orig_args.remove(pos);
            orig_args[0] = "rustc".to_string();

            let mut args: Vec<String> = orig_args.clone();
            pass_sysroot_env_if_given(&mut args, sys_root_env);

            if prof {
                rustc_driver::run_compiler(&args, &mut ProfCallbacks);
            } else {
                rustc_driver::run_compiler(&args, &mut DefaultCallbacks);
            }
            return ExitCode::SUCCESS;
        }

        if orig_args.iter().any(|a| a == "--version" || a == "-V") {
            let version_info = rustc_tools_util::get_version_info!();

            return match writeln!(&mut anstream::stdout().lock(), "{version_info}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            };
        }

        // Setting RUSTC_WRAPPER causes Cargo to pass 'rustc' as the first argument.
        // We're invoking the compiler programmatically, so we ignore this/
        let wrapper_mode =
            !restricted && orig_args.get(1).map(Path::new).and_then(Path::file_stem) == Some("rustc".as_ref());

        if wrapper_mode {
            // we still want to be able to invoke it normally though
            orig_args.remove(1);
        }

        if !wrapper_mode && (orig_args.iter().any(|a| a == "--help" || a == "-h") || orig_args.len() == 1) {
            return display_help();
        }

        let mut args: Vec<String> = orig_args.clone();
        pass_sysroot_env_if_given(&mut args, sys_root_env);

        let mut no_deps = false;
        let clippy_args_var = (!restricted).then(|| env::var("CLIPPY_ARGS").ok()).flatten();
        let clippy_args = clippy_args_var
            .as_deref()
            .unwrap_or_default()
            .split("__CLIPPY_HACKERY__")
            .filter_map(|s| match s {
                "" => None,
                "--no-deps" => {
                    no_deps = true;
                    None
                },
                _ => Some(s.to_string()),
            })
            .chain(vec!["--cfg".into(), "clippy".into()])
            .collect::<Vec<String>>();

        // If no Clippy lints will be run we do not need to run Clippy
        let cap_lints_allow = arg_value(&orig_args, "--cap-lints", |val| val == "allow")
            && !arg_value(&orig_args, "--force-warn", |val| val.contains("clippy::"));

        // If `--no-deps` is enabled only lint the primary package
        let relevant_package = !no_deps || env::var("CARGO_PRIMARY_PACKAGE").is_ok();

        // Do not run Clippy for Cargo's info queries so that invalid CLIPPY_ARGS are not cached
        // https://github.com/rust-lang/cargo/issues/14385
        let info_query = args.iter().any(|arg| arg == "-vV")
            || arg_value(&orig_args, "--print", |val| val != "crate-root-lint-levels");

        let clippy_enabled = (restricted || !cap_lints_allow) && relevant_package && !info_query;
        if clippy_enabled {
            args.extend(clippy_args);
            if restricted {
                args.extend(["-F".into(), "rr".into()]);
            }
            rustc_driver::run_compiler(
                &args,
                &mut ClippyCallbacks {
                    clippy_args_var,
                    restricted,
                    prof,
                },
            );
        } else {
            rustc_driver::run_compiler(&args, &mut RustcCallbacks { clippy_args_var });
        }
        ExitCode::SUCCESS
    })
}

#[must_use]
fn help_message() -> &'static str {
    color_print::cstr!(
        "Checks a file to catch common mistakes and improve your Rust code.
Run <cyan>clippy-driver</> with the same arguments you use for <cyan>rustc</>

<green,bold>Usage</>:
    <cyan,bold>clippy-driver</> <cyan>[OPTIONS] INPUT</>

<green,bold>Common options:</>
    <cyan,bold>-h</>, <cyan,bold>--help</>               Print this message
    <cyan,bold>-V</>, <cyan,bold>--version</>            Print version info and exit
    <cyan,bold>--rustc</>                  Pass all arguments to <cyan>rustc</>

<green,bold>Allowing / Denying lints</>
You can use tool lints to allow or deny lints from your code, e.g.:

    <yellow,bold>#[allow(clippy::needless_lifetimes)]</>
"
    )
}
