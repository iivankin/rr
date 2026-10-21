//! rr fmt: rustfmt over a crate, from its root through the modules it
//! declares, in one style for every rr project: rustfmt's defaults for
//! edition 2024. A rustfmt.toml is not read, so no project can loosen it.

use rustfmt_nightly::{Color, Config, Edition, EmitMode, Input, Session, StyleEdition};
use std::io::{self, IsTerminal as _};
use std::path::PathBuf;
use std::process::ExitCode;

pub fn run(args: &[String]) -> io::Result<ExitCode> {
    let check = args.iter().any(|arg| arg == "--check");
    let files: Vec<&String> = args.iter().filter(|arg| *arg != "--check").collect();
    if files.is_empty() || files.iter().any(|arg| arg.starts_with('-')) {
        return Err(io::Error::other("usage: rr fmt [--check] FILE..."));
    }
    let mut config =
        Config::default_for_possible_style_edition(Some(StyleEdition::Edition2024), Some(Edition::Edition2024), None);
    config.set().edition(Edition::Edition2024);
    config
        .set()
        .emit_mode(if check { EmitMode::Diff } else { EmitMode::Files });
    config.set().color(if io::stdout().is_terminal() {
        Color::Always
    } else {
        Color::Never
    });
    let mut out = io::stdout();
    let mut session = Session::new(config, Some(&mut out));
    for file in files {
        session
            .format(Input::File(PathBuf::from(file)))
            .map_err(|error| io::Error::other(format!("{file}: {error}")))?;
    }
    let failed = session.has_operational_errors() || session.has_parsing_errors() || (check && session.has_diff());
    Ok(if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}
