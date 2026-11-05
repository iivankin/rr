//! rr add: copy a component of a registry into the project, as its own
//! code. A component is one JSON file: its name, the rr it was checked
//! with, the components it needs, the questions whose answers add more,
//! and its files, each with its text or beside the JSON, for src/ or
//! scripts/. A registry is wherever those files are served.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{fs, io};

use serde_json::Value;

/// Where a bare name is looked up, unless rr.json names another `@rr`.
const DEFAULT: &str = "https://raw.githubusercontent.com/iivankin/rr/main/registry/{name}.json";

struct Options {
    overwrite: bool,
    dir: PathBuf,
    items: Vec<String>,
    /// Answers given as --option name=value.
    answers: Vec<(String, String)>,
    /// Take each question's default without asking.
    defaults: bool,
}

/// One file of a component: where it goes under src/ or scripts/, and
/// its text.
struct File {
    path: String,
    script: bool,
    text: String,
}

/// What an add gathers: the components seen, their files and names, and
/// the answers it took.
struct Gathered {
    registries: Vec<(String, String)>,
    seen: Vec<String>,
    files: Vec<File>,
    names: Vec<String>,
    taken: Vec<String>,
}

pub fn run(args: &[String]) -> io::Result<ExitCode> {
    let mut o = Options {
        overwrite: false,
        dir: PathBuf::from("src"),
        items: Vec::new(),
        answers: Vec::new(),
        defaults: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(ExitCode::SUCCESS);
            },
            "--overwrite" => o.overwrite = true,
            "--yes" | "-y" => o.defaults = true,
            "--list" => {
                let registries = registries()?;
                return list(args.get(i + 1).map(String::as_str), &registries);
            },
            "--option" => {
                i += 1;
                let (name, value) = args
                    .get(i)
                    .and_then(|a| a.split_once('='))
                    .ok_or_else(|| io::Error::other(usage()))?;
                o.answers.push((name.to_owned(), value.to_owned()));
            },
            "--dir" => {
                i += 1;
                o.dir = PathBuf::from(args.get(i).ok_or_else(|| io::Error::other(usage()))?);
            },
            item if !item.starts_with('-') => o.items.push(item.to_owned()),
            _ => return Err(io::Error::other(usage())),
        }
        i += 1;
    }
    if o.items.is_empty() {
        return Err(io::Error::other(usage()));
    }
    let mut g = Gathered {
        registries: registries()?,
        seen: Vec::new(),
        files: Vec::new(),
        names: Vec::new(),
        taken: Vec::new(),
    };
    // Questions are asked only of a person at a terminal; a script or an
    // agent gets the defaults, and is told how to choose.
    let ask = !o.defaults && io::stdin().is_terminal() && io::stdout().is_terminal();
    for item in &o.items {
        let location = locate(item, None, &g.registries)?;
        collect(&location, &o, ask, &mut g)?;
    }
    let files = g.files;
    // Refuse before writing anything: an add never leaves half a
    // component or replaces code the project changed.
    let mut writes = Vec::new();
    for file in &files {
        let target = if file.script {
            Path::new("scripts").join(&file.path)
        } else {
            o.dir.join(&file.path)
        };
        match fs::read_to_string(&target) {
            Ok(old) if old == file.text => println!("Unchanged {}", target.display()),
            Ok(_) if !o.overwrite => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and differs; --overwrite replaces it", target.display()),
                ));
            },
            Ok(_) => writes.push((target, file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => writes.push((target, file)),
            Err(error) => return Err(error),
        }
    }
    for (target, file) in &writes {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, &file.text)?;
        println!("Added {}", target.display());
    }
    declarations(&o.dir, &files);
    if g.taken.is_empty() {
        println!("rr add: {}", g.names.join(", "));
    } else {
        println!("rr add: {} ({})", g.names.join(", "), g.taken.join(", "));
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints a registry's components, from its index.json: rr's, a scope
/// rr.json names, or an index's path or URL.
fn list(registry: Option<&str>, registries: &[(String, String)]) -> io::Result<ExitCode> {
    let location = match registry {
        None => locate("index", None, registries)?,
        Some(scope) if scope.starts_with('@') => locate(&format!("{scope}/index"), None, registries)?,
        Some(other) => other.to_owned(),
    };
    let text = fetch(&location)?;
    let json: Value = serde_json::from_str(&text).map_err(|e| io::Error::other(format!("{location}: {e}")))?;
    let components = json
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other(format!("{location}: no components")))?;
    let text_of = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or_default().to_owned();
    let list_of = |v: Option<&Value>| -> Vec<String> {
        v.and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    for component in components {
        println!("{}  {}", text_of(component, "name"), text_of(component, "description"));
        let needs = list_of(component.get("dependencies"));
        if !needs.is_empty() {
            println!("    needs: {}", needs.join(", "));
        }
        for option in component.get("options").and_then(Value::as_array).into_iter().flatten() {
            println!(
                "    asks: --option {}={} (default {})",
                text_of(option, "name"),
                list_of(option.get("choices")).join("|"),
                text_of(option, "default")
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The registries rr.json names, as `{"registries": {"@scope": URL}}`,
/// each URL with `{name}` where the component's name goes.
fn registries() -> io::Result<Vec<(String, String)>> {
    let text = match fs::read_to_string("rr.json") {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let json: Value = serde_json::from_str(&text).map_err(|e| io::Error::other(format!("rr.json: {e}")))?;
    let mut found = Vec::new();
    if let Some(map) = json.get("registries").and_then(Value::as_object) {
        for (scope, url) in map {
            let url = url
                .as_str()
                .filter(|u| u.contains("{name}"))
                .ok_or_else(|| io::Error::other(format!("rr.json: {scope} needs a URL with {{name}}")))?;
            found.push((scope.clone(), url.to_owned()));
        }
    }
    Ok(found)
}

/// Where an item is: a URL, a file, `@scope/name` in a registry of
/// rr.json, or a name. A dependency's bare name is looked up beside the
/// component that needs it.
fn locate(item: &str, beside: Option<&str>, registries: &[(String, String)]) -> io::Result<String> {
    if item.starts_with("https://")
        || item.starts_with("http://")
        || Path::new(item)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    {
        return Ok(match beside {
            Some(base) if !item.contains("://") && !Path::new(item).is_absolute() => join(base, item),
            _ => item.to_owned(),
        });
    }
    let (scope, name) = match item.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((scope, name)) => (Some(format!("@{scope}")), name),
        None => (None, item),
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(io::Error::other(format!("{item}: not a component name")));
    }
    let template = match (&scope, beside) {
        (Some(scope), _) => registries
            .iter()
            .find(|(s, _)| s == scope)
            .map(|(_, url)| url.clone())
            .ok_or_else(|| io::Error::other(format!("{scope}: no such registry in rr.json")))?,
        (None, Some(base)) => return Ok(join(base, &format!("{name}.json"))),
        (None, None) => registries
            .iter()
            .find(|(s, _)| s == "@rr")
            .map_or_else(|| DEFAULT.to_owned(), |(_, url)| url.clone()),
    };
    Ok(template.replace("{name}", name))
}

/// path relative to the directory of the component at base.
fn join(base: &str, path: &str) -> String {
    match base.rfind(['/', '\\']) {
        Some(end) => format!("{}/{path}", &base[..end]),
        None => path.to_owned(),
    }
}

/// The component at location and those it needs, those first, each
/// once; then those its answers add.
fn collect(location: &str, o: &Options, ask: bool, g: &mut Gathered) -> io::Result<()> {
    if g.seen.iter().any(|s| s == location) {
        return Ok(());
    }
    g.seen.push(location.to_owned());
    let text = fetch(location)?;
    let json: Value = serde_json::from_str(&text).map_err(|e| io::Error::other(format!("{location}: {e}")))?;
    let name = json
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other(format!("{location}: no name")))?;
    if let Some(wanted) = json.get("rr").and_then(Value::as_str)
        && newer(wanted, super::VERSION)
    {
        return Err(io::Error::other(format!(
            "{name} needs rr {wanted}; this is rr {}",
            super::VERSION
        )));
    }
    let mut needs = strings(json.get("dependencies"), location)?;
    for question in json.get("options").and_then(Value::as_array).into_iter().flatten() {
        needs.extend(answer(question, location, o, ask, &mut g.taken)?);
    }
    for dependency in &needs {
        let next = locate(dependency, Some(location), &g.registries)?;
        collect(&next, o, ask, g)?;
    }
    let listed = json
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other(format!("{location}: no files")))?;
    for file in listed {
        let path = file
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other(format!("{location}: a file without a path")))?;
        if !relative(path) {
            return Err(io::Error::other(format!(
                "{location}: {path} leaves the source directory"
            )));
        }
        let script = match file.get("target").and_then(Value::as_str) {
            None | Some("src") => false,
            Some("scripts") => true,
            Some(other) => {
                return Err(io::Error::other(format!(
                    "{location}: {path} has target {other}; src or scripts"
                )));
            },
        };
        let text = match file.get("content").and_then(Value::as_str) {
            Some(text) => text.to_owned(),
            None => fetch(&join(location, path))?,
        };
        if g.files.iter().any(|f| f.path == path && f.script == script) {
            return Err(io::Error::other(format!("{path} comes from two components")));
        }
        g.files.push(File {
            path: path.to_owned(),
            script,
            text,
        });
    }
    g.names.push(name.to_owned());
    Ok(())
}

/// A list of strings in a component's JSON, or none.
fn strings(list: Option<&Value>, location: &str) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for value in list.and_then(Value::as_array).into_iter().flatten() {
        let text = value
            .as_str()
            .ok_or_else(|| io::Error::other(format!("{location}: a dependency is not a string")))?;
        out.push(text.to_owned());
    }
    Ok(out)
}

/// The components one question's answer adds: from --option, from the
/// person asked, or the default.
fn answer(
    question: &Value,
    location: &str,
    o: &Options,
    ask: bool,
    taken: &mut Vec<String>,
) -> io::Result<Vec<String>> {
    let bad = || io::Error::other(format!("{location}: an option needs a name, choices and a default"));
    let name = question.get("name").and_then(Value::as_str).ok_or_else(bad)?;
    let choices = question.get("choices").and_then(Value::as_array).ok_or_else(bad)?;
    let default = question.get("default").and_then(Value::as_str).ok_or_else(bad)?;
    let value_of = |c: &Value| c.get("value").and_then(Value::as_str).unwrap_or_default().to_owned();
    let values: Vec<String> = choices.iter().map(value_of).collect();
    if !values.iter().any(|v| v == default) {
        return Err(bad());
    }
    let chosen = if let Some((_, value)) = o.answers.iter().find(|(n, _)| n == name) {
        if !values.contains(value) {
            return Err(io::Error::other(format!(
                "--option {name}={value}: one of {}",
                values.join(", ")
            )));
        }
        value.clone()
    } else if ask {
        prompt(question, name, choices, &values, default)?
    } else {
        println!(
            "{name}: {default}, the default; --option {name}=VALUE chooses one of {}",
            values.join(", ")
        );
        default.to_owned()
    };
    taken.push(format!("{name}={chosen}"));
    let choice = choices.iter().find(|c| value_of(c) == chosen).ok_or_else(bad)?;
    strings(choice.get("dependencies"), location)
}

/// Asks the question at the terminal; an empty line takes the default.
fn prompt(question: &Value, name: &str, choices: &[Value], values: &[String], default: &str) -> io::Result<String> {
    let text = question.get("question").and_then(Value::as_str).unwrap_or(name);
    println!("{text}");
    for (i, (choice, value)) in choices.iter().zip(values).enumerate() {
        let about = choice.get("description").and_then(Value::as_str).unwrap_or_default();
        let mark = if value == default { " (default)" } else { "" };
        println!("  {}. {value}{mark}  {about}", i + 1);
    }
    let stdin = io::stdin();
    loop {
        print!("{name} [1-{}]: ", values.len());
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            return Ok(default.to_owned());
        }
        let line = line.trim();
        if line.is_empty() {
            return Ok(default.to_owned());
        }
        if let Some(value) = line
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| values.get(n))
            .or_else(|| values.iter().find(|v| *v == line))
        {
            return Ok(value.clone());
        }
    }
}

/// A path that stays under the source directory: relative, of plain
/// names.
fn relative(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        })
}

/// The text at a URL, through curl, or of a file.
fn fetch(location: &str) -> io::Result<String> {
    if !location.starts_with("https://") && !location.starts_with("http://") {
        return fs::read_to_string(location).map_err(|e| io::Error::new(e.kind(), format!("{location}: {e}")));
    }
    let output = Command::new("curl")
        .args(["-fsSL", "--max-time", "60", location])
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("curl: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{location}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout).map_err(|_| io::Error::other(format!("{location}: not UTF-8")))
}

/// Whether version wanted, as 0.3.2, is above have.
fn newer(wanted: &str, have: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> { v.split('.').map(|p| p.parse().unwrap_or(0)).collect() };
    parts(wanted) > parts(have)
}

/// The `mod` lines the crate still needs for what was added: a module
/// of the root, or of sys.
fn declarations(dir: &Path, files: &[File]) {
    let root = ["main.rs", "lib.rs"]
        .iter()
        .find_map(|name| fs::read_to_string(dir.join(name)).ok())
        .unwrap_or_default();
    let mut missing = Vec::new();
    for file in files.iter().filter(|f| !f.script) {
        let (parent, module) = match file.path.split_once('/') {
            None => ("the crate root", file.path.strip_suffix(".rs")),
            Some((dir, rest)) if !rest.contains('/') && rest != "mod.rs" => {
                if dir == "sys" {
                    ("each file of sys", rest.strip_suffix(".rs"))
                } else {
                    continue;
                }
            },
            Some((dir, "mod.rs")) => ("the crate root", Some(dir)),
            Some(_) => continue,
        };
        let Some(module) = module else { continue };
        let line = format!("mod {module};");
        if parent == "the crate root" && root.contains(&line) {
            continue;
        }
        missing.push(format!("  {line:<24} in {parent}"));
    }
    if !missing.is_empty() {
        println!("Declare the new modules, then make check test:");
        for line in missing {
            println!("{line}");
        }
    }
}

fn usage() -> &'static str {
    "Usage:\n  rr add --list [@scope | INDEX]\n  rr add [--overwrite] [--yes] [--option NAME=VALUE]... [--dir DIR] COMPONENT...\n\nCopies each COMPONENT, and those it needs, into DIR (src by default) as\nthe project's own code, and its scripts into scripts/. A component may\nask questions, such as where TLS takes its trusted roots from: at a\nterminal rr add asks; --option answers one, and --yes or a run without\na terminal takes the defaults and says how to choose. COMPONENT is a name in rr's registry, @scope/name\nin a registry rr.json names ({\"registries\": {\"@scope\": \"https://…/{name}.json\"}}),\nor the URL or path of a component's JSON. A file that exists and differs\nstops the add unless --overwrite. --list prints a registry's components\n(its index.json), what each needs and what it asks."
}
