//! rr add: copy a component of a registry into the project, as its own
//! code, in src/base/NAME.rs, so that what came from a registry stays
//! apart from what the project wrote. A component is one Rust file of a
//! registry, NAME.rs, as stb has a library (see component.rs): its header
//! says the rr it was checked with, the components it needs, the
//! questions whose answers cut parts of it away or add components, and
//! data files beside it. A registry is a directory of such files, served
//! from anywhere, with index.json at its root.

use std::fmt::Write as _;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{fs, io};

use serde_json::Value;

use super::component;

/// Where a bare name is looked up, unless rr.json names another `@rr`:
/// rr's registry as this release of rr has it, so that a later change to
/// the registry never reaches an rr that does not know it.
fn default_registry() -> String {
    format!(
        "https://raw.githubusercontent.com/iivankin/rr/v{}/registry",
        super::VERSION
    )
}

/// The directory under the source directory that holds what rr add
/// copied, a module of the crate root.
const BASE: &str = "base";

struct Options {
    overwrite: bool,
    dir: PathBuf,
    items: Vec<String>,
    /// Answers given as --option name=value or name=a,b.
    answers: Vec<(String, Vec<String>)>,
    /// Take each question's default without asking.
    defaults: bool,
}

/// One file rr add writes, under the source directory, and its text.
struct File {
    path: String,
    text: String,
}

/// What an add gathers: the components seen, their files and names, and
/// the answers taken, each option's once for every component that asks
/// it.
struct Gathered {
    registries: Vec<(String, String)>,
    seen: Vec<String>,
    files: Vec<File>,
    names: Vec<String>,
    taken: Vec<(String, Vec<String>)>,
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
            "--index" => {
                let dir = args.get(i + 1).ok_or_else(|| io::Error::other(usage()))?;
                return index(Path::new(dir));
            },
            "--option" => {
                i += 1;
                let (name, value) = args
                    .get(i)
                    .and_then(|a| a.split_once('='))
                    .ok_or_else(|| io::Error::other(usage()))?;
                let values = value.split(',').filter(|v| !v.is_empty()).map(str::to_owned).collect();
                o.answers.push((name.to_owned(), values));
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
    // Refuse before writing anything: an add never leaves half a
    // component or replaces code the project changed.
    for name in &g.names {
        let old = o.dir.join(BASE).join(name);
        if old.join("mod.rs").exists() {
            return Err(io::Error::other(format!(
                "{} is a component as rr 0.5 added it, a directory; it is one file now, {}.rs: remove the directory and add it again",
                old.display(),
                old.display()
            )));
        }
    }
    let mut writes = Vec::new();
    for file in &g.files {
        let target = o.dir.join(&file.path);
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
    modules(&o.dir, &g.names)?;
    declarations(&o.dir);
    if g.taken.is_empty() {
        println!("rr add: {}", g.names.join(", "));
    } else {
        let taken: Vec<String> = g.taken.iter().map(|(n, v)| format!("{n}={}", v.join(","))).collect();
        println!("rr add: {} ({})", g.names.join(", "), taken.join(" "));
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints a registry's components, from its index.json: rr's, a scope
/// rr.json names, or an index's path or URL.
fn list(registry: Option<&str>, registries: &[(String, String)]) -> io::Result<ExitCode> {
    let location = match registry {
        None => format!("{}/index.json", root(None, registries)?),
        Some(scope) if scope.starts_with('@') => format!("{}/index.json", root(Some(scope), registries)?),
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

/// Writes DIR/index.json, what --list prints, from the header of each
/// component in DIR.
fn index(dir: &Path) -> io::Result<ExitCode> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<io::Result<_>>()?;
    paths.retain(|p| p.extension().is_some_and(|e| e == "rs"));
    paths.sort();
    let mut items = Vec::new();
    for path in &paths {
        let text = fs::read_to_string(path)?;
        let h = component::header(&text).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        let mut entry = serde_json::json!({
            "name": name,
            "description": h.description,
            "dependencies": h.needs,
        });
        let options: Vec<Value> = h
            .questions
            .iter()
            .map(|q| {
                let defaults: Vec<&str> = q
                    .choices
                    .iter()
                    .filter(|c| c.default)
                    .map(|c| c.value.as_str())
                    .collect();
                serde_json::json!({
                    "name": q.name,
                    "default": defaults.join(","),
                    "choices": q.choices.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect();
        if !options.is_empty() {
            entry["options"] = Value::Array(options);
        }
        items.push(entry);
    }
    let mut text =
        serde_json::to_string_pretty(&serde_json::json!({ "components": items })).map_err(io::Error::other)?;
    text.push('\n');
    let target = dir.join("index.json");
    if fs::read_to_string(&target).ok().as_deref() == Some(text.as_str()) {
        println!("Unchanged {}", target.display());
    } else {
        fs::write(&target, text)?;
        println!("Wrote {}", target.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// The registries rr.json names, as `{"registries": {"@scope": URL}}`,
/// each URL the registry's root directory.
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
            let url = url.as_str().filter(|u| !u.contains("{name}")).ok_or_else(|| {
                io::Error::other(format!(
                    "rr.json: {scope} names the registry's root directory, which holds NAME.rs"
                ))
            })?;
            found.push((scope.clone(), url.trim_end_matches('/').to_owned()));
        }
    }
    Ok(found)
}

/// The root of a registry: a scope rr.json names, `@rr` if it names
/// one, or rr's own.
fn root(scope: Option<&str>, registries: &[(String, String)]) -> io::Result<String> {
    match scope {
        Some(scope) => registries
            .iter()
            .find(|(s, _)| s == scope)
            .map(|(_, url)| url.clone())
            .ok_or_else(|| io::Error::other(format!("{scope}: no such registry in rr.json"))),
        None => Ok(registries
            .iter()
            .find(|(s, _)| s == "@rr")
            .map_or_else(default_registry, |(_, url)| url.clone())),
    }
}

/// Where an item is: the URL or path of a component's file, `@scope/name`
/// in a registry of rr.json, or a name. A dependency's bare name is a
/// file beside the component that needs it, in the same registry.
fn locate(item: &str, beside: Option<&str>, registries: &[(String, String)]) -> io::Result<String> {
    if item.starts_with("https://")
        || item.starts_with("http://")
        || Path::new(item)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
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
    if !word(name) {
        return Err(io::Error::other(format!("{item}: not a component name")));
    }
    let registry = match (&scope, beside) {
        (None, Some(base)) => parent(base),
        (scope, _) => root(scope.as_deref(), registries)?,
    };
    Ok(format!("{registry}/{name}.rs"))
}

/// A component's name: letters, digits, `_` and `-`.
fn word(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The directory location is in, without the separator.
fn parent(location: &str) -> String {
    match location.rfind(['/', '\\']) {
        Some(end) => location[..end].to_owned(),
        None => ".".to_owned(),
    }
}

/// path relative to the directory of the component at base.
fn join(base: &str, path: &str) -> String {
    format!("{}/{path}", parent(base))
}

/// The component at location and those it needs, those first, each
/// once.
fn collect(location: &str, o: &Options, ask: bool, g: &mut Gathered) -> io::Result<()> {
    if g.seen.iter().any(|s| s == location) {
        return Ok(());
    }
    g.seen.push(location.to_owned());
    let file = location.rsplit(['/', '\\']).next().unwrap_or_default();
    let name = file.strip_suffix(".rs").unwrap_or(file).to_owned();
    if !word(&name) {
        return Err(io::Error::other(format!("{location}: {name} is not a component name")));
    }
    let text = fetch(location)?;
    let h = component::header(&text).map_err(|e| io::Error::other(format!("{location}: {e}")))?;
    if let Some(wanted) = &h.checked
        && newer(wanted, super::VERSION)
    {
        return Err(io::Error::other(format!(
            "{name} needs rr {wanted}; this is rr {}",
            super::VERSION
        )));
    }
    let mut needs = h.needs.clone();
    let mut chosen = Vec::new();
    for q in &h.questions {
        let values = answer(q, &name, o, ask, &mut g.taken)?;
        for c in q.choices.iter().filter(|c| values.contains(&c.value)) {
            needs.extend(c.needs.iter().cloned());
        }
        chosen.push((q.name.clone(), values));
    }
    for dependency in &needs {
        let next = locate(dependency, Some(location), &g.registries)?;
        collect(&next, o, ask, g)?;
    }
    let mut added = format!("// rr: added({name}, rr {}", super::VERSION);
    for (option, values) in &chosen {
        let _ = write!(added, "; {option} = {}", values.join(" "));
    }
    added.push(')');
    let body = component::cut(&text, &h.questions, &chosen, &added)
        .map_err(|e| io::Error::other(format!("{location}: {e}")))?;
    push(g, format!("{BASE}/{name}.rs"), body)?;
    for d in &h.data {
        if d.when.as_ref().is_some_and(|c| !component::holds(c, &chosen)) {
            continue;
        }
        let own = d
            .path
            .strip_prefix(name.as_str())
            .is_some_and(|rest| rest.starts_with(['-', '.']));
        if !own || !relative(&d.path) {
            return Err(io::Error::other(format!(
                "{location}: {} is not a file of {name}'s own beside it, {name}-… or {name}.…",
                d.path
            )));
        }
        let text = fetch(&join(location, &d.path))?;
        push(g, format!("{BASE}/{}", d.path), text)?;
    }
    g.names.push(name);
    Ok(())
}

/// Adds a file to write, once.
fn push(g: &mut Gathered, path: String, text: String) -> io::Result<()> {
    if g.files.iter().any(|f| f.path == path) {
        return Err(io::Error::other(format!("{path} comes from two components")));
    }
    g.files.push(File { path, text });
    Ok(())
}

/// What is chosen of one question: from --option, from an earlier
/// component's question of the same name, from the person asked, or the
/// defaults.
fn answer(
    q: &component::Question,
    name: &str,
    o: &Options,
    ask: bool,
    taken: &mut Vec<(String, Vec<String>)>,
) -> io::Result<Vec<String>> {
    let values: Vec<&str> = q.choices.iter().map(|c| c.value.as_str()).collect();
    let defaults: Vec<String> = q
        .choices
        .iter()
        .filter(|c| c.default)
        .map(|c| c.value.clone())
        .collect();
    let given = o
        .answers
        .iter()
        .chain(taken.iter())
        .find(|(n, _)| *n == q.name)
        .map(|(_, v)| v.clone());
    let chosen = if let Some(given) = given {
        given
    } else if ask {
        prompt(q, &values, &defaults)?
    } else {
        println!(
            "{name}: {} = {}, the default; --option {}={} chooses {}",
            q.name,
            defaults.join(","),
            q.name,
            if q.many { "A,B" } else { "VALUE" },
            if q.many { "any of" } else { "one of" },
        );
        println!("    {}", values.join(", "));
        defaults
    };
    let wrong =
        chosen.is_empty() || (!q.many && chosen.len() > 1) || chosen.iter().any(|v| !values.contains(&v.as_str()));
    if wrong {
        return Err(io::Error::other(format!(
            "{name}: --option {}={}: {} of {}",
            q.name,
            chosen.join(","),
            if q.many { "one or more" } else { "one" },
            values.join(", ")
        )));
    }
    if !taken.iter().any(|(n, _)| *n == q.name) {
        taken.push((q.name.clone(), chosen.clone()));
    }
    Ok(chosen)
}

/// Asks the question at the terminal; an empty line takes the defaults.
fn prompt(q: &component::Question, values: &[&str], defaults: &[String]) -> io::Result<Vec<String>> {
    println!("{}", if q.text.is_empty() { &q.name } else { &q.text });
    for (i, c) in q.choices.iter().enumerate() {
        let mark = if c.default { " (default)" } else { "" };
        println!("  {}. {}{mark}  {}", i + 1, c.value, c.about);
    }
    let stdin = io::stdin();
    loop {
        if q.many {
            print!("{} [numbers or names, separated by spaces]: ", q.name);
        } else {
            print!("{} [1-{}]: ", q.name, values.len());
        }
        io::stdout().flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 || line.trim().is_empty() {
            return Ok(defaults.to_vec());
        }
        let picked: Option<Vec<String>> = line
            .split([' ', ','])
            .filter(|w| !w.is_empty())
            .map(|w| {
                w.parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|n| values.get(n))
                    .or_else(|| values.iter().find(|v| **v == w))
                    .map(|v| (*v).to_owned())
            })
            .collect();
        if let Some(picked) = picked
            && (q.many || picked.len() == 1)
        {
            return Ok(picked);
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

/// Declares each component added in base/mod.rs, which rr add keeps:
/// the module of everything it copied.
fn modules(dir: &Path, names: &[String]) -> io::Result<()> {
    let path = dir.join(BASE).join("mod.rs");
    let mut text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::from(
            "//! What rr add copied from a registry: the project's own code now,\n\
             //! kept apart from what it wrote. rr add declares each component here.\n\n",
        ),
        Err(error) => return Err(error),
    };
    let old = text.clone();
    for name in names {
        let line = format!("pub mod {name};");
        if !text.lines().any(|l| l.trim() == line) {
            text.push_str(&line);
            text.push('\n');
        }
    }
    if text != old {
        fs::create_dir_all(path.parent().unwrap_or(dir))?;
        fs::write(&path, text)?;
        println!("Declared in {}", path.display());
    }
    Ok(())
}

/// Says to declare base in the crate root, if it does not.
fn declarations(dir: &Path) {
    let root = ["main.rs", "lib.rs"]
        .iter()
        .find_map(|name| fs::read_to_string(dir.join(name)).ok())
        .unwrap_or_default();
    let line = format!("mod {BASE};");
    if !root
        .lines()
        .any(|l| l.trim() == line || l.trim() == format!("pub {line}"))
    {
        println!("Declare `{line}` in the crate root, then make check test.");
    }
}

fn usage() -> &'static str {
    "Usage:\n  rr add --list [@scope | INDEX]\n  rr add --index DIR\n  rr add [--overwrite] [--yes] [--option NAME=A[,B]]... [--dir DIR] COMPONENT...\n\nCopies each COMPONENT, one Rust file, and those it needs into\nDIR/base/NAME.rs (DIR is src by default) as the project's own code, with\nwhat its options leave out cut away, and declares it in DIR/base/mod.rs.\nA component asks questions, such as which systems it builds for or where\nTLS takes its trusted roots from: at a terminal rr add asks; --option\nanswers one for every component that asks it (os=linux,macos), and --yes\nor a run without a terminal takes the defaults and says how to choose.\nCOMPONENT is a name in rr's registry, @scope/name in a registry rr.json\nnames ({\"registries\": {\"@scope\": \"https://…/registry\"}}, its root,\nholding NAME.rs), or the URL or path of a component's file. A file that\nexists and differs stops the add unless --overwrite. --list prints a\nregistry's components (its index.json), what each needs and what it\nasks; --index writes DIR/index.json from the components in DIR."
}
