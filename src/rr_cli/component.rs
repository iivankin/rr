//! A component of a registry, as stb has a library: one Rust file. Its
//! `//!` docs say what it is, the first paragraph of them in a listing;
//! its header, the `// rr:` lines among the comments before the first
//! line of code, says what rr add needs to know:
//!
//! ```text
//! // rr: checked(0.6.0)                 the rr it was checked with
//! // rr: needs(digest, cpu)             components it needs
//! // rr: option(os, many): Which systems?
//! // rr: choice(os = linux, default): Linux 6.1 and later
//! // rr: choice(os = windows, needs(x)): a choice can need more
//! // rr: file(NAME-vectors.txt, tests = yes)   data beside it, if
//! ```
//!
//! An option is `one` (a single choice) or `many` (any of its choices, at
//! least one). Its body keeps or drops what is between
//! `// rr: section(os = linux macos)` and `// rr: end(os = linux macos)`
//! (kept when any of those is chosen) and between `// rr: unless(…)` and
//! its end (kept when none is); they nest. What rr add writes has no
//! header and no marks, and one line that says what was chosen.

/// A question a component asks, and its choices.
pub struct Question {
    pub name: String,
    pub many: bool,
    pub text: String,
    pub choices: Vec<Choice>,
}

pub struct Choice {
    pub value: String,
    pub default: bool,
    pub needs: Vec<String>,
    pub about: String,
}

/// A data file beside the component, copied when its condition holds.
pub struct Data {
    pub path: String,
    pub when: Option<Condition>,
}

/// `name = a b`: holds when any of a, b is chosen for the option name.
#[derive(PartialEq)]
pub struct Condition {
    pub option: String,
    pub values: Vec<String>,
}

pub struct Header {
    pub description: String,
    pub checked: Option<String>,
    pub needs: Vec<String>,
    pub questions: Vec<Question>,
    pub data: Vec<Data>,
}

/// What a header line says: its directive, what its parentheses hold and
/// the text after them.
struct Line<'a> {
    directive: &'a str,
    inside: &'a str,
    text: &'a str,
}

const HEADER: [&str; 5] = ["checked", "needs", "option", "choice", "file"];
const MARKS: [&str; 3] = ["section", "unless", "end"];

/// `// rr: directive(inside): text`, the parentheses balanced.
fn line(raw: &str) -> Option<Line<'_>> {
    let rest = raw.trim().strip_prefix("// rr: ")?;
    let open = rest.find('(')?;
    let directive = &rest[..open];
    if !directive.bytes().all(|b| b.is_ascii_lowercase()) {
        return None;
    }
    let mut depth = 0usize;
    for (i, c) in rest[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let close = open + i;
                    let after = rest[close + 1..].trim();
                    let text = after.strip_prefix(':').map_or(after, str::trim);
                    return Some(Line {
                        directive,
                        inside: &rest[open + 1..close],
                        text,
                    });
                }
            },
            _ => {},
        }
    }
    None
}

/// The parts of a list split at its commas outside parentheses, trimmed.
fn parts(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0);
    for (i, c) in text.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(text[start..i].trim());
                start = i + 1;
            },
            _ => {},
        }
    }
    out.push(text[start..].trim());
    out
}

/// Whether a line belongs to the leading comments, where the header is.
fn leading(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.is_empty() || trimmed.starts_with("//")
}

/// A list `a, b` or `a b`.
fn list(text: &str) -> Vec<String> {
    text.split([',', ' '])
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn condition(text: &str) -> Result<Condition, String> {
    let (option, values) = text
        .split_once('=')
        .ok_or_else(|| format!("`{text}` is not `option = value ...`"))?;
    let values = list(values);
    if values.is_empty() {
        return Err(format!("`{text}` names no value"));
    }
    Ok(Condition {
        option: option.trim().to_owned(),
        values,
    })
}

/// Reads the header of a component's text.
pub fn header(text: &str) -> Result<Header, String> {
    let mut h = Header {
        description: String::new(),
        checked: None,
        needs: Vec::new(),
        questions: Vec::new(),
        data: Vec::new(),
    };
    let mut paragraph = true;
    let mut in_header = true;
    for raw in text.lines() {
        in_header &= leading(raw);
        if let Some(doc) = raw.trim().strip_prefix("//!") {
            let doc = doc.trim();
            if doc.is_empty() {
                paragraph = h.description.is_empty();
            } else if paragraph {
                if !h.description.is_empty() {
                    h.description.push(' ');
                }
                h.description.push_str(doc);
            }
        }
        let Some(l) = line(raw) else {
            continue;
        };
        if !HEADER.contains(&l.directive) {
            if in_header && !MARKS.contains(&l.directive) && !matches!(l.directive, "escape" | "added") {
                return Err(format!(
                    "`{}`: rr: {} is not one of {}",
                    raw.trim(),
                    l.directive,
                    HEADER.join(", ")
                ));
            }
            continue;
        }
        if !in_header {
            return Err(format!("`{}` belongs in the header, before the code", raw.trim()));
        }
        directive(&mut h, &l)?;
    }
    for q in &h.questions {
        let defaults = q.choices.iter().filter(|c| c.default).count();
        if q.choices.is_empty() || defaults == 0 || (!q.many && defaults > 1) {
            return Err(format!(
                "option {} needs choices and {} default",
                q.name,
                if q.many { "at least one" } else { "one" }
            ));
        }
    }
    for d in &h.data {
        if let Some(c) = &d.when {
            check(&h.questions, c)?;
        }
    }
    Ok(h)
}

/// Adds what one header line says.
fn directive(h: &mut Header, l: &Line<'_>) -> Result<(), String> {
    match l.directive {
        "checked" => h.checked = Some(l.inside.trim().to_owned()),
        "needs" => h.needs.extend(list(l.inside)),
        "option" => {
            let (name, kind) = l
                .inside
                .split_once(',')
                .ok_or_else(|| format!("option({}) needs a kind, one or many", l.inside))?;
            let many = match kind.trim() {
                "one" => false,
                "many" => true,
                other => return Err(format!("option {name}: kind {other}, not one or many")),
            };
            let name = name.trim().to_owned();
            if h.questions.iter().any(|q| q.name == name) {
                return Err(format!("option {name} is asked twice"));
            }
            h.questions.push(Question {
                name,
                many,
                text: l.text.to_owned(),
                choices: Vec::new(),
            });
        },
        "choice" => {
            let parts = parts(l.inside);
            let (option, value) = parts[0]
                .split_once('=')
                .ok_or_else(|| format!("choice({}) needs option = value", l.inside))?;
            let (option, value) = (option.trim(), value.trim().to_owned());
            let q = h
                .questions
                .iter_mut()
                .find(|q| q.name == option)
                .ok_or_else(|| format!("choice of {option}, an option not asked before it"))?;
            if q.choices.iter().any(|c| c.value == value) || value.is_empty() || value.contains(' ') {
                return Err(format!("choice {option} = {value} is not a new single word"));
            }
            let mut choice = Choice {
                value,
                default: false,
                needs: Vec::new(),
                about: l.text.to_owned(),
            };
            for &part in &parts[1..] {
                if part == "default" {
                    choice.default = true;
                } else if let Some(needs) = part.strip_prefix("needs(").and_then(|p| p.strip_suffix(')')) {
                    choice.needs = list(needs);
                } else {
                    return Err(format!("choice {option} = {}: `{part}`", choice.value));
                }
            }
            q.choices.push(choice);
        },
        "file" => {
            let (path, when) = match l.inside.split_once(',') {
                Some((path, when)) => (path.trim(), Some(condition(when)?)),
                None => (l.inside.trim(), None),
            };
            h.data.push(Data {
                path: path.to_owned(),
                when,
            });
        },
        _ => {},
    }
    Ok(())
}

/// Whether a condition names an option the header asks and its choices.
fn check(questions: &[Question], c: &Condition) -> Result<(), String> {
    let q = questions
        .iter()
        .find(|q| q.name == c.option)
        .ok_or_else(|| format!("{} is not an option of the header", c.option))?;
    for v in &c.values {
        if !q.choices.iter().any(|choice| &choice.value == v) {
            return Err(format!("{v} is not a choice of {}", c.option));
        }
    }
    Ok(())
}

/// Whether a condition holds for what was chosen.
pub fn holds(c: &Condition, chosen: &[(String, Vec<String>)]) -> bool {
    chosen
        .iter()
        .find(|(name, _)| *name == c.option)
        .is_some_and(|(_, values)| c.values.iter().any(|v| values.contains(v)))
}

/// The text rr add writes: the header and the marks gone, what the
/// choices drop dropped, and `added` where the header was.
pub fn cut(
    text: &str,
    questions: &[Question],
    chosen: &[(String, Vec<String>)],
    added: &str,
) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    // Each open mark: its condition's text, and whether what it holds is
    // kept.
    let mut open: Vec<(&str, bool)> = Vec::new();
    let mut header = true;
    let mut placed = false;
    let mut dropped = false;
    for (number, raw) in text.split_inclusive('\n').enumerate() {
        let at = || format!("line {}", number + 1);
        header &= leading(raw);
        let l = line(raw);
        if header && l.as_ref().is_some_and(|l| HEADER.contains(&l.directive)) {
            if !placed {
                out.push_str(added);
                out.push('\n');
                placed = true;
            }
            continue;
        }
        if let Some(l) = l.filter(|l| MARKS.contains(&l.directive)) {
            if l.directive == "end" {
                match open.pop() {
                    Some((inside, _)) if inside == l.inside => {},
                    Some((inside, _)) => return Err(format!("{}: end({}) closes ({inside})", at(), l.inside)),
                    None => return Err(format!("{}: end({}) closes nothing", at(), l.inside)),
                }
            } else {
                let c = condition(l.inside).map_err(|e| format!("{}: {e}", at()))?;
                check(questions, &c).map_err(|e| format!("{}: {e}", at()))?;
                let keep = holds(&c, chosen) == (l.directive == "section");
                open.push((l.inside, keep));
            }
            dropped = true;
            continue;
        }
        if !open.iter().all(|&(_, keep)| keep) {
            dropped = true;
            continue;
        }
        // A blank line after what was dropped, after another blank line
        // or the brace that opens a block, would be one rr fmt removes.
        let blank = raw.trim().is_empty();
        if blank && dropped && (out.is_empty() || out.ends_with("\n\n") || out.ends_with("{\n")) {
            continue;
        }
        // Nor a blank line before the brace that closes what held it.
        if dropped && raw.trim_start().starts_with(['}', ')', ']']) {
            while out.ends_with("\n\n") {
                out.pop();
            }
        }
        dropped = false;
        out.push_str(raw);
    }
    if let Some((inside, _)) = open.last() {
        return Err(format!("section({inside}) is not ended"));
    }
    // What was dropped at the end leaves the blank line before it.
    while out.ends_with("\n\n") {
        out.pop();
    }
    if !placed {
        out.insert_str(0, &format!("{added}\n"));
    }
    Ok(out)
}
