use clippy_utils::tokenize_with_text;
use rustc_data_structures::fx::{FxBuildHasher, FxHashSet};
use rustc_lexer::TokenKind;
use rustc_lint::LintContext;
use rustc_span::{BytePos, Pos as _, Span};
use std::sync::Mutex;

/// What answers an operation of a kind: an adjacent `// rr: escape(kinds):
/// reason` whose kinds name it, or an adjacent reason that does not.
pub enum Escape {
    Named,
    /// The comment there names other kinds, or none.
    Unnamed(Span),
    Missing,
}

// Lex the whole file so a marker inside a string (including a multiline raw
// string) cannot masquerade as a justification comment.
pub fn has_escape_reason(cx: &impl LintContext, statement: Span, call: Span, kind: &'static str) -> bool {
    matches!(escape_for(cx.sess(), statement, call, kind), Escape::Named)
}

/// For a diagnostic: the adjacent reason that does not name kind.
pub fn unnamed(sess: &rustc_session::Session, statement: Span, call: Span, kind: &'static str) -> Option<Span> {
    match escape_for(sess, statement, call, kind) {
        Escape::Unnamed(span) => Some(span),
        Escape::Named | Escape::Missing => None,
    }
}

/// Point a diagnostic at an adjacent reason that does not name kind, and
/// say how to write one that does.
pub fn note(
    diag: &mut rustc_errors::Diag<'_, ()>,
    sess: &rustc_session::Session,
    statement: Span,
    call: Span,
    kind: &'static str,
) {
    if let Some(comment) = unnamed(sess, statement, call, kind) {
        diag.span_note(
            comment,
            format!("this reason does not name `{kind}`; write `// rr: escape({kind}): ...`"),
        );
    } else {
        diag.help(format!(
            "if the design needs it, add an adjacent `// rr: escape({kind}): <reason>`"
        ));
    }
}

/// The kinds of each reason that answered an operation, by where the
/// reason starts: what is left over answers nothing.
static USED: Mutex<FxHashSet<(BytePos, &'static str)>> = Mutex::new(FxHashSet::with_hasher(FxBuildHasher));

/// Whether the reason starting at lo answered an operation of kind.
pub fn used(lo: BytePos, kind: &'static str) -> bool {
    USED.lock().is_ok_and(|used| used.contains(&(lo, kind)))
}

/// The kinds a comment's text names and whether it gives a reason:
/// `rr: escape(a, b): reason`. The old `rr: escape: reason` names none.
pub fn parse(text: &str) -> Option<Vec<&str>> {
    let rest = text.trim().strip_prefix("rr: escape")?;
    let (kinds, reason) = if let Some(rest) = rest.strip_prefix(':') {
        (Vec::new(), rest)
    } else {
        let rest = rest.strip_prefix('(')?;
        let (list, reason) = rest.split_once("):")?;
        (
            list.split(',').map(str::trim).filter(|k| !k.is_empty()).collect(),
            reason,
        )
    };
    (!reason.trim().is_empty()).then_some(kinds)
}

/// Whether an operation of kind has its reason, from the session alone:
/// what rr's hook into Clippy's diagnostics has too. A reason found
/// answers the operation, and so is used.
pub fn escape_for(sess: &rustc_session::Session, statement: Span, call: Span, kind: &'static str) -> Escape {
    let (escape, at) = find(sess, statement, call, kind);
    if let Some(at) = at
        && let Ok(mut used) = USED.lock()
    {
        used.insert((at, kind));
    }
    escape
}

/// Whether there is a reason for kind, without using it: for an operation
/// that needs one only if what it leads to does.
pub fn peek(sess: &rustc_session::Session, statement: Span, call: Span, kind: &'static str) -> bool {
    matches!(find(sess, statement, call, kind).0, Escape::Named)
}

/// The reason for kind, and where the one that names it starts.
fn find(sess: &rustc_session::Session, statement: Span, call: Span, kind: &'static str) -> (Escape, Option<BytePos>) {
    let source_map = sess.source_map();
    let file = source_map.lookup_source_file(statement.lo());
    let Some(source) = &file.src else {
        return (Escape::Missing, None);
    };
    let start = (statement.lo() - file.start_pos).to_usize();
    let call_start = (call.lo() - file.start_pos).to_usize();
    let line_start = source[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let call_line_start = source[..call_start].rfind('\n').map_or(0, |pos| pos + 1);
    // The rest of the operation's line: where a trailing reason sits.
    let call_line_end = source[call_start..]
        .find('\n')
        .map_or(source.len(), |pos| call_start + pos);

    let mut found = Escape::Missing;
    for (token, text, range) in tokenize_with_text(source) {
        if !matches!(
            token,
            TokenKind::LineComment { doc_style: None }
                | TokenKind::BlockComment {
                    doc_style: None,
                    terminated: true
                }
        ) {
            continue;
        }
        let text = text
            .strip_prefix("//")
            .or_else(|| text.strip_prefix("/*").and_then(|text| text.strip_suffix("*/")))
            .unwrap_or("");
        let Some(kinds) = parse(text) else { continue };
        let lo = range.start;
        let hi = range.end;
        // An immediately preceding comment block, or a comment on a line of
        // this statement. A previous statement's trailing comment is excluded.
        // Directly above the statement, the operation, or the line the
        // operation is on, such as a match arm.
        let before = [start, call_start, call_line_start]
            .into_iter()
            .any(|position| hi <= position && continues_to(&source[hi..position]))
            && source[source[..lo].rfind('\n').map_or(0, |pos| pos + 1)..lo]
                .trim()
                .is_empty();
        // A comment on the operation's own line; one inside a statement that
        // spans lines answers only what is on its line.
        let beside = lo >= call_line_start.max(line_start) && hi <= call_line_end;
        if !(before || beside) {
            continue;
        }
        let at = file.start_pos + BytePos::from_usize(lo);
        if kinds.contains(&kind) {
            return (Escape::Named, Some(at));
        }
        let end = file.start_pos + BytePos::from_usize(hi);
        found = Escape::Unnamed(statement.with_lo(at).with_hi(end));
    }
    (found, None)
}

// Between a reason and its statement: the rest of the reason's line, then
// only further plain line comments that continue it, one per line, with no
// blank line or code in between.
fn continues_to(gap: &str) -> bool {
    let mut lines = gap.split('\n');
    if !lines.next().is_some_and(|rest| rest.trim().is_empty()) {
        return false;
    }
    let mut lines = lines.peekable();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if lines.peek().is_none() {
            // The statement's own line, up to the statement.
            return line.is_empty();
        }
        if !line.starts_with("//") || line.starts_with("///") || line.starts_with("//!") {
            return false;
        }
    }
    true
}
