use clippy_utils::tokenize_with_text;
use rustc_lexer::TokenKind;
use rustc_lint::LintContext;
use rustc_span::{Pos as _, Span};

// Lex the whole file so a marker inside a string (including a multiline raw
// string) cannot masquerade as a justification comment.
pub fn has_escape_reason(cx: &impl LintContext, statement: Span, call: Span) -> bool {
    let source_map = cx.sess().source_map();
    let file = source_map.lookup_source_file(statement.lo());
    let Some(source) = &file.src else { return false };
    let start = (statement.lo() - file.start_pos).to_usize();
    let call_start = (call.lo() - file.start_pos).to_usize();
    let line_start = source[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let call_line_start = source[..call_start].rfind('\n').map_or(0, |pos| pos + 1);
    let statement_end = (statement.hi() - file.start_pos).to_usize();
    let line_end = source[statement_end..]
        .find('\n')
        .map_or(source.len(), |pos| statement_end + pos);

    tokenize_with_text(source).any(|(kind, text, range)| {
        if !matches!(
            kind,
            TokenKind::LineComment { doc_style: None }
                | TokenKind::BlockComment {
                    doc_style: None,
                    terminated: true
                }
        ) {
            return false;
        }
        let text = text
            .strip_prefix("//")
            .or_else(|| text.strip_prefix("/*").and_then(|text| text.strip_suffix("*/")))
            .unwrap_or("");
        let reason = text
            .trim()
            .strip_prefix("rr: escape:")
            .is_some_and(|reason| !reason.trim().is_empty());
        if !reason {
            return false;
        }
        let lo = range.start;
        let hi = range.end;
        // An immediately preceding comment block, or a comment on a line of
        // this statement. A previous statement's trailing comment is excluded.
        let before = [start, call_start].into_iter().any(|position| {
            hi <= position
                && source[hi..position].trim().is_empty()
                && source[hi..position].bytes().filter(|&byte| byte == b'\n').count() <= 1
        }) && source[source[..lo].rfind('\n').map_or(0, |pos| pos + 1)..lo]
            .trim()
            .is_empty();
        let beside = lo >= start && hi <= line_end && lo >= call_line_start.max(line_start);
        before || beside
    })
}
