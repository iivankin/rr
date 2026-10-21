//! Reasons that answer nothing: a `// rr: escape(kind): reason` beside no
//! operation of that kind, a kind rr does not know, or the old form that
//! names none. A reason outlives the code it was for, and then claims a
//! need the code no longer has. Checked once every rule has heard its
//! reasons; a reason in code that cfg leaves out, an item or a statement,
//! is not looked at.

use clippy_utils::tokenize_with_text;
use rustc_data_structures::fx::FxHashSet;
use rustc_errors::DiagDecorator;
use rustc_hir::def::DefKind;
use rustc_hir::intravisit::{self, Visitor};
use rustc_hir::{CRATE_HIR_ID, Expr, HirId, Stmt};
use rustc_lexer::TokenKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::{BytePos, InnerSpan, Pos as _, SourceFile, Span};
use std::sync::Arc;

use super::comments::{parse, used};
use super::{RR_UNUSED_ESCAPE, kind};

type Token<'a> = (TokenKind, &'a str, InnerSpan);

pub fn check(tcx: TyCtxt<'_>) {
    // The items the crate compiled, each with its body, and whether it
    // holds other items, which cfg may have left out of it.
    let items: Vec<(Span, bool)> = tcx
        .hir_crate_items(())
        .owners()
        .map(|owner| {
            let holds = matches!(
                tcx.def_kind(owner.def_id),
                DefKind::Mod | DefKind::Impl { .. } | DefKind::Trait | DefKind::ForeignMod
            );
            (tcx.hir_span_with_body(HirId::make_owner(owner.def_id)), holds)
        })
        .filter(|(span, _)| !span.from_expansion())
        .collect();
    let source_map = tcx.sess.source_map();
    let mut files: Vec<Arc<SourceFile>> = Vec::new();
    for (span, _) in &items {
        let file = source_map.lookup_source_file(span.lo());
        if !files.iter().any(|seen| Arc::ptr_eq(seen, &file)) {
            files.push(file);
        }
    }
    let starts = starts(tcx);
    for file in &files {
        check_file(tcx, file, &items, &starts);
    }
}

/// Where each expression and statement the crate compiled begins: code
/// that cfg left out of a body has none.
fn starts(tcx: TyCtxt<'_>) -> FxHashSet<BytePos> {
    struct Starts(FxHashSet<BytePos>);
    impl<'tcx> Visitor<'tcx> for Starts {
        fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
            self.0.insert(expr.span.lo());
            intravisit::walk_expr(self, expr);
        }
        fn visit_stmt(&mut self, stmt: &'tcx Stmt<'tcx>) {
            self.0.insert(stmt.span.lo());
            intravisit::walk_stmt(self, stmt);
        }
    }
    let mut starts = Starts(FxHashSet::default());
    for owner in tcx.hir_body_owners() {
        starts.visit_body(tcx.hir_body_owned_by(owner));
    }
    starts.0
}

fn check_file(tcx: TyCtxt<'_>, file: &SourceFile, items: &[(Span, bool)], starts: &FxHashSet<BytePos>) {
    let Some(source) = &file.src else { return };
    let tokens: Vec<_> = tokenize_with_text(source).collect();
    let at = |offset: usize| file.start_pos + BytePos::from_usize(offset);
    for (i, (token, text, range)) in tokens.iter().enumerate() {
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
        let Some(code) = target(source, &tokens, i) else {
            continue;
        };
        // The start of an item, or inside one that holds no other items.
        let start = after_attributes(&tokens, code);
        let live = items.iter().any(|(span, holds)| {
            span.lo() == at(start.unwrap_or(code))
                || (start.is_none() && !holds && span.lo() <= at(code) && at(code) < span.hi())
        });
        // A statement under #[cfg] that the crate left out.
        if !live || (after_cfg(&tokens, i) && !starts.contains(&at(code))) {
            continue;
        }
        let span = Span::with_root_ctxt(at(range.start), at(range.end));
        let cold_only = kinds == ["cold"];
        let message = if kinds.is_empty() {
            "this reason names no kind, so it answers nothing".to_owned()
        } else if let Some(unknown) = kinds.iter().find(|name| kind(name).is_none()) {
            format!("`{unknown}` is not a kind rr knows")
        } else {
            let unused: Vec<&str> = kinds
                .iter()
                .filter_map(|name| kind(name))
                .filter(|kind| !used(span.lo(), kind))
                .collect();
            match unused.as_slice() {
                [] => continue,
                ["cold"] => "`cold` marks a call that leads off a hot path to something the path forbids; this one leads to nothing of the kind"
                    .to_owned(),
                _ if unused.len() == kinds.len() => "this reason answers no operation beside it".to_owned(),
                [kind] => format!("`{kind}` in this reason answers no operation beside it"),
                _ => format!("`{}` in this reason answer no operation beside it", unused.join("`, `")),
            }
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "after analysis there is no LateContext for span_lint_hir"
        )]
        tcx.emit_node_span_lint(
            RR_UNUSED_ESCAPE,
            CRATE_HIR_ID,
            span,
            DiagDecorator(|diag| {
                diag.primary_message(message);
                if kinds.is_empty() || kinds.iter().any(|name| kind(name).is_none()) {
                    diag.help(format!("the kinds are {}", super::kinds()));
                } else if cold_only {
                    diag.help("remove the mark: rr follows this call, and finds nothing there for a hot path to avoid");
                } else {
                    diag.help("remove what the code no longer needs; a reason stands beside the operation it is for");
                }
            }),
        );
    }
}

/// Where the code a reason stands for begins, as an offset into source: the
/// start of its own line when it trails code, else the first code after it
/// and the comments that continue it.
fn target(source: &str, tokens: &[Token<'_>], i: usize) -> Option<usize> {
    let start = tokens[i].2.start;
    let line = source[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let lead = &source[line..start];
    if !lead.trim().is_empty() {
        return Some(line + (lead.len() - lead.trim_start().len()));
    }
    tokens[i + 1..]
        .iter()
        .find(|(token, ..)| !is_trivia(*token))
        .map(|(_, _, range)| range.start)
}

/// When the code at offset begins with attributes, where what they belong
/// to begins.
fn after_attributes(tokens: &[Token<'_>], offset: usize) -> Option<usize> {
    let mut i = tokens.iter().position(|(_, _, range)| range.start == offset)?;
    if tokens[i].0 != TokenKind::Pound {
        return None;
    }
    while tokens.get(i).is_some_and(|(token, ..)| *token == TokenKind::Pound) {
        let mut depth = 0usize;
        i += 1;
        while let Some((token, ..)) = tokens.get(i) {
            i += 1;
            match token {
                TokenKind::OpenBracket => depth += 1,
                TokenKind::CloseBracket => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                },
                _ => {},
            }
        }
        while tokens.get(i).is_some_and(|(token, ..)| is_trivia(*token)) {
            i += 1;
        }
    }
    tokens.get(i).map(|(_, _, range)| range.start)
}

/// Whether the comment at i follows an attribute `#[cfg(...)]`, as a
/// reason for a statement under cfg does.
fn after_cfg(tokens: &[Token<'_>], i: usize) -> bool {
    let mut j = i;
    while j > 0 && is_trivia(tokens[j - 1].0) {
        j -= 1;
    }
    if j == 0 || tokens[j - 1].0 != TokenKind::CloseBracket {
        return false;
    }
    // Back to the attribute's `#[`: its name is the token after it.
    let mut depth = 0usize;
    while j > 0 {
        j -= 1;
        match tokens[j].0 {
            TokenKind::CloseBracket => depth += 1,
            TokenKind::OpenBracket => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            },
            _ => {},
        }
    }
    j > 0 && tokens[j - 1].0 == TokenKind::Pound && tokens.get(j + 1).is_some_and(|(_, text, _)| *text == "cfg")
}

fn is_trivia(token: TokenKind) -> bool {
    matches!(
        token,
        TokenKind::Whitespace | TokenKind::LineComment { .. } | TokenKind::BlockComment { .. }
    )
}
