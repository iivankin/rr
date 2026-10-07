use clippy_utils::diagnostics::span_lint_and_help;
use rustc_ast::token::{Token, TokenKind};
use rustc_ast::tokenstream::{TokenStream, TokenTree};
use rustc_lint::EarlyContext;

use super::RR_NO_MACROS;

// Macro arguments are opaque to the AST visitor. Inspect their token trees too,
// including code inside debug_assert! that would disappear in a release build.
pub fn check_arguments(cx: &EarlyContext<'_>, tokens: &TokenStream) {
    for (index, tree) in tokens.iter().enumerate() {
        if let TokenTree::Delimited(_, _, _, inner) = tree {
            check_arguments(cx, inner);
        }
        let TokenTree::Token(
            Token {
                kind: TokenKind::Ident(name, _),
                span,
            },
            _,
        ) = tree
        else {
            continue;
        };
        if !matches!(
            tokens.get(index + 1),
            Some(TokenTree::Token(
                Token {
                    kind: TokenKind::Bang,
                    ..
                },
                _
            ))
        ) {
            continue;
        }
        let Some(TokenTree::Delimited(delimiters, _, _, _)) = tokens.get(index + 2) else {
            continue;
        };
        let mut names = vec![name.as_str()];
        let mut start = index;
        while start >= 2
            && matches!(
                tokens.get(start - 1),
                Some(TokenTree::Token(
                    Token {
                        kind: TokenKind::PathSep,
                        ..
                    },
                    _
                ))
            )
        {
            let Some(TokenTree::Token(
                Token {
                    kind: TokenKind::Ident(prefix, _),
                    ..
                },
                _,
            )) = tokens.get(start - 2)
            else {
                break;
            };
            names.insert(0, prefix.as_str());
            start -= 2;
        }
        if !super::syntax::allowed_macro_names(&names) && !span.from_expansion() {
            span_lint_and_help(
                cx,
                RR_NO_MACROS,
                span.with_hi(delimiters.close.hi()),
                "nested macro calls are forbidden by rr",
                None,
                "only core panic/assert macros are allowed, including inside other macros",
            );
        }
    }
}
