# rr — Restricted Rust

A standalone Rust compiler and linter based on Clippy rust-1.99.0.

```sh
rr init demo
rr check demo/main.rs
rr lint demo/main.rs
rr demo/main.rs -O -o demo/app
```

Requires no_std; restricts generic definitions, macros, complex traits, dyn Trait
and async/await. Ownership escape hatches require `// rr: escape: <reason>`.
There is no Cargo interface or project manifest for rr programs.

[Usage and exact policy](RR.md) · [Local verification](verification/summary.txt)

The manual [GitHub Actions workflow](.github/workflows/rr-arm64.yml) rebuilds
LLVM with only AArch64 and statically links the matching Rust compiler driver
into rr, then tests and packages a macOS arm64 artifact. Builds run in Actions.
Cross compilation to excluded architectures is unavailable in that artifact.

The pinned private compiler API is Rust 1.99.0-nightly, commit 84b36a78a (2026-08-06).
The original Clippy documentation is retained in [UPSTREAM.md](UPSTREAM.md).
