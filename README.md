# rr — Restricted Rust

A standalone Rust compiler and linter based on the Clippy of Rust 1.99.1.

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

## Install

macOS arm64, Linux x86_64 and aarch64 (glibc 2.31 or later):

```sh
curl -fsSL https://raw.githubusercontent.com/iivankin/rr/main/install.sh | sh
```

Windows x86_64 and aarch64, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/iivankin/rr/main/install.ps1 | iex
```

By default the distribution goes to `~/.local/share/rr`, linked from
`~/.local/bin/rr`, or on Windows to `%LOCALAPPDATA%\Programs\rr`, added to the
user's PATH. `RR_INSTALL` names another directory and leaves PATH alone: rr is
then `$RR_INSTALL/rr`. `RR_VERSION` installs a release tag other than the
latest. A distribution is also just an archive from
[Releases](https://github.com/iivankin/rr/releases): unpacked anywhere, its `rr`
runs from there, as long as its directory stays whole.

The [release workflow](.github/workflows/rr-release.yml) rebuilds LLVM with the
host's backend only and statically links it and the matching Rust compiler
driver into rr on each host, then tests, packages and publishes the
distributions. Each builds for its own host only.

The pinned private compiler API is Rust 1.99.1, commit 58cf8f9c3 (2026-10-13).
The original Clippy documentation is retained in [UPSTREAM.md](UPSTREAM.md).
