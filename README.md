# rr — Restricted Rust

A checker for restricted Rust, based on the Clippy of Rust 1.99.1: it runs on
the official Rust 1.99.1 that rustup installs, as clippy-driver does. rustc
builds the program; rr checks it.

```sh
rr init demo && cd demo
make                    # rustc builds it
make check lint test    # rr checks it and runs its tests
```

Requires no_std; restricts generic definitions, macros, complex traits, dyn Trait
and async/await. Ownership escape hatches require `// rr: escape: <reason>`.
There is no Cargo interface or project manifest for rr programs: a Makefile
calls rustc and rr.

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

Both need rustup. They install Rust 1.99.1 with it, put rr into that
toolchain's `bin/` beside rustc, with libFuzzer and rr fuz's flags in
`lib/rustlib/rr/`, and put rr on PATH: a link in `~/.local/bin`, or on Windows
the toolchain's `bin\` at the end of the user's PATH, after rustup's own
tools. `RR_VERSION` installs a release tag other than the latest. A project's
`rust-toolchain.toml` names the same release, so `rustc` there is the
compiler rr checks with.

The [release workflow](.github/workflows/rr-release.yml) builds rr on each
host against the official release, with libFuzzer from that release's LLVM,
installs and checks it there, and publishes the archives.

The private compiler API rr builds against is Rust 1.99.1, commit 58cf8f9c3 (2026-10-13).
The original Clippy documentation is retained in [UPSTREAM.md](UPSTREAM.md).
