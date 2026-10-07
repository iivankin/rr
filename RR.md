# rr — Restricted Rust

A compiler and linter forked from Clippy's `rust-1.99.0` tag, commit
`49e2f89a2605a9a340e04955fdbefa9803e6027a`. Its matching private compiler API is
**rustc 1.99.0-nightly (84b36a78a, 2026-08-06)**, toolchain `nightly-2026-08-07`.
It is not the stable 1.99.0 compiler binary.

## Use

The local distribution is `dist/rr-macos-arm64/`. Keep the whole directory together;
its `rr` executable loads the bundled compiler dylibs and selects the bundled
sysroot. It works without installed Rust, rustup or Cargo. Native executable
linking still requires the macOS linker and SDK (Xcode Command Line Tools).
Only the host `aarch64-apple-darwin` libraries are included.

```sh
/path/to/rr-macos-arm64/rr init demo
/path/to/rr-macos-arm64/rr check demo/main.rs
/path/to/rr-macos-arm64/rr lint demo/main.rs
/path/to/rr-macos-arm64/rr demo/main.rs -O -o demo/app
./demo/app

/path/to/rr-macos-arm64/rr init library --lib
/path/to/rr-macos-arm64/rr library/lib.rs --crate-name example -o libexample.rlib
/path/to/rr-macos-arm64/rr main.rs --extern example=libexample.rlib -o app
```

`rr FILE` and `rr build FILE` compile; `rr check FILE` and `rr lint FILE` write
metadata to a temporary directory and remove it on return, including compiler
errors. `lint` also enables Clippy's normal default lints; build/check run the rr
rules plus ordinary compiler diagnostics. Rustc flags are forwarded, including
`-O`, `-o`, `--cfg`, `--extern`, `-L`, `--crate-type`, `--target`, `--sysroot` and
`@argument-file`. Check/lint reject explicit output flags.

Defaults: edition 2024, panic=abort, and rlib for an input named lib.rs. Otherwise
rustc's normal binary default applies. `init` creates main.rs (or lib.rs with
--lib), refuses to overwrite it, and creates no manifest. Its native binary
scaffold uses the C runtime for entry and abort and has no Rust allocator.
No registry dependency manager or Cargo interface is included. Prebuilt
libraries must match this compiler and target. Upstream Cargo tools remain in
the source checkout for developing/testing the fork; they are not distributed.

## Required rules

Rules are compiler errors and cannot be lowered with `allow`, `-A rr`,
`--cap-lints` or Cargo environment variables.

| Rule | Restriction |
| --- | --- |
| rr_no_std | Require #![no_std]; forbid explicit std imports |
| rr_no_generics | Forbid own type/const generic parameters, impl Trait, async fn/blocks/closures and await |
| rr_simple_traits | Forbid associated types/GATs, supertraits, where clauses, trait aliases and dyn Trait |
| rr_no_macros | Forbid macro definitions, calls, derive and procedural attributes, including nested calls and cfg_attr derives |
| rr_unexplained_escape | Require a nearby real comment with a nonempty explanation for the operations below |

Lifetime parameters, ordinary traits/impls, and concrete uses of existing generic
library types such as Vec<u8> remain allowed. This policy restricts user-defined
generics, not every generic inside core/alloc. It checks the current crate and
its local modules, not previously compiled dependencies.

The macro exceptions are bare or core-qualified panic!, unreachable!,
unimplemented!, todo!, assert!, assert_eq!, assert_ne! and debug_assert variants.
Their own implementation expansions are not user macro calls. No explicit
format!/println!/vec!/derive exceptions exist.
Builtin attributes, cfg/cfg_attr, clippy and rustfmt tool attributes are allowed.

## Escape comments

```rust
// rr: escape: the caller needs an independent snapshot after the source changes.
let snapshot = value.clone();
```

Also accepts a block comment, or a trailing comment on the same statement.
A marker inside a string, documentation comment, empty reason or distant comment
is rejected. One comment can justify several related operations on a statement.
The tool checks that a reason exists, not that the explanation is truthful.

Required for:

- All resolved Clone::clone/clone_from calls, including scalar, reference, Rc/Arc
  and UFCS calls. A clone can copy a scalar, allocate or increment a reference
  count; rr does not claim every clone allocates.
- ToOwned::to_owned/clone_into, slice to_vec, Iterator::cloned, and collect when
  the result is an owned standard collection.
- Standard operations creating/acquiring Rc, Arc or RefCell, and RefCell's
  borrow/borrow_mut/try_borrow/try_borrow_mut.
- Box::leak, mem::forget, transmute/transmute_copy/transmute_unchecked.
- User-written unsafe blocks, unsafe functions and unsafe trait implementations.

Operations are matched using resolved definitions and result types. An unrelated
inherent method called clone is not Clone. Arbitrary user functions may hide
these operations, and previously compiled libraries are not audited. This is an
explicit lint policy, not a proof that all possible ownership escape hatches are
absent. Comments document a decision; they do not make unsafe code sound.

## Development and packaging

The Clippy fork itself uses upstream Cargo build/test infrastructure. This is
separate from compiling rr projects, which never invokes Cargo. Cargo.lock pins
resolved dependency versions. Build with the pinned toolchain from
rust-toolchain.toml, including rustc-dev, rust-src, rustfmt and clippy.

```sh
cargo build --locked --release --bin rr
scripts/package-rr.sh target/release/rr /path/to/matching/toolchain dist/rr-macos-arm64
```

The current packaging script supports macOS arm64 and accepts an existing
compiler binary, matching toolchain and a new destination directory. It packages
rustc_driver, LLVM and core/alloc/compiler_builtins archives with their metadata;
adds a relative runtime search path; strips local/debug symbols while retaining
dynamic exports; then ad-hoc signs rr and both compiler libraries. Compiler version and
license notices are included. The distribution contains no Cargo/rustup/rustc
executable and creates no Cargo cache.

## Local verification (2026-10-08)

22 rr tests pass. Formatting, cargo check, Clippy with all targets/features and
-D warnings, and the release build pass. The upstream suite and dogfood pass
with one old Cargo fixture excluded: nix 0.9.0 in
5041_allow_dev_build is incompatible with libc 0.2.190 on macOS. The unfiltered
run and the final successful run are preserved in verification/. See
verification/summary.txt for commands and limitations.

The release bundle was copied to a path containing spaces and exercised with no
Rust/Cargo binaries in PATH or loader/sysroot overrides. Native compilation and
execution, checks, lints, local modules, explicit dependencies and alloc work.
Temporary build/Cargo caches and generated fixture lockfiles were removed.


## Distribution size

The macOS arm64 bundle is stripped by default: approximately 296 MiB instead of
329 MiB. This removes local/debug symbols from rr, rustc_driver and LLVM, so
compiler-crash stacks can have fewer function names. Source diagnostics,
metadata and generated programs are unaffected. LLVM target support is retained.
The stripped package passed the relocated distribution smoke checks.

Only macOS arm64 core/alloc/compiler_builtins are bundled. Cross compilation
requires a matching target sysroot and linker/SDK supplied separately. Building
LLVM with only AArch64 would remove code generation for other architectures;
ARM64 targets on other operating systems would still require their own target
libraries and linking tools. No such LLVM rebuild has been applied.


## GitHub Actions: reduced LLVM and static compiler driver

The manual workflow `.github/workflows/rr-arm64.yml` runs on macOS 15 arm64.
It fetches Rust commit 84b36a78a28a63f134171c670be1932ffa2485f8 and its exact LLVM
submodule, builds stage2 Rust with LLVM.targets=AArch64, and compiles rr against
that matching compiler. No prebuilt full LLVM or compiler driver is substituted.
LLVM stays a shared library; rustc_driver is built as an rlib and linked into rr.
The bootstrap artifact filter also retains private compiler rlibs, because
metadata-only rustc-dev packages cannot support static linking.

The workflow runs formatting, check, all-target/all-feature Clippy, tests and
relocated standalone smoke checks before uploading a tar.gz artifact. It checks
that rr has no dynamic rustc_driver dependency and LLVM has no excluded backend
exports. The exact bootstrap configuration accompanies the artifact.
The compiler/LLVM build script refuses to run outside GitHub Actions.
No persistent Actions build cache is configured; compiler build directories are
on the ephemeral runner. Artifacts are kept for 14 days.

Run the **Build rr with static driver and ARM64 LLVM** workflow manually under
Actions in github.com/iivankin/rr. The source repository uses Cargo to bootstrap
rr; projects compiled by the distributed rr still use only its direct CLI.
