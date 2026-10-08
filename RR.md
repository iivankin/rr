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

The new macOS ARM64 bundle is approximately 217.37 MiB unpacked, compared with
296.33 MiB for the previous stripped stock-toolchain bundle (329 MiB unstripped).
The reduction is 78.95 MiB, or 26.64%. The executable embeds rustc_driver and
AArch64-only LLVM with ThinLTO; it depends dynamically only on system macOS
libraries. It is stripped and ad-hoc signed. Compiler-crash stacks can therefore
have fewer function names; source diagnostics and compiler inputs are retained.

| Part | Size |
| --- | ---: |
| rr, including compiler driver and LLVM | 125.21 MiB |
| Complete core/alloc/compiler_builtins objects and metadata | 76.86 MiB |
| License notices | 15.29 MiB |
| Version, configuration and documentation | about 0.01 MiB |

The bundle passed relocated init/check/lint/build, native execution, explicit
dependency, local module, alloc and restriction checks without Rust/Cargo tools
in PATH or loader/sysroot overrides. Compiler libraries were built from the
pinned source; core and alloc source code was not modified. The compiler keeps
its language machinery and auxiliary interfaces.

Only the macOS ARM64 target sysroot and AArch64 backend are bundled. Other ARM64
targets need their own libraries and linker/SDK. This executable cannot generate
code for x86_64 or other LLVM architectures. Detailed build/check logs are in
verification/static-compiler-2026-10-08/.


## GitHub Actions: reduced LLVM and static compiler driver

The manual workflow `.github/workflows/rr-arm64.yml` runs on Blacksmith macOS 15
arm64 (12 vCPU / 48 GB RAM), with six compilation workers and one LLVM link job.
It fetches Rust commit 84b36a78a28a63f134171c670be1932ffa2485f8 and its exact LLVM
submodule, builds stage2 Rust with LLVM.targets=AArch64, and compiles rr against
that matching compiler. No prebuilt full LLVM or compiler driver is substituted.
LLVM, stage2 compiler libraries and the release rr executable use ThinLTO.
LLVM and rustc_driver are statically linked into rr. System macOS libraries
remain dynamic; core/alloc objects and metadata stay external as compiler inputs.
The bootstrap artifact filter also retains private compiler rlibs, because
metadata-only rustc-dev packages cannot support static linking.

The workflow runs formatting, check, all-target/all-feature Clippy, tests and
relocated standalone smoke checks before uploading a tar.gz artifact. It checks
that rr has only system dynamic dependencies and records the AArch64-only backend
list from the built llvm-config. The exact bootstrap configuration accompanies the artifact.
The same `scripts/build-toolchain.sh` can build locally with explicit source,
scratch and installation directories. Put these directories, CARGO_HOME,
CARGO_TARGET_DIR and TMPDIR on the build volume; RR_BUILD_JOBS sets parallelism.
Set SYSROOT to the installed compiler directory when checking or testing the
unpackaged static development drivers. The packaged rr selects its adjacent
sysroot automatically.
The upstream formatting test also needs the existing rustup executable in PATH.
Sticky disks and persistent Actions build caches are not used; compiler build directories are
on the ephemeral runner. Artifacts are kept for 14 days.

Run the **Build rr with static driver and ARM64 LLVM** workflow manually under
Actions in github.com/loomatech/rr. The source repository uses Cargo to bootstrap
rr; projects compiled by the distributed rr still use only its direct CLI.

## Planned native distributions

The intended release set is one independent bundle per OS and architecture:

| OS | Architecture | LLVM backend |
| --- | --- | --- |
| macOS | ARM64 | AArch64 |
| macOS | x86_64 | X86 |
| Linux | ARM64 | AArch64 |
| Linux | x86_64 | X86 |
| Windows | ARM64 | AArch64 |
| Windows | x86_64 | X86 |

Each bundle contains its own native executable and matching target sysroot,
with only its native LLVM backend. These are planned distributions, not six
verified releases: the current packaging and release workflow support macOS
ARM64 only. Each additional platform needs native build and execution checks.
Cross compilation between architectures is outside the bundled release set.

Keep core and alloc intact. Do not remove compiler language machinery or
auxiliary rustc interfaces in this pass; the current compiler changes only
enable static driver linking and retain the necessary object archives.
