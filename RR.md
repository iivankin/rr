# rr — Restricted Rust

A compiler and linter forked from Clippy's `rust-1.99.0` tag, commit
`49e2f89a2605a9a340e04955fdbefa9803e6027a`. Its matching private compiler API is
**rustc 1.99.0-nightly (84b36a78a, 2026-08-06)**, toolchain `nightly-2026-08-07`.
It is not the stable 1.99.0 compiler binary.

## Use

Keep the whole distribution directory together. Static release builds embed
the compiler driver and LLVM, with the host's backend only, in `rr`;
core/alloc/compiler_builtins object archives and metadata remain in the bundled
sysroots: the host's, and on Linux and Windows that of the host's rr target
(see Targets), which the bundled rust-lld links. A small rust-objcopy utility
supports -Cstrip on macOS. It works without installed Rust, rustup or Cargo.
Each distribution builds for its own host only. Distributions are built for
macOS arm64, Linux x86_64 and aarch64 (glibc 2.31 or later) and Windows x86_64
and aarch64. On macOS, native executable linking still requires the macOS
linker and SDK (Xcode Command Line Tools); on Linux and Windows nothing else is
needed, except for fuzzing.

```sh
rr init demo            # a project: see below
cd demo
make                    # build
make test               # rr test: the #[test] items; FILTER=word narrows
make bench              # rr bench: time, allocations and copies per iteration
make fmt                # rr fmt: rewrite in rr's one style
make format check lint  # rr fmt --check, rr's rules, then Clippy's
make fuzz               # rr fuz --target: each fn named in FUZZ
make prof               # where the program allocates and copies

rr init library --lib   # src/lib.rs alone, for a crate to depend on
rr library/src/lib.rs --crate-name example -o libexample.rlib
rr main.rs --extern example=libexample.rlib -o app
```

`rr FILE` and `rr build FILE` compile; `rr check FILE` and `rr lint FILE` write
metadata to a temporary directory and remove it on return, including compiler
errors. `lint` also enables Clippy's normal default lints; build/check run the rr
rules plus ordinary compiler diagnostics. Rustc flags are forwarded, including
`-O`, `-o`, `--cfg`, `--extern`, `-L`, `--crate-type`, `--target`, `--sysroot` and
`@argument-file`. Check/lint reject explicit output flags.

`rr fmt FILE...` formats crates with rustfmt, which rr links at its compiler's
own commit (rustfmt/ in the source): each root and the modules it declares,
in rustfmt's defaults for edition 2024. A rustfmt.toml is not read, so every
rr crate has one style. `rr fmt --check` writes nothing; it prints what differs
and fails, for CI. As in Rust's usual pipeline, format, check and lint are
separate steps: rustfmt, the compiler with rr's rules, and Clippy.

Defaults: edition 2024, panic=abort, and rlib for an input named lib.rs. Otherwise
rustc's normal binary default applies. `init` lays out a project and refuses to
overwrite any of it: src/main.rs (the program, one crate, with a malloc-backed
global allocator, a panic handler and the C entry), src/sys.rs (the operating
system and unsafe), src/greet.rs (a module with its tests, a bench and a fuzz
target beside the code), a Makefile with build, test, bench, fmt, format,
check, lint, fuzz and prof targets, and AGENTS.md
with the rules for whoever changes the code: format with rr fmt, then rr check
and rr lint, after every change. `init --lib` writes src/lib.rs alone. No manifest
is created.

## Targets

On macOS a program links against the system's C library, as Apple requires.
On Linux and Windows it needs none: rr's own targets, `x86_64-rr-linux`,
`aarch64-rr-linux`, `x86_64-rr-windows` and `aarch64-rr-windows`, are the
default there, each in the distribution for its host. A Linux program is a static executable that calls the
kernel itself; a Windows program calls kernel32.dll through `raw-dylib`
imports, with no C runtime and no Visual Studio. Both start in `rr_crt`, which
hands argc and argv (UTF-8, split as the Microsoft C runtime splits them, on
Windows) to the program's `extern "C" fn main`, so a program's entry is the
same everywhere; its `src/sys/` has a file for each system with the same
functions. The targets are described in targets/*.json, made from the pinned
compiler's own by scripts/make-target-specs.py; scripts/build-target-sysroot.py
builds their sysroots.

`RR_RUNNER`, a command and its arguments split at spaces, runs what rr test and
rr bench build under another program, such as a debugger or a container. Tests run in a child
process on every system: a fork on macOS and Linux; on Windows, which has
none, the executable runs again for each test. rr bench and rr prof count
allocations and copies on all of them; on Windows the stacks come from the
system's unwinder, as a frame pointer there need not point at the caller's.

## Tests, benches and fuzz targets

Tests sit beside the code they check, as in any Rust crate: `#[test]` and
`#[bench]` functions in a `#[cfg(test)] mod tests`. No lib.rs is needed for
them. `rr test FILE [RUSTC FLAGS] [-- FILTER...]` builds the crate as rustc's
`--test` does, against rr's own test runtime (a no_std crate named `test`,
built into a temporary directory each run), and runs it: each test in a child
process, so that a panic, which aborts, fails that test only.
`#[should_panic]` and `#[ignore]` work as usual; a filter runs the tests whose
path holds it; the exit status is 101 when one failed. Inside a test,
`panic!`, `unwrap`, `expect` and indexing are allowed: a panic is how a test
fails. `rr test FILE --check` and `--lint` check the crate with its tests
instead of building it.

`rr bench FILE [RUSTC FLAGS] [-- FILTER...]` builds with `-Copt-level=3`
(unless given one) and rr prof's runtime, and runs each `#[bench]`: its body
under `Bencher::iter` repeats for about a second, and the line printed is the
time, the allocations and the bytes copied of one iteration. rr test runs each
bench once, as a test.

The program's `main` stays: under rr test and rr fuz --target it is renamed
and is no longer the C entry, and the run's entry takes its place. A fuzz
target is a `fn(&[u8])` under `#[cfg(fuzzing)]`; `rr fuz src/main.rs --target
module::function` builds the crate with `--cfg fuzzing` and libFuzzer's entry
calling it, and keeps its corpus/ and artifacts/ in
fuzz/module_function/.

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
| rr_no_macros | Allow no_std compiler builtins and core panic/assert; forbid own/library macros, derive and external procedural attributes, including nested calls and cfg_attr derives |
| rr_unexplained_escape | Require a nearby real comment with a nonempty explanation for the operations below |
| rr_hot_path | Forbid a new buffer, a copy of data the program holds, a move of more than 256 bytes, and a loop that shows no bound, on a path marked #[rr::hot] without such a comment |
| rr_match_chain | Forbid an if chain that compares one value with constants: it is a match |
| rr_variadic | Forbid declaring a variadic C library function (open, fcntl, ioctl, syscall, printf and others) without its `...`; rr knows the C library's by name, not other libraries' |
| rr_unbounded | Forbid growing a collection kept in a field that nothing in the crate holds to a limit, without such a comment |
| rr_no_recursion | Forbid a call that closes a cycle of the crate's call graph (direct or mutual recursion, see Call graph) without such a comment, such as a bound on the depth, and a type that owns a value of itself, whose drop recurses as deep as the data |
| rr_unused_escape | Forbid a reason that answers nothing: a kind with no such operation beside it, a kind rr does not know, or the old form that names none |

Lifetime parameters, ordinary traits/impls, and concrete uses of existing generic
library types such as Vec<u8> remain allowed. This policy restricts user-defined
generics, not every generic inside core/alloc. It checks the current crate and
its local modules, not previously compiled dependencies.

Compiler builtin macros that do not require std are allowed: concat!, cfg!,
format_args!, stringify!, env!/option_env!, file!/line!/column!/module_path!,
include!/include_str!/include_bytes!, compile_error!, and compiler assembly and
other builtin expanders supported by the pinned compiler. Unstable builtins still
require their normal feature gates. Core panic/assert-family macros, and write!
and writeln! (sugar for core::fmt::Write::write_fmt), also remain allowed. Both bare and canonical core-qualified paths work, including core::arch.
The full allowlist lives in src/restricted/builtins.rs and follows the pinned
compiler's register_builtin_macros; std_panic and proc_macro quote are excluded.

Own macro definitions, library macros such as vec!, format! and matches!, derive
(including derive_const), and procedural macros remain forbidden. Importing a
library macro under a builtin's name does not grant an exception. Code brought
in with include! must obey the same language and ownership-comment restrictions.
Compiler builtin attribute expanders that work without std are also allowed,
including global_allocator, alloc_error_handler and cfg_eval. Their generated
implementation code is exempt from user-source restrictions; code inside
include! and user-authored macro arguments remains restricted. Feature gates and
optional backend capabilities still apply. The std test/bench harness attributes
and the current offload_kernel expander (which emits a std stub) are excluded.
Builtin attributes, cfg/cfg_attr, clippy and rustfmt tool attributes are allowed.

## Escape comments

```rust
// rr: escape(copy): the caller needs an independent snapshot after the source changes.
let snapshot = value.clone();
```

A reason names the kinds of operation it answers, and answers only those:
`unsafe`, `copy`, `shared`, `leak`, `alloc`, `cold`, `bound`, `recursion`, `panic`, `discard`,
`wildcard`, `cast`, `move`, `stack`, `loop`, `bools`; several are written
`// rr: escape(unsafe, cast): ...`. A reason for one kind does not cover an
operation of another on the same line. The old `// rr: escape: ...` names no
kind and answers nothing; a diagnostic points at an adjacent reason that does
not name its kind, and says which to add.

Each kind a reason names must answer an operation beside it: a reason the
code outgrew, a kind left in its list after the operation went, an unknown
kind and the old form are errors (rr_unused_escape). Reasons in code that cfg
leaves out of the build are not looked at.

The comment sits directly above the statement, the operation, or the
operation's line (such as a match arm), or trails on the operation's own line;
a reason may continue on the plain comment lines below it. Inside a statement
that spans lines, a comment answers only what is on its line. A marker inside a
string, documentation comment, empty reason or distant comment is rejected.
The tool checks that a reason exists, not that the explanation is truthful.

Required for:

- All resolved Clone::clone/clone_from calls, including scalar, reference, Rc/Arc
  and UFCS calls. A clone can copy a scalar, allocate or increment a reference
  count; rr does not claim every clone allocates.
- ToOwned::to_owned/clone_into, slice to_vec, Iterator::cloned, and collect when
  the result is an owned standard collection.
- Standard operations creating/acquiring Rc, Arc or RefCell, and RefCell's
  borrow/borrow_mut/try_borrow/try_borrow_mut.
- Leaks: leak (Box, Vec, String), into_raw, into_raw_parts and into_non_null,
  mem::forget and ManuallyDrop; transmute/transmute_copy/transmute_unchecked.
- Copies of borrowed data spelled as conversions: From/Into from a reference
  into String, Vec, Box or VecDeque, Cow::into_owned/to_mut, and ToString on
  a string. Literals and constants are exempt: copying them builds new data.
- A fresh String/Vec/VecDeque whose only write copies borrowed data into it:
  one extend_from_slice, extend or push_str of a reference (outside a loop),
  or a `for` loop over a borrowed collection pushing its own elements. The
  buffer is a `let` binding, or a field of a struct a `let` builds. The
  reason may sit on the `let` or on the copy. A buffer written more than
  once, lent out with `&mut` (a field also through its struct), or filled
  with transformed items is building.
- Calls to a local function whose whole body returns a copy of a parameter
  (a copy helper): the reason belongs where the copy is wanted.
- Cell, UnsafeCell, OnceCell, LazyCell and atomic creation; `static mut`, and
  statics with interior mutability such as atomics (global mutable state).
- `impl Copy` for a type larger than 64 bytes, which every use then copies
  whole without a clone() to show it (kind `copy`).
- User-written unsafe blocks, unsafe functions and unsafe trait implementations;
  unsafe attributes such as `#[unsafe(no_mangle)]`, `export_name` and
  `link_section`, where a symbol can stand in for another, such as malloc;
  and global_asm!; an `unsafe extern` block, which vouches for its
  signatures, and each `safe` function or static declared in one, which
  is then used with no unsafe block. The entry of a `#![no_main]` crate (main, or libFuzzer's
  LLVMFuzzerTestOneInput and LLVMFuzzerInitialize) takes its no_mangle
  without a reason.
- A fresh buffer made again on every turn of a loop, written there and never
  moved out of the turn: make it once before the loop and clear() it.
- A call that lends a local String or Vec (`&v`, `&v[..]`, `v.as_slice()`) to a
  local function that makes an owned copy of that parameter, when the caller
  does not use the buffer afterwards: take the parameter by value and move it.

## Clippy lints rr enforces

rr also forbids, in every command and whatever the command line or an
`#[allow]` asks, these Clippy restriction lints: unwrap_used, expect_used,
panic, unreachable, todo, unimplemented, unwrap_in_result (a panic where an
error was due), let_underscore_must_use and map_err_ignore (an error thrown
away, or its cause), wildcard_enum_match_arm (`_ =>` on an enum, which
would take any variant added later), cast_possible_truncation, cast_sign_loss
and cast_possible_wrap (an `as` that loses bits or the sign: use `try_from`),
cast_ptr_alignment, needless_pass_by_value, large_stack_arrays, string_slice
and unchecked_time_subtraction (panics), infinite_loop (a loop without an
exit in a function that returns: say `-> !`), struct_excessive_bools and
fn_params_excessive_bools (more than three flags, which are usually the
states of one enum); and the compiler's unused_must_use (a must_use result
dropped as a statement; `let _ =` with a reason drops one on purpose), and
implicit_provenance_casts (an integer cast to a pointer or a pointer to an
integer: write `addr`, `with_addr` or `expose_provenance`),
unsafe_op_in_unsafe_fn (each unsafe operation of an unsafe fn in a block of
its own, with its reason), and its checks for undefined behavior and
certain panics, which `#![allow]` could otherwise turn off:
invalid_reference_casting, dangling_pointers_from_temporaries and
dangling_pointers_from_locals, static_mut_refs, invalid_value,
invalid_null_arguments, mutable_transmutes, useless_ptr_null_checks,
invalid_from_utf8_unchecked, ptr_to_integer_transmute_in_consts,
invalid_atomic_ordering, deref_nullptr, uninhabited_static,
missing_unsafe_on_extern, unsafe_attr_outside_unsafe, arithmetic_overflow
and unconditional_panic. An
adjacent `// rr: escape(kind): <reason>` answers them as it answers rr's own
rules.

Some lints name a rewrite that is always possible, and no reason answers
them: multiple_unsafe_ops_per_block (one unsafe operation per block, each
with its own reason), borrow_as_ptr (`&raw const x`), ptr_as_ptr and
ptr_cast_constness (`cast`, `cast_mut`), as_ptr_cast_mut,
fn_to_numeric_cast, transmute_ptr_to_ptr, trivially_copy_pass_by_ref,
ref_option (`Option<&T>`), if_not_else (a condition states what holds:
`if x { b } else { a }`, not `if !x { a } else { b }`),
else_if_without_else (each `else if` chain ends in an `else`, every case
handled), comparison_chain (`<`, `==`, `>` on two values is a match on
their `cmp`), and these, for state, copies and correctness:
collection_is_never_read, redundant_clone, needless_collect,
assigning_clones (`a.clone_from(&b)` reuses `a`), format_push_string,
unnecessary_box_returns, linkedlist, read_zero_byte_vec,
mixed_read_write_in_expression, suspicious_operation_groupings,
unused_result_ok, host_endian_bytes (bytes on the wire have an order),
checked_conversions, manual_midpoint, float_cmp, range_minus_one,
range_plus_one, precedence_bits, decimal_bitwise_operands,
let_underscore_untyped, unnecessary_wraps, option_option, unused_self,
or_fun_call; allow_attributes_without_reason (an `#[allow]` says why);
invalid_upcast_comparisons, suspicious_xor_used_as_pow,
fallible_impl_from, maybe_infinite_iter, match_wild_err_arm,
overly_complex_bool_expr, needless_bitwise_bool,
same_functions_in_if_condition, nonminimal_bool, lossy_float_literal,
while_float, empty_drop, trailing_empty_array,
literal_string_with_formatting_args, mut_mut; implicit_clone,
inefficient_to_string, cloned_instead_of_copied, string_add,
string_add_assign, clear_with_drain, iter_with_drain,
unnecessary_struct_initialization, set_contains_or_insert,
naive_bytecount, stable_sort_primitive, format_collect,
with_capacity_zero; as_underscore, as_pointer_underscore,
alloc_instead_of_core, non_ascii_literal (non-ASCII in a literal is
escaped: nothing invisible or look-alike in the source); and for unsafe
code and the system: transmute_undefined_repr, uninhabited_references,
volatile_composites, default_union_representation,
no_mangle_with_rust_abi, ref_as_ptr, same_length_and_capacity and
ptr_offset_by_literal; for one way to write each thing and one meaning
for each name: match_same_arms, items_after_statements,
manual_let_else, needless_continue and shadow_unrelated.
fn_to_numeric_cast_any
takes `cast` (an address the system asks for). needless_pass_by_ref_mut takes `move` (a signature
fixed by a table of handlers), missing_asserts_for_indexing `panic` and
large_stack_frames `stack`.
collapsible_if and collapsible_else_if stay off in rr lint: a nested
condition is a branch of its own, each a case to handle.
slow_vector_initialization stays off too: it asks for `vec!`, a macro. The rest of the restriction group are styles that
contradict one another and stay off.

## Hot paths

`#[rr::hot]` marks a function that runs for every event. rr registers its
attribute namespace and sets `--cfg rr`, so the portable spelling is
`#[cfg_attr(rr, rr::hot)]`: plain rustc and rust-analyzer skip it. Rule
rr_hot_path then forbids in it, and in every local function it reaches
through the call graph, a new buffer (`alloc`): with_capacity,
Box/Rc/Arc::new, a fresh String or Vec that is written,
to_vec/to_owned/to_string/into_owned, an owned clone, collect, into or From,
and formatting into a new String. It forbids as well a copy of data the
program holds into other memory it holds (`copy`): copy_from_slice,
clone_from_slice, extend_from_slice, push_str, insert_str, write_str,
clone_from, extend or append from borrowed data, copy_within,
extend_from_within, remove, insert and a drain that ends before the end
of a Vec or String (each moves the tail; in a loop the work goes
quadratic), ptr::copy and copy_nonoverlapping and their methods, a
clone of a value that is not Copy, and a copy one element at a time in a
loop or a closure: an element or what a reference points to, read as it is
and stored into an element or through a reference (`out[i] = x[i]`,
`*d = *s`), or pushed (`for &b in x { out.push(b) }`). Data is held when it
is reached through a reference or a buffer, by either way of an `if` or a
`match`; a literal, a constant, a number, an array on the stack and a value
a call has just made are built, and writing them is not a copy, nor is
filling an array on the stack. A move of a value larger than 256 bytes
out of memory (a variable, a field, an element) into a `let`, an
assignment, an argument or a field of a value being built is a memcpy,
and needs `escape(move)` there; building a value in place and lending
it move nothing. A `loop`, or a `while` whose condition
shows no bound, needs `escape(loop)` there too: a `for` walks what it is
given, and a `while` is bounded when a part of its condition compares
with a length, a literal or a constant, waits for `is_empty()`, or takes
by `while let` from `next()` or `pop()`. A reason of the kind allows the
operation.
A `// rr: escape(cold): ...` at a call says that the branch is off the path,
such as an error or once per item, and the callee is not followed from
there. Such a reason is used only when what the path forbids, without its
own reason, lies beyond the call; otherwise rr_unused_escape reports it.
The diagnostic shows the calls from the hot root down. A copy rr does not
see by its form still shows in rr prof.

## Bounds

A collection a value keeps in a field, a Vec, String, VecDeque or a
B-tree collection, grows by push, extend, insert, append or resize. Rule
rr_unbounded asks of each field that grows so that something in the
crate holds it to a limit: a comparison of its len() with anything, or
a clear() or truncate() that starts it over. Without one, the field's
declaration, or each place it grows, takes `// rr: escape(bound): <what
bounds it>`. A field of a value the function owns and builds is not
looked at: it grows once, as the value is made.

## Call graph

rr_no_recursion and rr_hot_path follow the crate's call graph, read from
MIR, where a call that is not written as one is a call too: an operator,
an index, a deref (an explicit `*` or one a method call makes), the `next`
of a `for` loop, and the destructor that a drop runs, with the destructors
of everything the value owns. A call the optimizer inlined still counts.
What cannot be resolved counts every local function it may reach: a call
through a function pointer reaches every local function turned into a
pointer of that type anywhere in the crate, statics included; a call
through dyn or a generic parameter, every local body of the method; a
call into foreign code, every function whose pointer it is given, alone
or within what an argument holds or points to, as `qsort` and a struct
of callbacks are; a function or closure handed to other code, as `map(f)` does, may be called
by it; and a value moved into a function of another crate, as `drop(v)`
does, may be dropped there. A closure is part of the function it is
written in.

## Allocation and copy profiles

`rr build --prof` builds a crate with frame pointers and line tables; the final
artifact also links rr prof's runtime (built by rr itself, in a temporary
directory). There rr renames the `__rust_*` allocator functions that
`#[global_allocator]` defines to `__rg_*` and gives the runtime's functions the
`__rust_*` names: each allocation is counted by its stack, then handed on to the
program's allocator. Nothing in the program changes, wherever its allocator is
defined. The runtime defines `memcpy` and `memmove` as well, which the
linker prefers to the C library's for every call in the program, the
standard library's included: each copy is counted by its stack and its
bytes, then handed to the C library. Small copies of a known size that the
compiler writes inline are not calls and are not counted. Build every crate
of the program with --prof; a --prof build keeps its symbols.
`rr prof [--top N] [--max N] [--max-copied BYTES] [--keep DIR] -- COMMAND`
runs a command with RR_PROF_DIR set, so that each process of such a program
it starts, each image after exec included, writes its counts to a file
mapped shared there; then reports the program's own lines that allocate
most, and those that copy the most bytes, with their callers (core, alloc,
the allocator and memcpy are left out), from DWARF or the dSYM. --max fails
above a budget of allocations, --max-copied above one of bytes copied: an
allocation traded for copies shows. Without RR_PROF_DIR a --prof build runs
as usual.

Operations are matched using resolved definitions and result types. An unrelated
inherent method called clone is not Clone. Arbitrary user functions may hide
these operations, and previously compiled libraries are not audited. This is an
explicit lint policy, not a proof that all possible ownership escape hatches are
absent. Comments document a decision; they do not make unsafe code sound.

## Fuzzing user programs

The distribution includes a pinned libFuzzer runtime for its host, an optional
matching AddressSanitizer runtime, and a no_std harness. Fuzzing runs on the
host and needs its C and C++ libraries: a fuzz target is built for the host's
own target (on Linux `*-unknown-linux-gnu`, linked by the system's cc with
libstdc++; on Windows `*-pc-windows-msvc`, with Visual Studio's tools), not
rr's library-free one; a program's `src/sys/` is the same. Cargo is not needed. The compiler
and ordinary builds retain the same behavior; fuzzing instrumentation is opt-in.

```sh
rr fuz init
# Replace test_input in fuz.rs with your parser/API and its invariants.
rr fuz fuz.rs -- -runs=100000
```

To check memory errors in instrumented unsafe code, add ASan when compiling:

```sh
rr fuz fuz.rs --asan -- -runs=100000
```

The native `fuz` command compiles and launches the harness using this rr executable;
it never invokes Cargo or a separate rustc. Compiler flags go before `--`, and
libFuzzer arguments go after it. Coverage, native library paths and ASan's Darwin
rpath are set automatically. Default corpus/ and artifacts/ directories live
beside the source file; explicit libFuzzer paths are relative to the current directory.
The temporary executable is removed after completion, a crash or terminal Ctrl-C;
corpus and crash files persist. A captured failure can be replayed with
`rr fuz fuz.rs -- artifacts/crash-HASH -runs=1`. Harnesses retain all rr restrictions and
escape-comment requirements. ASan does not instrument precompiled core/alloc or
external libraries. The precompiled C++ fuzzing engine uses system libc/libc++.

The pinned LLVM fuzzer is built separately with scripts/build-fuzz-runtime.py;
scripts/add-fuzz-runtime.py adds its libraries and templates to a distribution.
The optional ASan library is a test runtime, not a dynamic compiler/LLVM driver.
scripts/smoke-fuzz.py checks the native CLI, actual coverage, mutation-driven crash
discovery, artifact replay, rr restrictions, cleanup on Ctrl-C, and a deliberate
memory error detected by ASan in a relocated bundle without Rust/Cargo in PATH.

## Development and packaging

The Clippy fork itself uses upstream Cargo build/test infrastructure. This is
separate from compiling rr projects, which never invokes Cargo. Cargo.lock pins
resolved dependency versions. Build with the pinned toolchain from
rust-toolchain.toml, including rustc-dev, rust-src, rustfmt and clippy.

```sh
scripts/build-toolchain.sh /path/to/pinned/rust-source /path/to/scratch /path/to/toolchain
scripts/release.sh /path/to/pinned/rust-source /path/to/toolchain /path/to/scratch rr-linux-x86_64
```

release.sh builds rr with the toolchain, the sysroots of the host and of rr's
targets (scripts/build-target-sysroot.py), libFuzzer, then packages
(scripts/package-rr.sh), verifies (scripts/verify-bundle.py and the smoke
checks) and archives the distribution in dist/.

The packaging script takes a static rr executable,
matching development toolchain, abort client sysroot and new destination. The
compiler driver and LLVM are embedded in rr. Full core/alloc/compiler_builtins
object archives and separate metadata are compiler inputs beside it. The client
libraries are built with panic=abort; their complete upstream APIs are retained.
The stock toolchain's unwind alloc would require an exception personality at
native link time. This distribution is tested with panic=abort, not unwind.

The real LLVM rust-objcopy helper supports Darwin -Cstrip. Executables are
stripped and ad-hoc signed; compiler version and license notices are included.
Only system macOS dynamic libraries are needed. No Cargo/rustup/rustc executable
or Cargo cache is included. The development toolchain must come from the static
bootstrap below, rather than a stock dynamic compiler installation.

## Local verification (2026-10-08)

24 rr restriction tests and 4 CLI tests pass. Formatting, cargo check, Clippy with all targets/features and
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

The earlier static macOS ARM64 bundle was 217.37 MiB unpacked, compared with
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


## Builtin update (2026-10-08)

The updated ordinary rr release is 219.89 MiB unpacked. The executable is
125.23 MiB; the bundle now includes rust-objcopy and full abort client libraries.
Compiler builtins, their attributes and source brought in with include! are
covered by the rr tests and scripts/smoke-builtins.py. The native smoke executes
Option, an actually allocating Vec and explained clone, assertions, format_args
and inline assembly, with no Rust/Cargo tools or loader overrides.

The full check suite passes with the same documented upstream fixture exclusion.
Logs and the current report are in verification/builtins-2026-10-08/.

## GitHub Actions: static compiler driver

The release workflow builds stage2 Rust at commit
84b36a78a28a63f134171c670be1932ffa2485f8 with its exact LLVM submodule, LLVM's
backend for the host and rust-lld, and compiles rr against that matching
compiler on each host. No prebuilt LLVM or compiler driver is substituted.
LLVM, stage2 compiler libraries and the release rr executable use ThinLTO.
LLVM and rustc_driver are statically linked into rr; system libraries remain
dynamic; core/alloc objects and metadata stay external as compiler inputs. The
bootstrap artifact filter also retains private compiler rlibs, because
metadata-only rustc-dev packages cannot support static linking. Put the
source, scratch and installation directories, CARGO_HOME, CARGO_TARGET_DIR and
TMPDIR on the build volume; RR_BUILD_JOBS sets parallelism. Set SYSROOT to the
installed compiler directory when checking or testing the unpackaged static
development drivers. The packaged rr selects its adjacent sysroot itself.

## Releases

`.github/workflows/rr-release.yml` builds the static compiler and rr on each
host, verifies each distribution and, on a `v*` tag or a dispatch naming one,
publishes them as a GitHub release with their SHA256SUMS:

| Archive | Host |
| --- | --- |
| rr-macos-arm64.tar.gz | macOS 11+ on Apple silicon |
| rr-linux-x86_64.tar.gz | Linux x86_64, glibc 2.31+ |
| rr-linux-aarch64.tar.gz | Linux aarch64, glibc 2.31+ |
| rr-windows-x86_64.zip | Windows 10+ x86_64 |
| rr-windows-aarch64.zip | Windows 11 on ARM |

Each holds rr with LLVM's backend for its host, the host's sysroot, on Linux
and Windows that of the host's rr target and rust-lld, and libFuzzer. scripts/build-toolchain.sh
builds the compiler on any of these hosts, scripts/release.sh the rest; the
Linux ones build in an Ubuntu 20.04 container, for an old glibc.

Keep core and alloc intact. Do not remove compiler language machinery or
auxiliary rustc interfaces in this pass; the current compiler changes only
enable static driver linking and retain the necessary object archives.
