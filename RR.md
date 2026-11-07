# rr — Restricted Rust

A checker forked from Clippy, at the Clippy of Rust 1.99.1 (Clippy's
`rust-1.99.0` tag with that release's own changes). It runs on the official
**Rust 1.99.1 (58cf8f9c3, 2026-10-13)** that rustup installs, as clippy-driver
does: rr sits in that toolchain's bin/ and loads its compiler, with all of
LLVM's backends. rustc builds a program; rr checks it with its rules and
Clippy's, and builds only what its own commands run (tests, benches, fuzz
targets, profiles). Development builds use the same release, with
RUSTC_BOOTSTRAP for the compiler's private crates.

## Use

install.sh (macOS arm64, Linux x86_64 and aarch64 with glibc 2.31 or later) and
install.ps1 (Windows x86_64 and aarch64) install Rust 1.99.1 with rustup, put rr
and what is its own (libFuzzer and rr fuz's flags, in lib/rustlib/rr/) into
that toolchain, and put rr on PATH: a link in ~/.local/bin, or on Windows the
toolchain's bin\ at the end of the user's PATH, after rustup's own tools. A
project's rust-toolchain.toml names the same release, so its rustc is the
compiler rr checks with. Other targets are rustup's: `rustup target add`, then
`--target` for rustc and rr alike; where to build for what is rustc's and the
project's business.

```sh
rr init demo            # a project: see below
cd demo
make                    # rustc builds the program
make test               # rr test: the #[test] items; FILTER=word narrows
make bench              # rr bench: time, allocations and copies per iteration
make fmt                # rr fmt: rewrite in rr's one style
make format check lint  # rr fmt --check, rr's rules, then Clippy's
make fuzz               # rr fuz: the fns named in FUZZ, sharing FUZZTIME
make prof               # where the program allocates and copies
rr add tls              # copy a component, and those it needs, into src/

rr init library --lib   # src/lib.rs alone, for a crate to depend on
rustc --edition 2024 -C panic=abort library/src/lib.rs --crate-type rlib --crate-name example -o libexample.rlib
rr check main.rs --extern example=libexample.rlib
```

`rr check FILE` and `rr lint FILE` write metadata to a temporary directory and
remove it on return, including compiler errors. `lint` also enables Clippy's
normal default lints; check runs the rr rules plus ordinary compiler
diagnostics. Rustc flags are forwarded, including `--cfg`, `--extern`, `-L`,
`--crate-type`, `--target`, `--sysroot` and `@argument-file`; `--print` asks
the compiler and builds nothing. Check/lint reject explicit output flags. rr
does not build a program: `rr build` takes `--prof`, for rr prof (below), and
otherwise says to build with rustc; rr test, rr bench and rr fuz build what
they run themselves.

`rr fmt FILE...` formats crates with rustfmt, which rr links at its compiler's
own commit (rustfmt/ in the source): each root and the modules it declares,
in rustfmt's defaults for edition 2024. A rustfmt.toml is not read, so every
rr crate has one style. `rr fmt --check` writes nothing; it prints what differs
and fails, for CI. As in Rust's usual pipeline, format, check and lint are
separate steps: rustfmt, the compiler with rr's rules, and Clippy.

Defaults: edition 2024, panic=abort, and rlib for an input named lib.rs. Otherwise
rustc's normal binary default applies. `init` lays out a project and refuses to
overwrite any of it: src/main.rs (the program, one crate, with a malloc-backed
global allocator, a panic handler and the C entry, which the C library calls),
src/sys/unix.rs and src/sys/windows.rs (the operating system and unsafe),
src/greet.rs (a module with its tests, a bench and a fuzz target beside the
code), rust-toolchain.toml (Rust 1.99.1), a Makefile whose build is rustc and
whose test, bench, fmt, format, check, lint, fuzz and prof targets are rr's,
and AGENTS.md
with the rules for whoever changes the code: format with rr fmt, then rr check
and rr lint, after every change. `init --lib` writes src/lib.rs alone. No manifest
is created.

`rr add COMPONENT...` copies code from a registry into src/, as shadcn
copies a component: the project then owns it. A component is a JSON file
with its name, the rr it was checked with, the components it needs and
its files; COMPONENT is a name in rr's registry (registry/ in this
repository, fetched from GitHub with curl), `@scope/name` in a registry
that rr.json maps (`{"registries": {"@acme": "https://…/{name}.json"}}`),
or a component's URL or path. A component may put scripts in scripts/ and
ask questions whose answers add components (tls: where its trusted
roots come from); at a terminal rr add asks, `--option NAME=VALUE`
answers, and `--yes` or a run without a terminal takes the defaults and
says how to choose. A file that exists and differs stops the
add before anything is written, unless `--overwrite`; a component that
needs a newer rr, or a path outside src/, is refused. rr add prints the
`mod` lines still to write. registry/README.md says what a component of
rr's registry is: no I/O of its own, so one serves a blocking loop, a
poll loop or a thread; its own errors; unsafe only in sys; and the
template's checks, which scripts/registry-check.sh runs on it.

## Targets

A program links the system's C library, on Rust's own targets: on macOS
libSystem, as Apple requires; on Linux `*-unknown-linux-gnu` and its glibc; on
Windows `*-pc-windows-msvc` and the C runtime (the DLL one, or the static one
with `-C target-feature=+crt-static`), which the build tools of Visual Studio
link. The C library starts the program in its `extern "C" fn main(argc, argv)`
and gives what the compiler calls, such as memcpy. src/sys/unix.rs reaches
macOS and Linux through the C library; src/sys/windows.rs calls kernel32.dll
through `raw-dylib` imports, and takes its arguments from Windows's own command
line, in UTF-8, since the C runtime's argv is in the system's code page. The
standard library rustup installs is built to unwind, and its alloc names the
routine that would unwind a panic; a program aborts on panic and defines an
empty `rust_eh_personality` for the linker.

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
fuzz/module_function/. Several `--target` flags build the crate once, and
`--budget SECONDS` (60 by default) is the time they share: half evenly,
the rest to each by the coverage features it found in its share, so a
target still finding new paths gets the time one that stopped does not
need. rr runs them one after another, passing `--rr-target=N` (libFuzzer
ignores flags that start with `--`), keeps each libFuzzer log in
fuzz/module_function/last.log, stops at the first crash with its code,
and ends with what each found and which found nothing new in its time:
a target whose corpus covers what it reaches, or one that checks a
property of a function that takes already-parsed data, which a test over
edge values checks too. Fuzz where outside input enters the program.
Then rr replays each target's corpus with libFuzzer's coverage by PC,
which the harness lets libFuzzer name by its distance from
LLVMFuzzerTestOneInput (the same in every run of the binary), and finds
the program's functions there, inlined ones too, from the line tables.
It says which target reaches nothing another does not, apart from the
target itself, and which reaches nothing past its own module, the system
layer in `sys` aside: a test of its properties over edge values checks as
much.
`rr check` and `rr lint` under `--cfg fuzzing` check the targets without
the harness, so they allow dead code there.

No registry dependency manager or Cargo interface is included. Prebuilt
libraries must match this compiler and target. Upstream Cargo tools remain in
the source checkout for developing/testing the fork; they are not distributed.

## Required rules

Rules are compiler errors and cannot be lowered with `allow`, `-A rr`,
`--cap-lints` or Cargo environment variables.

| Rule | Restriction |
| --- | --- |
| rr_no_std | Require #![no_std]; forbid explicit std imports |
| rr_no_generics | Forbid own type/const generic parameters, impl Trait other than a closure parameter, async fn/blocks/closures and await |
| rr_simple_traits | Forbid associated types/GATs, supertraits, where clauses, trait aliases and dyn of a trait from another crate |
| rr_no_macros | Allow no_std compiler builtins, core panic/assert, matches! and seven of the compiler's own derives; forbid own/library macros, other derives and external procedural attributes, including nested calls and cfg_attr derives |
| rr_unexplained_escape | Require a nearby real comment with a nonempty explanation for the operations below |
| rr_hot_path | Forbid a new buffer, a copy of data the program holds, a move of more than 256 bytes, and a loop that shows no bound, on a path marked #[rr::hot] without such a comment; a scratch buffer, made and freed there or by a call for it, takes none |
| rr_match_chain | Forbid an if chain that compares one value with constants: it is a match |
| rr_variadic | Forbid declaring a variadic C library function (open, fcntl, ioctl, syscall, printf and others) without its `...`; rr knows the C library's by name, not other libraries' |
| rr_loop_buffer | Forbid a fresh buffer made again on every turn of a loop, written there and never moved out of the turn; no reason answers it: make it once before the loop and clear() it |
| rr_unbounded | Forbid growing a collection kept in a field that nothing in the crate holds to a limit, without such a comment |
| rr_no_recursion | Forbid a call that closes a cycle of the crate's call graph (direct or mutual recursion, see Call graph) without such a comment, such as a bound on the depth, beside the call or once above a function every such cycle passes through; and a type that owns a value of itself, whose drop recurses as deep as the data |
| rr_unused_escape | Forbid a reason that answers nothing: a kind with no such operation beside it, a kind rr does not know, or the old form that names none |
| rr_c_signature | Forbid a reference in a C function's declaration: C has pointers |
| rr_unused_derive | Forbid a derived trait that nothing in the program uses |
| rr_duplicate | Forbid a function whose body repeats another's, token for token without comments and spacing and type for type, of four statements or more, without a `duplicate` reason: one function, called from both places, says it once. Two types spelled the same way (`Self { memo: Memo::new() }`, `self.workspace.abort()`) are not a copy: one function for both would need a trait |

Lifetime parameters, ordinary traits/impls, and concrete uses of existing generic
library types such as Vec<u8> remain allowed. A function's parameter may be
`impl Fn(..)`, `impl FnMut(..)` or `impl FnOnce(..)`: a closure handed in,
one bound and nothing else, so that work around a call, such as undoing a
step when it fails, is written once. `Send` and `Sync` may stand beside
that bound, and beside the trait behind `dyn`: they run nothing, and the
compiler checks that what goes to another thread may go there
(`dyn Job + Send`, `impl FnOnce() + Send`). The compiler copies such a function
for each closure it is given, so it has at most 30 lines; a longer one
calls the rest as an ordinary function. A closure is part of the function that
writes it: what it calls, that function calls. `dyn` may name a trait of the
crate: every implementation is then in the crate, and a call through it
reaches each in the call graph, as a hot path and recursion see it; a
trait of another crate behind dyn hides what runs. This policy restricts user-defined
generics, not every generic inside core/alloc. It checks the current crate and
its local modules, not previously compiled dependencies.

### Instead of a generic

Code that would be generic over the types the crate itself knows takes
an enum of them, with a variant for each: one parser over a slice or a
reader, one serializer into a string or to standard output. The match
that picks the variant costs a branch that goes the same way every
time; the enum is the whole set, in one place, and the optimizer still
sees each body. Code that calls what its caller brings, such as the next
stage of a pipeline, takes `&mut dyn` of a trait of the crate. A JSON
parser that reads a file and also parses a string:

```rust
enum Source<'a> {
    Slice(&'a [u8]),
    Read(Reader<'a>), // an input, a fixed window of it, and how much is in it
}
impl Source<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Source::Slice(s) => s,
            Source::Read(r) => r.window.get(..r.end).unwrap_or_default(),
        }
    }
}
```

The parser keeps its place in `bytes()` and, at its end, asks the
reader for the next window, keeping the bytes of a token cut in two. It
never holds a whole file, and a writer drains its own window to output
the same way: what a program keeps grows with the value it works on,
not with its input or output. Copying input into a buffer to hand a
slice parser all of it holds the whole input twice, once as bytes and
once parsed.

The window is read as a slice, not a byte at a time through a method:
the parser scans `bytes()` with an index, a whole string or number at a
time, and refills only where the slice ends. A `peek()` that matches the
variant, checks for a refill and returns `Result<Option<u8>, _>` for
every byte costs more than the parse. A writer takes runs the same way:
a string from one character that needs escaping to the next, an indent
as one slice of a constant of spaces, a number formatted into a small
array on the stack; a `push(char)` per character is a call to memcpy
for each, which rr prof counts.

Compiler builtin macros that do not require std are allowed: concat!, cfg!,
format_args!, stringify!, env!/option_env!, file!/line!/column!/module_path!,
include!/include_str!/include_bytes!, compile_error!, and compiler assembly and
other builtin expanders supported by the pinned compiler. Unstable builtins still
require their normal feature gates. Core panic/assert-family macros, and write!
and writeln! (sugar for core::fmt::Write::write_fmt), and matches! (a match
that answers true or false), also remain allowed. Both bare and canonical core-qualified paths work, including core::arch.
The full allowlist lives in src/restricted/builtins.rs and follows the pinned
compiler's register_builtin_macros; std_panic and proc_macro quote are excluded.

The compiler's own derives that ordinary syntax needs on a type of the
program are allowed: Copy and Clone (passing a value and using it after),
PartialEq and Eq (`==`, a constant of the type in a pattern), PartialOrd
and Ord (`<`, sorting), and Debug (unwrap, expect, `{:?}`, assert_eq!).
They write the impl a reader expects and nothing else. Hash serves the hash
maps of std, and a constructor says what Default would; neither is
allowed. A derive the program never uses is an error (rr_unused_derive):
nothing calls its method or operator, nothing that requires it of the
type is called (`sort` requires Ord, `unwrap` requires the error's Debug,
`{:?}` requires Debug), nothing copies a value of the type for Copy, no
pattern names a constant of it for PartialEq, and no used trait or
derived type needs it. What only tests use is derived under
`#[cfg_attr(test, derive(..))]`, and stays out of the program. An
exported type of a library is not looked at. `ok().unwrap()` and
`ok().expect()` throw the error away before the failure could name it,
and are errors in tests too: give the error type Debug for the tests;
`ok().unwrap_or(..)` and the like say what the Result's own does. A
derived Copy past 64 bytes needs `escape(copy)` above the derive, as an
`impl Copy` does, and a derived Clone is called as any clone.
Own macro definitions, library macros such as vec! and format!, other derives
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
`wildcard`, `cast`, `move`, `stack`, `loop`, `bools`, `sentinel`, `tag`, `duplicate`, `dyn`; several are written
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
that spans lines, a comment answers only what is on its line. A `recursion`
reason may instead stand directly above a function, after its documentation
and above its attributes: it answers every call back into the function, from
itself or through others, as the one bound on the depth a descent through it
keeps, such as a depth parameter it checks. A cycle that does not pass
through such a function still needs its own reason, and a reason beside a
call the function's reason answers answers nothing. A marker inside a
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
  a string, and to_vec and to_owned. Literals and constants are exempt:
  copying them builds new data.
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
- A call that lends a local String or Vec (`&v`, `&v[..]`, `v.as_slice()`) to a
  local function that makes an owned copy of that parameter, when the caller
  does not use the buffer afterwards: take the parameter by value and move it.
- The same operations spelled another way. A truncating or sign-changing
  cast written as bytes (`cast`): a byte of a wider number's bytes,
  `x.to_le_bytes()[0]`; a number made from some of a wider one's bytes;
  or one made from all the bytes of a number of the other sign,
  `i32::from_le_bytes(u.to_le_bytes())`. A must_use value bound to a
  `_name` nothing reads, which drops it as `let _ =` does (`discard`; a
  guard that drops at the end of its scope is what a binding is for), and
  `ok().ok_or(..)`, which throws away the error's cause as `map_err(|_|..)`
  does. A `Box::new` of more than 256 bytes, which builds the value on the
  stack and copies it into the heap (`move`).
- A bug reported as bad input (`panic`): `x.get(i).ok_or(..)` with an
  index the function computed from x's own length and nothing it was
  given or read (`x.len() - 1`, the counter of a loop over `0..x.len()`,
  the index `enumerate` gives). Out of bounds, it is a bug in the
  function: index it with a reason, and the bug stops the program where
  it is. A range with both ends, `2..x.len() - 4`, is out of bounds when
  the input is short, and is not looked at.
- A magic number standing for none (`sentinel`): `x == u32::MAX`, and
  `u32::MAX` as the default of an Option (`map_or`, `unwrap_or`); an
  Option says there is none. On a Result, as from try_from, such a default
  clamps what does not fit, and needs no reason.
- An integer saying which kind a value is (`tag`): a field named `kind`,
  `tag`, `mode`, `variant` or ending in `_kind` or `_tag`, and a match,
  in a `for` over a list of integer literals, on the item it takes, which
  is a table of kinds by number. An enum names each kind and carries the
  data only that kind has.

A catch-all arm that returns `Err`, in a match on `x & MASK` or `x % N`
(x unsigned, the mask or divisor a literal) whose other arms already
cover every value, cannot run: if it does, it is a bug, not bad input.
rr asks for `_ => unreachable!()` there, with its `escape(panic)` reason.

Unsafe code and the operating system stay in a module named `sys` (or one
inside it), behind safe functions: an unsafe block, an unsafe fn, an
unsafe impl or a foreign block anywhere else is an error that no reason
answers. The C entry of a `#![no_main]` crate may call into `sys` with
the raw arguments the system hands it. A C function is declared with C's
types (rr_c_signature): a pointer, not a reference, which would promise
Rust's rules about the memory to code that does not keep them; lend a
reference with `&raw` at the call.

## Clippy lints rr enforces

rr also forbids, in every command and whatever the command line or an
`#[allow]` asks, these Clippy restriction lints: unwrap_used, expect_used,
panic, unreachable, todo, unimplemented, unwrap_in_result (a panic where an
error was due), let_underscore_must_use and map_err_ignore (an error thrown
away, or its cause), wildcard_enum_match_arm (`_ =>` on an enum, which
would take any variant added later), cast_possible_truncation, cast_sign_loss
and cast_possible_wrap (an `as` that loses bits or the sign: use `try_from`),
cast_ptr_alignment, needless_pass_by_value, large_stack_arrays, string_slice,
indexing_slicing (an index or slice that may be out of bounds: `get`) and
unchecked_time_subtraction (panics), infinite_loop (a loop without an
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
stable_sort_primitive, format_collect,
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
fixed by a table of handlers) and large_stack_frames `stack`. In a test,
and in a fuzz target under `cfg(fuzzing)`, which the fuzzer runs as a test,
a panic is how the check fails: unwrap, expect, panic and indexing there
need no reason.
collapsible_if and collapsible_else_if stay off in rr lint: a nested
condition is a branch of its own, each a case to handle.
slow_vector_initialization stays off too: it asks for `vec!`, a macro. Where another lint's suggestion would write a
macro or name a crate rr has no way to use (vec_init_then_push's `vec!`,
the pedantic naive_bytecount's `bytecount`), rr drops the suggestion and
says what to write instead; to shadow_unrelated, indexing_slicing and
let_underscore_untyped it adds what each asks for in rr. The rest of the restriction group are styles that
contradict one another and stay off.

## Hot paths

`#[rr::hot]` marks a function that runs for every event, where an event
comes in: rr follows the calls from there, and a mark on a function
another hot root already reaches adds nothing and is an error. rr registers its
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
`*d = *s`), or pushed (`for &b in x { out.push(b) }`), whole or rebuilt
field by field (`out[i] = Item { position: x[i].position, weight:
x[i].weight }`, `Id(x[i].0)`). A Copy value of at most 8 bytes moved
within one buffer (`ids[hole] = ids[next]`, `*ids.get_mut(hole)? =
*ids.get(next)?`) is a permutation, as `swap`
makes one, and not a copy. rr finds such a copy in the function's MIR
too, whatever the source looks like: a value read out of memory the
function reaches by reference, which passes through locals, a
destructuring, an iterator's item, a struct built of it or a local
function that returns what it was given (`make(x.pos, x.w)`, a `copy()`
of one's own), and is stored into an element of a buffer or the whole of
what a reference points to, or pushed, in a loop. A value computed from
what was read, such as `x.pos + 1`, is built. Data is held when it
is reached through a reference or a buffer, by either way of an `if` or a
`match`; a literal, a constant, a number, an array on the stack and a value
a call has just made are built, and writing them is not a copy, nor is
filling an array on the stack. A move of a value larger than 256 bytes
out of memory (a variable, a field, an element) into a `let`, an
assignment, an argument or a field of a value being built is a memcpy,
and needs `escape(move)` there; building a value in place and lending
it move nothing. A `loop`, or a `while` whose condition
shows no bound, needs `escape(loop)` there too: a `for` walks what it is
given, and a `while` is bounded when a part of its condition puts a
count in order against a limit (`i < n`), compares with a length, waits
for `is_empty()`, takes by `while let` from `next()` or `pop()`, or reads
at a moving index (`while let Some(x) = v.get(i)`), and its body changes
what the condition tests. A count compared for equality with a number
(`while n != 0`) may step past it, and states no bound. A `for _` over a
count worked out from data, whose turns go unused and which ends by
`break`, is a `loop` with a cap and needs `escape(loop)` as well: its
real end is the break. A count fixed in the program, a literal or a
constant (`for _ in 0..TURNS_MAX`), states a limit; a `return` from such
a loop gives a result found before the count runs out. A cursor whose
reads end (a `while let` over it) names its method `next`, or implements
Iterator. A subtraction from a length (`v.len() - 1`), which underflows
on an empty collection, and a division or remainder by a value that is
not a constant need `escape(panic)`, or `checked_sub`, `checked_div` and
`checked_rem`. A method call through `dyn`, which the compiler cannot
inline, needs `escape(dyn)`. A push, extend, insert or resize into a collection the
function takes as a parameter (`out.push(b)`) needs a comparison of that
collection's `len()` with a limit in the function, or `escape(alloc)`:
the path may grow it without end; `capacity()` is what the allocator
gave, not a limit, and a resize to another collection's length follows
that one. The methods of the program's `GlobalAlloc` are on every path
that allocates, and rr checks them as hot whether marked or not. A
reason of the kind allows the operation, except for a scratch buffer: a
fresh String or Vec bound by a `let` and freed before the function
returns, because it is only lent, written and read, consumed by a `for`,
or moved into a local function that does the same. The path makes and
frees it on every run, and no reason answers that: it belongs in a field
of what outlives the path, such as the parser or the writer, cleared
before each use. A buffer the function returns or stores takes a reason
as before; but a call to a local function that makes and returns one,
whose caller only reads and frees it (`out.push_str(&number_text(n))`),
is scratch made one call away, and no reason answers it either: lend the
function a buffer to write into. A temporary the path makes itself, such
as an error's text, takes a reason.
A `// rr: escape(cold): ...` at a call says that the branch is off the path,
such as an error or once per item, and the callee is not followed from
there. Such a reason is used only when what the path forbids, without its
own reason, lies beyond the call; otherwise rr_unused_escape reports it.
The diagnostic shows the calls from the hot root down. A copy rr does not
see by its form still shows in rr prof.

## Bounds

A collection a value keeps in a field, a Vec, String, VecDeque, BinaryHeap or a
B-tree collection, grows by push, extend, insert, append or resize. Rule
rr_unbounded asks of each field that grows so that something in the
crate holds it to a limit: a comparison of its len() with a limit other
than its capacity(), which is what the allocator gave. A clear() that
starts it over does not bound what one turn adds. Without one, the field's
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
`rr prof [--top N] [--max N] [--max-copied BYTES] [--max-heap BYTES] [--keep DIR] [--stdin FILE] -- COMMAND`
runs a command with RR_PROF_DIR set, so that each process of such a program
it starts, each image after exec included, writes its counts to a file
mapped shared there; then reports the program's own lines that allocate
most, and those that copy the most bytes, with their callers (core, alloc,
the allocator and memcpy are left out), from DWARF or the dSYM. --max fails
above a budget of allocations, --max-copied above one of bytes copied: an
allocation traded for copies shows. Each place that copies shows the
bytes of one copy, and the places that copy most often are listed apart:
millions of copies of a few bytes each, a call for each value, rank low
by bytes and cost time. It reports as well the most bytes the
heap held at once, in any one process image, and --max-heap fails above a
budget of them: a buffer reserved for the worst case, so that nothing
allocates later, shows there. Without RR_PROF_DIR a --prof build runs
as usual.

`rr time [--runs N] [--max-ms MS] [--stdin FILE] -- COMMAND` runs a
command N times (5 by default) and reports its fastest run and its
middle one, in milliseconds of wall time; --max-ms fails when the
fastest took longer. --stdin gives each run a file to read, for rr prof
too, and what the command writes to stdout is dropped by both.
It times the program as it ships: a --prof build records each copy and
runs slower. The template's `make time` runs the workload of `make prof`
on the program `make` builds, with PROFIN on stdin, against TIMEMS: memory saved at a cost in
time shows there. The template builds with `-C opt-level=3`, and its
`make bench` with the same flags as the program.

Operations are matched using resolved definitions and result types. An unrelated
inherent method called clone is not Clone. Arbitrary user functions may hide
these operations, and previously compiled libraries are not audited. This is an
explicit lint policy, not a proof that all possible ownership escape hatches are
absent. Comments document a decision; they do not make unsafe code sound.

## Fuzzing user programs

rr keeps a libFuzzer for its host, built from the LLVM of Rust 1.99.1, in the
toolchain's lib/rustlib/rr/, with rr fuz's coverage flags; AddressSanitizer is
the toolchain's own runtime. Fuzzing runs on the host and needs its C and C++
libraries (on Linux the system's cc with libstdc++; on Windows Visual Studio's
tools). Cargo is not needed. Ordinary builds retain the same behavior;
fuzzing instrumentation is opt-in.

A fuzz target is a function of the crate, `fn(&[u8])` under `#[cfg(fuzzing)]`,
beside the code it fuzzes; a project's Makefile names them in FUZZ, and
`make fuzz` runs them:

```sh
rr fuz src/main.rs --target parse::fuzz_parse -- -runs=100000
rr fuz src/main.rs --target parse::fuzz_parse --asan -- -runs=100000
```

rr fuz builds the crate with libFuzzer's entry in place of the program's,
calling the target, using this rr; it never invokes Cargo or a separate rustc.
Compiler flags go before `--`, and libFuzzer arguments go after it. Coverage,
native library paths and ASan's Darwin rpath are set automatically. Each
target keeps its corpus/ and artifacts/ in fuzz/PATH/; explicit libFuzzer paths
are relative to the current directory. The temporary executable is removed
after completion, a crash or terminal Ctrl-C; corpus and crash files persist. A
captured failure is replayed by naming its file after `--` with `-runs=1`.
Targets retain all rr restrictions and escape-comment requirements. ASan does
not instrument precompiled core/alloc or external libraries. The precompiled
C++ fuzzing engine uses system libc/libc++.

scripts/build-fuzz-runtime.py builds libFuzzer and lays out rr fuz's flags.
scripts/smoke-fuzz.py checks the native CLI, actual coverage, mutation-driven crash
discovery, artifact replay, rr restrictions, cleanup on Ctrl-C, and a deliberate
memory error detected by ASan, with rr run through a link as install.sh makes it.

## Development and packaging

The Clippy fork itself uses upstream Cargo build/test infrastructure. This is
separate from checking rr projects, which never invokes Cargo. Cargo.lock pins
resolved dependency versions. rust-toolchain.toml names Rust 1.99.1 with
rustc-dev, rust-src and rustfmt; rr uses the compiler's private crates, so
Cargo runs with RUSTC_BOOTSTRAP=1, and rr sets it for itself at its start, for
what only a nightly compiler takes (a tool attribute, a no_std test harness, a
forced extern for its runtimes). `cargo dev fmt` formats rr's own code with the
rustfmt of nightly-2026-08-15, the nightly the release branched from, whose
unstable options rustfmt.toml uses.

```sh
RUSTC_BOOTSTRAP=1 cargo test -- --skip 5041_allow_dev_build
scripts/release.sh /path/to/scratch rr-macos-arm64
```

release.sh builds rr in release, fetches libFuzzer's source from
rust-lang/llvm-project at the release's LLVM commit and builds it
(scripts/build-fuzz-runtime.py), lays out rr for a toolchain
(scripts/package-rr.sh: bin/rr and lib/rustlib/rr/, with the Rust release it
needs in rust-version), installs it into the toolchain, runs the smoke checks
there (scripts/smoke-distribution.py and scripts/smoke-fuzz.py: a project,
the corpus programs and every registry component through their Makefiles,
with only that toolchain on PATH) and archives it in dist/.

## Releases

`.github/workflows/rr-release.yml` builds rr on each host, installs and checks
it, and on a `v*` tag or a dispatch naming one publishes the archives as a
GitHub release with their SHA256SUMS; then it runs the installers on each host
(rr-install.yml).

| Archive | Host |
| --- | --- |
| rr-macos-arm64.tar.gz | macOS 11+ on Apple silicon |
| rr-linux-x86_64.tar.gz | Linux x86_64, glibc 2.31+ |
| rr-linux-aarch64.tar.gz | Linux aarch64, glibc 2.31+ |
| rr-windows-x86_64.zip | Windows 10+ x86_64 |
| rr-windows-aarch64.zip | Windows 11 on ARM |

Each holds rr and its lib/rustlib/rr/ for the official Rust 1.99.1, which the
installers add with rustup. The Linux ones build in an Ubuntu 20.04 container,
for an old glibc.
