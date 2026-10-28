# Instructions

This project is restricted Rust: every compile goes through rr, no
Cargo. rr's rules are part of the compiler. An rr error says what the
design must change, never what to hide from it.

When goals pull apart, safety comes first, then performance, then ease
of work.

## Before writing code

Think the change through first. Design is cheap next to code, tests and
operation, and the simple design is rarely the first one.

- Sketch the cost. For network, disk, memory and CPU, estimate bandwidth
  and latency per event and in total. Look first at the slowest
  resource, weighted by how often it is used. Run make prof for a
  baseline.
- Work with the grain of the machine: data read in order and kept
  together, few pointer hops on the data plane, branches that mostly go
  the same way.
- Decide whether the code runs for every event (the data plane) or
  rarely (the control plane: setup, errors, configuration). Mark the
  path of each event `#[cfg_attr(rr, rr::hot)]`: rr can follow a path,
  not find one.
- Set the limits: the largest input, the most items, the longest wait.
  Each is a constant with its unit last (`TIMEOUT_MS`, `QUEUE_MAX`).
  Decide what happens at each: a full queue refuses, drops or closes; it
  does not grow.
- Ask what can go wrong: a peer that stalls, cuts or lies, input that is
  malformed or turns malformed midway, a slow reader, a full disk.
  Decide each case before writing the one that works.
- Check how the cost grows with the input. Nothing a peer controls may
  make the work quadratic, or make one event stall the rest.
- Decide where each piece of state lives: one place for each fact, no
  copy of it in another field, no alias to keep in step.
- Work at the program's own pace: take what came in batches, and bound
  the work of one turn of the event loop.

## While writing

- Own data in one place and lend it. Borrow, move or reuse a buffer
  rather than copy; data is written once, where it ends up. A buffer
  with its length kept apart from it (an array and a count, or memory
  written through unsafe) is read only up to what was written into it;
  a `Vec` keeps its own length and needs no care.
- A variable lives in the smallest scope, computed next to where it is
  used.
- Every length, count or index that comes from outside is checked
  against its limit before it is used to index, allocate or loop.
- A value of fixed size (a key, a digest, an id) is an array; a part of
  other data is a slice of it. A large value is passed by reference and
  built in place through &mut, not returned by value: each move of it
  is a memcpy.
- Variants are enums carrying their own data; absence is Option, failure
  is Result. No sentinel values, no kind tag beside fields only some
  kinds use.
- Keep control flow in the caller: push ifs up and fors down. A function
  takes few arguments, returns something simple and does its work
  inside; helpers compute, and the caller changes state. Arguments a
  caller could swap (two lengths, two ids) get distinct types or go in a
  struct with named fields. Add an abstraction only where the domain
  has the thing.
- A compound condition becomes nested branches, each one handled.
- Index, count and size differ: an index plus one is a count, a count
  times the unit is a size.
- Sizes on the wire and on disk have their width, u8 to u64. usize is
  for lengths and indexes in memory.
- An assertion states what the design says must hold: arguments,
  results, invariants, and what must never happen as well as what must.
  A bug or corrupt state stops the program; a failure of the world
  outside (network, disk, input) is handled. Pair assertions across
  paths: check data before it is written and after it is read back.
  One condition per assertion; an implication is
  `if a { assert!(b) }`. A relation between constants is checked when
  the program compiles: `const _: () = assert!(HEAD_MAX <= BUF_MAX);`.
  Assertions are not counted; one that restates the line above it says
  nothing.
- A resource owns itself and is released on drop. unsafe and the
  operating system stay in src/sys/: a file for each of macOS, Linux and
  Windows, each with the same functions; a new one goes into all three.
  macOS is reached through its C library, Linux by system calls,
  Windows through kernel32.dll. A C function is declared as its
  header declares it, word for word; one that takes a variable number
  of arguments ends in `...`, or its arguments go where the callee does
  not look.
- Time, randomness and every byte from outside come through src/sys/,
  so that a simulation can stand in for the system: a test drives the
  event loop with a seeded fake of it (connections that stall, cut or
  answer in pieces, a clock that jumps) and checks what must always
  hold after every step. The fuzzer picks the seed; a failure replays
  from it.
- One thread unless the design needs more.
- Pass options where they matter, at the call, not left to defaults.
- Names are whole words that mean one thing everywhere, and say what
  the thing is for, not its type (`pending`, not `vec`). Units and
  qualifiers come last (`latency_ms_max`). Names that go together have
  the same length (`source`, `target`). A helper is named after its
  caller; a callback comes last among the arguments. The important
  things come first in a file and in a struct.
- Comments are sentences about why. A test begins with what it checks
  and how.

## After every change

    make fmt          # rr fmt: rewrite the code in rr's one style
    make format       # rr fmt --check: fail on code not in that style
    make check lint   # rr's rules, then Clippy's; on the tests too
    make              # build
    make test         # the #[test] items; FILTER=word narrows
    make bench        # the #[bench] items: time, allocations, copies
    make fuzz         # when parsing changed; FUZZ=target FUZZTIME=seconds
    make prof         # allocations, copies and heap against the baseline

A change is done when all of them are clean and it is right as it
stands: no TODO, no workaround to come back to.

make prof runs PROFRUN, a fixed workload that drives the data path as
real use does. PROFMAX, PROFCOPIED and PROFHEAP are its measured
maximum over a few runs plus 1-2%: lowered in the same commit when a
change saves, raised only with the reason in the commit message. The
workload changes only with the budgets, and says why.

Tests sit beside the code they check, in `#[cfg(test)] mod tests`, as
`#[test]` functions; a path that runs for every event has a `#[bench]`
there too. They cover invalid input, input that turns invalid midway,
and every error path, not only the case that works. A parser of outside
input has a fuzz target: a `fn(&[u8])` under `#[cfg(fuzzing)]`, named in
FUZZ in the Makefile. State that must survive a failure of the disk,
the network or the clock is tested under simulation: the module that
talks to the system has a simulated twin under `cfg(any(test, fuzzing))`
that injects faults, driven by a seed or by the fuzzer's bytes. The
commit message says what changed and why: the history keeps nothing
else.

## When rr objects

Change the design. A `// rr: escape(kind): <reason>` is for an operation
the design needs, and its reason says why. The same operation spelled a
way rr does not see is still that operation.
