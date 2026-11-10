# rr registry

Components `rr add` copies into a project as its own code, the way shadcn
copies a component: the project owns the copy, reads it and changes it.
Each is one Rust file, as an stb library is one header: it goes into
src/base/NAME.rs, apart from what the project wrote, cut to what the
project chose (its systems, its CPUs, its tests), and rr add declares it
in src/base/mod.rs; the crate root declares `mod base;`.

    rr add tls                          # this registry
    rr add tls --option os=linux        # only the code Linux builds
    rr add @acme/geo                    # a registry rr.json names
    rr add ./x/geo.rs                   # a component's file, by path or URL
    rr add --list                       # what this registry has (index.json)

## Components

| Name | Needs | What |
|---|---|---|
| random | | the system's randomness: arc4random_buf, getrandom(2), ProcessPrng; seeds of 32 and 64 bytes that only it (or a test) makes, which keys are made from, wiped when dropped |
| digest | | a digest that names its hash, SHA-256, SHA-384 or SHA-512, at its length: what ecdsa and rsa verify |
| sha256 | cpu | SHA-256, HMAC with a constant-time verify, HKDF whose Expand takes only a Prk; SHA instructions where the CPU has them |
| sha384 | cpu | SHA-384 and SHA-512 (digest384, digest512), HMAC with verify, HKDF-SHA384 by its Prk; SHA512 instructions where the CPU has them |
| aesgcm | cpu | AES-128-GCM and AES-256-GCM in place: a SealingKey and an OpeningKey that number their own nonces (seal_with_nonce for the rest), a tag that must be used, key schedules wiped; AES and carry-less multiply instructions, on 256-bit vectors where x86-64 has VAES, constant-time portable code elsewhere |
| x25519 | random | X25519 key agreement, constant time: a Secret from random's seed, a PublicKey, a SharedSecret only a key derivation takes, LowOrder refused |
| mlkem | random | ML-KEM-768 key encapsulation (FIPS 203), constant time, for TLS's X25519MLKEM768: a key generated in place and an encapsulation, each from random's seed; its own SHA-3 and SHAKE |
| ecdh | random | P-256 Diffie-Hellman for TLS key shares, constant time: a Secret from random's seed, a PublicKey checked as a point, a SharedSecret only a key derivation takes |
| ecdsa | digest | ECDSA verification on P-256, P-384 and P-521 of a digest that names its hash; which part is wrong (key, encoding, signature) |
| rsa | digest, sha256, sha384 | RSA PKCS#1 v1.5 and PSS verification, 2048 to 8192 bits, of a SHA-256, SHA-384 or SHA-512 digest that names its hash; which part is wrong |
| x509 | digest, sha256, sha384, ecdsa, rsa | certificates, a store of anchors, chain verification for a host that yields an Approval (leaf and host, unforgeable); a Policy of revocations, distrust dates and imposed name constraints over other anchors or paths, a type of its own |
| roots | x509 | Mozilla's trust anchors and OneCRL, with Chrome's announced distrusts and Firefox's imposed name constraints; policy(), an x509::Policy, for the system's anchors |
| tls | random, sha256, sha384, aesgcm, x25519, mlkem, ecdh, x509; asks for trust or roots | TLS 1.3 client, its randomness a tls::Random that only random or a test makes, given as the time is, AES-128-GCM and AES-256-GCM, with post-quantum X25519MLKEM768, bytes in any split, counts that must be used and loud errors for a step a loop forgets, eof that refuses a truncation; the chain verified by x509 or by the caller (the system, through trust) with an x509::Approval bound to the leaf and host; secrets wiped |
| http1 | | HTTP/1.1 requests, pipelined in order, bodies counted by an Upload, and an incremental response parser; misuse refused with a reason |
| io | thread | completion I/O for a loop on each thread, after TigerBeetle's: accept, connect, receive, send and timeouts started with a key and handed back once as Events, what each works on (a Listener, a Stream, a buffer) moved in and back, a table of operations fixed at the start that hands back what it has no room for, cancel by Op; UDP datagrams; work that blocks on thread's pool (run); a Waker for other threads; an Io made on one thread and moved to its loop's before its first wait; io_uring on Linux 6.1 and later (nothing else there, and Io::new says why the system gives none), kqueue on macOS, an I/O completion port on Windows |
| resolve | io, thread | host lookup that never blocks the loop, by the system, on io's pool: getaddrinfo on Linux and macOS, GetAddrInfoW on Windows, sorted by RFC 6724; names answered before the system (no name, .onion, localhost, IPv4 literals) the same everywhere; a Lookup whose Event says it is done |
| trust | x509, io, thread | the system verifies a chain, as Go does: SecTrust on macOS, CertGetCertificateChain on Windows, x509 with the system's roots on Linux or SSL_CERT_FILE's and SSL_CERT_DIR's anywhere; a policy (roots::policy) over either; a check on io's pool whose Event says it answered with an x509::Approval, or verify_blocking off the loop |
| thread | | threads for loops, as libuv has them: a pool of at most 32 for work that blocks, a Box<dyn Work + Send> moved in and given back, a Job that cancels what is still in line and tells a Notify when done (io's run); a thread of its own for a loop on another core; the system's mutex and condition variable |
| queue | io, thread | a bounded queue between threads of io Streams, each push waking the worker's Io, under the system's mutex; a full queue refuses at once and gives the connection back; its tests run a server on a loop for each core, fed by an accept thread |
| cpu | | what the CPU has of the instructions the components use, asked once, by Features only it names |

poll and net are gone: io takes their place, with completions instead
of readiness. A program that has them adds io; a loop that polled for
readiness and read starts a receive and takes its Event, and a component
that gave a Want (resolve, trust) now runs on io's pool and says by an
Event when it is done. thread's Done is a Notify, which io's run gives.

## A component

One file, NAME.rs, as it goes into src/base/NAME.rs. Its `//!` docs say
what it is, the first paragraph of them what `rr add --list` prints; its
unsafe is in a `mod sys { ... }` inside it, the module rr lets touch the
system. A header, `// rr:` lines among the comments before the first
line of code, says what rr add needs:

```rust
//! ECDSA signature verification on P-256, P-384 and P-521 ...

// rr: checked(0.5.2)
// rr: needs(digest)
// rr: option(os, many): Which systems does it build for?
// rr: choice(os = linux, default): Linux
// rr: choice(os = macos, default): macOS
// rr: choice(os = windows, default): Windows
// rr: option(roots, one): Where does TLS take the roots it trusts from?
// rr: choice(roots = system, default, needs(trust)): the system's
// rr: choice(roots = none): a store the program fills
// rr: option(tests, one): Its tests, which rr test runs?
// rr: choice(tests = yes, default): the tests, and the data files they read
// rr: choice(tests = no): none
// rr: file(ecdsa-wycheproof.txt, tests = yes)
```

- `checked`: the rr the component was checked with; an older rr refuses
  it.
- `needs`: names in the same registry (files beside this one),
  `@scope/name`, or URLs. A choice can need more, as a roots choice
  needs trust or roots.
- `option`: a question, `one` (a single choice) or `many` (any of its
  choices, at least one), and its `choice`s, those marked `default`
  taken without a terminal. An option's name means the same in every
  component, and one answer serves all that ask it: `--option
  os=linux,macos` cuts each component to those two systems.
- `file`: data beside it, named NAME-… or NAME.…, that goes beside it in
  src/base/, when its condition holds: the standards' test vectors with
  the tests, Mozilla's roots always.

The body is kept or cut by the answers: what is between `// rr:
section(os = linux macos)` and `// rr: end(os = linux macos)` stays when
either is chosen, what is between `// rr: unless(os = windows)` and its
end only when that is not. They nest. Each item under `#[cfg]` of a
system or a CPU stands in a section of it; each item only tests or fuzz
targets have, in `section(tests = yes)`; and for each system or CPU that
can be cut, an `unless` holds a `compile_error!` that says to add the
component again with it, so that a build where it was cut fails loudly
at once. What rr add writes has no header and no marks, and one line,
`// rr: added(ecdsa, rr 0.5.2; os = linux; tests = yes)`, that says what
was chosen.

At a terminal rr add asks; `--option NAME=A,B` answers, and `--yes` or
a run without a terminal (an agent's) takes the defaults and prints how
to choose.

`rr add` refuses a file that exists and differs, unless `--overwrite`,
and says when the crate root still needs `mod base;`. A registry of your
own is any place that serves such files, with index.json at its root
(`rr add --index DIR` writes it from their headers): rr.json maps a
scope to that root,

```json
{ "registries": { "@acme": "https://acme.dev/registry" } }
```

rr fetches its own registry at the tag of its release, so a change here
reaches only the rr made with it.

## The rule over every component

As fast as the machine allows; boilerplate is cheap; an agent that uses
the component cannot get it wrong. A wrong call that compiles and runs
quietly is a defect of the component, not of its caller. In order of
strength:

- **What is wrong does not compile.** Distinct things have distinct
  types: a secret, a public key and a shared secret; a digest of a named
  hash and a message; an interest and a readiness; a policy and a store
  of anchors. A size is an array, not a slice checked at run time.
- **A proof is a value only the component makes.** A verdict that a
  chain is trusted for a host is a struct with private fields that the
  verifier returns, never a `bool` the caller passes in.
- **Nothing the component can do is asked of the caller.** It numbers
  its own nonces, keeps its own order of calls and checks its own host.
- **No outcome goes unread.** A function that returns a verdict, a
  count or a tag returns a `Result` or is `#[must_use]`, and so is a
  value whose drop cancels work. `bool` answers questions, not outcomes.
  rr asks it of every function that changes something (takes `&mut`
  or calls C) and returns a bool, an integer or an Option, and of each
  C declaration; a value dropped on purpose says why in an
  `escape(discard)` reason.
- **What blocks says so.** A function that waits for an answer, such as
  resolve::resolve or trust::Trust::verify_blocking, is
  `#[cfg_attr(rr, rr::blocking)]`, which rr refuses on the path of a
  loop the program marks `#[cfg_attr(rr, rr::poll)]`; no component
  marks a function `rr::poll`, as the loop is the program's.
- **Every failure is a variant, and loud.** An error enum says what went
  wrong; which errors end the value and which leave it usable is written
  at the enum. A call that cannot go on says why, never `Ok(0)` or the
  end again forever, and behaves the same on every system.
- **A resource leaves once.** One owner closes it; nothing hands out a
  handle another can close.
- **Secrets are not Copy, Clone or Debug, and are wiped when dropped.**
- **The safe way is the short way**; what is less safe has a name that
  says so (`seal_with_nonce`, `verify_blocking`).
- **The intended loop is a test.** Each component has a test that drives
  it as a program does: short reads and writes, the end of input, each
  error, and every rule its docs state.

These cost nothing at run time: no generics, no heap, no copy of a large
value. A state that changes when the system says so (a socket connects,
a handshake ends) is held as data and checked at each call, with the
same loud error everywhere; a type for each state is for code where the
change is a line of the program.

## What a component here is

- **No I/O of its own.** Bytes and time come in as arguments; bytes to
  send, data received and the next deadline go out. The same component
  then serves a blocking loop, a poll loop or a thread: the caller moves
  the bytes.
- **Randomness from random alone.** A key is made from random's Seed32
  or Seed64, values only random makes, from the system's randomness
  (random::seed32, seed64), never from bytes: a constant or a test
  array does not compile where a key is made. A test or a fuzz target
  makes a seed of a standard's vector by Seed32::for_tests, which only
  cfg(test) and cfg(fuzzing) have. A protocol that needs randomness of
  its own, as tls's ClientHello does, draws it from random, with a test
  constructor beside for its replays. random's sys module is the one place
  that asks the system, which never blocks once the system's pool is
  ready at boot; random::wipe is the volatile wipe the others share.
- **Its own errors.** A component does not name the project's error type;
  it returns its own small enum.
- **Unsafe only in sys.** CPU instructions (AES, SHA, carry-less
  multiply) are in the component's sys module behind a safe function
  that says whether it ran; `cpu` says what the CPU has. The portable
  code is always there and passes the same vectors. What talks to the
  system (poll, thread, resolve, trust, cpu) is all in its sys module,
  through the C library on Linux and macOS and the system's DLLs on
  Windows; the top of the file says what it is and exports it.
- **Arithmetic that cannot overflow, or says it wraps.** The template
  builds without overflow checks, as Cargo's release profile does, so
  nothing stops an overflow there. Arithmetic meant to wrap is written
  `wrapping_*` or `core::num::Wrapping`; elsewhere a comment states the
  bounds that keep it in range, or `checked_*` returns the error.
- **One style, except generated tables.** `#[rustfmt::skip]` stands
  only on a constant a script writes, under a comment naming the script
  and the test that recomputes it. The script is in registry/gen/, with
  the inputs it reads, and writes into the component's file (splice.py:
  a module in place, formatted by rr fmt); rr add copies neither. One
  whose data goes stale says how to run it on a project's copy
  (roots-gen.py --out src/base/roots.pem: Mozilla's roots).
- **Checked as the template checks a program.** Each file passes rr
  check, lint, fmt and test with the template's flags; its tests carry
  the standard's vectors, its bench the cost of one operation, and what
  parses input from a peer has a fuzz target under cfg(fuzzing).

index.json lists the components for `rr add --list`; `rr add --index
registry` writes it from their headers. `scripts/registry-check.sh DIR
NAME...` adds components to a fresh project and runs those checks; with
`OPTIONS` (`os=linux arch=x86_64`, `tests=no`) it adds them so cut, and
with `TARGETS`, other targets whose standard library rustup added, it
checks them for each target too. The Registry workflow runs it on each
host for every push that changes registry/: every component whole, cut
to the host's system and CPU, and without its tests.
