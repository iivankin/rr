# rr registry

Components `rr add` copies into a project as its own code, the way shadcn
copies a component: the project owns the copy, reads it and changes it.
Each goes into src/base/NAME/, apart from what the project wrote, and rr
add declares it in src/base/mod.rs; the crate root declares `mod base;`.

    rr add tls                  # this registry
    rr add @acme/geo            # a registry rr.json names
    rr add ./x/tls/tls.json     # a component's JSON, by path or URL
    rr add --list               # what this registry has (index.json)

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
| tls | random, sha256, sha384, aesgcm, x25519, mlkem, ecdh, x509; asks for trust or roots | TLS 1.3 client, its randomness drawn from random, AES-128-GCM and AES-256-GCM, with post-quantum X25519MLKEM768, bytes in any split, counts that must be used and loud errors for a step a loop forgets, eof that refuses a truncation; the chain verified by x509 or by the caller (the system, through trust) with an x509::Approval bound to the leaf and host; secrets wiped |
| http1 | | HTTP/1.1 requests, pipelined in order, bodies counted by an Upload, and an incremental response parser; misuse refused with a reason |
| net | wait | TCP for a loop of many connections: a Listener and Streams that own their socket and their Owned entry in a wait Set, closed once; non-blocking, not inherited, no SIGPIPE; NotConnected the same everywhere; errors by kind |
| resolve | wait | host lookup that never blocks the loop, by the system: DNSServiceGetAddrInfo on macOS and GetAddrInfoExW on Windows, asynchronous and cancellable; getaddrinfo on a thread on Linux |
| trust | x509, wait | the system verifies a chain, as Go does: SecTrust on macOS, CertGetCertificateChain on Windows, x509 with the system's roots on Linux or SSL_CERT_FILE's and SSL_CERT_DIR's anywhere; a policy (roots::policy) over either; a check that never blocks and answers with an x509::Approval, or verify_blocking off the loop |
| wait | | what a program's loop waits on: a Set of many sockets with deadlines (epoll, kqueue, socket notifications or WSAPoll), Interest in and Ready out the same on every system, refusals as SetError, and wakes from other threads; a component's Wait; a thread that signals when done |
| cpu | | what the CPU has of the instructions the components use, asked once, by Features only it names |

## A component

A directory, NAME/, as it goes into src/base/NAME/: NAME.json, mod.rs,
the component's other files, and its unsafe in sys.rs, the module rr
lets touch the system. A script that writes a table sits beside them.

```json
{
  "name": "aesgcm",
  "description": "AES-128-GCM (RFC 5116), with AES and GHASH instructions where the CPU has them.",
  "rr": "0.5.2",
  "dependencies": ["cpu"],
  "files": [{ "path": "mod.rs" }, { "path": "sys.rs" }]
}
```

- `rr`: the rr the component was checked with; an older rr refuses it.
- `dependencies`: names in the same registry (directories beside this
  one), `@scope/name`, or URLs.
- `files`: `path` under src/base/NAME/, or under `scripts/` with
  `"target": "scripts"`; the text is `content`, or the file at `path`
  beside the JSON.
- `options`: questions whose answers add components, as shadcn's
  prompts do. tls asks where its trusted roots come from:

```json
"options": [{
  "name": "roots", "question": "Where does TLS take the roots it trusts from?",
  "default": "system",
  "choices": [
    { "value": "system", "description": "…", "dependencies": ["trust"] },
    { "value": "mozilla", "description": "…", "dependencies": ["roots"] },
    { "value": "none", "description": "…" }
  ]
}]
```

  At a terminal rr add asks; `--option roots=mozilla` answers, and
  `--yes` or a run without a terminal (an agent's) takes the default and
  prints how to choose.

`rr add` refuses a file that exists and differs, unless `--overwrite`,
and says when the crate root still needs `mod base;`. A registry of your
own is any place that serves such directories, with index.json at its
root: rr.json maps a scope to that root,

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
  constructor beside for its replays. random's sys.rs is the one place
  that asks the system, which never blocks once the system's pool is
  ready at boot; random::wipe is the volatile wipe the others share.
- **Its own errors.** A component does not name the project's error type;
  it returns its own small enum.
- **Unsafe only in sys.** CPU instructions (AES, SHA, carry-less
  multiply) are in the component's sys.rs behind a safe function that
  says whether it ran; `cpu` says what the CPU has. The portable code is
  always there and passes the same vectors. What talks to the system
  (wait, resolve, trust, cpu) is all in its sys.rs, through the C
  library on Linux and macOS and the system's DLLs on Windows; mod.rs
  says what it is and exports it.
- **Arithmetic that cannot overflow, or says it wraps.** The template
  builds without overflow checks, as Cargo's release profile does, so
  nothing stops an overflow there. Arithmetic meant to wrap is written
  `wrapping_*` or `core::num::Wrapping`; elsewhere a comment states the
  bounds that keep it in range, or `checked_*` returns the error.
- **One style, except generated tables.** `#[rustfmt::skip]` stands
  only on a constant a script writes, under a comment naming the script
  and the test that recomputes it. The script sits beside the component
  (registry/NAME/NAME-gen.py). It goes to the project's scripts/ only when
  what it writes goes stale there (roots-gen.py: Mozilla's roots); a
  table that a standard fixes stays in the registry.
- **Checked as the template checks a program.** Each file passes rr
  check, lint, fmt and test with the template's flags; its tests carry
  the standard's vectors, its bench the cost of one operation, and what
  parses input from a peer has a fuzz target under cfg(fuzzing).

index.json lists the components for `rr add --list`;
`scripts/registry-index.py` writes it from their JSON, and `--check`
says whether it is current. `scripts/registry-check.sh DIR NAME...` adds
components to a fresh project and runs those checks; with `TARGETS`,
other targets whose standard library rustup added, it checks them for
each target too. The
Registry workflow runs it on each host for every push that changes
registry/.
