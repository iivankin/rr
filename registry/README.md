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
| sha256 | cpu | SHA-256, HMAC, HKDF; SHA instructions where the CPU has them |
| sha384 | cpu | SHA-384, HMAC, HKDF; SHA512 instructions where the CPU has them |
| aesgcm | cpu | AES-128-GCM in place; AES and carry-less multiply instructions, on 256-bit vectors where x86-64 has VAES, constant-time portable code elsewhere |
| x25519 | | X25519 key agreement, constant time |
| ecdsa | | ECDSA verification on P-256 and P-384 |
| rsa | sha256, sha384 | RSA PKCS#1 v1.5 and PSS verification |
| x509 | sha256, sha384, ecdsa, rsa | certificates, a store of anchors, chain verification for a host |
| roots | x509 | Mozilla's trust anchors |
| tls | sha256, aesgcm, x25519, x509; asks for trust or roots | TLS 1.3 client, bytes in any split; the chain verified by x509 or by the caller (the system, through trust) |
| http1 | | HTTP/1.1 requests and an incremental response parser |
| resolve | wait | host lookup that never blocks the loop, by the system: DNSServiceGetAddrInfo on macOS and GetAddrInfoExW on Windows, asynchronous and cancellable; getaddrinfo on a thread on Linux |
| trust | x509, wait | the system verifies a chain, as Go does: SecTrust on macOS, CertGetCertificateChain on Windows, x509 with the system's roots on Linux; never blocks |
| wait | | what a program's loop waits on for any component: descriptors or an event, a timeout; a thread that signals when done |
| cpu | | what the CPU has of the instructions the components use, asked once |

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

## What a component here is

- **No I/O of its own.** Bytes, time and random bytes come in as
  arguments; bytes to send, data received and the next deadline go out.
  The same component then serves a blocking loop, a poll loop or a
  thread: the caller moves the bytes.
- **Its own errors.** A component does not name the project's error type;
  it returns its own small enum, or false.
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
