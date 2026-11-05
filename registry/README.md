# rr registry

Components `rr add` copies into a project as its own code, the way shadcn
copies a component: the project owns the copy, reads it and changes it.

    rr add tls                  # this registry
    rr add @acme/geo            # a registry rr.json names
    rr add ./x/tls.json         # a component's JSON, by path or URL
    rr add --list               # what this registry has (index.json)

## Components

| Name | Needs | What |
|---|---|---|
| sha256 | | SHA-256, HMAC, HKDF; SHA instructions where the CPU has them |
| sha384 | | SHA-384, HMAC, HKDF |
| aesgcm | | AES-128-GCM in place; AES and carry-less multiply instructions, constant-time portable code elsewhere |
| x25519 | | X25519 key agreement, constant time |
| ecdsa | | ECDSA verification on P-256 and P-384 |
| rsa | sha256, sha384 | RSA PKCS#1 v1.5 and PSS verification |
| x509 | sha256, sha384, ecdsa, rsa | certificates, a store of anchors, chain verification for a host |
| roots | x509 | Mozilla's trust anchors |
| tls | sha256, aesgcm, x25519, x509; asks for trust or roots | TLS 1.3 client, bytes in any split; the chain verified by x509 or by the caller (the system, through trust) |
| http1 | | HTTP/1.1 requests and an incremental response parser |
| dns | | DNS wire format: queries, replies, TCP framing |
| resolver | dns | Go's resolver without I/O: resolv.conf, hosts, nsswitch, the lookup, RFC 6724 order |
| resolve | resolver, wait, file | host lookup that never blocks: Linux on its own syscalls, getaddrinfo on macOS, GetAddrInfoExW on Windows |
| trust | x509, wait, file | the system verifies a chain, as Go does: SecTrust on macOS, CertGetCertificateChain on Windows, x509 with the system's roots on Linux; never blocks |
| wait | | what a program's loop waits on for any component: descriptors or an event, a timeout; a thread that signals when done |
| file | | Linux: whole files read by system calls, descriptors closed on drop |

## A component

One JSON file beside its sources, which sit where they go under `src/`:

```json
{
  "name": "aesgcm",
  "description": "AES-128-GCM (RFC 5116), with AES and GHASH instructions where the CPU has them.",
  "rr": "0.3.2",
  "dependencies": [],
  "files": [{ "path": "aesgcm.rs" }, { "path": "sys/aes.rs" }]
}
```

- `rr`: the rr the component was checked with; an older rr refuses it.
- `dependencies`: names in the same registry, `@scope/name`, or URLs.
- `files`: `path` under `src/`, or under `scripts/` with
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
and prints the `mod` lines still to write. A registry of your own is any
place that serves such files: rr.json maps a scope to it,

```json
{ "registries": { "@acme": "https://acme.dev/r/{name}.json" } }
```

## What a component here is

- **No I/O of its own.** Bytes, time and random bytes come in as
  arguments; bytes to send, data received and the next deadline go out.
  The same component then serves a blocking loop, a poll loop or a
  thread: the caller moves the bytes.
- **Its own errors.** A component does not name the project's error type;
  it returns its own small enum, or false.
- **Unsafe only in sys.** CPU instructions (AES, SHA, carry-less
  multiply) are in `sys/<name>.rs` behind a safe function that says
  whether it ran. The portable code is always there and passes the same
  vectors.
- **Fast with overflow checks on.** The template keeps them on, and on
  arithmetic they cost: 40% of X25519's time. Where the bounds are
  proven, the arithmetic wraps (`wrapping_*`, `core::num::Wrapping`) and
  a comment states the bounds; the bench is compared with checks off.
- **One style, except generated tables.** `#[rustfmt::skip]` stands
  only on a constant a script writes, under a comment naming the script
  and the test that recomputes it. The script sits beside the component
  (registry/NAME-gen.py). It goes to the project's scripts/ only when
  what it writes goes stale there (roots-gen.py: Mozilla's roots); a
  table that a standard fixes stays in the registry.
- **Checked as the template checks a program.** Each file passes rr
  check, lint, fmt and test with the template's flags; its tests carry
  the standard's vectors, its bench the cost of one operation, and what
  parses input from a peer has a fuzz target under cfg(fuzzing).

index.json lists the components for `rr add --list`;
`scripts/registry-index.py` writes it from their JSON, and `--check`
says whether it is current. `scripts/registry-check.sh DIR NAME...` adds components to a fresh
project and runs those checks.
