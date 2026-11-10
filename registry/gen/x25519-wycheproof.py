#!/usr/bin/env python3
"""Writes x25519-wycheproof.txt, Wycheproof's X25519 cases for the tests.

    python3 x25519-wycheproof.py               # fetch, write the file
    python3 x25519-wycheproof.py --check       # the file is what it gives
    python3 x25519-wycheproof.py --dir DIR     # x25519_test.json from DIR

The JSON comes from C2SP/wycheproof at COMMIT and must hash to SHA256.
Each case is a line: tcId, the private key, the peer's public key and
the shared secret, in hex. Wycheproof marks the low-order points
"acceptable" with a shared secret of zeros (ZeroSharedSecret), which
x25519::shared refuses as RFC 7748 6.1 allows; the test expects None for
those and the secret for every other case, twist and non-canonical
points included.
"""

import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
NAME = "x25519_test.json"
SHA256 = "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "x25519-wycheproof.txt")


def source(directory):
    if directory:
        with open(os.path.join(directory, NAME), "rb") as f:
            data = f.read()
    else:
        url = f"https://raw.githubusercontent.com/C2SP/wycheproof/{COMMIT}/testvectors_v1/{NAME}"
        with urllib.request.urlopen(url) as r:
            data = r.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        sys.exit(f"{NAME}: not the pinned file")
    return json.loads(data)


def text(doc):
    lines = [
        f"# Wycheproof (C2SP/wycheproof) testvectors_v1 at {COMMIT}",
        f"# {NAME} sha256 {SHA256}, by x25519-wycheproof.py",
        "# tcId private public shared",
    ]
    for group in doc["testGroups"]:
        for t in group["tests"]:
            zero = t["shared"] == "00" * 32
            if zero != ("ZeroSharedSecret" in t["flags"]) or t["result"] == "invalid":
                sys.exit(f"tcId {t['tcId']}: not a case the test reads")
            lines.append(f"{t['tcId']} {t['private']} {t['public']} {t['shared']}")
    return "\n".join(lines) + "\n"


def main():
    args = sys.argv[1:]
    directory = args[args.index("--dir") + 1] if "--dir" in args else None
    out = text(source(directory))
    if "--check" in args:
        with open(OUT) as f:
            if f.read() != out:
                sys.exit("x25519-wycheproof.txt differs")
        return
    with open(OUT, "w") as f:
        f.write(out)


main()
