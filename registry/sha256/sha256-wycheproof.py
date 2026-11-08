#!/usr/bin/env python3
"""Writes sha256-wycheproof.txt, Wycheproof's HMAC-SHA256 and HKDF-SHA256
cases for the tests.

    python3 sha256-wycheproof.py               # fetch, write the file
    python3 sha256-wycheproof.py --check       # the file is what it gives
    python3 sha256-wycheproof.py --dir DIR     # the JSON files from DIR

The JSON comes from C2SP/wycheproof at COMMIT and each file must hash
to its SHA-256 in SOURCES. A case is a line of fields in hex, - for an
empty one:

    hmac tcId valid tag-bytes key message tag
    hkdf tcId ikm salt info size okm

An HMAC case is valid when the first tag-bytes of the MAC are the tag
(Wycheproof truncates to 128 bits too); an invalid one has a modified
tag. An HKDF case without okm (-) asks for more than 255 blocks, which
hkdf_expand refuses.
"""

import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
SOURCES = {
    "hkdf_sha256_test.json": "bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e",
    "hmac_sha256_test.json": "2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f",
}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sha256-wycheproof.txt")


def source(directory, name):
    if directory:
        with open(os.path.join(directory, name), "rb") as f:
            data = f.read()
    else:
        url = f"https://raw.githubusercontent.com/C2SP/wycheproof/{COMMIT}/testvectors_v1/{name}"
        with urllib.request.urlopen(url) as r:
            data = r.read()
    if hashlib.sha256(data).hexdigest() != SOURCES[name]:
        sys.exit(f"{name}: not the pinned file")
    return json.loads(data)


def h(field):
    return field or "-"


def text(directory):
    lines = [f"# Wycheproof (C2SP/wycheproof) testvectors_v1 at {COMMIT}"]
    lines += [f"# {name} sha256 {digest}" for name, digest in SOURCES.items()]
    lines.append("# by sha256-wycheproof.py; see it for the fields")
    for group in source(directory, "hmac_sha256_test.json")["testGroups"]:
        size = group["tagSize"] // 8
        for t in group["tests"]:
            if t["result"] == "acceptable" or len(t["tag"]) != 2 * size:
                sys.exit(f"hmac tcId {t['tcId']}: not a case the test reads")
            valid = int(t["result"] == "valid")
            lines.append(f"hmac {t['tcId']} {valid} {size} {h(t['key'])} {h(t['msg'])} {h(t['tag'])}")
    for group in source(directory, "hkdf_sha256_test.json")["testGroups"]:
        for t in group["tests"]:
            if (t["result"] == "valid") != (t["size"] <= 255 * 32):
                sys.exit(f"hkdf tcId {t['tcId']}: not a case the test reads")
            okm = t["okm"] if t["result"] == "valid" else ""
            lines.append(f"hkdf {t['tcId']} {h(t['ikm'])} {h(t['salt'])} {h(t['info'])} {t['size']} {h(okm)}")
    return "\n".join(lines) + "\n"

def main():
    args = sys.argv[1:]
    directory = args[args.index("--dir") + 1] if "--dir" in args else None
    out = text(directory)
    if "--check" in args:
        with open(OUT) as f:
            if f.read() != out:
                sys.exit("sha256-wycheproof.txt differs")
        return
    with open(OUT, "w") as f:
        f.write(out)


main()
