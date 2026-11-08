#!/usr/bin/env python3
"""Writes sha384-wycheproof.txt, Wycheproof's HMAC-SHA384, HMAC-SHA512
and HKDF-SHA384 cases for the tests.

    python3 sha384-wycheproof.py               # fetch, write the file
    python3 sha384-wycheproof.py --check       # the file is what it gives
    python3 sha384-wycheproof.py --dir DIR     # the JSON files from DIR

The JSON comes from C2SP/wycheproof at COMMIT and each file must hash
to its SHA-256 in SOURCES. A case is a line of fields in hex, - for an
empty one:

    hmac hash tcId valid tag-bytes key message tag
    hkdf tcId ikm salt info size okm

hash is 384 or 512. An HMAC case is valid when the first tag-bytes of
the MAC are the tag (Wycheproof truncates too); an invalid one has a
modified tag. An HKDF case without okm (-) asks for more than 255
blocks, which hkdf_expand refuses.
"""

import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
SOURCES = {
    "hkdf_sha384_test.json": "69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678",
    "hmac_sha384_test.json": "28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0",
    "hmac_sha512_test.json": "b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207",
}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sha384-wycheproof.txt")


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
    lines.append("# by sha384-wycheproof.py; see it for the fields")
    for bits in (384, 512):
        for group in source(directory, f"hmac_sha{bits}_test.json")["testGroups"]:
            size = group["tagSize"] // 8
            for t in group["tests"]:
                if t["result"] == "acceptable" or len(t["tag"]) != 2 * size:
                    sys.exit(f"hmac tcId {t['tcId']}: not a case the test reads")
                valid = int(t["result"] == "valid")
                lines.append(
                    f"hmac {bits} {t['tcId']} {valid} {size} {h(t['key'])} {h(t['msg'])} {h(t['tag'])}"
                )
    for group in source(directory, "hkdf_sha384_test.json")["testGroups"]:
        for t in group["tests"]:
            if (t["result"] == "valid") != (t["size"] <= 255 * 48):
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
                sys.exit("sha384-wycheproof.txt differs")
        return
    with open(OUT, "w") as f:
        f.write(out)


main()
