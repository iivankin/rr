#!/usr/bin/env python3
"""Writes aesgcm-wycheproof.txt, Wycheproof's AES-GCM cases that aesgcm
can run: a 128-bit key, a 96-bit nonce and a 128-bit tag.

    python3 aesgcm-wycheproof.py               # fetch, write the file
    python3 aesgcm-wycheproof.py --check       # the file is what it gives
    python3 aesgcm-wycheproof.py --dir DIR     # aes_gcm_test.json from DIR

The JSON comes from C2SP/wycheproof at COMMIT and must hash to its
SHA-256 in SOURCES. The other groups (192- and 256-bit keys, other
nonce sizes) are counted in the header and left out. A case is a line
of fields in hex, - for an empty one:

    tcId valid key nonce aad message ciphertext tag

A valid case seals to the ciphertext and tag and opens back; an invalid
one (a modified tag) is refused.
"""

import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
SOURCES = {
    "aes_gcm_test.json": "985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7",
}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aesgcm-wycheproof.txt")


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
    doc = source(directory, "aes_gcm_test.json")
    kept, skipped, cases = [], 0, 0
    for group in doc["testGroups"]:
        if (group["keySize"], group["ivSize"], group["tagSize"]) != (128, 96, 128):
            skipped += 1
            cases += len(group["tests"])
            continue
        for t in group["tests"]:
            if t["result"] == "acceptable":
                sys.exit(f"tcId {t['tcId']}: not a case the test reads")
            valid = int(t["result"] == "valid")
            fields = [t["key"], t["iv"], t["aad"], t["msg"], t["ct"], t["tag"]]
            kept.append(f"{t['tcId']} {valid} " + " ".join(h(f) for f in fields))
    lines = [f"# Wycheproof (C2SP/wycheproof) testvectors_v1 at {COMMIT}"]
    lines += [f"# {name} sha256 {digest}" for name, digest in SOURCES.items()]
    lines.append(f"# by aesgcm-wycheproof.py; {skipped} groups ({cases} cases) left out")
    lines.append("# tcId valid key nonce aad message ciphertext tag")
    return "\n".join(lines + kept) + "\n"

def main():
    args = sys.argv[1:]
    directory = args[args.index("--dir") + 1] if "--dir" in args else None
    out = text(directory)
    if "--check" in args:
        with open(OUT) as f:
            if f.read() != out:
                sys.exit("aesgcm-wycheproof.txt differs")
        return
    with open(OUT, "w") as f:
        f.write(out)


main()
