#!/usr/bin/env python3
"""Writes ecdsa-wycheproof.txt, Wycheproof's ECDSA cases with DER
signatures for the tests.

    python3 ecdsa-wycheproof.py               # fetch, write the file
    python3 ecdsa-wycheproof.py --check       # the file is what it gives
    python3 ecdsa-wycheproof.py --dir DIR     # the JSON files from DIR

The JSON comes from C2SP/wycheproof at COMMIT and each file must hash
to its SHA-256 in SOURCES. Lines are fields in hex, - for an empty one:

    key name point
    hash name digest
    sig curve key hash tcId valid signature

curve is 256, 384 or 521; point is the key's uncompressed encoding;
digest is that of the case's message under the file's hash, which is
what ecdsa verifies, cut to the order's bits by ecdsa itself. Every
case of each curve under its own hash is here, and the valid cases of
P-256 under SHA-512 and P-384 under SHA-256, a hash longer and shorter
than the order (VALID_ONLY): their invalid cases are the same mutations
again, and would double the file. The P1363 files are left out: ecdsa
reads DER.
"""

import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
SOURCES = {
    "ecdsa_secp256r1_sha256_test.json": "182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332",
    "ecdsa_secp256r1_sha512_test.json": "8e940baad7c6172c58c8f354b10366d307be43a3cb82a5880cb46686c3e8f858",
    "ecdsa_secp384r1_sha256_test.json": "660c948e5433279ecdf966e8a1386b69ecec618efc1ff00269e85aa9dc84f0a6",
    "ecdsa_secp384r1_sha384_test.json": "8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc",
    "ecdsa_secp521r1_sha512_test.json": "0fa3bb09a2319242253028b53d555fb8ec2081d891271321205cdaeabb3eef3e",
}
CURVES = {"secp256r1": 256, "secp384r1": 384, "secp521r1": 521}
HASHES = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
# Files of a hash other than the curve's own, of which only the valid cases
# are here: their invalid ones are the same mutations again.
VALID_ONLY = ["ecdsa_secp256r1_sha512_test.json", "ecdsa_secp384r1_sha256_test.json"]
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecdsa-wycheproof.txt")


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


def text(directory):
    lines = [f"# Wycheproof (C2SP/wycheproof) testvectors_v1 at {COMMIT}"]
    lines += [f"# {name} sha256 {digest}" for name, digest in SOURCES.items()]
    lines.append("# by ecdsa-wycheproof.py; see it for the fields")
    keys, digests = {}, {}
    for name in SOURCES:
        for group in source(directory, name)["testGroups"]:
            curve = CURVES[group["publicKey"]["curve"]]
            hash = HASHES[group["sha"]]
            point = group["publicKey"]["uncompressed"]
            tests = [t for t in group["tests"] if name not in VALID_ONLY or t["result"] == "valid"]
            if not tests:
                continue
            if point not in keys:
                keys[point] = len(keys)
                lines.append(f"key {keys[point]} {point}")
            for t in tests:
                if t["result"] == "acceptable":
                    sys.exit(f"{name} tcId {t['tcId']}: not a case the test reads")
                valid = int(t["result"] == "valid")
                digest = hash(bytes.fromhex(t["msg"])).hexdigest()
                if digest not in digests:
                    digests[digest] = len(digests)
                    lines.append(f"hash {digests[digest]} {digest}")
                lines.append(f"sig {curve} {keys[point]} {digests[digest]} {t['tcId']} {valid} {t['sig'] or '-'}")
    return "\n".join(lines) + "\n"


def main():
    args = sys.argv[1:]
    directory = args[args.index("--dir") + 1] if "--dir" in args else None
    out = text(directory)
    if "--check" in args:
        with open(OUT) as f:
            if f.read() != out:
                sys.exit("ecdsa-wycheproof.txt differs")
        return
    with open(OUT, "w") as f:
        f.write(out)


main()
