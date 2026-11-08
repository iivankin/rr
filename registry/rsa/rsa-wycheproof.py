#!/usr/bin/env python3
"""Writes rsa-wycheproof.txt, Wycheproof's RSA signature cases for the
tests.

    python3 rsa-wycheproof.py               # fetch, write the file
    python3 rsa-wycheproof.py --check       # the file is what it gives
    python3 rsa-wycheproof.py --dir DIR     # the JSON files from DIR

The JSON comes from C2SP/wycheproof at COMMIT and each file must hash
to its SHA-256 in SOURCES. Lines are fields in hex:

    key name modulus exponent
    pkcs1 hash key tcId valid digest signature
    pss hash key tcId valid digest signature

hash is 256, 384 or 512; key names a key line above; digest is the
hash of the case's message, which is what rsa verifies. valid is 1 when
rsa must accept: Wycheproof's acceptable PKCS #1 cases (a DigestInfo
without the NULL parameters) it refuses, as BoringSSL and Go do; and
rsa_pss_misc's signatures, valid under their own parameters, it accepts
only when MGF1 uses the same hash and the salt is the hash's length,
the one choice rsa takes. Groups of other hashes (SHA-1, SHA-224) are
left out.

Every case of rsa_signature_2048_sha256 and of the PSS files is here;
of the other PKCS #1 files, the valid and acceptable ones only: their
invalid cases are the same mutations again under another hash or a
longer key, at up to twice the bytes each. rsa_pss_misc has SHA-512 PSS
at 2048 bits, and the PKCS #1 files 4096-bit keys, so the 4096-bit PSS
files are left out for their size. FULL and VALID_ONLY name the files.
"""

import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
SOURCES = {
    "rsa_signature_2048_sha256_test.json": "94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393",
    "rsa_signature_2048_sha384_test.json": "c571c105d261c0ff588a2888a529f152563fb3b77894b7620d4e4f8f934f2c1d",
    "rsa_signature_2048_sha512_test.json": "16ea24b039905d054bdb6004f5fd179374e150b7b6d73a7ba654b6d00eab12ef",
    "rsa_signature_3072_sha256_test.json": "0f5f18cabfaad3e2792e82f7e9882f8999049b456714de924b8a5e202f61ca43",
    "rsa_signature_3072_sha384_test.json": "73499ee649d8fb703b3f0f455fa36f7682fde677c590a736958ebce05ab27dae",
    "rsa_signature_3072_sha512_test.json": "09aa3336fdb7be216180ce944ca7b2a052e1de38c210435c19506327d4a36ebd",
    "rsa_signature_4096_sha256_test.json": "957aca128e30bd02c8982f8ca482d6521d16683f4bbc3f193cdfd4c8f04bc667",
    "rsa_signature_4096_sha384_test.json": "bc26f16b9fc9a90628864d3d1111ef48a4bd00b9d4870bfab88ff326e309e073",
    "rsa_signature_4096_sha512_test.json": "9d6e67b1eb0d7040db411835238efd20e9302399a258bdff82de3f38e0f2855a",
    "rsa_pss_2048_sha256_mgf1_32_test.json": "7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c",
    "rsa_pss_2048_sha384_mgf1_48_test.json": "66d464778b0b2f683a1d1a20e94f77e9472b8cc393b45f423fa08a48e677063c",
    "rsa_pss_misc_test.json": "1fac515f67fea8ccbf44ea08fde2de00cd76169f774a54ce2994c9963c31e84f",
}
VALID_ONLY = [name for name in SOURCES if name.startswith("rsa_signature_") and "2048_sha256" not in name]
FULL = [name for name in SOURCES if name not in VALID_ONLY]
HASHES = {"SHA-256": (256, hashlib.sha256), "SHA-384": (384, hashlib.sha384), "SHA-512": (512, hashlib.sha512)}
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rsa-wycheproof.txt")


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
    lines.append("# by rsa-wycheproof.py; see it for the fields and the files in part")
    keys = {}
    skipped = 0
    for name in SOURCES:
        for group in source(directory, name)["testGroups"]:
            if group["sha"] not in HASHES:
                skipped += len(group["tests"])
                continue
            bits, hash = HASHES[group["sha"]]
            if group["type"] == "RsaesPkcs1VerifySchema" or "Pkcs1" in group["type"]:
                kind, ours = "pkcs1", True
            else:
                kind = "pss"
                ours = group["mgf"] == "MGF1" and group["mgfSha"] == group["sha"] and group["sLen"] == bits // 8
            pair = (group["publicKey"]["modulus"], group["publicKey"]["publicExponent"])
            if pair not in keys:
                keys[pair] = len(keys)
                lines.append(f"key {keys[pair]} {pair[0]} {pair[1]}")
            for t in group["tests"]:
                if name in VALID_ONLY and t["result"] == "invalid":
                    continue
                valid = int(t["result"] == "valid" and ours)
                digest = hash(bytes.fromhex(t["msg"])).hexdigest()
                lines.append(f"{kind} {bits} {keys[pair]} {t['tcId']} {valid} {digest} {t['sig'] or '-'}")
    lines.insert(len(SOURCES) + 2, f"# {skipped} cases of SHA-1 and SHA-224 left out")
    return "\n".join(lines) + "\n"


def main():
    args = sys.argv[1:]
    directory = args[args.index("--dir") + 1] if "--dir" in args else None
    out = text(directory)
    if "--check" in args:
        with open(OUT) as f:
            if f.read() != out:
                sys.exit("rsa-wycheproof.txt differs")
        return
    with open(OUT, "w") as f:
        f.write(out)


main()
