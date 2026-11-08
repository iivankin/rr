#!/usr/bin/env python3
"""Writes mlkem-tests.txt, the ML-KEM-768 vectors mlkem's tests run, from
Wycheproof (C2SP/wycheproof testvectors_v1) and NIST's ACVP (every
ML-KEM-768 keyGen case, a few of each encapDecap group), pinned:

    W=https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1
    for f in mlkem_768_test mlkem_768_encaps_test mlkem_768_keygen_seed_test \\
        mlkem_768_semi_expanded_decaps_test; do curl -sfLO $W/$f.json; done
    A=https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
    for f in ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203; do
        curl -sfL -o $f-internalProjection.json $A/$f/internalProjection.json; done
    python3 -I registry/mlkem/mlkem-tests.py DIR > registry/mlkem/mlkem-tests.txt
    python3 -I registry/mlkem/mlkem-tests.py DIR --check registry/mlkem/mlkem-tests.txt

Every case of the four Wycheproof files is kept but those whose lengths are wrong
(the API takes arrays: a wrong length does not compile). A key, a
ciphertext and a secret key that the test derives from a seed are not
written out, only the SHA3-256 of each; the script asserts that each
derivation the file relies on holds in the sources: one key per seed,
ciphertexts equal or one byte apart, unreduced keys the reduced key with
q added to each coefficient below 2^12 - q. C2SP/CCTV's unlucky and
strcmp vectors are FIPS 203 ipd's, whose KeyGen lacks the final's
domain separator k: Wycheproof's "Rho leads to frequent rejection" and
Strcmp cases are the final's. rr add does not copy this
script: mlkem.json does not list it.

Lines, hex, after the header:

    kem SEED M EKH DKH CH K   keygen(SEED) has ek and expanded dk of these
                              SHA3-256 (DKH - when unknown); encapsulate(ek,
                              M) gives a ciphertext of SHA3-256 CH and K;
                              decapsulate gives K back
    decaps SEED C K           keygen(SEED) decapsulates C to K
    flip SEED M POS XOR K     the ciphertext of encapsulate(ek, M) with byte
                              POS xored decapsulates to K (rejection)
    unreduced SEED            keygen(SEED)'s ek with q added to every
                              coefficient below 2^12 - q is refused
    base EK                   an ek for the overflow lines
    overflow I V              base with coefficient I set to V is refused
    encaps EK M CH K          encapsulate(EK, M) gives CH and K
    expanded DK C K           the expanded dk decapsulates C to K
    corrupt POS XOR           the last expanded dk with byte POS xored is
                              refused
    keygen SEED EKH DKH       keygen(SEED) has ek and dk of these SHA3-256
    ekcheck EK OK             EK is taken (1) or refused (0)
    dkcheck DK OK             the expanded DK is taken (1) or refused (0)
"""

import hashlib
import json
import os
import sys

WYCHEPROOF = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
ACVP = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCES = {
    "mlkem_768_test.json": "c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90",
    "mlkem_768_encaps_test.json": "9d4381f94c40853bba430245b94968b7390d9175aacd9f1ae4e250a71c78b713",
    "mlkem_768_keygen_seed_test.json": "fde5abe284396f4cb3c4610b90d680f0b57782e94c3365c97aee59e24881ebe4",
    "mlkem_768_semi_expanded_decaps_test.json": "e4438ab7d4dd7b6ace7165e45aeed4403082f981f86300c8369f69d3d071060a",
    "ML-KEM-keyGen-FIPS203-internalProjection.json": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "ML-KEM-encapDecap-FIPS203-internalProjection.json": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
}
Q = 3329
EK = 1184
CT = 1088
DK = 2400


def h(hexstr):
    return hashlib.sha3_256(bytes.fromhex(hexstr)).hexdigest()


def coefficients(ek):
    b = bytes.fromhex(ek)
    out = []
    for i in range(0, 1152, 3):
        d = b[i] | b[i + 1] << 8 | b[i + 2] << 16
        out += [d & 0xFFF, d >> 12]
    return out, b[1152:]


def encode(c, rho):
    out = bytearray()
    for i in range(0, 768, 2):
        x = c[i] | c[i + 1] << 12
        out += bytes([x & 0xFF, x >> 8 & 0xFF, x >> 16])
    return (bytes(out) + rho).hex()


def diff(a, b):
    a, b = bytes.fromhex(a), bytes.fromhex(b)
    assert len(a) == len(b)
    return [(i, x ^ y) for i, (x, y) in enumerate(zip(a, b)) if x != y]


def generate(src):
    header = [
        "# ML-KEM-768 vectors for mlkem's tests, made by mlkem-tests.py from",
        f"# C2SP/wycheproof {WYCHEPROOF} and usnistgov/ACVP-Server {ACVP}:",
    ]
    for name, want in SOURCES.items():
        data = open(os.path.join(src, name), "rb").read()
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            sys.exit(f"{name}: SHA-256 {got}, not the pinned {want}")
        header.append(f"# {name} SHA-256 {got}")
    tests = lambda f: [
        t for g in json.load(open(os.path.join(src, f)))["testGroups"] for t in g["tests"]
    ]
    full = tests("mlkem_768_test.json")
    encaps = tests("mlkem_768_encaps_test.json")
    keygen = tests("mlkem_768_keygen_seed_test.json")
    expanded = tests("mlkem_768_semi_expanded_decaps_test.json")
    lines = []

    # One ek per seed, and its dk where keygen gives it.
    ek_of, dk_of = {}, {}
    for t in keygen + full:
        if len(t["seed"]) == 128 and "ek" in t:
            assert ek_of.setdefault(t["seed"], t["ek"]) == t["ek"]
    for t in keygen:
        dk_of[t["seed"]] = t["dk"]
    seed_of = {ek: s for s, ek in ek_of.items()}

    # Encapsulations of a key from a seed: kem lines, which also cover the
    # same ciphertexts in mlkem_768_test.
    by_c = {}
    done = set()
    for t in encaps:
        if t["result"] != "valid" or t["ek"] not in seed_of:
            continue
        s = seed_of[t["ek"]]
        by_c[t["c"]] = (s, t["m"], t["K"])
        lines.append(
            f"kem {s} {t['m']} {h(t['ek'])} {h(dk_of[s]) if s in dk_of else '-'} {h(t['c'])} {t['K']}"
        )
        done.add(s)
    for s in dk_of:
        assert s in done, "a keygen seed without an encapsulation"
    for t in full:
        if len(t["seed"]) != 128 or len(t["c"]) != 2 * CT:
            assert t["result"] == "invalid"
            continue
        assert t["result"] == "valid"
        s = t["seed"]
        if t["c"] in by_c:
            assert by_c[t["c"]] == (s, by_c[t["c"]][1], t["K"])
            continue
        near = [(c, diff(c, t["c"])) for c, v in by_c.items() if v[0] == s]
        near = [(c, d) for c, d in near if len(d) == 1]
        if near:
            c, [(pos, x)] = near[0]
            lines.append(f"flip {s} {by_c[c][1]} {pos} {x:02x} {t['K']}")
        else:
            lines.append(f"decaps {s} {t['c']} {t['K']}")

    # Keys refused: unreduced versions of a seed's key, single overflows
    # of one key, written once with each overflow's coefficient restored.
    overflows = []
    for t in encaps:
        if t["result"] != "invalid" or len(t["ek"]) != 2 * EK:
            continue
        c, rho = coefficients(t["ek"])
        if "ModulusOverflow" in t["flags"]:
            bad = [(i, v) for i, v in enumerate(c) if v >= Q]
            assert len(bad) == 1
            overflows.append((c, rho, bad[0]))
            continue
        refs = [s for s, ek in ek_of.items() if coefficients(ek)[1] == rho]
        assert len(refs) == 1
        good, _ = coefficients(ek_of[refs[0]])
        assert c == [x + Q if x + Q < 4096 else x for x in good]
        lines.append(f"unreduced {refs[0]}")
    base = [None] * 768
    for c, rho, (i, _) in overflows:
        assert rho == overflows[0][1]
        for j in range(768):
            if j != i:
                assert base[j] in (None, c[j])
                base[j] = c[j]
    assert None not in base
    lines.append(f"base {encode(base, overflows[0][1])}")
    for _, _, (i, v) in overflows:
        lines.append(f"overflow {i} {v}")

    for t in encaps:
        if t["result"] == "valid" and t["ek"] not in seed_of:
            lines.append(f"encaps {t['ek']} {t['m']} {h(t['c'])} {t['K']}")

    last = None
    for t in expanded:
        if len(t["dk"]) != 2 * DK or len(t["c"]) != 2 * CT:
            assert t["result"] == "invalid"
            continue
        if t["result"] == "invalid":
            d = diff(last, t["dk"])
            assert len(d) == 1
            lines.append(f"corrupt {d[0][0]} {d[0][1]:02x}")
            continue
        lines.append(f"expanded {t['dk']} {t['c']} {t['K']}")
        last = t["dk"]

    acvp = lambda f: json.load(open(os.path.join(src, f)))["testGroups"]
    for g in acvp("ML-KEM-keyGen-FIPS203-internalProjection.json"):
        if g["parameterSet"] == "ML-KEM-768":
            for t in g["tests"]:
                lines.append(f"keygen {t['d']}{t['z']} {h(t['ek'])} {h(t['dk'])}".lower())
    for g in acvp("ML-KEM-encapDecap-FIPS203-internalProjection.json"):
        if g["parameterSet"] != "ML-KEM-768":
            continue
        tests = g["tests"]
        kind = g["function"]
        if kind == "encapsulation":
            for t in tests[:3]:
                lines.append(f"encaps {t['ek']} {t['m']} {h(t['c'])} {t['k']}".lower())
            continue
        # One case of each reason the group gives.
        seen = set()
        for t in tests:
            if t["reason"] in seen:
                continue
            seen.add(t["reason"])
            ok = "1" if t.get("testPassed") else "0"
            if kind == "decapsulation":
                lines.append(f"expanded {t['dk']} {t['c']} {t['k']}".lower())
            elif kind == "decapsulationKeyCheck":
                lines.append(f"dkcheck {t['dk']} {ok}".lower())
            else:
                assert kind == "encapsulationKeyCheck"
                lines.append(f"ekcheck {t['ek']} {ok}".lower())

    return "\n".join(header + ["#"] + lines) + "\n"


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--check"):
        sys.exit("usage: mlkem-tests.py DIR [--check FILE]")
    text = generate(sys.argv[1])
    if len(sys.argv) == 4:
        if open(sys.argv[3]).read() != text:
            sys.exit(f"{sys.argv[3]} differs from the sources")
        return
    sys.stdout.write(text)


main()
