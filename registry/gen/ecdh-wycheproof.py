#!/usr/bin/env python3
"""Writes ecdh-wycheproof.txt, the Wycheproof P-256 ECDH cases ecdh's
tests run, from C2SP/wycheproof's testvectors_v1 at one commit.

    python3 -I registry/gen/ecdh-wycheproof.py COMMIT \
        ecdh_secp256r1_ecpoint_test.json ecdh_secp256r1_test.json \
        KAS_ECC_CDH_PrimitiveTest.txt > registry/ecdh-wycheproof.txt

The last file is NIST CAVP's ECC CDH primitive vectors (from
ecccdhtestvectors.zip); its P-256 cases follow Wycheproof's, as
"cCOUNT v private peer shared public", with the private key's public key.

Every case of the ecpoint file is kept: the peer's key there is a SEC 1
point, as TLS 1.3's key share carries it. From the file whose keys are
SubjectPublicKeyInfo, the cases whose key names another curve
(WrongCurve) are kept with their bare point, which ecdh must refuse; the
rest are the ecpoint file's points again, or keys with explicit curve
parameters, which a TLS key share cannot carry. tcIds are the file's own:
the two files number their cases apart.

Each case is one line, "tcId result private public shared": result is
v (valid), i (invalid) or a (acceptable: either, but a secret must be the
right one); private is 32 bytes; public and shared are hex, "-" when
empty. Lines starting with # are comments. rr add does not copy this
script: it is not in ecdh.rs's header.
"""

import hashlib
import json
import sys

P256_OID = "2a8648ce3d030107"
EC_PUBLIC_KEY_OID = "2a8648ce3d0201"


def der(data, at):
    """The tag, contents and end of the DER element at offset at, or None."""
    if at + 2 > len(data):
        return None
    tag = data[at]
    length = data[at + 1]
    at += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 2 or at + count > len(data):
            return None
        length = int.from_bytes(data[at : at + count], "big")
        at += count
    if at + length > len(data):
        return None
    return tag, data[at : at + length], at + length


def spki(data):
    """The named curve's OID and the point of a well-formed EC key, or None."""
    outer = der(data, 0)
    if outer is None or outer[0] != 0x30 or outer[2] != len(data):
        return None
    body = outer[1]
    algorithm = der(body, 0)
    if algorithm is None or algorithm[0] != 0x30:
        return None
    bits = der(body, algorithm[2])
    if bits is None or bits[0] != 0x03 or bits[2] != len(body):
        return None
    oid = der(algorithm[1], 0)
    if oid is None or oid[0] != 0x06 or oid[1].hex() != EC_PUBLIC_KEY_OID:
        return None
    curve = der(algorithm[1], oid[2])
    if curve is None or curve[0] != 0x06 or curve[2] != len(algorithm[1]):
        return None
    if not bits[1] or bits[1][0] != 0:
        return None
    return curve[1].hex(), bits[1][1:].hex()


def scalar(text):
    """The private key as 32 bytes: Wycheproof writes it as an INTEGER's
    contents, with a leading zero or short."""
    return int(text, 16).to_bytes(32, "big").hex()


def line(test, public):
    result = {"valid": "v", "invalid": "i", "acceptable": "a"}[test["result"]]
    return "%d %s %s %s %s" % (
        test["tcId"],
        result,
        scalar(test["private"]),
        public or "-",
        test["shared"] or "-",
    )


def cavp(text):
    """The P-256 section's cases as lines."""
    lines = []
    case = {}
    section = None
    for row in text.splitlines():
        row = row.strip()
        if row.startswith("["):
            section = row
        elif section == "[P-256]" and " = " in row:
            key, value = row.split(" = ")
            case[key] = value
            if key == "ZIUT":
                lines.append(
                    "c%s v %s 04%s%s %s 04%s%s"
                    % (
                        case["COUNT"],
                        scalar(case["dIUT"]),
                        case["QCAVSx"],
                        case["QCAVSy"],
                        case["ZIUT"],
                        case["QIUTx"],
                        case["QIUTy"],
                    )
                )
                case = {}
    if len(lines) != 25:
        sys.exit("CAVP: %d P-256 cases, not 25" % len(lines))
    return lines


def main():
    if len(sys.argv) != 5:
        sys.exit("usage: ecdh-wycheproof.py COMMIT ECPOINT_JSON ASN_JSON CAVP_TXT")
    commit, ecpoint_path, asn_path, cavp_path = sys.argv[1:]
    raw = [open(path, "rb").read() for path in (ecpoint_path, asn_path, cavp_path)]
    ecpoint, asn = [json.loads(data) for data in raw[:2]]
    out = [
        "# Wycheproof (github.com/C2SP/wycheproof) at %s, Apache 2.0." % commit,
        "# Written by ecdh-wycheproof.py; tcId result private peer shared [public].",
    ]
    for path, data in zip((ecpoint_path, asn_path, cavp_path), raw):
        name = path.rsplit("/", 1)[-1]
        out.append("# %s sha256 %s" % (name, hashlib.sha256(data).hexdigest()))
    out.append("# ecdh_secp256r1_ecpoint_test")
    for group in ecpoint["testGroups"]:
        for test in group["tests"]:
            out.append(line(test, test["public"]))
    out.append("# ecdh_secp256r1_test: keys of other named curves")
    for group in asn["testGroups"]:
        for test in group["tests"]:
            if "WrongCurve" not in test["flags"]:
                continue
            key = spki(bytes.fromhex(test["public"]))
            if key is None:
                sys.exit("tcId %d: not a named curve's key" % test["tcId"])
            # P-256's own are compressed, the ecpoint file's again.
            if key[0] == P256_OID:
                continue
            if test["result"] != "invalid":
                sys.exit("tcId %d: another curve's key is not invalid" % test["tcId"])
            out.append(line(test, key[1]))
    out.append("# NIST CAVP KAS ECC CDH primitive, P-256")
    out.extend(cavp(raw[2].decode()))
    print("\n".join(out))


main()
