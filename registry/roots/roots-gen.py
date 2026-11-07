#!/usr/bin/env python3
"""Builds roots.pem from Mozilla's NSS certdata.txt at a release tag.

    python3 roots-gen.py                    # fetch the tag, write roots.pem
    python3 roots-gen.py --check            # roots.pem is what the tag gives
    python3 roots-gen.py --tag NSS_3_134_RTM --certdata FILE

Kept: the certificates NSS trusts to issue TLS server certificates
(CKA_TRUST_SERVER_AUTH CKT_NSS_TRUSTED_DELEGATOR). A root that Mozilla
distrusts for certificates issued after a date
(CKA_NSS_SERVER_DISTRUST_AFTER) carries a line

    # distrust-after: 2024-11-30T23:59:59Z

before its PEM block, which x509::Store::add_pem reads: a path ending at
it fails when the leaf's notBefore is later. curl's cacert.pem leaves
those dates out and so trusts such roots fully.

certdata.txt rather than CCADB's CSV report: it is what Firefox ships,
it is versioned by NSS's release tags, so --check reproduces the file
from a fixed input, and its trust records are the ones NSS applies.
"""

import argparse
import base64
import hashlib
import os
import sys
import urllib.request

TAG = "NSS_3_133_RTM"
URL = "https://hg.mozilla.org/projects/nss/raw-file/{tag}/lib/ckfw/builtins/certdata.txt"
HERE = os.path.dirname(os.path.abspath(__file__))


def objects(text):
    """certdata.txt's objects, each a dict of attribute to (type, value);
    MULTILINE_OCTAL values become bytes."""
    found, current, lines = [], None, iter(text.splitlines())
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ", 2)
        if parts[0] == "CKA_CLASS":
            current = {}
            found.append(current)
        if current is None or not parts[0].startswith("CKA_"):
            continue
        kind = parts[1] if len(parts) > 1 else ""
        if kind == "MULTILINE_OCTAL":
            data = bytearray()
            for octal in lines:
                if octal == "END":
                    break
                data += bytes(int(digits, 8) for digits in octal.split("\\")[1:])
            current[parts[0]] = (kind, bytes(data))
        else:
            current[parts[0]] = (kind, parts[2] if len(parts) > 2 else "")
    return found


def iso(der_time):
    """UTCTime or GeneralizedTime digits as RFC 3339."""
    text = der_time.decode("ascii")
    if len(text) == 13:
        year = int(text[:2])
        text = ("20" if year < 50 else "19") + text
    if len(text) != 15 or not text.endswith("Z"):
        sys.exit("roots-gen: odd distrust-after %r" % der_time)
    return "%s-%s-%sT%s:%s:%sZ" % (text[0:4], text[4:6], text[6:8], text[8:10], text[10:12], text[12:14])


def build(text, tag):
    found = objects(text)
    trusted = set()
    for item in found:
        if item.get("CKA_CLASS", ("", ""))[1] != "CKO_NSS_TRUST":
            continue
        if item.get("CKA_TRUST_SERVER_AUTH", ("", ""))[1] == "CKT_NSS_TRUSTED_DELEGATOR":
            trusted.add((item["CKA_ISSUER"][1], item["CKA_SERIAL_NUMBER"][1]))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    out = [
        "Mozilla's trust anchors for TLS servers, made by roots-gen.py from",
        "NSS's lib/ckfw/builtins/certdata.txt at " + tag + ",",
        URL.format(tag=tag),
        "SHA-256 " + digest + ".",
        "",
        "The data is Mozilla's, under the Mozilla Public License 2.0",
        "(http://mozilla.org/MPL/2.0/). Kept: the roots NSS trusts to issue",
        "TLS server certificates; a distrust-after line gives the time after",
        "which a leaf's notBefore makes a path to that root fail.",
        "",
    ]
    count = 0
    for item in found:
        if item.get("CKA_CLASS", ("", ""))[1] != "CKO_CERTIFICATE":
            continue
        if (item["CKA_ISSUER"][1], item["CKA_SERIAL_NUMBER"][1]) not in trusted:
            continue
        label = item["CKA_LABEL"][1].strip('"')
        out.append(label)
        out.append("=" * len(label))
        distrust = item.get("CKA_NSS_SERVER_DISTRUST_AFTER", ("", ""))
        if distrust[0] == "MULTILINE_OCTAL":
            out.append("# distrust-after: " + iso(distrust[1]))
        encoded = base64.b64encode(item["CKA_VALUE"][1]).decode("ascii")
        out.append("-----BEGIN CERTIFICATE-----")
        out.extend(encoded[i : i + 64] for i in range(0, len(encoded), 64))
        out.append("-----END CERTIFICATE-----")
        out.append("")
        count += 1
    return "\n".join(out), count


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tag", default=TAG, help="NSS release tag (%(default)s)")
    parser.add_argument("--certdata", help="a local certdata.txt of that tag")
    # Beside the script in rr's registry; in a project, scripts/ beside
    # src/, which has it in base/roots/.
    beside = os.path.join(HERE, "roots.pem")
    default = beside if os.path.exists(beside) else os.path.join(HERE, "..", "src", "base", "roots", "roots.pem")
    parser.add_argument("--out", default=default)
    parser.add_argument("--check", action="store_true", help="compare, do not write")
    args = parser.parse_args()
    if args.certdata:
        with open(args.certdata, encoding="utf-8") as f:
            text = f.read()
    else:
        with urllib.request.urlopen(URL.format(tag=args.tag)) as response:
            text = response.read().decode("utf-8")
    pem, count = build(text, args.tag)
    if args.check:
        with open(args.out, encoding="utf-8") as f:
            if f.read() != pem:
                sys.exit("roots-gen: %s differs from %s" % (args.out, args.tag))
        print("roots-gen: %s is %s's %d roots" % (args.out, args.tag, count))
        return
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(pem)
    print("roots-gen: wrote %d roots to %s" % (count, args.out))


if __name__ == "__main__":
    main()
