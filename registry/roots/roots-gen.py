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

Chrome's distrusts of roots Mozilla still trusts are applied too, from
Google's announcements (CHROME below), the earlier date winning: Chrome
judges by a certificate's earliest SCT, which x509 does not read, so the
leaf's notBefore stands for it, as for Mozilla's dates. Chrome's root
store also sunsets old roots for its newest versions; those are its
own policy for its own store, and are left out.

certdata.txt rather than CCADB's CSV report: it is what Firefox ships,
it is versioned by NSS's release tags, so --check reproduces the file
from a fixed input, and its trust records are the ones NSS applies.

revoked.txt is Mozilla's OneCRL, the certificates Firefox refuses
wherever they are on a path: intermediates revoked, cross-certificates
withdrawn, and since NSS 3.116 the roots certdata.txt used to mark
CKT_NSS_NOT_TRUSTED (DigiNotar and the like). Firefox applies every
record of the collection, enabled or not, by issuer and serial number or
by subject and the SHA-256 of the key; each becomes one line, the hex
SHA-256 of

    01 || issuer DER || serial INTEGER contents
    02 || subject DER || SHA-256(SubjectPublicKeyInfo)

which x509::Store::add_revoked reads. OneCRL is not versioned: the
header names the collection's timestamp and the SHA-256 of what came,
and --check tells whether the file is today's.

    python3 roots-gen.py --onecrl FILE      # from a saved records JSON
"""

import argparse
import base64
import hashlib
import os
import sys
import urllib.request

TAG = "NSS_3_133_RTM"
URL = "https://hg.mozilla.org/projects/nss/raw-file/{tag}/lib/ckfw/builtins/certdata.txt"
ONECRL = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records"
HERE = os.path.dirname(os.path.abspath(__file__))

# Roots Chrome distrusts for certificates whose earliest SCT is after the
# date, by the SHA-256 of their DER: Chrome 139 and later, announced
# 2025-05-30 at
# https://blog.google/security/sustaining-digital-certificate-security-chrome-root-store-changes/
CHROME = {
    # OU=ePKI Root Certification Authority, O=Chunghwa Telecom Co., Ltd.
    "c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5": "2025-07-31T23:59:59Z",
    # CN=HiPKI Root CA - G1, O=Chunghwa Telecom Co., Ltd.
    "f015ce3cc239bfef064be9f1d2c417e1a0264a0a94be1f0c8d121864eb6949cc": "2025-07-31T23:59:59Z",
    # CN=NetLock Arany (Class Gold) Főtanúsítvány, O=NetLock Kft.
    "6c61dac3a2def031506be036d2a6fe401994fbd13df9c8d466599274c446ec98": "2025-07-31T23:59:59Z",
}


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
        "which a leaf's notBefore makes a path to that root fail, Mozilla's",
        "or Chrome's, whichever is earlier.",
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
        dates = [iso(distrust[1])] if distrust[0] == "MULTILINE_OCTAL" else []
        chrome = CHROME.get(hashlib.sha256(item["CKA_VALUE"][1]).hexdigest())
        if chrome:
            dates.append(chrome)
        if dates:
            # RFC 3339 times of one form sort as they come.
            out.append("# distrust-after: " + min(dates))
        encoded = base64.b64encode(item["CKA_VALUE"][1]).decode("ascii")
        out.append("-----BEGIN CERTIFICATE-----")
        out.extend(encoded[i : i + 64] for i in range(0, len(encoded), 64))
        out.append("-----END CERTIFICATE-----")
        out.append("")
        count += 1
    return "\n".join(out), count


def revoked(text):
    """revoked.txt's text from OneCRL's records JSON, and its count."""
    import json

    records = json.loads(text)["data"]
    digests = set()
    for record in records:
        if record.get("issuerName") and record.get("serialNumber"):
            name = base64.b64decode(record["issuerName"])
            other = base64.b64decode(record["serialNumber"])
            kind = b"\x01"
        elif record.get("subject") and record.get("pubKeyHash"):
            name = base64.b64decode(record["subject"])
            other = base64.b64decode(record["pubKeyHash"])
            kind = b"\x02"
        else:
            sys.exit("roots-gen: a OneCRL record of no kind: %r" % record.get("id"))
        if name[:1] != b"\x30" or (kind == b"\x02" and len(other) != 32):
            sys.exit("roots-gen: an odd OneCRL record: %r" % record.get("id"))
        digests.add(hashlib.sha256(kind + name + other).hexdigest())
    stamp = max((record["last_modified"] for record in records), default=0)
    out = [
        "# Mozilla's OneCRL, made by roots-gen.py from",
        "# " + ONECRL,
        "# at timestamp %d, SHA-256 %s." % (stamp, hashlib.sha256(text.encode("utf-8")).hexdigest()),
        "#",
        "# One certificate a line: the SHA-256 of 01, its issuer's DER and its",
        "# serial number's INTEGER contents, or of 02, its subject's DER and",
        "# the SHA-256 of its SubjectPublicKeyInfo.",
    ]
    out.extend(sorted(digests))
    return "\n".join(out) + "\n", len(digests)


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
    parser.add_argument("--onecrl", help="a saved OneCRL records JSON")
    args = parser.parse_args()
    if args.certdata:
        with open(args.certdata, encoding="utf-8") as f:
            text = f.read()
    else:
        with urllib.request.urlopen(URL.format(tag=args.tag)) as response:
            text = response.read().decode("utf-8")
    pem, count = build(text, args.tag)
    if args.onecrl:
        with open(args.onecrl, encoding="utf-8") as f:
            records = f.read()
    else:
        with urllib.request.urlopen(ONECRL) as response:
            records = response.read().decode("utf-8")
    listed, revocations = revoked(records)
    out_revoked = os.path.join(os.path.dirname(args.out), "revoked.txt")
    if args.check:
        with open(args.out, encoding="utf-8") as f:
            if f.read() != pem:
                sys.exit("roots-gen: %s differs from %s" % (args.out, args.tag))
        with open(out_revoked, encoding="utf-8") as f:
            if f.read() != listed:
                sys.exit("roots-gen: %s differs from OneCRL now" % out_revoked)
        print("roots-gen: %s is %s's %d roots, %s OneCRL's %d" % (args.out, args.tag, count, out_revoked, revocations))
        return
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(pem)
    with open(out_revoked, "w", encoding="utf-8") as f:
        f.write(listed)
    print("roots-gen: wrote %d roots to %s, %d revocations to %s" % (count, args.out, revocations, out_revoked))


if __name__ == "__main__":
    main()
