#!/usr/bin/env python3
"""Writes ecdsa's p256.rs, p384.rs and p521.rs from curve.rs.in.

rr has no const generics, so each curve has its own copy of the
arithmetic, over numbers of its own limbs: 4 for P-256, 6 for P-384, 9
for P-521. Arithmetic over the widest number for all three would copy
and loop over limbs the narrower curves do not use. curve.rs.in holds
what the copies share; its "//@@ field NAME" and "//@@ tests NAME"
sections, from the end of the shared part on, are each curve's own
multiplication and its tests, put where the shared part says
"//@@ field" and "//@@ tests". This script computes the rest, where it
says "//@@ constants":

- p and n with -m^-1 mod 2^64 and R^2 mod m, R = 2^(64 limbs); P-521's
  p is reduced by its shape, as if R were 1;
- b and R mod p in Montgomery form;
- G, 3G, 5G, ... as affine (x, y) in Montgomery form: 32 points for
  P-256 (u1 in width-7 NAF), 8 for P-384 and P-521 (width 5).

The curve constants are FIPS 186-4's. Constants are one line a number,
under #[rustfmt::skip]: rr fmt would put each limb on a line of its own.

    python3 registry/ecdsa/ecdsa-gen.py           # write the three files
    python3 registry/ecdsa/ecdsa-gen.py --check   # exit 1 if one differs

Run the tests after writing: each file's test constants recomputes its
numbers. rr add does not copy this script or curve.rs.in: ecdsa.json
does not list them.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

CURVES = [
    # name, limbs, bits of n, G's entries, p, n, b, gx, gy
    (
        "P256",
        4,
        256,
        32,
        2**256 - 2**224 + 2**192 + 2**96 - 1,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
    (
        "P384",
        6,
        384,
        8,
        2**384 - 2**128 - 2**96 + 2**32 - 1,
        int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
            "581A0DB248B0A77AECEC196ACCC52973",
            16,
        ),
        int(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
            "C656398D8A2ED19D2A85C8EDD3EC2AEF",
            16,
        ),
        int(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
            "5502F25DBF55296C3A545E3872760AB7",
            16,
        ),
        int(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
            "0A60B1CE1D7E819D7A431D7C90EA0E5F",
            16,
        ),
    ),
    (
        "P521",
        9,
        521,
        8,
        2**521 - 1,
        int(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"
            "51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
            16,
        ),
        int(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
            "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
            16,
        ),
        int(
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBA"
            "A14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
            16,
        ),
        int(
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C"
            "97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
            16,
        ),
    ),
]

DOCS = {
    "P256": "P-256's numbers in four limbs, multiplied with the reduction its\n"
    "//! special prime allows.",
    "P384": "P-384's numbers in six limbs, multiplied and reduced\n"
    "//! (Montgomery) against p as a constant.",
    "P521": "P-521's numbers in nine limbs: p = 2^521 - 1 reduces by adding the\n"
    "//! bits past 521 to those below, so its numbers are plain, with R = 1.",
}


def add(a, b, p):
    """Affine a + b on y^2 = x^3 - 3x + b; neither is infinity or -the other."""
    if a == b:
        slope = 3 * (a[0] * a[0] - 1) * pow(2 * a[1], -1, p) % p
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (slope * slope - a[0] - b[0]) % p
    return (x, (slope * (a[0] - x) - a[1]) % p)


def words(value, count):
    assert 0 <= value < 2 ** (64 * count)
    return "[%s]" % ", ".join("0x%016x" % (value >> (64 * i) & (2**64 - 1)) for i in range(count))


def modulus(name, m, r, count):
    return "\n".join(
        [
            "#[rustfmt::skip]",
            "const %s: Modulus = Modulus {" % name,
            "    m: %s," % words(m, count),
            "    m0inv: 0x%016x," % (-pow(m, -1, 2**64) % 2**64),
            "    rr: %s," % words(r * r % m, count),
            "};",
        ]
    )


def constants(name, count, bits, entries, p, n, b, gx, gy):
    # P-521 reduces mod p by its shape, without Montgomery's R: R is 1.
    r = 1 if name == "P521" else 2 ** (64 * count)
    lines = [
        "// The curve's numbers, from FIPS 186-4's, and the odd multiples of G",
        "// as affine x and y in Montgomery form, which registry/ecdsa/",
        "// ecdsa-gen.py in rr's repository computes.",
        "",
        modulus("P", p, r, count),
        modulus("N", n, 2 ** (64 * count), count),
        "/// b, in Montgomery form.",
        "#[rustfmt::skip]",
        "const B: Fe = %s;" % words(b * r % p, count),
        "/// One in Montgomery form: R mod p.",
        "#[rustfmt::skip]",
        "const ONE: Fe = %s;" % words(r % p, count),
        "",
        "#[rustfmt::skip]",
        "const G: [[Fe; 2]; %d] = [" % entries,
    ]
    g = (gx, gy)
    twice = add(g, g, p)
    point = g
    for _ in range(entries):
        lines.append("    [%s," % words(point[0] * r % p, count))
        lines.append("     %s]," % words(point[1] * r % p, count))
        point = add(point, twice, p)
    lines.append("];")
    return "\n".join(lines)


def sections(template):
    """The shared part, and each curve's sections by their heading."""
    shared, rest = template.split("\n//@@ field P256\n", 1)
    parts = re.split(r"^(//@@ (?:field|tests) P\d+)\n", "//@@ field P256\n" + rest, flags=re.M)
    return shared + "\n", dict(zip(parts[1::2], parts[2::2]))


def render(curve, shared, own):
    name, count, bits, entries, p, n, b, gx, gy = curve
    size = (p.bit_length() + 7) // 8
    point = "04" + "%0*x" % (2 * size, gx) + "%0*x" % (2 * size, gy)
    head = "\n".join(
        [
            "//! %s" % DOCS[name],
            "//!",
            "//! registry/ecdsa/ecdsa-gen.py in rr's repository writes this file",
            "//! from curve.rs.in beside it, which is where to change it.",
            "",
            "use super::{TABLE, mac, width};",
            "",
            "/// The limbs of a number.",
            "const LIMBS: usize = %d;" % count,
            "/// Bytes of a coordinate and of a scalar.",
            "pub(super) const BYTES: usize = %d;" % size,
            "/// Bits of the order n.",
            "const BITS: usize = %d;" % bits,
            "",
            "",
        ]
    )
    tests = own["//@@ tests " + name].rstrip("\n")
    tests = "    /// G, uncompressed and plain.\n    #[rustfmt::skip]\n    const G_POINT: &str = \"%s\";\n\n%s" % (point, tests)
    text = shared
    text = text.replace("//@@ field\n", own["//@@ field " + name])
    text = text.replace("//@@ constants\n", constants(*curve) + "\n")
    text = text.replace("    //@@ tests\n", tests + "\n")
    assert "//@@" not in text, name
    return head + text


def main():
    with open(os.path.join(HERE, "curve.rs.in")) as source:
        shared, own = sections(source.read())
    check = sys.argv[1:] == ["--check"]
    if sys.argv[1:] not in ([], ["--check"]):
        sys.exit("usage: ecdsa-gen.py [--check]")
    differ = False
    for curve in CURVES:
        path = os.path.join(HERE, curve[0].lower() + ".rs")
        text = render(curve, shared, own)
        if check:
            with open(path) as old:
                if old.read() != text:
                    print("ecdsa-gen: %s differs" % path)
                    differ = True
        else:
            with open(path, "w") as out:
                out.write(text)
    if differ:
        sys.exit(1)


main()
