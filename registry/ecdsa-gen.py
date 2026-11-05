#!/usr/bin/env python3
"""Generates the base-point tables P256_G and P384_G of ecdsa.rs.

Each table lists G, 3G, 5G, ... as affine (x, y), each coordinate in
Montgomery form (times R = 2^(64 limbs) mod p) as little-endian 64-bit
limbs: 32 points for P-256 (u1 in width-7 NAF), 8 for P-384 (width 5).
The curve constants are FIPS 186-4's. Each coordinate is one line, under
#[rustfmt::skip]: rr fmt would put each limb on a line of its own.

    python3 registry/ecdsa-gen.py                          # print them
    python3 registry/ecdsa-gen.py --write registry/ecdsa.rs
    python3 registry/ecdsa-gen.py --check registry/ecdsa.rs

--write replaces the two tables in the file, from the #[rustfmt::skip]
of P256_G to the "];" closing P384_G; then run the tests: ecdsa's test
constants recomputes every entry. --check compares instead and exits 1
if they differ. rr add does not copy this script: ecdsa.json
does not list it.
"""

import sys

CURVES = [
    # name, limbs, entries, length constant in ecdsa.rs, p, gx, gy
    (
        "P256",
        4,
        32,
        "BASE_P256",
        2**256 - 2**224 + 2**192 + 2**96 - 1,
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
    (
        "P384",
        6,
        8,
        "TABLE",
        2**384 - 2**128 - 2**96 + 2**32 - 1,
        0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38
        * 2**128
        + 0x5502F25DBF55296C3A545E3872760AB7,
        0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0
        * 2**128
        + 0x0A60B1CE1D7E819D7A431D7C90EA0E5F,
    ),
]


def add(a, b, p):
    """Affine a + b on y^2 = x^3 - 3x + b; neither is infinity or -the other."""
    if a == b:
        slope = 3 * (a[0] * a[0] - 1) * pow(2 * a[1], -1, p) % p
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (slope * slope - a[0] - b[0]) % p
    return (x, (slope * (a[0] - x) - a[1]) % p)


def limbs(value, count):
    return ["0x%016x" % (value >> (64 * i) & (2**64 - 1)) for i in range(count)]


def table(name, count, entries, length, p, gx, gy):
    r = 2 ** (64 * count)
    lines = ["#[rustfmt::skip]", "const %s_G: [[[u64; %d]; 2]; %s] = [" % (name, count, length)]
    g = (gx, gy)
    twice = add(g, g, p)
    point = g
    for _ in range(entries):
        x, y = (", ".join(limbs(c * r % p, count)) for c in point)
        lines.append("    [[%s]," % x)
        lines.append("     [%s]]," % y)
        point = add(point, twice, p)
    lines.append("];")
    return "\n".join(lines) + "\n"


def span(text):
    """Where the two tables are, old layout or new."""
    first = text.index("const P256_G")
    if text[:first].endswith("#[rustfmt::skip]\n"):
        first -= len("#[rustfmt::skip]\n")
    return first, text.index("];\n", text.index("const P384_G")) + 3


def main():
    output = "\n".join(table(*curve) for curve in CURVES)
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        with open(sys.argv[2]) as source:
            text = source.read()
        start, end = span(text)
        if text[start:end] != output:
            print("ecdsa-gen: the tables in %s differ" % sys.argv[2])
            sys.exit(1)
        print("ecdsa-gen: the tables in %s match" % sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "--write":
        with open(sys.argv[2]) as source:
            text = source.read()
        start, end = span(text)
        with open(sys.argv[2], "w") as source:
            source.write(text[:start] + output + text[end:])
    elif len(sys.argv) == 1:
        sys.stdout.write(output)
    else:
        sys.exit("usage: ecdsa-gen.py [--check|--write ecdsa.rs]")


main()
