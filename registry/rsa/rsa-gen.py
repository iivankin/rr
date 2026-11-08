#!/usr/bin/env python3
"""Writes rsa's bits2048.rs, bits3072.rs, bits4096.rs and bits8192.rs
from modulus.rs.in.

rr has no const generics, so each width of modulus has its own copy of
the arithmetic, over numbers of its own limbs: 32, 48, 64 and 128.
Numbers as wide as 8192 bits for every key would zero and copy limbs a
2048-bit key does not use. The widths are the sizes keys have: of the
Mozilla roots in registry/roots, 59 RSA keys have 4096 bits and 20 have
2048; leaves and intermediates have 2048 most, then 3072 and 4096; 8192
is the largest verify takes. A key between two widths, as one of 2049 bits,
takes the wider, and its arithmetic runs over the limbs it has.

modulus.rs.in is each file but its head, which this script writes: the
documentation, what it uses from mod.rs, and LIMBS. Where every modulus
a file takes has LIMBS limbs, as in bits2048.rs, which takes 2048-bit
moduli only, the limbs are a constant the compiler unrolls loops over.

    python3 registry/rsa/rsa-gen.py           # write the four files
    python3 registry/rsa/rsa-gen.py --check   # exit 1 if one differs

rr add does not copy this script or modulus.rs.in: rsa.json does not
list them.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Bits of the widest modulus of each file.
WIDTHS = [2048, 3072, 4096, 8192]


def render(bits, body):
    head = "\n".join(
        [
            "//! The arithmetic of moduli of up to %d bits, in numbers of %d"
            % (bits, bits // 64),
            "//! limbs.",
            "//!",
            "//! registry/rsa/rsa-gen.py in rr's repository writes this file",
            "//! from modulus.rs.in beside it, which is where to change it.",
            "",
            "use super::{",
            "    Column, Encoding, Key, MODULUS_BITS_MIN, below, load, low, negative_inverse, shift_left,",
            "    shift_right, subtract,",
            "};",
            "",
            "/// The limbs of the widest modulus.",
            "pub(super) const LIMBS: usize = %d;" % (bits // 64),
            "",
            "",
        ]
    )
    return head + body


def main():
    check = sys.argv[1:] == ["--check"]
    if sys.argv[1:] not in ([], ["--check"]):
        sys.exit("usage: rsa-gen.py [--check]")
    with open(os.path.join(HERE, "modulus.rs.in")) as source:
        body = source.read()
    differ = False
    for bits in WIDTHS:
        path = os.path.join(HERE, "bits%d.rs" % bits)
        text = render(bits, body)
        if check:
            with open(path) as old:
                if old.read() != text:
                    print("rsa-gen: %s differs" % path)
                    differ = True
        else:
            with open(path, "w") as out:
                out.write(text)
    if differ:
        sys.exit(1)


main()
