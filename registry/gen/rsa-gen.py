#!/usr/bin/env python3
"""Writes rsa's modules bits2048, bits3072, bits4096 and bits8192 in
registry/rsa.rs from modulus.rs.in.

rr has no const generics, so each width of modulus has its own copy of
the arithmetic, over numbers of its own limbs: 32, 48, 64 and 128.
Numbers as wide as 8192 bits for every key would zero and copy limbs a
2048-bit key does not use. The widths are the sizes keys have: of the
Mozilla roots in registry/roots, 59 RSA keys have 4096 bits and 20 have
2048; leaves and intermediates have 2048 most, then 3072 and 4096; 8192
is the largest verify takes. A key between two widths, as one of 2049 bits,
takes the wider, and its arithmetic runs over the limbs it has.

modulus.rs.in is each module but its head, which this script writes: the
documentation, what it uses from the rest of rsa.rs, and LIMBS. Where
every modulus a module takes has LIMBS limbs, as in bits2048, which
takes 2048-bit moduli only, the limbs are a constant the compiler
unrolls loops over.

    python3 registry/gen/rsa-gen.py           # write the four modules
    python3 registry/gen/rsa-gen.py --check   # exit 1 if one differs

rr fmt formats them (splice.py). rr add does not copy this script or
modulus.rs.in: they are not in rsa.rs's header.
"""

import os
import sys

from splice import splice

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
            "//! registry/gen/rsa-gen.py in rr's repository writes this module",
            "//! from gen/modulus.rs.in beside it, which is where to change it.",
            "",
            "use super::{",
            "    Column, Encoding, Error, Key, MODULUS_BITS_MIN, below, load, low, negative_inverse, shift_left,",
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
    if sys.argv[1:] not in ([], ["--check"]):
        sys.exit("usage: rsa-gen.py [--check]")
    with open(os.path.join(HERE, "modulus.rs.in")) as source:
        body = source.read()
    modules = {"bits%d" % bits: render(bits, body) for bits in WIDTHS}
    splice("rsa.rs", modules, sys.argv[1:] == ["--check"])


main()
