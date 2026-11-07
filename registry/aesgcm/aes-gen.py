#!/usr/bin/env python3
"""Writes the asm! body of aarch64's eight-block GCM turn in aesgcm/sys.rs.

    python3 registry/aesgcm/aes-gen.py [LATE] [--write]

The turn runs eight AES-128 chains (states v11-v18, round keys v0-v10)
and the GHASH of eight blocks (v19-v28 scratch, y in v29, the counter
base in v30, 0x87 in v31). LATE says where the GHASH steps go: spread
between the last LATE of the eight middle rounds. Each AESE stays beside
its AESMC, which Apple's cores fuse.

Chosen: LATE = 4. 16 KiB / 64 KiB seal on an M4 Pro, by LATE: 2 1469 /
5770 ns, 3 1466 / 5800, 4 1443 / 5700, 5 1454 / 5699, 6 1459 / 5763, 8
(every round) 1510 / 5944; all GHASH before the rounds 1548 / 6104, all
after them 1473 / 5786.

Without --write the lines are printed; with it they replace the body of
the asm! in fn turns of sys.rs beside this file. Run rr fmt after.
"""

import os
import sys

STATES = list(range(11, 19))


def aes_round(r):
    out = []
    for s in STATES:
        out += [f"aese v{s}.16b, v{r}.16b", f"aesmc v{s}.16b, v{s}.16b"]
    return out


def counters_and_round0():
    """Counter blocks: the base with the big-endian counter in lane 3."""
    out = []
    for j, s in enumerate(STATES):
        t = "t0" if j % 2 == 0 else "t1"
        out += [
            f"add {{{t}:w}}, {{c:w}}, #{j}",
            f"rev {{{t}:w}}, {{{t}:w}}",
            f"mov v{s}.16b, v30.16b",
            f"mov v{s}.s[3], {{{t}:w}}",
            f"aese v{s}.16b, v0.16b",
            f"aesmc v{s}.16b, v{s}.16b",
        ]
    return out


def ghash():
    """Eight blocks at g times H^8..H (Karatsuba), then one reduction.

    The table holds H^1..H^8 at 0..112 and their halves at 128..240.
    Accumulators: v23 low, v24 middle, v25 high.
    """
    out = []
    for pair in range(4):
        for j in (2 * pair, 2 * pair + 1):
            first = j % 2 == 0
            out += [
                f"ldr q19, [{{g}}, #{16 * j}]",
                f"ldr q21, [{{tbl}}, #{16 * (7 - j)}]",
                f"ldr q22, [{{tbl}}, #{128 + 16 * (7 - j)}]",
                "rbit v19.16b, v19.16b",
            ]
            if j == 0:
                out.append("eor v19.16b, v19.16b, v29.16b")
            out += [
                "ext v20.16b, v19.16b, v19.16b, #8",
                "eor v20.16b, v20.16b, v19.16b",
            ]
            if first:
                out += [
                    "pmull v26.1q, v19.1d, v21.1d",
                    "pmull2 v27.1q, v19.2d, v21.2d",
                    "pmull v28.1q, v20.1d, v22.1d",
                ]
            else:
                out += [
                    "pmull v22.1q, v20.1d, v22.1d",
                    "pmull v20.1q, v19.1d, v21.1d",
                    "pmull2 v21.1q, v19.2d, v21.2d",
                ]
        if pair == 0:
            out += [
                "eor v23.16b, v26.16b, v20.16b",
                "eor v25.16b, v27.16b, v21.16b",
                "eor v24.16b, v28.16b, v22.16b",
            ]
        else:
            out += [
                "eor3 v23.16b, v23.16b, v26.16b, v20.16b",
                "eor3 v25.16b, v25.16b, v27.16b, v21.16b",
                "eor3 v24.16b, v24.16b, v28.16b, v22.16b",
            ]
    # The middle to its place, then hi * x^128 = hi * 0x87 into lo, and
    # that product's own overflow once more.
    out += [
        "eor3 v24.16b, v24.16b, v23.16b, v25.16b",
        "movi v19.2d, #0",
        "ext v20.16b, v19.16b, v24.16b, #8",
        "ext v21.16b, v24.16b, v19.16b, #8",
        "eor v23.16b, v23.16b, v20.16b",
        "eor v25.16b, v25.16b, v21.16b",
        "pmull v20.1q, v25.1d, v31.1d",
        "pmull2 v21.1q, v25.2d, v31.2d",
        "pmull2 v22.1q, v21.2d, v31.2d",
        "ext v26.16b, v19.16b, v21.16b, #8",
        "eor3 v23.16b, v23.16b, v20.16b, v26.16b",
        "eor v29.16b, v23.16b, v22.16b",
    ]
    return out


def body(late):
    gh = ghash()
    out = ["2:"] + counters_and_round0()
    step = -(-len(gh) // late)
    for r in range(1, 9):
        out += aes_round(r)
        i = r - (9 - late)
        if i >= 0:
            out += gh[i * step:(i + 1) * step]
    out += [
        "ldp q19, q20, [{p}]",
        "ldp q21, q22, [{p}, #32]",
        "ldp q23, q24, [{p}, #64]",
        "ldp q25, q26, [{p}, #96]",
    ]
    for i, s in enumerate(STATES):
        out += [
            f"aese v{s}.16b, v9.16b",
            f"eor3 v{s}.16b, v{s}.16b, v10.16b, v{19 + i}.16b",
        ]
    out += [
        "stp q11, q12, [{p}]",
        "stp q13, q14, [{p}, #32]",
        "stp q15, q16, [{p}, #64]",
        "stp q17, q18, [{p}, #96]",
        "add {p}, {p}, #128",
        "add {g}, {g}, #128",
        "add {c:w}, {c:w}, #8",
        "subs {n}, {n}, #1",
        "b.ne 2b",
    ]
    return out


def lines(late):
    prologue = [
        "ld1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{rk}], #64",
        "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{rk}], #64",
        "ld1 {{v8.16b, v9.16b, v10.16b}}, [{rk}]",
        "mov {t0}, #0x87",
        "dup v31.2d, {t0}",
    ]
    return "".join(f'                "{l}",\n' for l in prologue + body(late))


def write(text):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sys.rs")
    with open(path) as f:
        s = f.read()
    start = s.index("core::arch::asm!(\n", s.index("fn turns(")) + len("core::arch::asm!(\n")
    end = s.rindex("\n", 0, s.index("rk = inout(reg)", start)) + 1
    with open(path, "w") as f:
        f.write(s[:start] + text + s[end:])


def main():
    args = [a for a in sys.argv[1:] if a != "--write"]
    text = lines(int(args[0]) if args else 4)
    if "--write" in sys.argv:
        write(text)
    else:
        sys.stdout.write(text)


main()
