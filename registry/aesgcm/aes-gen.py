#!/usr/bin/env python3
"""Writes the asm! bodies of aarch64's eight-block GCM turns in
aesgcm/sys.rs, AES-128's and AES-256's.

    python3 registry/aesgcm/aes-gen.py [128|256 [LATE]] [--write]

A turn runs eight AES chains (states v11-v18) and the GHASH of eight
blocks (scratch from v19 on, y in v29, 0x87 or 0x86 in v31). LATE says
where the GHASH steps go: spread between the last LATE of the middle
rounds. Each AESE stays beside its AESMC, which Apple's cores fuse.

AES-128: the 11 round keys stay in v0-v10, the counter base in v30.

Chosen: LATE = 4. 16 KiB / 64 KiB seal on an M4 Pro, by LATE: 2 1469 /
5770 ns, 3 1466 / 5800, 4 1443 / 5700, 5 1454 / 5699, 6 1459 / 5763, 8
(every round) 1510 / 5944; all GHASH before the rounds 1548 / 6104, all
after them 1473 / 5786.

AES-256: 15 round keys do not fit beside the states and the GHASH. As
OpenSSL's unroll8 kernels do, which load every round key and power of H
again each turn into three registers, some keys are loaded each turn:
v0-v10 keep k0 and k5-k14 (the last two rounds' in v9 and v10, as
AES-128's), and k1-k4 are loaded into v19-v22 at the top of the turn,
registers the GHASH takes only after round 4. Every vector unit is busy
here (four a cycle: AES pairs, PMULL, EOR3 alike), so the turn is cut in
vector instructions, not in registers:

- the counter blocks are made in general registers and stored to a
  buffer of the caller, then loaded: no MOV and INS a block;
- a pair of blocks shares one XOR of halves for Karatsuba (TRN1, TRN2,
  EOR, as OpenSSL does) instead of an EXT and an EOR each;
- the reduction is seven instructions, not twelve: x^128 = 1 + 0x86, the
  1 a swap of halves (EXT), so the high half folds into the middle and
  the middle into the low with an EXT and a PMULL2 by 0x86 each.

184 vector instructions a turn (an AESE and its AESMC counted once),
against 209 in AES-128's way.
Chosen: LATE = 3. 16 KiB seal, by LATE (two runs): 2 1621 / 1594 ns, 3
1607 / 1600, 4 1608 / 1619, 5 1627 / 1627, 6 1624 / 1634, 7 1646 /
1637, 8 1626 / 1646, 9 1629; the intrinsics 1700.

Without --write the lines of one turn are printed (AES-128's by
default); with it both bodies replace those of the asm! blocks in fn
turns of sys.rs beside this file, AES-128's first. Run rr fmt after.
"""

import os
import sys

STATES = list(range(11, 19))


def aes_round(k):
    out = []
    for s in STATES:
        out += [f"aese v{s}.16b, {k}.16b", f"aesmc v{s}.16b, v{s}.16b"]
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
    """AES-128's turn."""
    gh = ghash()
    out = ["2:"] + counters_and_round0()
    step = -(-len(gh) // late)
    for r in range(1, 9):
        out += aes_round(f"v{r}")
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
    return out + tail()


def tail():
    return [
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


def counters_and_round0_256():
    """Counter blocks built in general registers and stored to ctrs,
    then loaded: no vector instruction to make them."""
    out = []
    for j in range(8):
        t = "t0" if j % 2 == 0 else "t1"
        out += [
            f"add {{{t}:w}}, {{c:w}}, #{j}",
            f"rev {{{t}:w}}, {{{t}:w}}",
            f"orr {{{t}}}, {{bh}}, {{{t}}}, lsl #32",
            f"stp {{bl}}, {{{t}}}, [{{ctrs}}, #{16 * j}]",
        ]
    for j, s in enumerate(STATES):
        out += [
            f"ldr q{s}, [{{ctrs}}, #{16 * j}]",
            f"aese v{s}.16b, v0.16b",
            f"aesmc v{s}.16b, v{s}.16b",
        ]
    return out


def ghash256():
    """ghash() in fewer instructions: a pair of blocks shares the XOR of
    halves (TRN1, TRN2, EOR, as OpenSSL's unroll8 does), and the
    reduction folds hi, then the middle, each with one EXT and one PMULL2
    by 0x86 (x^128 = 1 + 0x86, the 1 a swap of halves).

    Scratch v19-v26; accumulators: v27 low, v28 high, v30 middle.
    """
    out = []
    for pair in range(4):
        j = 2 * pair
        out += [
            f"ldp q19, q20, [{{g}}, #{16 * j}]",
            f"ldp q22, q21, [{{tbl}}, #{16 * (6 - j)}]",
            f"ldp q24, q23, [{{tbl}}, #{128 + 16 * (6 - j)}]",
            "rbit v19.16b, v19.16b",
            "rbit v20.16b, v20.16b",
        ]
        if pair == 0:
            out.append("eor v19.16b, v19.16b, v29.16b")
        out += [
            "trn1 v25.2d, v19.2d, v20.2d",
            "trn2 v26.2d, v19.2d, v20.2d",
            "eor v25.16b, v25.16b, v26.16b",
            "pmull v26.1q, v19.1d, v21.1d",
            "pmull2 v19.1q, v19.2d, v21.2d",
            "pmull v21.1q, v20.1d, v22.1d",
            "pmull2 v20.1q, v20.2d, v22.2d",
            "pmull v22.1q, v25.1d, v23.1d",
            "pmull2 v25.1q, v25.2d, v24.2d",
        ]
        if pair == 0:
            out += [
                "eor v27.16b, v26.16b, v21.16b",
                "eor v28.16b, v19.16b, v20.16b",
                "eor v30.16b, v22.16b, v25.16b",
            ]
        else:
            out += [
                "eor3 v27.16b, v27.16b, v26.16b, v21.16b",
                "eor3 v28.16b, v28.16b, v19.16b, v20.16b",
                "eor3 v30.16b, v30.16b, v22.16b, v25.16b",
            ]
    # The middle to its place; hi * x^128 = (h1 + h0 x^64 + h1 * 0x86)
    # x^64 into the middle, then the middle's high half the same way.
    out += [
        "eor3 v30.16b, v30.16b, v27.16b, v28.16b",
        "ext v19.16b, v28.16b, v28.16b, #8",
        "pmull2 v20.1q, v28.2d, v31.2d",
        "eor3 v30.16b, v30.16b, v19.16b, v20.16b",
        "ext v19.16b, v30.16b, v30.16b, #8",
        "pmull2 v20.1q, v30.2d, v31.2d",
        "eor3 v29.16b, v27.16b, v19.16b, v20.16b",
    ]
    return out


# Where each of AES-256's round keys is during a turn.
KEYS256 = ["v0", "v19", "v20", "v21", "v22"] + [f"v{r}" for r in range(1, 11)]


def body256(late):
    """AES-256's turn: k1-k4 loaded again into v19-v22 for rounds 1-4,
    then the GHASH takes those registers."""
    assert 1 <= late <= 9
    gh = ghash256()
    out = [
        "2:",
        "ldp q19, q20, [{rk}, #-192]",
        "ldp q21, q22, [{rk}, #-160]",
    ] + counters_and_round0_256()
    step = -(-len(gh) // late)
    for r in range(1, 13):
        out += aes_round(KEYS256[r])
        i = r - (13 - late)
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
    return out + tail()


def prologue(bits):
    if bits == 128:
        return [
            "ld1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{rk}], #64",
            "ld1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [{rk}], #64",
            "ld1 {{v8.16b, v9.16b, v10.16b}}, [{rk}]",
            "mov {t0}, #0x87",
            "dup v31.2d, {t0}",
        ]
    # k0 and k5-k14, the pointer left at k13.
    return [
        "ldr q0, [{rk}], #80",
        "ld1 {{v1.16b, v2.16b, v3.16b, v4.16b}}, [{rk}], #64",
        "ld1 {{v5.16b, v6.16b, v7.16b, v8.16b}}, [{rk}], #64",
        "ld1 {{v9.16b, v10.16b}}, [{rk}]",
        "mov {t0}, #0x86",
        "dup v31.2d, {t0}",
    ]


def lines(bits, late):
    turn = body(late) if bits == 128 else body256(late)
    return "".join(f'{" " * 20}"{l}",\n' for l in prologue(bits) + turn)


def write(texts):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sys.rs")
    with open(path) as f:
        s = f.read()
    at = s.index("fn turns(")
    for text in texts:
        start = s.index("core::arch::asm!(\n", at) + len("core::arch::asm!(\n")
        end = s.rindex("\n", 0, s.index("rk = inout(reg)", start)) + 1
        s = s[:start] + text + s[end:]
        at = start + len(text)
    with open(path, "w") as f:
        f.write(s)


def main():
    args = [int(a) for a in sys.argv[1:] if a != "--write"]
    bits = args[0] if args else 128
    late = args[1] if len(args) > 1 else {128: 4, 256: 3}[bits]
    if "--write" in sys.argv:
        write([lines(128, 4), lines(256, 3)])
    else:
        sys.stdout.write(lines(bits, late))


main()
