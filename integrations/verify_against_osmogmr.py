#!/usr/bin/env python3
"""
Optional verifier: compare this Python GMR-1 keystream against osmo-gmr output.

This script requires a local osmo-gmr build that can generate keystream bits
via gmr1_a5(). It does NOT perform RF capture or decode; it is purely a
keystream equivalence check (Python vs C).

How to use (example):
  python3 integrations/verify_against_osmogmr.py \\
    --osmogmr-tool ./osmo_gmr_keystream \\
    --kc 0123456789abcdef --fn 0x1a2b3 --nbits 658

You must provide `--osmogmr-tool` executable that prints keystream bits as
ASCII '0'/'1' (no spaces) on stdout.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

import gmr1_cipher as g1


def _b(hexstr: str) -> bytes:
    s = hexstr.strip().replace(" ", "")
    if len(s) % 2:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(s)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify GMR-1 keystream vs osmo-gmr"
    )
    ap.add_argument(
        "--osmogmr-tool",
        required=True,
        help="path to helper executable",
    )
    ap.add_argument("--kc", required=True, help="8-byte Kc hex")
    ap.add_argument("--fn", required=True, help="frame number (int or 0x...)")
    ap.add_argument(
        "--nbits",
        type=int,
        required=True,
        help="number of bits to compare",
    )
    ap.add_argument("--uplink", action="store_true", help="compare uplink stream")
    args = ap.parse_args()

    kc = _b(args.kc)
    fn = int(args.fn, 0)
    nbits = int(args.nbits)

    py_bits = (
        g1.keystream_bits_ul(kc, fn, nbits)
        if args.uplink
        else g1.keystream_bits(kc, fn, nbits)
    )
    py_str = "".join(str(b) for b in py_bits)

    cmd = [
        args.osmogmr_tool,
        "--kc",
        args.kc,
        "--fn",
        str(args.fn),
        "--nbits",
        str(nbits),
    ] + (["--uplink"] if args.uplink else [])

    proc = subprocess.run(
        cmd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    c_str = proc.stdout.strip()

    if c_str == py_str:
        print("[+] MATCH")
        return 0

    # Find first mismatch to aid debugging
    m = next(
        (i for i, (a, b) in enumerate(zip(c_str, py_str)) if a != b),
        None,
    )
    print("[-] MISMATCH")
    if m is not None:
        print(f"    first_mismatch_bit: {m}")
        print(f"    c:  {c_str[m:m+64]}")
        print(f"    py: {py_str[m:m+64]}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
