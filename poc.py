#!/usr/bin/env python3
"""
PoC: GMR-1 & GMR-2 stream cipher encrypt/decrypt (authorized lab / research).

Usage:
  python3 poc.py gmr1 --kc deadbeefcafebabe --fn 0x12345 --hex 0011223344556677
  python3 poc.py gmr2 --key 0011223344556677 --fn 42 --text "Hello satphone"
"""

from __future__ import annotations

import argparse
import logging
import sys

import gmr1_cipher as g1
import gmr2_cipher as g2

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def _parse_hex(s: str) -> bytes:
    s = s.strip().replace(" ", "")
    if len(s) % 2:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(s)


def cmd_gmr1(args: argparse.Namespace) -> int:
    kc = _parse_hex(args.kc)
    if len(kc) != 8:
        log.error("GMR-1 Kc must be 8 bytes (16 hex digits)")
        return 2
    fn = int(args.fn, 0) & 0x7FFFF
    pt = (
        _parse_hex(args.hex)
        if args.hex
        else args.text.encode("utf-8", errors="strict")
    )
    ks = g1.keystream_bytes_dl(kc, fn, len(pt))
    ct = g1.xor_keystream(pt, ks)
    roundtrip = g1.xor_keystream(ct, ks)
    print(f"[*] GMR-1  fn=0x{fn:x}  len={len(pt)}")
    print(f"[+] keystream (first 16): {ks[:16].hex()}")
    print(f"[+] ciphertext hex: {ct.hex()}")
    print(f"[+] decrypt check OK: {roundtrip == pt}")
    return 0 if roundtrip == pt else 1


def cmd_gmr2(args: argparse.Namespace) -> int:
    key = _parse_hex(args.key)
    if len(key) != 8:
        log.error("GMR-2 key must be 8 bytes")
        return 2
    fn22 = int(args.fn, 0) & ((1 << 22) - 1)
    pt = (
        _parse_hex(args.hex)
        if args.hex
        else args.text.encode("utf-8", errors="strict")
    )
    initial_s = _parse_hex(args.s_init) if args.s_init else None
    ct = g2.encrypt_decrypt(
        pt,
        key,
        fn22,
        initial_s=initial_s,
        direction=args.direction,
    )
    back = g2.encrypt_decrypt(
        ct,
        key,
        fn22,
        initial_s=initial_s,
        direction=args.direction,
    )
    k0 = g2.keystream_keyframe(
        key,
        fn22,
        initial_s=initial_s,
        direction=args.direction,
    )
    kchain_head = g2.keystream_chained(
        key,
        fn22,
        min(32, len(pt)),
        initial_s=initial_s,
        direction=args.direction,
    )
    print(
        f"[*] GMR-2  fn22={fn22}  len={len(pt)}  "
        f"key-frame={g2.KEYFRAME_BYTES} B"
    )
    print(f"[+] keyframe0 ({g2.KEYFRAME_BYTES} B): {k0.hex()}")
    print(f"[+] chained KS head (<=32 B): {kchain_head.hex()}")
    print(f"[+] ciphertext hex: {ct.hex()}")
    print(f"[+] decrypt check OK: {back == pt}")
    if initial_s is None:
        print(
            "[!] S-register init = default pack_frame_to_s(); "
            "untuk interop perangkat nyata gunakan --s-init jika perlu."
        )
    return 0 if back == pt else 1


def main() -> int:
    p = argparse.ArgumentParser(description="GMR-1 / GMR-2 stream PoC")
    sub = p.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser(
        "gmr1",
        help="Thuraya-class A5-GMR-1 (Osmocom-compatible core)",
    )
    p1.add_argument("--kc", required=True, help="64-bit Kc as 16 hex chars")
    p1.add_argument(
        "--fn",
        required=True,
        help="19-bit frame number (e.g. 0x12345)",
    )
    g = p1.add_mutually_exclusive_group(required=True)
    g.add_argument("--hex", help="plaintext as hex")
    g.add_argument("--text", help="plaintext as UTF-8 string")
    p1.set_defaults(func=cmd_gmr1)

    p2 = sub.add_parser(
        "gmr2",
        help="Inmarsat-class A5-GMR-2 (IEEE S&P 2012 structure)",
    )
    p2.add_argument("--key", required=True, help="8-byte key as hex")
    p2.add_argument(
        "--fn",
        required=True,
        help="22-bit frame counter (e.g. 42 or 0x3ffff)",
    )
    p2.add_argument(
        "--direction",
        action="store_true",
        help="direction bit for default S packing",
    )
    p2.add_argument(
        "--s-init",
        help=(
            "optional 16 hex chars = explicit 8-byte initial S "
            "(first key-frame only)"
        ),
    )
    g2_ = p2.add_mutually_exclusive_group(required=True)
    g2_.add_argument("--hex", help="plaintext as hex")
    g2_.add_argument("--text", help="plaintext as UTF-8 string")
    p2.set_defaults(func=cmd_gmr2)

    args = p.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
