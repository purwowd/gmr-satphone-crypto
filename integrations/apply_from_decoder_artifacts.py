#!/usr/bin/env python3
"""
Bridge script: apply GMR keystream to already-decoded artifacts.

This script does NOT do RF capture, demod, channel decoding, or protocol parsing.
It assumes you already have *authorized* decoder artifacts:
  - ciphertext aligned to the ciphering step
  - session key (GMR-1 Kc / GMR-2 key)
  - frame counter(s) (GMR-1 fn / GMR-2 fn22 start)
  - direction / initial S override if needed

Input format: JSON (see integrations/schema.json).
Output: plaintext (hex + optional UTF-8) + keystream head for sanity checks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import gmr1_cipher as g1
import gmr2_cipher as g2


def _b(hexstr: str) -> bytes:
    s = hexstr.strip().replace(" ", "")
    if len(s) % 2:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(s)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _print_result(plaintext: bytes, keystream_head: bytes) -> None:
    print(f"[+] keystream_head_hex: {keystream_head.hex()}")
    print(f"[+] plaintext_hex:      {plaintext.hex()}")
    try:
        txt = plaintext.decode("utf-8")
        print(f"[+] plaintext_utf8:     {txt!r}")
    except Exception:
        pass


def do_gmr1(obj: dict) -> int:
    kc = _b(obj["kc"])
    fn = int(obj["fn"], 0) if isinstance(obj["fn"], str) else int(obj["fn"])
    uplink = bool(obj.get("uplink", False))
    # Bit-level path (more realistic for L1 alignment)
    if obj.get("ciphertext_bits") is not None:
        ctb = str(obj["ciphertext_bits"]).strip()
        nbits = int(obj.get("nbits", len(ctb)))
        ctb = ctb[:nbits]
        if any(ch not in "01" for ch in ctb):
            raise ValueError("ciphertext_bits must contain only '0'/'1'")

        channel = obj.get("channel")
        if channel:
            ks_bits = g1.keystream_for_channel(kc, fn, channel, uplink=uplink)
        else:
            ks_bits = g1.keystream_bits_ul(kc, fn, nbits) if uplink else g1.keystream_bits(kc, fn, nbits)

        pt_bits = [(int(b) ^ int(k)) for b, k in zip(ctb, ks_bits)]
        pt_bytes = g1.bits_msb_first_to_bytes(pt_bits)

        head_bits = ks_bits[: min(128, len(ks_bits))]
        ks_head = g1.bits_msb_first_to_bytes(head_bits)
        _print_result(pt_bytes, ks_head)
        return 0

    # Byte-level path
    ciphertext = _b(obj["ciphertext"])
    plaintext = g1.encrypt_decrypt(ciphertext, kc, fn, uplink=uplink)
    head_len = min(16, len(ciphertext))
    if uplink:
        bits = g1.keystream_bits_ul(kc, fn, head_len * 8)
        ks_head = g1.bits_msb_first_to_bytes(bits)
    else:
        ks_head = g1.keystream_bytes_dl(kc, fn, head_len)
    _print_result(plaintext, ks_head)
    return 0


def do_gmr2(obj: dict) -> int:
    key = _b(obj["key"])
    fn22 = int(obj["fn22"], 0) if isinstance(obj["fn22"], str) else int(obj["fn22"])
    direction = bool(obj.get("direction", False))
    initial_s = _b(obj["initial_s"]) if obj.get("initial_s") else None
    ciphertext = _b(obj["ciphertext"])
    plaintext = g2.encrypt_decrypt(
        ciphertext,
        key,
        fn22,
        initial_s=initial_s,
        direction=direction,
    )
    ks_head = g2.keystream_chained(
        key,
        fn22,
        min(32, len(ciphertext)),
        initial_s=initial_s,
        direction=direction,
    )
    _print_result(plaintext, ks_head)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Apply GMR-1/GMR-2 keystream to decoder artifacts (JSON)."
    )
    ap.add_argument("input_json", help="Path to JSON artifacts")
    args = ap.parse_args()

    obj = _load_json(Path(args.input_json))
    scheme = obj.get("scheme")
    if scheme == "gmr1":
        return do_gmr1(obj)
    if scheme == "gmr2":
        return do_gmr2(obj)
    raise SystemExit("scheme must be 'gmr1' or 'gmr2'")


if __name__ == "__main__":
    sys.exit(main())

