#!/usr/bin/env python3
"""
Offline harness for artifacts exported from real PHY/L1 decoders.

Supported inputs:
- GMR-1 artifacts exported by patched osmo-gmr `gmr1_rx.c`
  (ciphertext_bits + keystream_bits)
- Generic artifacts following `integrations/schema.json`

This is intentionally offline: it does not implement RF capture or demod.
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


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _xor_bitstrings(a: str, b: str) -> str:
    n = min(len(a), len(b))
    return "".join("1" if a[i] != b[i] else "0" for i in range(n))


def handle_gmr1(obj: dict) -> int:
    kc = bytes.fromhex(obj["kc"])
    fn = int(obj["fn"], 0) if isinstance(obj["fn"], str) else int(obj["fn"])
    uplink = bool(obj.get("uplink", False))

    # If keystream_bits is present (exported by patched osmo-gmr), use it directly.
    ctb = obj.get("ciphertext_bits")
    ksb = obj.get("keystream_bits")
    if ctb and ksb:
        ptb = _xor_bitstrings(ctb, ksb)
        pt = g1.bits_msb_first_to_bytes([1 if ch == "1" else 0 for ch in ptb])
        print("[+] scheme=gmr1 (direct XOR from artifact)")
        print(f"[+] fn={fn} channel={obj.get('channel')} nbits={obj.get('nbits')}")
        print(f"[+] plaintext_hex: {pt.hex()}")
        return 0

    # Otherwise fall back to normal bridge logic via keystream generation.
    if obj.get("ciphertext_bits") is not None:
        nbits = int(obj.get("nbits", len(obj["ciphertext_bits"])))
        ct_bits = obj["ciphertext_bits"][:nbits]
        ks = g1.keystream_bits_ul(kc, fn, nbits) if uplink else g1.keystream_bits(kc, fn, nbits)
        pt_bits = [(int(b) ^ k) for b, k in zip(ct_bits, ks)]
        pt = g1.bits_msb_first_to_bytes(pt_bits)
        print("[+] scheme=gmr1 (generated keystream)")
        print(f"[+] plaintext_hex: {pt.hex()}")
        return 0

    ct = bytes.fromhex(obj["ciphertext"])
    pt = g1.encrypt_decrypt(ct, kc, fn, uplink=uplink)
    print("[+] scheme=gmr1 (byte XOR)")
    print(f"[+] plaintext_hex: {pt.hex()}")
    return 0


def handle_gmr2(obj: dict) -> int:
    key = bytes.fromhex(obj["key"])
    fn22 = int(obj["fn22"], 0) if isinstance(obj["fn22"], str) else int(obj["fn22"])
    direction = bool(obj.get("direction", False))
    initial_s = bytes.fromhex(obj["initial_s"]) if obj.get("initial_s") else None

    if obj.get("ciphertext_bits") is not None:
        nbits = int(obj.get("nbits", len(obj["ciphertext_bits"])))
        ct_bits = obj["ciphertext_bits"][:nbits]
        ks_bits = g2.keystream_bits_chained(
            key,
            fn22,
            nbits,
            initial_s=initial_s,
            direction=direction,
        )
        pt_bits = [(int(b) ^ k) for b, k in zip(ct_bits, ks_bits)]
        pt = g1.bits_msb_first_to_bytes(pt_bits)
        print("[+] scheme=gmr2 (bit XOR)")
        print(f"[+] plaintext_hex: {pt.hex()}")
        return 0

    ct = bytes.fromhex(obj["ciphertext"])
    pt = g2.encrypt_decrypt(ct, key, fn22, initial_s=initial_s, direction=direction)
    print("[+] scheme=gmr2 (byte XOR)")
    print(f"[+] plaintext_hex: {pt.hex()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline artifact harness")
    ap.add_argument("artifact_json", help="artifact json path")
    args = ap.parse_args()

    obj = _load(Path(args.artifact_json))
    scheme = obj.get("scheme")
    if scheme == "gmr1":
        return handle_gmr1(obj)
    if scheme == "gmr2":
        return handle_gmr2(obj)
    raise SystemExit("scheme must be gmr1 or gmr2")


if __name__ == "__main__":
    raise SystemExit(main())
