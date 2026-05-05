#!/usr/bin/env python3
"""
Generate synthetic example artifacts for gmr_satphone_crypto.

This produces:
  - plaintext files
  - ciphertext in artifacts JSON
  - metadata (kc/key, counters, direction, uplink)

No RF capture, no real satphone traffic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PARENT = ROOT.parent
if str(PARENT) not in sys.path:
    sys.path.insert(0, str(PARENT))

import gmr1_cipher as g1
import gmr2_cipher as g2


def _w_text(path: Path, s: str) -> None:
    path.write_text(s, encoding="utf-8")


def _w_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    # --- GMR-1 example ---
    gmr1_kc = bytes.fromhex("0123456789abcdef")
    gmr1_fn = 0x1A2B3
    gmr1_uplink = False
    # Simulate a realistic L1-encrypted field length: 208 bits (tch3_speech)
    gmr1_channel = "tch3_speech"
    gmr1_nbits = g1.CHANNEL_CIPH_BITS[gmr1_channel]
    # Plaintext bits: deterministic, non-trivial pattern
    gmr1_plain_bits = [(i * 7 + 3) & 1 for i in range(gmr1_nbits)]
    gmr1_plain_bytes = g1.bits_msb_first_to_bytes(gmr1_plain_bits)
    # Ciphertext bits = plaintext_bits XOR keystream_bits (aligned)
    ks_bits = g1.keystream_for_channel(
        gmr1_kc,
        gmr1_fn,
        gmr1_channel,
        uplink=gmr1_uplink,
    )
    gmr1_cipher_bits = [p ^ k for p, k in zip(gmr1_plain_bits, ks_bits)]
    gmr1_cipher_bytes = g1.bits_msb_first_to_bytes(gmr1_cipher_bits)

    _w_text(
        ROOT / "gmr1_plaintext.txt",
        "GMR-1 synthetic L1 sample (bit-level)\n"
        f"channel={gmr1_channel} nbits={gmr1_nbits}\n"
        "plaintext_bits are deterministic; NOT real intercepted traffic.\n",
    )
    _w_json(
        ROOT / "gmr1_artifacts.json",
        {
            "scheme": "gmr1",
            "kc": gmr1_kc.hex(),
            "fn": hex(gmr1_fn),
            "uplink": gmr1_uplink,
            "channel": gmr1_channel,
            "nbits": gmr1_nbits,
            "ciphertext_bits": "".join("1" if b else "0" for b in gmr1_cipher_bits),
            "ciphertext": gmr1_cipher_bytes.hex(),
            "expected_plaintext_hex": gmr1_plain_bytes.hex(),
        },
    )

    # --- GMR-2 example ---
    gmr2_key = bytes.fromhex("0011223344556677")
    gmr2_fn22 = 42
    gmr2_direction = False
    gmr2_initial_s = None  # keep default pack_frame_to_s for demo
    gmr2_plain = (
        "GMR-2 synthetic example payload.\n"
        "This is NOT real intercepted satphone data.\n"
        "fn22=42 key=0011223344556677\n"
        "Chained keystream is used for length > 15 bytes.\n"
    ).encode("utf-8")
    gmr2_cipher = g2.encrypt_decrypt(
        gmr2_plain,
        gmr2_key,
        gmr2_fn22,
        initial_s=gmr2_initial_s,
        direction=gmr2_direction,
    )

    _w_text(ROOT / "gmr2_plaintext.txt", gmr2_plain.decode("utf-8"))
    _w_json(
        ROOT / "gmr2_artifacts.json",
        {
            "scheme": "gmr2",
            "key": gmr2_key.hex(),
            "fn22": gmr2_fn22,
            "direction": gmr2_direction,
            "initial_s": None,
            "ciphertext": gmr2_cipher.hex(),
        },
    )

    print("[+] Wrote example plaintext + artifacts JSON")


if __name__ == "__main__":
    main()

