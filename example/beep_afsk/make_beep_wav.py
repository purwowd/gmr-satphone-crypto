#!/usr/bin/env python3
"""
Generate a synthetic AFSK (1200/2200 Hz) WAV that sounds like "beep beep",
containing a small framed payload.

Framing (very small, demo-grade):
  - Preamble: 0x55 repeated (bits 01010101...) for clock recovery
  - Sync word: 0x2DD4
  - Len (1 byte)
  - Payload (UTF-8 bytes)
  - CRC16-CCITT (2 bytes, big-endian)

Bit encoding: NRZ-L, 1 bit per symbol.
Modulation: f_mark=1200 (bit=1), f_space=2200 (bit=0).
"""

from __future__ import annotations

import argparse
import math
import struct
import wave


def crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    crc = init
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def bytes_to_bits_msb(data: bytes) -> list[int]:
    bits: list[int] = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits


def build_frame(payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("payload too long (max 255)")
    preamble = bytes([0x55]) * 32
    sync = bytes([0x2D, 0xD4])
    ln = bytes([len(payload)])
    body = ln + payload
    crc = crc16_ccitt(body)
    return preamble + sync + body + struct.pack(">H", crc)


def gen_afsk_pcm(
    bits: list[int],
    *,
    sample_rate: int = 48000,
    baud: int = 1200,
    f_mark: float = 1200.0,
    f_space: float = 2200.0,
    amplitude: float = 0.6,
) -> bytes:
    samples_per_sym = sample_rate / baud
    phase = 0.0
    out = bytearray()
    t = 0.0
    dt = 1.0 / sample_rate

    for bit in bits:
        f = f_mark if bit == 1 else f_space
        n = int(round(samples_per_sym))
        for _ in range(n):
            phase += 2.0 * math.pi * f * dt
            # keep phase bounded
            if phase > 2.0 * math.pi:
                phase -= 2.0 * math.pi
            s = int(max(-1.0, min(1.0, amplitude * math.sin(phase))) * 32767)
            out += struct.pack("<h", s)
            t += dt
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate AFSK beep WAV with payload")
    ap.add_argument("--message", required=True, help="UTF-8 payload text")
    ap.add_argument("--out", required=True, help="output wav path")
    ap.add_argument("--sample-rate", type=int, default=48000)
    ap.add_argument("--baud", type=int, default=1200)
    ap.add_argument("--mark", type=float, default=1200.0)
    ap.add_argument("--space", type=float, default=2200.0)
    args = ap.parse_args()

    payload = args.message.encode("utf-8")
    frame = build_frame(payload)
    bits = bytes_to_bits_msb(frame)
    pcm = gen_afsk_pcm(
        bits,
        sample_rate=args.sample_rate,
        baud=args.baud,
        f_mark=args.mark,
        f_space=args.space,
    )

    with wave.open(args.out, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)  # int16
        wf.setframerate(args.sample_rate)
        wf.writeframes(pcm)

    print(f"[+] wrote: {args.out}")
    print(f"[+] payload_len: {len(payload)} bytes")
    print(f"[+] total_frame_bytes: {len(frame)}")
    print(f"[+] total_bits: {len(bits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

