#!/usr/bin/env python3
"""
Demodulate and decode the synthetic AFSK WAV produced by make_beep_wav.py.

Demod: non-coherent Goertzel energy at f_mark/f_space per symbol window.
Decode: find preamble+sync, parse len/payload, verify CRC16-CCITT.
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


def bits_to_bytes_msb(bits: list[int]) -> bytes:
    nfull = (len(bits) // 8) * 8
    out = bytearray()
    for i in range(0, nfull, 8):
        v = 0
        for j in range(8):
            v |= (bits[i + j] & 1) << (7 - j)
        out.append(v)
    return bytes(out)


def goertzel_energy(samples: list[float], sample_rate: int, freq: float) -> float:
    # Standard Goertzel
    n = len(samples)
    if n == 0:
        return 0.0
    k = int(0.5 + (n * freq) / sample_rate)
    w = (2.0 * math.pi * k) / n
    cos_w = math.cos(w)
    coeff = 2.0 * cos_w
    s_prev = 0.0
    s_prev2 = 0.0
    for x in samples:
        s = x + coeff * s_prev - s_prev2
        s_prev2 = s_prev
        s_prev = s
    power = s_prev2 * s_prev2 + s_prev * s_prev - coeff * s_prev * s_prev2
    return max(0.0, power)


def demod_afsk_bits(
    pcm: bytes,
    *,
    sample_rate: int,
    baud: int,
    f_mark: float,
    f_space: float,
) -> list[int]:
    # int16 mono
    nsamp = len(pcm) // 2
    samples = list(struct.unpack("<" + "h" * nsamp, pcm))
    # normalize to [-1, 1]
    fs = [s / 32768.0 for s in samples]

    sps = sample_rate / baud
    sym_n = int(round(sps))
    bits: list[int] = []
    for i in range(0, len(fs) - sym_n + 1, sym_n):
        win = fs[i : i + sym_n]
        e_mark = goertzel_energy(win, sample_rate, f_mark)
        e_space = goertzel_energy(win, sample_rate, f_space)
        bits.append(1 if e_mark >= e_space else 0)
    return bits


def find_sync(data: bytes) -> int:
    # Look for preamble (0x55*8+) then sync 0x2DD4
    sync = b"\x2d\xd4"
    # naive search for sync, then verify some preamble before it
    for i in range(0, len(data) - 2):
        if data[i : i + 2] == sync:
            pre = data[max(0, i - 32) : i]
            if pre.count(0x55) >= 8:
                return i
    return -1


def main() -> int:
    ap = argparse.ArgumentParser(description="Demod+decode synthetic AFSK WAV")
    ap.add_argument("--in", dest="inp", required=True, help="input wav path")
    ap.add_argument("--baud", type=int, default=1200)
    ap.add_argument("--mark", type=float, default=1200.0)
    ap.add_argument("--space", type=float, default=2200.0)
    args = ap.parse_args()

    with wave.open(args.inp, "rb") as wf:
        if wf.getnchannels() != 1 or wf.getsampwidth() != 2:
            raise SystemExit("expected mono int16 wav")
        sr = wf.getframerate()
        pcm = wf.readframes(wf.getnframes())

    bits = demod_afsk_bits(
        pcm,
        sample_rate=sr,
        baud=args.baud,
        f_mark=args.mark,
        f_space=args.space,
    )
    by = bits_to_bytes_msb(bits)
    off = find_sync(by)
    if off < 0:
        print("[-] sync not found")
        return 1

    # Parse: sync (2) + len (1) + payload + crc (2)
    p = off + 2
    if p + 1 > len(by):
        print("[-] truncated after sync")
        return 1
    ln = by[p]
    p += 1
    if p + ln + 2 > len(by):
        print("[-] truncated payload/crc")
        return 1
    payload = by[p : p + ln]
    p += ln
    crc_rx = (by[p] << 8) | by[p + 1]
    body = bytes([ln]) + payload
    crc_ok = (crc16_ccitt(body) == crc_rx)

    print(f"[+] sync_offset_bytes: {off}")
    print(f"[+] payload_len: {ln}")
    print(f"[+] payload_hex: {payload.hex()}")
    try:
        print(f"[+] payload_utf8: {payload.decode('utf-8')!r}")
    except Exception:
        pass
    print(f"[+] crc16_ok: {crc_ok}")
    return 0 if crc_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())

