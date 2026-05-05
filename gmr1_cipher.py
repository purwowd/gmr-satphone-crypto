#!/usr/bin/env python3
"""
GMR-1 (Thuraya / GEO-Mobile Radio) — A5-GMR-1 stream cipher.

Bit-faithful Python port of Osmocom GMR-1 reference:
  osmo-gmr/src/l1/a5.c (Sylvain Munaut, AGPL-3.0)
Algorithm source: reverse-engineering in
  Driessen et al., IEEE S&P 2012, "Don't Trust Satellite Phones..."

Encrypt/decrypt: XOR payload with keystream (self-inverse).

Bit order: `keystream_bits` / `keystream_bits_ul` emit bits in generation order;
`keystream_bytes_dl` packs eight bits per byte **MSB first** (bit 7 = first bit out).

Channel keystream lengths (encrypted payload bits after channel coding — see
Osmocom `osmo-gmr` L1). Use `keystream_bits(kc, fn, n)` then XOR at bit level,
or `keystream_bytes_dl` when the encrypted field is byte-aligned.
"""

from __future__ import annotations

# Keystream bit counts used with gmr1_a5(..., nbits) in Osmocom (approximate names).
CHANNEL_CIPH_BITS: dict[str, int] = {
    "tch3_speech": 208,
    "facch9_mux": 658,  # as in gmr1_rx.c (FACCH9 path)
    "burst96": 96,  # per-burst slice (e.g. FACCH3 / NT3)
}

# --- LFSR parameters (same naming as osmo-gmr a5.c) ---
A51_R1_LEN = 19
A51_R2_LEN = 22
A51_R3_LEN = 23
A51_R4_LEN = 17

A51_R1_MASK = (1 << A51_R1_LEN) - 1
A51_R2_MASK = (1 << A51_R2_LEN) - 1
A51_R3_MASK = (1 << A51_R3_LEN) - 1
A51_R4_MASK = (1 << A51_R4_LEN) - 1

A51_R1_TAPS = 0x072000
A51_R2_TAPS = 0x311000
A51_R3_TAPS = 0x660000
A51_R4_TAPS = 0x013100


def _parity32(x: int) -> int:
    x ^= x >> 16
    x ^= x >> 8
    x ^= x >> 4
    x &= 0xF
    return (0x6996 >> x) & 1


def _majority(v1: int, v2: int, v3: int) -> int:
    return int((bool(v1) + bool(v2) + bool(v3)) >= 2)


def _clock(r: int, mask: int, taps: int) -> int:
    return ((r << 1) & mask) | _parity32(r & taps)


def _bit_r4(n: int) -> int:
    return 1 << n


def _a5_1_set_bits(r: list[int]) -> None:
    r[0] |= 1
    r[1] |= 1
    r[2] |= 1
    r[3] |= 1


def _a5_1_clock_force(r: list[int]) -> None:
    r[0] = _clock(r[0], A51_R1_MASK, A51_R1_TAPS)
    r[1] = _clock(r[1], A51_R2_MASK, A51_R2_TAPS)
    r[2] = _clock(r[2], A51_R3_MASK, A51_R3_TAPS)
    r[3] = _clock(r[3], A51_R4_MASK, A51_R4_TAPS)


def _a5_1_clock(r: list[int]) -> None:
    cb = [
        bool(r[3] & _bit_r4(15)),
        bool(r[3] & _bit_r4(6)),
        bool(r[3] & _bit_r4(1)),
    ]
    m = int(sum(cb) >= 2)
    if cb[0] == m:
        r[0] = _clock(r[0], A51_R1_MASK, A51_R1_TAPS)
    if cb[1] == m:
        r[1] = _clock(r[1], A51_R2_MASK, A51_R2_TAPS)
    if cb[2] == m:
        r[2] = _clock(r[2], A51_R3_MASK, A51_R3_TAPS)
    r[3] = _clock(r[3], A51_R4_MASK, A51_R4_TAPS)


def _a5_1_output(r: list[int]) -> int:
    m = [0, 0, 0]
    m[0] = _majority(r[0] & _bit_r4(1), r[0] & _bit_r4(6), r[0] & _bit_r4(15))
    m[1] = _majority(r[1] & _bit_r4(3), r[1] & _bit_r4(8), r[1] & _bit_r4(14))
    m[2] = _majority(r[2] & _bit_r4(4), r[2] & _bit_r4(15), r[2] & _bit_r4(19))
    m[0] ^= bool(r[0] & _bit_r4(11))
    m[1] ^= bool(r[1] & _bit_r4(1))
    m[2] ^= bool(r[2] & _bit_r4(0))
    return m[0] ^ m[1] ^ m[2]


def _mix_frame_into_key(key: bytes, fn: int) -> bytes:
    """Replicate osmo-gmr key XOR with 19-bit GMR frame counter."""
    if len(key) != 8:
        raise ValueError("Kc must be 8 bytes (64-bit session key).")
    lkey = bytearray(key[i ^ 1] for i in range(8))
    lkey[6] ^= (fn & 0x0000F) << 4
    lkey[3] ^= (fn & 0x00030) << 2
    lkey[1] ^= (fn & 0x007C0) >> 3
    lkey[0] ^= (fn & 0x0F800) >> 11
    lkey[0] ^= (fn & 0x70000) >> 11
    return bytes(lkey)


def keystream_bits(kc: bytes, fn: int, nbits: int) -> list[int]:
    """Generate nbits of keystream as 0/1 list (downlink direction)."""
    if nbits < 0:
        raise ValueError("nbits must be non-negative")
    lkey = _mix_frame_into_key(kc, fn)
    r = [0, 0, 0, 0]
    for i in range(64):
        byte_idx = i >> 3
        bit_idx = 7 - (i & 7)
        b = (lkey[byte_idx] >> bit_idx) & 1
        _a5_1_clock_force(r)
        r[0] ^= b
        r[1] ^= b
        r[2] ^= b
        r[3] ^= b
    _a5_1_set_bits(r)
    for _ in range(250):
        _a5_1_clock(r)
    out: list[int] = []
    for _ in range(nbits):
        _a5_1_clock(r)
        out.append(_a5_1_output(r))
    return out


def keystream_bytes_dl(kc: bytes, fn: int, nbytes: int) -> bytes:
    """Downlink keystream as bytes (MSB-first within each byte)."""
    bits = keystream_bits(kc, fn, nbytes * 8)
    out = bytearray(nbytes)
    for i in range(nbytes):
        v = 0
        for j in range(8):
            v |= bits[i * 8 + j] << (7 - j)
        out[i] = v
    return bytes(out)


def keystream_bits_ul(kc: bytes, fn: int, nbits: int) -> list[int]:
    """Uplink keystream: same init as DL, skip nbits DL, then take nbits UL."""
    if nbits < 0:
        raise ValueError("nbits must be non-negative")
    lkey = _mix_frame_into_key(kc, fn)
    r = [0, 0, 0, 0]
    for i in range(64):
        byte_idx = i >> 3
        bit_idx = 7 - (i & 7)
        b = (lkey[byte_idx] >> bit_idx) & 1
        _a5_1_clock_force(r)
        r[0] ^= b
        r[1] ^= b
        r[2] ^= b
        r[3] ^= b
    _a5_1_set_bits(r)
    for _ in range(250):
        _a5_1_clock(r)
    for _ in range(nbits):
        _a5_1_clock(r)
        _a5_1_output(r)
    out: list[int] = []
    for _ in range(nbits):
        _a5_1_clock(r)
        out.append(_a5_1_output(r))
    return out


def xor_keystream(data: bytes, ks: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, ks))


def keystream_bits_dl(kc: bytes, fn: int, nbits: int) -> list[int]:
    """Alias for `keystream_bits` (explicit downlink naming)."""
    return keystream_bits(kc, fn, nbits)


def bits_msb_first_to_bytes(bits: list[int]) -> bytes:
    """Pack bits (MSB-first per byte); trailing <8 bits are ignored."""
    out = bytearray()
    nfull = (len(bits) // 8) * 8
    for i in range(0, nfull, 8):
        v = sum((bits[i + j] & 1) << (7 - j) for j in range(8))
        out.append(v)
    return bytes(out)


def keystream_for_channel(
    kc: bytes,
    fn: int,
    channel: str,
    *,
    uplink: bool = False,
) -> list[int]:
    """
    Generate keystream bits for a named logical channel (see CHANNEL_CIPH_BITS).
    Unknown channel keys raise KeyError.
    """
    nbits = CHANNEL_CIPH_BITS[channel]
    if uplink:
        return keystream_bits_ul(kc, fn, nbits)
    return keystream_bits(kc, fn, nbits)


def encrypt_decrypt(
    data: bytes,
    kc: bytes,
    fn: int,
    *,
    uplink: bool = False,
) -> bytes:
    """Stream XOR with A5-GMR-1 (same function encrypts and decrypts)."""
    n = len(data)
    if uplink:
        bits = keystream_bits_ul(kc, fn, n * 8)
        ks = bytes(
            sum(bits[i * 8 + j] << (7 - j) for j in range(8)) for i in range(n)
        )
    else:
        ks = keystream_bytes_dl(kc, fn, n)
    return xor_keystream(data, ks)
