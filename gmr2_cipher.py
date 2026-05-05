#!/usr/bin/env python3
"""
GMR-2+ (Inmarsat IsatPhone class) — A5-GMR-2 stream cipher (byte-oriented).

Specification from published cryptanalysis / reverse-engineering:
  Driessen et al., IEEE S&P 2012, Section V — structure F / G / H, Table IV,
  DES S-boxes S2 and S6 with column = bits 5..2, row = bits 1..0 of
  6-bit input.

The 22-bit frame number → 8-byte state register S is only partially described
(direction bit). Use `initial_s=` only for the *first* key-frame when matching
firmware; following segments use `pack_frame_to_s(fn22 + k)`.

Encrypt/decrypt: XOR payload with keystream (self-inverse).

Keystream is consumed in **15-byte key-frames** per frame counter N; after each
frame, N is incremented and the cipher is re-initialized (IEEE S&P 2012).
"""

from __future__ import annotations

from typing import Iterator, Optional

# One key-frame of usable keystream after 8 discarded warmup bytes (paper).
KEYFRAME_BYTES = 15

# Table IV — T1 : {0,1}^4 -> {0,1}^3 index into K; T2 : 3-bit -> rotation
_T1 = [
    2,
    5,
    0,
    6,
    3,
    7,
    4,
    1,  # 0000 .. 0111
    3,
    0,
    6,
    1,
    5,
    7,
    4,
    2,  # 1000 .. 1111
]

# T2 o T1 — last column of Table IV (rotation 0..7)
_T2 = [4, 5, 6, 7, 4, 3, 2, 1]


def _ror8(x: int, r: int) -> int:
    r &= 7
    x &= 0xFF
    return ((x >> r) | (x << (8 - r))) & 0xFF


def _nibble_select(c_mod2: int, x: int) -> int:
    """N(t,x): low nibble if c_mod2==0 else high nibble."""
    if c_mod2 & 1:
        return (x >> 4) & 0xF
    return x & 0xF


# DES S-boxes (FIPS 46-3) — 4 rows x 16 columns
_DES_S2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
]

_DES_S6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
]


def _sbox_lookup(table: list[list[int]], inp6: int) -> int:
    """GMR-2 addressing: column = bits 5..2, row = bits 1..0 (MSB = bit 5)."""
    col = (inp6 >> 2) & 0xF
    row = inp6 & 0x3
    return table[row][col]


def _f_component(
    k: bytes, c: int, t: int, prev_z: int
) -> tuple[int, int]:
    """Returns O0 (byte), O1 (4-bit)."""
    Kc = k[c]
    alpha = _nibble_select(c & 1, Kc ^ prev_z)
    t1v = _T1[alpha]
    rot = _T2[t1v]
    o0 = _ror8(k[t1v], rot)
    o1 = (
        ((Kc >> 7) & 1)
        ^ ((prev_z >> 7) & 1)
        ^ ((Kc >> 3) & 1)
        ^ ((prev_z >> 3) & 1)
    ) << 3
    o1 |= (
        ((Kc >> 6) & 1)
        ^ ((prev_z >> 6) & 1)
        ^ ((Kc >> 2) & 1)
        ^ ((prev_z >> 2) & 1)
    ) << 2
    o1 |= (
        ((Kc >> 5) & 1)
        ^ ((prev_z >> 5) & 1)
        ^ ((Kc >> 1) & 1)
        ^ ((prev_z >> 1) & 1)
    ) << 1
    o1 |= (
        ((Kc >> 4) & 1)
        ^ ((prev_z >> 4) & 1)
        ^ ((Kc >> 0) & 1)
        ^ ((prev_z >> 0) & 1)
    )
    return o0, o1 & 0xF


def _g_component(i0: int, i1: int, s0: int) -> tuple[int, int]:
    """Linear G: 6-bit outputs (MSB = first bit in paper tuple)."""
    ib = [(i0 >> i) & 1 for i in range(7, -1, -1)]
    sb = [(s0 >> i) & 1 for i in range(7, -1, -1)]
    i1b = [(i1 >> i) & 1 for i in range(3, -1, -1)]
    I0 = ib
    I1 = i1b
    S0 = sb
    b0 = I0[0] ^ I0[3] ^ S0[2]
    b1 = I0[0] ^ I0[1] ^ I0[3] ^ S0[0]
    b2 = I0[0] ^ S0[3]
    b3 = I0[2] ^ S0[1]
    b4 = I1[0] ^ I1[2] ^ I1[3]
    b5 = I1[0] ^ I1[3]
    op0 = (b0 << 5) | (b1 << 4) | (b2 << 3) | (b3 << 2) | (b4 << 1) | b5
    c0 = I0[4] ^ I0[7] ^ S0[6]
    c1 = I0[4] ^ I0[5] ^ I0[7] ^ S0[4]
    c2 = I0[4] ^ S0[7]
    c3 = I0[6] ^ S0[5]
    c4 = I1[1]
    c5 = I1[3]
    op1 = (c0 << 5) | (c1 << 4) | (c2 << 3) | (c3 << 2) | (c4 << 1) | c5
    return op0, op1


def _h_component(ip0: int, ip1: int, t: int) -> int:
    if t & 1:
        hi = _sbox_lookup(_DES_S2, ip0)
        lo = _sbox_lookup(_DES_S6, ip1)
    else:
        hi = _sbox_lookup(_DES_S2, ip1)
        lo = _sbox_lookup(_DES_S6, ip0)
    return ((hi & 0xF) << 4) | (lo & 0xF)


def pack_frame_to_s(fn22: int, *, direction: bool = False) -> bytearray:
    """
    Default layout: 22-bit frame number in low bits of S (little-endian 3-byte).
    Override with explicit `initial_s` on the first key-frame only if interop
    requires it. `direction` XORs 0x40 into S[7] as a coarse
    uplink/downlink hook.
    """
    fn22 &= (1 << 22) - 1
    s = bytearray(8)
    s[0] = fn22 & 0xFF
    s[1] = (fn22 >> 8) & 0xFF
    s[2] = (fn22 >> 16) & 0x3F
    if direction:
        s[7] ^= 0x40
    return s


def _clock_cycle(
    k: bytes,
    s: bytearray,
    c: int,
    t: int,
    prev_z: int,
) -> tuple[int, int, int, int]:
    o0, o1 = _f_component(k, c, t, prev_z)
    ip0, ip1 = _g_component(o0, o1, s[0])
    z = _h_component(ip0, ip1, t)
    new_t = 1 - t
    new_c = 0 if c == 7 else c + 1
    for i in range(7, 0, -1):
        s[i] = s[i - 1]
    s[0] = z
    return z, new_c, new_t, z


def keystream(
    key: bytes,
    fn22: int,
    nbytes: int,
    *,
    initial_s: Optional[bytes] = None,
    direction: bool = False,
    skip_warmup: int = 8,
) -> bytes:
    """
    Generate `nbytes` of keystream for a **single** frame counter
    (one segment). For lengths beyond 15, use `keystream_chained`.
    """
    if len(key) != 8:
        raise ValueError("key must be 8 bytes")
    if nbytes > KEYFRAME_BYTES:
        raise ValueError(
            f"single-frame keystream max {KEYFRAME_BYTES} bytes; "
            "use keystream_chained() for longer output"
        )
    k = bytes(key)
    s = bytearray(
        initial_s
        if initial_s is not None
        else pack_frame_to_s(fn22, direction=direction)
    )
    if len(s) != 8:
        raise ValueError("initial_s must be 8 bytes")
    c = 0
    t = 0
    prev_z = 0
    for _ in range(skip_warmup):
        z, c, t, prev_z = _clock_cycle(k, s, c, t, prev_z)
    out = bytearray()
    for _ in range(nbytes):
        z, c, t, prev_z = _clock_cycle(k, s, c, t, prev_z)
        out.append(z)
    return bytes(out)


def keystream_keyframe(
    key: bytes,
    fn22: int,
    *,
    initial_s: Optional[bytes] = None,
    direction: bool = False,
) -> bytes:
    """One full 15-byte key-frame Z'_8..Z'_22 for frame counter fn22."""
    return keystream(
        key,
        fn22,
        KEYFRAME_BYTES,
        initial_s=initial_s,
        direction=direction,
        skip_warmup=8,
    )


def keystream_chained(
    key: bytes,
    fn22_start: int,
    nbytes: int,
    *,
    initial_s: Optional[bytes] = None,
    direction: bool = False,
) -> bytes:
    """
    Concatenate key-stream as in the paper: for each 15-byte block, increment
    the 22-bit frame counter and re-init the cipher. `initial_s` applies only
    to the first block; later blocks use `pack_frame_to_s(fn, direction=...)`.
    """
    if nbytes < 0:
        raise ValueError("nbytes must be non-negative")
    out = bytearray()
    f = fn22_start & ((1 << 22) - 1)
    remain = nbytes
    first = True
    while remain > 0:
        take = min(KEYFRAME_BYTES, remain)
        s_override = initial_s if first else None
        out.extend(
            keystream(key, f, take, initial_s=s_override, direction=direction)
        )
        remain -= take
        f = (f + 1) & ((1 << 22) - 1)
        first = False
    return bytes(out)


def keystream_bits_chained(
    key: bytes,
    fn22_start: int,
    nbits: int,
    *,
    initial_s: Optional[bytes] = None,
    direction: bool = False,
) -> list[int]:
    """
    Expand chained keystream to nbits bits, **MSB-first within each byte**
    (same convention as GMR-1 helpers). Useful when aligning to burst bit
    order.
    """
    nbytes = (nbits + 7) // 8
    raw = keystream_chained(
        key, fn22_start, nbytes, initial_s=initial_s, direction=direction
    )
    bits: list[int] = []
    for byte in raw:
        for j in range(8):
            bits.append((byte >> (7 - j)) & 1)
    return bits[:nbits]


def iter_keystream_bits_chained(
    key: bytes,
    fn22_start: int,
    *,
    initial_s: Optional[bytes] = None,
    direction: bool = False,
) -> Iterator[int]:
    """Lazily yield MSB-first bits from `keystream_chained` (unbounded)."""
    f = fn22_start & ((1 << 22) - 1)
    first = True
    while True:
        s_override = initial_s if first else None
        block = keystream_keyframe(
            key,
            f,
            initial_s=s_override,
            direction=direction,
        )
        for byte in block:
            for j in range(8):
                yield (byte >> (7 - j)) & 1
        f = (f + 1) & ((1 << 22) - 1)
        first = False


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_decrypt(
    data: bytes,
    key: bytes,
    fn22: int,
    *,
    initial_s: Optional[bytes] = None,
    direction: bool = False,
) -> bytes:
    """XOR full buffer with chained key-frame keystream (any length)."""
    if len(key) != 8:
        raise ValueError("key must be 8 bytes")
    fn22 &= (1 << 22) - 1
    ks = keystream_chained(
        key, fn22, len(data), initial_s=initial_s, direction=direction
    )
    return xor_bytes(data, ks)
