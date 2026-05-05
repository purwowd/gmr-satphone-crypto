"""Regression tests: golden vectors + round-trips."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import gmr1_cipher as g1
import gmr2_cipher as g2

_VECTORS_PATH = Path(__file__).resolve().parent.parent / "test_vectors.json"
_VECTORS = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))


def test_gmr1_golden_keystream() -> None:
    v = _VECTORS["gmr1"]
    ks = g1.keystream_bytes_dl(bytes(8), 0, 16)
    assert ks.hex() == v["kc_zero_fn0_dl_16"]
    ks2 = g1.keystream_bytes_dl(bytes.fromhex("0123456789abcdef"), 0x1A2B3, 4)
    assert ks2.hex() == v["kc_sample_fn_0x1a2b3_dl_4"]
    bits = g1.keystream_bits(bytes.fromhex("0123456789abcdef"), 0x1A2B3, 32)
    assert "".join(str(b) for b in bits) == v["kc_sample_fn_0x1a2b3_bits_32"]


def test_gmr1_roundtrip_dl_ul() -> None:
    kc = bytes(range(8))
    for fn in (0, 0x3FFFF):
        for n in (1, 100):
            pt = bytes((i + fn) & 0xFF for i in range(n))
            for uplink in (False, True):
                ct = g1.encrypt_decrypt(pt, kc, fn, uplink=uplink)
                assert g1.encrypt_decrypt(ct, kc, fn, uplink=uplink) == pt


def test_gmr1_channel_helper() -> None:
    kc = bytes(8)
    fn = 1
    b = g1.keystream_for_channel(kc, fn, "tch3_speech", uplink=False)
    assert len(b) == g1.CHANNEL_CIPH_BITS["tch3_speech"]


def test_gmr1_bits_pack() -> None:
    bits8 = [1, 1, 1, 1, 0, 0, 0, 0]
    assert g1.bits_msb_first_to_bytes(bits8) == bytes([0xF0])


def test_gmr2_golden() -> None:
    v = _VECTORS["gmr2"]
    kf = g2.keystream_keyframe(bytes.fromhex("0123456789abcdef"), 42)
    assert kf.hex() == v["key_sample_fn42_keyframe15"]
    ch = g2.keystream_chained(bytes(8), 0, 32)
    assert ch.hex() == v["key_zero_chained_32_fn0"]


def test_gmr2_chained_roundtrip_long() -> None:
    key = bytes(8)
    pt = bytes(range(100))
    fn = 0x3FFFF0
    ct = g2.encrypt_decrypt(pt, key, fn)
    assert g2.encrypt_decrypt(ct, key, fn) == pt


def test_gmr2_single_frame_cap() -> None:
    with pytest.raises(ValueError, match="single-frame"):
        g2.keystream(key=bytes(8), fn22=0, nbytes=20)


def test_gmr2_initial_s_only_first_segment() -> None:
    key = bytes.fromhex("0011223344556677")
    s0 = bytes.fromhex("0102030405060708")
    a = g2.keystream_chained(key, 5, 20, initial_s=s0)
    b = g2.keystream_chained(key, 5, 15, initial_s=s0) + g2.keystream_chained(
        key, 6, 5, initial_s=None
    )
    assert a == b


def test_gmr2_bits_chained_length() -> None:
    bits = g2.keystream_bits_chained(bytes(8), 0, 25)
    assert len(bits) == 25
