"""
Unit tests for StegoForge Compression Layer.
"""

from __future__ import annotations

import os
import pytest

from stegoforge.core.compression import (
    CompressionAlgoID,
    CompressionMode,
    compress_payload,
    decompress_payload,
)
from stegoforge.core.exceptions import StegoForgeError


def test_compression_none_round_trip():
    data = b"Arbitrary raw payload data"
    comp, mode = compress_payload(data, mode=CompressionMode.NONE)
    assert mode == "none"
    decomp, decomp_mode = decompress_payload(comp)
    assert decomp == data
    assert decomp_mode == "none"


def test_compression_deflate_round_trip():
    data = b"Highly compressible repeated string: " * 100
    comp, mode = compress_payload(data, mode=CompressionMode.DEFLATE)
    assert mode == "deflate"
    assert len(comp) < len(data)

    decomp, decomp_mode = decompress_payload(comp)
    assert decomp == data
    assert decomp_mode == "deflate"


def test_compression_lzma_round_trip():
    data = b"Repeating pattern for LZMA test " * 200
    comp, mode = compress_payload(data, mode=CompressionMode.LZMA)
    assert mode == "lzma"
    assert len(comp) < len(data)

    decomp, decomp_mode = decompress_payload(comp)
    assert decomp == data
    assert decomp_mode == "lzma"


def test_compression_bzip2_round_trip():
    data = b"Repeating pattern for BZIP2 test " * 200
    comp, mode = compress_payload(data, mode=CompressionMode.BZIP2)
    assert mode == "bzip2"
    assert len(comp) < len(data)

    decomp, decomp_mode = decompress_payload(comp)
    assert decomp == data
    assert decomp_mode == "bzip2"


def test_compression_auto_mode():
    data = b"Auto mode test with high redundancy payload: " * 150
    comp, mode = compress_payload(data, mode=CompressionMode.AUTO)
    assert mode in ("deflate", "lzma", "bzip2")
    assert len(comp) < len(data)

    decomp, _ = decompress_payload(comp)
    assert decomp == data


def test_compression_incompressible_data_fallback():
    # Random noise data shouldn't be compressed
    data = os.urandom(256)
    comp, mode = compress_payload(data, mode=CompressionMode.AUTO)
    assert mode == "none"

    decomp, _ = decompress_payload(comp)
    assert decomp == data


def test_legacy_uncompressed_data_passthrough():
    # If raw data does not have SFC0 header, it should return as-is
    raw = b"Legacy raw data without compression header"
    decomp, mode = decompress_payload(raw)
    assert decomp == raw
    assert mode == "none"
