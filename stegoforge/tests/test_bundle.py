"""
Unit tests for StegoForge Multi-Payload Bundle Architecture.
"""

from __future__ import annotations

import hashlib
import pytest
from pathlib import Path

from stegoforge.core.bundle import (
    PayloadObject,
    create_payload_from_bytes,
    create_payload_from_text,
    create_payload_from_file,
    is_bundle,
    pack_bundle,
    unpack_bundle,
)
from stegoforge.core.exceptions import StegoForgeError


def test_bundle_single_payload():
    p1 = create_payload_from_text("Secret text message 1", name="note.txt")
    bundle_bytes = pack_bundle([p1])

    assert is_bundle(bundle_bytes) is True
    assert bundle_bytes[:4] == b"SFB1"

    unpacked = unpack_bundle(bundle_bytes)
    assert len(unpacked) == 1
    assert unpacked[0].name == "note.txt"
    assert unpacked[0].data == b"Secret text message 1"
    assert unpacked[0].sha256 == hashlib.sha256(b"Secret text message 1").hexdigest()


def test_bundle_multiple_payloads():
    p1 = create_payload_from_text("Doc 1 contents", name="doc1.txt")
    p2 = create_payload_from_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32, name="image.png", mime="image/png")
    p3 = create_payload_from_text('{"key": "value"}', name="data.json")

    bundle_bytes = pack_bundle([p1, p2, p3])
    unpacked = unpack_bundle(bundle_bytes)

    assert len(unpacked) == 3
    assert unpacked[0].name == "doc1.txt"
    assert unpacked[1].name == "image.png"
    assert unpacked[1].mime_type == "image/png"
    assert unpacked[2].name == "data.json"
    assert unpacked[2].data == b'{"key": "value"}'


def test_bundle_empty_list_rejected():
    with pytest.raises(ValueError):
        pack_bundle([])


def test_bundle_corrupt_manifest():
    p1 = create_payload_from_text("test")
    raw = pack_bundle([p1])
    # Corrupt manifest byte
    corrupt = bytearray(raw)
    corrupt[12] ^= 0xFF
    with pytest.raises(StegoForgeError):
        unpack_bundle(bytes(corrupt))


def test_bundle_corrupt_payload_hash_mismatch():
    p1 = create_payload_from_text("test string")
    raw = pack_bundle([p1])
    # Corrupt last byte (payload data)
    corrupt = bytearray(raw)
    corrupt[-1] ^= 0xFF
    with pytest.raises(StegoForgeError, match="Integrity failure"):
        unpack_bundle(bytes(corrupt))
