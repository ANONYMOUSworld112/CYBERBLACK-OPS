"""
Unit tests for StegoForge Envelope Agent (pack/unpack).
"""

from __future__ import annotations

import pytest

from stegoforge.core.contracts import CipherID, ENVELOPE_HEADER_SIZE, ENVELOPE_MAGIC, MethodID
from stegoforge.core.envelope import detect_envelope_in_bytes, envelope_overhead, pack, unpack
from stegoforge.core.exceptions import CorruptEnvelopeError


def test_envelope_pack_unpack_roundtrip():
    salt = b"0123456789abcdef"  # 16B
    nonce = b"123456789012"     # 12B
    ciphertext = b"SecretEncryptedDataWithAuthTag123"

    packed = pack(
        method_id=MethodID.LSB_SPATIAL,
        cipher_id=CipherID.AES_256_GCM,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )

    assert len(packed) == ENVELOPE_HEADER_SIZE + len(ciphertext)
    assert packed[:4] == ENVELOPE_MAGIC

    envelope_data = unpack(packed)
    assert envelope_data.method_id == MethodID.LSB_SPATIAL
    assert envelope_data.cipher_id == CipherID.AES_256_GCM
    assert envelope_data.salt == salt
    assert envelope_data.nonce == nonce
    assert envelope_data.ciphertext == ciphertext


def test_envelope_unpack_with_trailing_carrier_padding():
    salt = b"A" * 16
    nonce = b"B" * 12
    ciphertext = b"MyEncryptedPayloadBytes"

    packed = pack(
        method_id=MethodID.EOF_APPEND,
        cipher_id=CipherID.CHACHA20_POLY1305,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )

    # Add trailing carrier noise (e.g. from unused pixels)
    packed_with_padding = packed + b"\x00\xFF\xAA\x55" * 100

    envelope_data = unpack(packed_with_padding)
    assert envelope_data.ciphertext == ciphertext


def test_envelope_invalid_magic():
    bad_data = b"BAD1" + b"\x00" * 50
    with pytest.raises(CorruptEnvelopeError, match="Invalid magic bytes"):
        unpack(bad_data)


def test_envelope_too_short():
    short_data = b"SGF1" + b"\x00" * 10
    with pytest.raises(CorruptEnvelopeError, match="Data too short"):
        unpack(short_data)


def test_envelope_truncated_payload():
    salt = b"A" * 16
    nonce = b"B" * 12
    ciphertext = b"1234567890"

    packed = pack(
        method_id=MethodID.LSB_SPATIAL,
        cipher_id=CipherID.AES_256_GCM,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )

    # Truncate by 3 bytes
    truncated = packed[:-3]
    with pytest.raises(CorruptEnvelopeError, match="Payload truncated"):
        unpack(truncated)


def test_detect_envelope_in_bytes():
    assert detect_envelope_in_bytes(b"SGF1extra") is True
    assert detect_envelope_in_bytes(b"SGF2extra") is False
    assert detect_envelope_in_bytes(b"SG") is False
    assert detect_envelope_in_bytes(b"") is False
    assert envelope_overhead() == ENVELOPE_HEADER_SIZE
