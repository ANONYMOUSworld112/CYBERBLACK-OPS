"""
StegoForge Envelope Agent — pack and unpack the binary envelope format.

Every embedded payload uses a fixed envelope so extraction is deterministic.
The envelope format (§2.5):

    [MAGIC:4B "SGF1"] [METHOD_ID:1B] [CIPHER_ID:1B] [SALT:16B] [NONCE:12B]
    [PAYLOAD_LEN:4B, uint32 LE] [CIPHERTEXT+AUTH_TAG:variable]

Total header: 38 bytes.  The MAGIC lets extract/analyze auto-detect a
StegoForge payload.  Salt and nonce are safe to store alongside ciphertext
(standard AEAD practice).
"""

from __future__ import annotations

import struct

from stegoforge.core.contracts import (
    CipherID,
    EnvelopeData,
    ENVELOPE_HEADER_SIZE,
    ENVELOPE_MAGIC,
    MethodID,
)
from stegoforge.core.exceptions import CorruptEnvelopeError


def pack(
    method_id: MethodID,
    cipher_id: CipherID,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    Pack encrypted payload data into the StegoForge binary envelope.

    Args:
        method_id: Which steg method is being used.
        cipher_id: Which cipher was used.
        salt: 16-byte Argon2id salt.
        nonce: 12-byte AEAD nonce.
        ciphertext: Encrypted payload including auth tag.

    Returns:
        Complete envelope as bytes, ready for concealment.

    Raises:
        ValueError: If salt or nonce are the wrong size.
    """
    if len(salt) != 16:
        raise ValueError(f"Salt must be 16 bytes, got {len(salt)}")
    if len(nonce) != 12:
        raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")

    payload_len = len(ciphertext)
    if payload_len > 0xFFFFFFFF:
        raise ValueError(
            f"Ciphertext too large for envelope: {payload_len:,} bytes "
            f"(max {0xFFFFFFFF:,} bytes = ~4 GB)"
        )

    header = struct.pack(
        "<4sBB16s12sI",
        ENVELOPE_MAGIC,      # 4B magic
        method_id.value,     # 1B method ID
        cipher_id.value,     # 1B cipher ID
        salt,                # 16B salt
        nonce,               # 12B nonce
        payload_len,         # 4B uint32 LE payload length
    )

    assert len(header) == ENVELOPE_HEADER_SIZE
    return header + ciphertext


def unpack(data: bytes) -> EnvelopeData:
    """
    Parse a StegoForge binary envelope back into its components.

    Args:
        data: Raw envelope bytes (header + ciphertext).

    Returns:
        Parsed EnvelopeData with all fields.

    Raises:
        CorruptEnvelopeError: If magic is wrong, header is truncated,
            or payload length doesn't match remaining data.
    """
    if len(data) < ENVELOPE_HEADER_SIZE:
        raise CorruptEnvelopeError(
            f"Data too short for envelope header: {len(data)} bytes, "
            f"need at least {ENVELOPE_HEADER_SIZE}"
        )

    # Unpack the fixed header
    magic, method_byte, cipher_byte, salt, nonce, payload_len = struct.unpack(
        "<4sBB16s12sI", data[:ENVELOPE_HEADER_SIZE]
    )

    # Validate magic bytes
    if magic != ENVELOPE_MAGIC:
        raise CorruptEnvelopeError(
            f"Invalid magic bytes: expected {ENVELOPE_MAGIC!r}, got {magic!r}"
        )

    # Validate method and cipher IDs
    try:
        method_id = MethodID(method_byte)
    except ValueError:
        raise CorruptEnvelopeError(
            f"Unknown method ID: 0x{method_byte:02X}"
        )

    try:
        cipher_id = CipherID(cipher_byte)
    except ValueError:
        raise CorruptEnvelopeError(
            f"Unknown cipher ID: 0x{cipher_byte:02X}"
        )

    total_needed = ENVELOPE_HEADER_SIZE + payload_len
    if len(data) < total_needed:
        raise CorruptEnvelopeError(
            f"Payload truncated: header says {payload_len:,} bytes, "
            f"but only {len(data) - ENVELOPE_HEADER_SIZE:,} bytes available"
        )

    ciphertext = data[ENVELOPE_HEADER_SIZE:total_needed]

    return EnvelopeData(
        method_id=method_id,
        cipher_id=cipher_id,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def envelope_overhead() -> int:
    """Return the fixed overhead (header size) of the envelope in bytes."""
    return ENVELOPE_HEADER_SIZE


def detect_envelope_in_bytes(data: bytes) -> bool:
    """
    Quick check: does this byte sequence start with the StegoForge magic?

    Used by the analyze command (FR-8) to detect possible payloads.
    """
    return data[:4] == ENVELOPE_MAGIC if len(data) >= 4 else False
