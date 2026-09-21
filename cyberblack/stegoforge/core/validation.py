"""
StegoForge Integrity/Validation Agent — verifies AEAD auth tags on extract.

Wraps the AEAD tag verification step.  On failure, raises a typed
AuthenticationError with a clear message — never silently returns garbage
(FR-6, ADR-007).
"""

from __future__ import annotations

from stegoforge.ciphers.base import get_cipher_by_id
from stegoforge.core.contracts import EnvelopeData
from stegoforge.core.exceptions import AuthenticationError, CorruptEnvelopeError


def validate_and_decrypt(envelope: EnvelopeData, passphrase: str) -> bytes:
    """
    Decrypt and validate an extracted envelope's payload.

    Looks up the cipher by ID, derives the key from passphrase + salt,
    decrypts, and verifies the AEAD auth tag.

    Args:
        envelope: Parsed EnvelopeData from the Envelope Agent.
        passphrase: Operator-supplied passphrase.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        AuthenticationError: Wrong passphrase or corrupted data.
        CorruptEnvelopeError: Unknown cipher ID.
    """
    cipher = get_cipher_by_id(envelope.cipher_id)
    if cipher is None:
        raise CorruptEnvelopeError(
            f"Unknown cipher ID in envelope: 0x{envelope.cipher_id:02X}"
        )

    try:
        plaintext = cipher.decrypt(
            ciphertext=envelope.ciphertext,
            passphrase=passphrase,
            salt=envelope.salt,
            nonce=envelope.nonce,
        )
    except AuthenticationError:
        raise  # Re-raise as-is — it's already the right type
    except Exception as e:
        # Wrap any unexpected cipher error into AuthenticationError
        # since the most likely cause is wrong passphrase
        raise AuthenticationError(str(e)) from e

    return plaintext


def compute_integrity_tag(data: bytes) -> str:
    """
    Compute a short integrity tag the operator can use to verify a payload.

    This is displayed after embed and can be checked against after extract.
    Uses first 8 hex chars of SHA-256 — short enough to compare visually.

    Args:
        data: The plaintext payload bytes.

    Returns:
        8-character hex string (e.g. "a3f8c912").
    """
    import hashlib

    return hashlib.sha256(data).hexdigest()[:8]
