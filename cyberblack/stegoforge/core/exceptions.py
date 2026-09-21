"""
StegoForge Exceptions — Typed, specific error hierarchy.

All errors are typed exceptions — never bare `except: pass` (§2.7).
Each exception carries enough context for the CLI to give the operator
an actionable, non-cryptic error message.
"""

from __future__ import annotations


class StegoForgeError(Exception):
    """Base exception for all StegoForge errors."""


class CapacityExceededError(StegoForgeError):
    """
    Payload is too large for the chosen carrier + method combination.

    Attributes:
        payload_size: Size of the payload (envelope) in bytes.
        capacity: Available capacity in the carrier for this method.
        shortfall: How many bytes over capacity.
    """

    def __init__(
        self, payload_size: int, capacity: int, method_name: str = ""
    ) -> None:
        self.payload_size = payload_size
        self.capacity = capacity
        self.shortfall = payload_size - capacity
        self.method_name = method_name
        msg = (
            f"Payload is {self.payload_size:,} bytes but "
            f"{method_name or 'this method'} only has capacity for "
            f"{self.capacity:,} bytes (short by {self.shortfall:,} bytes)."
        )
        super().__init__(msg)


class AuthenticationError(StegoForgeError):
    """
    AEAD authentication tag verification failed.

    This means either: (a) wrong passphrase, or (b) the carrier/envelope
    was corrupted after embedding.  StegoForge never silently returns
    garbage — it raises this instead.
    """

    def __init__(self, detail: str = "") -> None:
        msg = "Authentication failed: wrong passphrase or corrupted data."
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


class UnsupportedFormatError(StegoForgeError):
    """
    No method plugin can handle the detected file type.

    Note: EOF-append is a universal fallback, so this typically only fires
    if the file can't even be read (corrupt, zero-byte, etc.).
    """

    def __init__(self, mime_type: str = "", file_path: str = "") -> None:
        self.mime_type = mime_type
        self.file_path = file_path
        msg = f"No steganographic method available for type '{mime_type}'"
        if file_path:
            msg += f" (file: {file_path})"
        msg += "."
        super().__init__(msg)


class CorruptEnvelopeError(StegoForgeError):
    """
    The StegoForge envelope could not be parsed.

    Possible causes: magic bytes missing/wrong, truncated header,
    payload length exceeds remaining data, or the file simply doesn't
    contain a StegoForge payload.
    """

    def __init__(self, detail: str = "") -> None:
        msg = "Corrupt or missing StegoForge envelope."
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


class CipherLabRequiredError(StegoForgeError):
    """
    Operator selected a weak/educational cipher without enabling Cipher Lab mode.

    This is a guardrail, not a bug — weak ciphers require explicit opt-in
    via --cipher-lab flag (ADR-004).
    """

    def __init__(self, cipher_name: str = "") -> None:
        msg = (
            f"Cipher '{cipher_name}' is classified as educational/weak. "
            f"Enable Cipher Lab mode with --cipher-lab to use it. "
            f"This cipher provides NO real security — it's for learning only."
        )
        super().__init__(msg)


class PassphraseRequiredError(StegoForgeError):
    """Raised when a strong cipher is selected but no passphrase is provided."""

    def __init__(self) -> None:
        super().__init__(
            "A passphrase is required for this cipher. "
            "Use the interactive prompt or --passphrase-env to provide one."
        )
