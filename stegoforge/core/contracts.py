"""
StegoForge Core Contracts — Typed, immutable dataclasses shared across all agents.

All inter-agent data passes as these contract objects (never raw dicts).
No agent reaches into another agent's internals; they only exchange these.
This is what makes the plugin system possible without core changes.

Spec reference: §3.3 Agent Communication Contract
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class OperationType(StrEnum):
    """Types of operations StegoForge can perform."""
    EMBED = "embed"
    EXTRACT = "extract"
    ANALYZE = "analyze"


class SecurityTier(StrEnum):
    """Security classification for cipher plugins (§2.4)."""
    STRONG = "strong"
    ENCODING_ONLY = "encoding_only"
    EDUCATIONAL_WEAK = "educational_weak"


class MethodID(IntEnum):
    """Unique 1-byte identifiers for steg methods, stored in the envelope."""
    EOF_APPEND = 0x01
    LSB_SPATIAL = 0x10
    DCT_JPEG = 0x11
    PALETTE_LSB = 0x12
    LSB_SAMPLE = 0x20
    ECHO_HIDE = 0x21
    PHASE_CODING = 0x22
    WHITESPACE = 0x30
    ZERO_WIDTH = 0x31
    PDF_METADATA = 0x40
    PDF_OBJECT_STREAM = 0x41
    OOXML_PART = 0x50
    ZIP_EXTRA_FIELD = 0x60


class CipherID(IntEnum):
    """Unique 1-byte identifiers for cipher plugins, stored in the envelope."""
    AES_256_GCM = 0x01
    CHACHA20_POLY1305 = 0x02
    BASE64 = 0x10
    BASE85 = 0x11
    XOR = 0x20
    CAESAR = 0x21
    VIGENERE = 0x22
    RAIL_FENCE = 0x23
    NONE = 0x00  # For encoding-only modes that need no passphrase


# ---------------------------------------------------------------------------
# Data Contracts (frozen / immutable)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CarrierProfile:
    """
    Result of the Input Detection Agent's analysis of a carrier file.

    Attributes:
        file_path: Absolute path to the carrier file.
        mime_type: Detected MIME type (e.g. 'image/png', 'audio/x-wav').
        extension: File extension as detected (lowercase, with dot).
        size_bytes: Total file size in bytes.
        format_details: Format-specific metadata (e.g. image dimensions,
            audio sample rate). Keys are format-dependent.
        extension_mismatch: True if detected MIME doesn't match extension.
    """
    file_path: Path
    mime_type: str
    extension: str
    size_bytes: int
    format_details: dict[str, Any] = field(default_factory=dict)
    extension_mismatch: bool = False


@dataclass(frozen=True)
class MethodOption:
    """
    A single available steganographic method for a given carrier,
    as returned by the Method Advisor Agent.

    Attributes:
        name: Human-readable method name (e.g. 'LSB Spatial').
        method_id: Enum identifier stored in the envelope.
        capacity_bytes: Maximum payload capacity in bytes for this carrier.
        notes: Operator-facing notes about robustness/tradeoffs.
        plugin_name: Internal plugin registry key.
    """
    name: str
    method_id: MethodID
    capacity_bytes: int
    notes: str
    plugin_name: str


@dataclass(frozen=True)
class OperationResult:
    """
    Outcome of an embed/extract/analyze operation.

    Attributes:
        success: Whether the operation completed successfully.
        operation: The type of operation performed.
        method_name: Name of the steg method used.
        cipher_name: Name of the cipher used.
        integrity_tag: Short hex string the operator can use for verification.
        output_path: Path to the output file (embed) or extracted payload.
        payload_size: Size of the payload in bytes.
        message: Human-readable summary of the result.
    """
    success: bool
    operation: OperationType
    method_name: str = ""
    cipher_name: str = ""
    integrity_tag: str = ""
    output_path: Path | None = None
    payload_size: int = 0
    message: str = ""


@dataclass(frozen=True)
class EnvelopeData:
    """
    Parsed contents of a StegoForge envelope (§2.5).

    Used as the intermediate representation between the Envelope Agent
    and the Cipher/Validation agents during extraction.

    Attributes:
        method_id: Which steg method was used.
        cipher_id: Which cipher was used.
        salt: Argon2id salt for key derivation (16 bytes).
        nonce: AEAD nonce (12 bytes).
        ciphertext: Encrypted payload including auth tag.
    """
    method_id: MethodID
    cipher_id: CipherID
    salt: bytes
    nonce: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class AuditEntry:
    """
    A single audit log record (§2.7).

    Attributes:
        timestamp: ISO 8601 timestamp.
        operation: embed/extract/analyze.
        input_hash: SHA-256 hex digest of the input file (not content of payload).
        method_name: Name of the steg method used.
        cipher_name: Name of the cipher used.
        success: Whether the operation succeeded.
        error_message: If failed, the error description (never contains secrets).
    """
    timestamp: str
    operation: str
    input_hash: str
    method_name: str
    cipher_name: str
    success: bool
    error_message: str = ""


# ---------------------------------------------------------------------------
# Envelope constants (§2.5)
# ---------------------------------------------------------------------------

ENVELOPE_MAGIC = b"SGF1"
ENVELOPE_HEADER_SIZE = (
    4   # MAGIC
    + 1  # METHOD_ID
    + 1  # CIPHER_ID
    + 16  # SALT
    + 12  # NONCE
    + 4  # PAYLOAD_LEN (uint32 LE)
)  # = 38 bytes total header
