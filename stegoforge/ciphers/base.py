"""
StegoForge Cipher Plugin Interface — the extensibility surface for ciphers.

Every cipher/encoding handler implements this ABC.  The cipher layer is
fully decoupled from the steg method (§2.4, FR-4): any cipher can pair
with any method.  The cipher transforms plaintext → ciphertext blob;
the steg layer only ever sees an opaque byte blob to conceal.

Spec reference: §4.3 Plugin Architecture (Strategy Pattern)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Literal

from stegoforge.core.contracts import CipherID


class CipherPlugin(ABC):
    """
    Abstract base for all cipher/encoding plugins.

    Subclasses MUST define:
        name: Human-readable name (e.g. 'AES-256-GCM').
        cipher_id: Unique CipherID enum value stored in the envelope.
        security_tier: One of 'strong', 'encoding_only', 'educational_weak'.
        requires_passphrase: Whether a passphrase is needed.

    Subclasses MUST implement:
        encrypt(): Transform plaintext bytes into ciphertext.
        decrypt(): Reverse the transformation.
    """

    name: ClassVar[str]
    cipher_id: ClassVar[CipherID]
    security_tier: ClassVar[Literal["strong", "encoding_only", "educational_weak"]]
    requires_passphrase: ClassVar[bool] = True

    @abstractmethod
    def encrypt(
        self, plaintext: bytes, passphrase: str
    ) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext using the given passphrase.

        Args:
            plaintext: Raw payload bytes.
            passphrase: Operator-supplied passphrase (may be empty for
                encoding-only modes).

        Returns:
            Tuple of (ciphertext_with_tag, salt, nonce).
            - For AEAD ciphers: ciphertext includes the auth tag appended.
            - For encoding-only: salt and nonce may be zero-filled placeholders.
            - For educational ciphers: salt/nonce are passphrase-derived placeholders.
        """
        ...

    @abstractmethod
    def decrypt(
        self,
        ciphertext: bytes,
        passphrase: str,
        salt: bytes,
        nonce: bytes,
    ) -> bytes:
        """
        Decrypt ciphertext using the given passphrase, salt, and nonce.

        Args:
            ciphertext: Encrypted payload (may include auth tag).
            passphrase: Operator-supplied passphrase.
            salt: Salt from the envelope (for KDF).
            nonce: Nonce from the envelope (for AEAD).

        Returns:
            Decrypted plaintext bytes.

        Raises:
            AuthenticationError: If AEAD tag verification fails
                (wrong passphrase or corrupted data).
        """
        ...


# ---------------------------------------------------------------------------
# Plugin Registry
# ---------------------------------------------------------------------------

_CIPHER_REGISTRY: dict[str, CipherPlugin] = {}


def register_cipher(plugin: CipherPlugin) -> None:
    """Register a cipher plugin instance in the global registry."""
    key = plugin.name.lower().replace(" ", "-").replace("_", "-")
    _CIPHER_REGISTRY[key] = plugin


def get_cipher(name: str) -> CipherPlugin | None:
    """Look up a registered cipher by its registry key."""
    return _CIPHER_REGISTRY.get(name.lower().replace(" ", "-").replace("_", "-"))


def get_all_ciphers() -> dict[str, CipherPlugin]:
    """Return a copy of the full cipher registry."""
    return dict(_CIPHER_REGISTRY)


def get_cipher_by_id(cipher_id: CipherID) -> CipherPlugin | None:
    """Look up a registered cipher by its CipherID enum value."""
    for plugin in _CIPHER_REGISTRY.values():
        if plugin.cipher_id == cipher_id:
            return plugin
    return None


def get_strong_ciphers() -> list[CipherPlugin]:
    """Return all ciphers with 'strong' security tier."""
    return [c for c in _CIPHER_REGISTRY.values() if c.security_tier == "strong"]


def get_cipher_lab_ciphers() -> list[CipherPlugin]:
    """Return all ciphers that require Cipher Lab mode (weak/educational)."""
    return [
        c for c in _CIPHER_REGISTRY.values()
        if c.security_tier == "educational_weak"
    ]
