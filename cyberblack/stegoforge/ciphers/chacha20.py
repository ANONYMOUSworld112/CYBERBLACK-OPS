from __future__ import annotations

import os
import argon2
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from stegoforge.ciphers.base import CipherPlugin, register_cipher
from stegoforge.core.contracts import CipherID
from stegoforge.core.exceptions import AuthenticationError, PassphraseRequiredError


class ChaCha20Cipher(CipherPlugin):
    cipher_id = CipherID.CHACHA20_POLY1305
    security_tier = "strong"
    requires_passphrase = True
    name = "ChaCha20-Poly1305"

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        return argon2.low_level.hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=argon2.Type.ID,
        )

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        if not passphrase:
            raise PassphraseRequiredError()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(passphrase, salt)
        chacha = ChaCha20Poly1305(key)
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        return ciphertext, salt, nonce

    def decrypt(
        self,
        ciphertext: bytes,
        passphrase: str = "",
        salt: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        if not passphrase:
            raise PassphraseRequiredError()
        key = self._derive_key(passphrase, salt)
        chacha = ChaCha20Poly1305(key)
        try:
            return chacha.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise AuthenticationError("Invalid passphrase or corrupted data")


chacha20_instance = ChaCha20Cipher()
register_cipher(chacha20_instance)
