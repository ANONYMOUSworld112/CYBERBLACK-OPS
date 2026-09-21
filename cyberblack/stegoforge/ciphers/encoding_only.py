from __future__ import annotations

import base64
from stegoforge.ciphers.base import CipherPlugin, register_cipher
from stegoforge.core.contracts import CipherID


class Base64Encoding(CipherPlugin):
    cipher_id = CipherID.BASE64
    security_tier = "encoding_only"
    requires_passphrase = False
    name = "Base64"

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        ciphertext = base64.b64encode(plaintext)
        return ciphertext, bytes(16), bytes(12)

    def decrypt(
        self,
        ciphertext: bytes,
        passphrase: str = "",
        salt: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        return base64.b64decode(ciphertext)


class Base85Encoding(CipherPlugin):
    cipher_id = CipherID.BASE85
    security_tier = "encoding_only"
    requires_passphrase = False
    name = "Base85"

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        ciphertext = base64.b85encode(plaintext)
        return ciphertext, bytes(16), bytes(12)

    def decrypt(
        self,
        ciphertext: bytes,
        passphrase: str = "",
        salt: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        return base64.b85decode(ciphertext)


base64_instance = Base64Encoding()
register_cipher(base64_instance)

base85_instance = Base85Encoding()
register_cipher(base85_instance)
