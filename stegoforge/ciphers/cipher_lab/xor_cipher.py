from __future__ import annotations

from stegoforge.ciphers.base import CipherPlugin, register_cipher
from stegoforge.core.contracts import CipherID
from stegoforge.core.exceptions import PassphraseRequiredError


class XorCipher(CipherPlugin):
    cipher_id = CipherID.XOR
    security_tier = "educational_weak"
    requires_passphrase = True
    name = "XOR"

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        if not passphrase:
            raise PassphraseRequiredError()
        key = passphrase.encode("utf-8")
        ciphertext = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))
        return ciphertext, bytes(16), bytes(12)

    def decrypt(
        self,
        ciphertext: bytes,
        passphrase: str = "",
        salt: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        if not passphrase:
            raise PassphraseRequiredError()
        key = passphrase.encode("utf-8")
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(ciphertext))


xor_instance = XorCipher()
register_cipher(xor_instance)
