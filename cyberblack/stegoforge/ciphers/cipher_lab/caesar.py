from __future__ import annotations

from stegoforge.ciphers.base import CipherPlugin, register_cipher
from stegoforge.core.contracts import CipherID
from stegoforge.core.exceptions import PassphraseRequiredError


class CaesarCipher(CipherPlugin):
    cipher_id = CipherID.CAESAR
    security_tier = "educational_weak"
    requires_passphrase = True
    name = "Caesar"

    def _get_shift(self, passphrase: str) -> int:
        return sum(ord(c) for c in passphrase) % 256

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        if not passphrase:
            raise PassphraseRequiredError()
        shift = self._get_shift(passphrase)
        ciphertext = bytes((b + shift) % 256 for b in plaintext)
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
        shift = self._get_shift(passphrase)
        return bytes((b - shift) % 256 for b in ciphertext)


caesar_instance = CaesarCipher()
register_cipher(caesar_instance)
