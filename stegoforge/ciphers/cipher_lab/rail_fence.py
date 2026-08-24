from __future__ import annotations

from stegoforge.ciphers.base import CipherPlugin, register_cipher
from stegoforge.core.contracts import CipherID
from stegoforge.core.exceptions import PassphraseRequiredError


class RailFenceCipher(CipherPlugin):
    cipher_id = CipherID.RAIL_FENCE
    security_tier = "educational_weak"
    requires_passphrase = True
    name = "Rail Fence"

    def _get_rails(self, passphrase: str) -> int:
        r = sum(ord(c) for c in passphrase)
        return 2 + (r % 7)  # 2 to 8 rails

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        if not passphrase:
            raise PassphraseRequiredError()
        rails = self._get_rails(passphrase)
        if len(plaintext) <= rails or rails <= 1:
            return plaintext, bytes(16), bytes(12)

        fence: list[list[int]] = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for b in plaintext:
            fence[rail].append(b)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1

        ciphertext = bytes(b for row in fence for b in row)
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
        rails = self._get_rails(passphrase)
        if len(ciphertext) <= rails or rails <= 1:
            return ciphertext

        fence_lens = [0] * rails
        rail = 0
        direction = 1
        for _ in range(len(ciphertext)):
            fence_lens[rail] += 1
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1

        fence: list[list[int]] = []
        i = 0
        for l in fence_lens:
            fence.append(list(ciphertext[i : i + l]))
            i += l

        plaintext: list[int] = []
        rail = 0
        direction = 1
        for _ in range(len(ciphertext)):
            plaintext.append(fence[rail].pop(0))
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction *= -1

        return bytes(plaintext)


rail_fence_instance = RailFenceCipher()
register_cipher(rail_fence_instance)
