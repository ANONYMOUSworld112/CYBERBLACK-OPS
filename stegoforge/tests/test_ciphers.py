"""
Unit tests for all StegoForge Cipher Plugins.
"""

from __future__ import annotations

import pytest

from stegoforge.ciphers.base import get_all_ciphers, get_cipher
from stegoforge.core.exceptions import AuthenticationError, PassphraseRequiredError


@pytest.mark.parametrize("cipher_name", ["aes-256-gcm", "chacha20-poly1305"])
def test_strong_aead_ciphers_roundtrip(cipher_name: str):
    cipher = get_cipher(cipher_name)
    assert cipher is not None

    plaintext = b"Top secret classified message for authorized eyes only 12345!"
    passphrase = "correct_horse_battery_staple_123"

    ciphertext, salt, nonce = cipher.encrypt(plaintext, passphrase)
    assert len(salt) == 16
    assert len(nonce) == 12
    assert ciphertext != plaintext

    decrypted = cipher.decrypt(ciphertext, passphrase, salt, nonce)
    assert decrypted == plaintext


@pytest.mark.parametrize("cipher_name", ["aes-256-gcm", "chacha20-poly1305"])
def test_strong_aead_wrong_passphrase_raises_auth_error(cipher_name: str):
    cipher = get_cipher(cipher_name)
    assert cipher is not None

    plaintext = b"Sensitive information"
    ciphertext, salt, nonce = cipher.encrypt(plaintext, "correct_passphrase")

    with pytest.raises(AuthenticationError):
        cipher.decrypt(ciphertext, "wrong_passphrase", salt, nonce)


@pytest.mark.parametrize("cipher_name", ["aes-256-gcm", "chacha20-poly1305"])
def test_strong_aead_corrupted_ciphertext_raises_auth_error(cipher_name: str):
    cipher = get_cipher(cipher_name)
    assert cipher is not None

    plaintext = b"Sensitive information"
    ciphertext, salt, nonce = cipher.encrypt(plaintext, "mypassword")

    # Corrupt 1 byte in ciphertext
    corrupted = bytearray(ciphertext)
    corrupted[0] ^= 0x01

    with pytest.raises(AuthenticationError):
        cipher.decrypt(bytes(corrupted), "mypassword", salt, nonce)


@pytest.mark.parametrize("cipher_name", ["aes-256-gcm", "chacha20-poly1305"])
def test_empty_passphrase_raises_error(cipher_name: str):
    cipher = get_cipher(cipher_name)
    assert cipher is not None
    with pytest.raises(PassphraseRequiredError):
        cipher.encrypt(b"data", "")


@pytest.mark.parametrize("cipher_name", ["base64", "base85"])
def test_encoding_only_ciphers(cipher_name: str):
    cipher = get_cipher(cipher_name)
    assert cipher is not None
    assert cipher.requires_passphrase is False

    plaintext = b"Payload needing encoding without encryption \x00\xff\xfe"
    ciphertext, salt, nonce = cipher.encrypt(plaintext, "")

    decrypted = cipher.decrypt(ciphertext, "", salt, nonce)
    assert decrypted == plaintext


@pytest.mark.parametrize("cipher_name", ["xor", "caesar", "vigenere", "rail-fence"])
def test_cipher_lab_ciphers_roundtrip(cipher_name: str):
    cipher = get_cipher(cipher_name)
    assert cipher is not None

    plaintext = b"Educational cipher test payload 987654321!"
    passphrase = "secretKey"

    ciphertext, salt, nonce = cipher.encrypt(plaintext, passphrase)
    assert ciphertext != plaintext

    decrypted = cipher.decrypt(ciphertext, passphrase, salt, nonce)
    assert decrypted == plaintext
