"""
Hypothesis property-based fuzz tests and corruption resilience tests.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest
from hypothesis import given, settings, strategies as st

from stegoforge.ciphers.base import get_cipher
from stegoforge.core.contracts import CipherID, MethodID
from stegoforge.core.envelope import pack, unpack
from stegoforge.core.exceptions import AuthenticationError
from stegoforge.methods.base import get_method


@given(
    payload=st.binary(min_size=1, max_size=4096),
    passphrase=st.text(min_size=1, max_size=64),
)
@settings(max_examples=30, deadline=None)
def test_fuzz_aes_gcm_roundtrip(payload: bytes, passphrase: str):
    cipher = get_cipher("aes-256-gcm")
    assert cipher is not None

    ciphertext, salt, nonce = cipher.encrypt(payload, passphrase)
    decrypted = cipher.decrypt(ciphertext, passphrase, salt, nonce)
    assert decrypted == payload


@given(
    payload=st.binary(min_size=1, max_size=4096),
    passphrase=st.text(min_size=1, max_size=64),
)
@settings(max_examples=30, deadline=None)
def test_fuzz_chacha20_roundtrip(payload: bytes, passphrase: str):
    cipher = get_cipher("chacha20-poly1305")
    assert cipher is not None

    ciphertext, salt, nonce = cipher.encrypt(payload, passphrase)
    decrypted = cipher.decrypt(ciphertext, passphrase, salt, nonce)
    assert decrypted == payload


@given(
    payload=st.binary(min_size=1, max_size=2048),
    passphrase=st.text(min_size=1, max_size=32),
)
@settings(max_examples=25, deadline=None)
def test_fuzz_bit_flip_corruption_resilience(payload: bytes, passphrase: str):
    """
    Deliberately flip a random bit in the ciphertext and assert that
    AEAD raises AuthenticationError (never silent corruption).
    """
    cipher = get_cipher("aes-256-gcm")
    assert cipher is not None

    ciphertext, salt, nonce = cipher.encrypt(payload, passphrase)
    assert len(ciphertext) > 0

    # Flip 1 bit in ciphertext
    corrupted = bytearray(ciphertext)
    flip_idx = os.urandom(1)[0] % len(corrupted)
    flip_bit = 1 << (os.urandom(1)[0] % 8)
    corrupted[flip_idx] ^= flip_bit

    with pytest.raises(AuthenticationError):
        cipher.decrypt(bytes(corrupted), passphrase, salt, nonce)


@given(
    payload=st.binary(min_size=1, max_size=2048),
)
@settings(max_examples=20, deadline=None)
def test_fuzz_eof_append_carrier(tmp_path_factory, payload: bytes):
    tmp_path = tmp_path_factory.mktemp("fuzz_eof")
    carrier = tmp_path / "carrier.dat"
    carrier.write_bytes(b"HeaderData12345" * 10)
    output = tmp_path / "stego.dat"

    env = pack(
        method_id=MethodID.EOF_APPEND,
        cipher_id=CipherID.BASE64,
        salt=b"0" * 16,
        nonce=b"0" * 12,
        ciphertext=payload,
    )

    method = get_method("eof-append")
    assert method is not None

    method.embed(carrier, env, output)
    extracted = method.extract(output)
    env_data = unpack(extracted)
    assert env_data.ciphertext == payload
