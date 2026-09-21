# StegoForge Plugin SDK

StegoForge is designed around the **Strategy Pattern** (§4.3) with two primary extensibility surfaces:
1. `MethodPlugin` — For adding new carrier format steganography methods.
2. `CipherPlugin` — For adding new cryptographic ciphers or encodings.

Adding a new plugin requires **zero changes to core code**.

---

## 1. Writing a Custom `MethodPlugin`

To add a new steganographic carrier method:

```python
from __future__ import annotations
from pathlib import Path
from typing import ClassVar

from stegoforge.core.contracts import CarrierProfile, MethodID
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method

class CustomCarrierMethod(MethodPlugin):
    name: ClassVar[str] = "Custom Format Stego"
    method_id: ClassVar[MethodID] = MethodID.EOF_APPEND  # Or a custom integer ID
    applicable_types: ClassVar[list[str]] = ["application/x-custom"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        """Calculate max embeddable payload capacity in bytes for this carrier."""
        return carrier.size_bytes // 10

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        """Conceal opaque envelope bytes into carrier and save to out_path."""
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)
        
        # Read carrier, inject envelope bytes, write to out_path
        ...

    def extract(self, stego_path: Path | str) -> bytes:
        """Recover opaque envelope bytes from stego_path."""
        stego_path = Path(stego_path)
        
        # Read stego file, extract envelope bytes, return raw bytes
        ...

# Self-registration
custom_method_instance = CustomCarrierMethod()
register_method(custom_method_instance)
```

---

## 2. Writing a Custom `CipherPlugin`

To add a new cipher or encoding:

```python
from __future__ import annotations
from typing import ClassVar, Literal
from stegoforge.core.contracts import CipherID
from stegoforge.ciphers.base import CipherPlugin, register_cipher

class CustomCipher(CipherPlugin):
    name: ClassVar[str] = "Custom-Cipher"
    cipher_id: ClassVar[CipherID] = CipherID.AES_256_GCM
    security_tier: ClassVar[Literal["strong", "encoding_only", "educational_weak"]] = "strong"
    requires_passphrase: ClassVar[bool] = True

    def encrypt(
        self, plaintext: bytes, passphrase: str = ""
    ) -> tuple[bytes, bytes, bytes]:
        """Returns (ciphertext_with_auth_tag, 16_byte_salt, 12_byte_nonce)"""
        ...

    def decrypt(
        self,
        ciphertext: bytes,
        passphrase: str = "",
        salt: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        """Decrypts and validates AEAD tag. Raises AuthenticationError on failure."""
        ...

custom_cipher_instance = CustomCipher()
register_cipher(custom_cipher_instance)
```

---

## 3. Entry Points Registration

In `pyproject.toml`, expose your plugin via entry points:

```toml
[project.entry-points."stegoforge.methods"]
my_custom_method = "my_package.module:CustomCarrierMethod"

[project.entry-points."stegoforge.ciphers"]
my_custom_cipher = "my_package.module:CustomCipher"
```
