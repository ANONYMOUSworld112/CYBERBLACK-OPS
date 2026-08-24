"""
Unit tests for all StegoForge Method Plugins across 7 carrier categories.
"""

from __future__ import annotations

import wave
import zipfile
from pathlib import Path
from PIL import Image
import pytest
from pypdf import PdfWriter

from stegoforge.core.contracts import CipherID, MethodID
from stegoforge.core.detection import detect
from stegoforge.core.envelope import pack, unpack
from stegoforge.core.exceptions import CapacityExceededError
from stegoforge.methods.base import get_method


@pytest.fixture
def test_payload() -> bytes:
    # Pack a sample test envelope
    return pack(
        method_id=MethodID.EOF_APPEND,
        cipher_id=CipherID.AES_256_GCM,
        salt=b"0123456789abcdef",
        nonce=b"123456789012",
        ciphertext=b"SecretHiddenPayloadData12345",
    )


def test_eof_append_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"ArbitraryBinaryContentHeader" * 10)
    output = tmp_path / "stego.bin"

    method = get_method("eof-append")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_lsb_spatial_png_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.png"
    img = Image.new("RGB", (100, 100), color=(128, 128, 128))
    img.save(carrier, "PNG")
    output = tmp_path / "stego.png"

    method = get_method("lsb-spatial")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_lsb_spatial_bmp_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.bmp"
    img = Image.new("RGB", (100, 100), color=(64, 128, 192))
    img.save(carrier, "BMP")
    output = tmp_path / "stego.bmp"

    method = get_method("lsb-spatial")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_dct_jpeg_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.jpg"
    img = Image.new("RGB", (100, 100), color=(200, 100, 50))
    img.save(carrier, "JPEG")
    output = tmp_path / "stego.jpg"

    method = get_method("dct-jpeg")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_lsb_sample_wav_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.wav"
    with wave.open(str(carrier), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(b"\x00\x00" * 44100)  # 1 second = 44,100 samples
    output = tmp_path / "stego.wav"

    method = get_method("lsb-sample")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_whitespace_text_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.txt"
    # Need 1 line per bit -> 8 lines per byte
    lines = [f"This is document line {i}" for i in range(len(test_payload) * 8 + 50)]
    carrier.write_text("\n".join(lines), encoding="utf-8")
    output = tmp_path / "stego.txt"

    method = get_method("whitespace")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_zero_width_text_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.txt"
    carrier.write_text("Hello StegoForge text steganography carrier. " * (len(test_payload) * 2), encoding="utf-8")
    output = tmp_path / "stego.txt"

    method = get_method("zero-width")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_pdf_metadata_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    with open(carrier, "wb") as f:
        writer.write(f)

    output = tmp_path / "stego.pdf"
    method = get_method("pdf-metadata")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_ooxml_part_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.docx"
    with zipfile.ZipFile(carrier, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document></w:document>')

    output = tmp_path / "stego.docx"
    method = get_method("ooxml-part")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_zip_extrafield_method(tmp_path: Path, test_payload: bytes):
    carrier = tmp_path / "carrier.zip"
    with zipfile.ZipFile(carrier, "w") as zf:
        zf.writestr("file1.txt", "Content of file 1")
        zf.writestr("file2.txt", "Content of file 2")

    output = tmp_path / "stego.zip"
    method = get_method("zip-extra-field")
    assert method is not None

    method.embed(carrier, test_payload, output)
    extracted = method.extract(output)

    env_data = unpack(extracted)
    assert env_data.ciphertext == b"SecretHiddenPayloadData12345"


def test_capacity_exceeded_error_raised(tmp_path: Path):
    # Tiny 2x2 image = 4 pixels = 12 channel bytes = max 1 byte capacity (well below 38B envelope)
    carrier = tmp_path / "tiny.png"
    img = Image.new("RGB", (2, 2), color="red")
    img.save(carrier, "PNG")
    output = tmp_path / "stego.png"

    method = get_method("lsb-spatial")
    assert method is not None

    big_payload = b"A" * 500
    with pytest.raises(CapacityExceededError):
        method.embed(carrier, big_payload, output)
