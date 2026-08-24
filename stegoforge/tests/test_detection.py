"""
Unit tests for Input Detection Agent.
"""

from __future__ import annotations

import io
import wave
import zipfile
from pathlib import Path
from PIL import Image
import pytest

from stegoforge.core.detection import detect
from stegoforge.core.exceptions import UnsupportedFormatError


@pytest.fixture
def temp_carriers(tmp_path: Path):
    # 1. PNG Image
    png_path = tmp_path / "sample.png"
    img = Image.new("RGB", (64, 64), color="blue")
    img.save(png_path, "PNG")

    # 2. JPEG Image
    jpg_path = tmp_path / "sample.jpg"
    img.save(jpg_path, "JPEG")

    # 3. BMP Image
    bmp_path = tmp_path / "sample.bmp"
    img.save(bmp_path, "BMP")

    # 4. WAV Audio
    wav_path = tmp_path / "sample.wav"
    with wave.open(str(wav_path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(b"\x00\x00" * 44100)

    # 5. Plain Text
    txt_path = tmp_path / "sample.txt"
    txt_path.write_text("Line 1: Hello World\nLine 2: StegoForge\nLine 3: Test\n" * 20, encoding="utf-8")

    # 6. ZIP Archive
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("test.txt", "Sample file in zip")

    # 7. Mismatched Extension (PNG file named .jpg)
    mismatch_path = tmp_path / "fake_jpg.jpg"
    img.save(mismatch_path, "PNG")

    return {
        "png": png_path,
        "jpg": jpg_path,
        "bmp": bmp_path,
        "wav": wav_path,
        "txt": txt_path,
        "zip": zip_path,
        "mismatch": mismatch_path,
    }


def test_detection_png(temp_carriers):
    profile = detect(temp_carriers["png"])
    assert profile.mime_type == "image/png"
    assert profile.format_details["width"] == 64
    assert profile.format_details["height"] == 64
    assert profile.extension_mismatch is False


def test_detection_jpg(temp_carriers):
    profile = detect(temp_carriers["jpg"])
    assert profile.mime_type == "image/jpeg"
    assert profile.extension_mismatch is False


def test_detection_bmp(temp_carriers):
    profile = detect(temp_carriers["bmp"])
    assert profile.mime_type == "image/bmp"
    assert profile.extension_mismatch is False


def test_detection_wav(temp_carriers):
    profile = detect(temp_carriers["wav"])
    assert profile.mime_type == "audio/x-wav"
    assert profile.format_details["channels"] == 1
    assert profile.format_details["sample_width"] == 2
    assert profile.format_details["frame_rate"] == 44100


def test_detection_txt(temp_carriers):
    profile = detect(temp_carriers["txt"])
    assert profile.mime_type == "text/plain"
    assert profile.format_details["line_count"] == 60


def test_detection_zip(temp_carriers):
    profile = detect(temp_carriers["zip"])
    assert profile.mime_type == "application/zip"


def test_detection_extension_mismatch(temp_carriers):
    profile = detect(temp_carriers["mismatch"])
    assert profile.mime_type == "image/png"  # Magic detected PNG
    assert profile.extension_mismatch is True  # Warns about mismatch (FR-1)


def test_detection_nonexistent_file(tmp_path: Path):
    with pytest.raises(UnsupportedFormatError):
        detect(tmp_path / "nonexistent.xyz")


def test_detection_empty_file(tmp_path: Path):
    empty_file = tmp_path / "empty.txt"
    empty_file.touch()
    with pytest.raises(UnsupportedFormatError):
        detect(empty_file)
