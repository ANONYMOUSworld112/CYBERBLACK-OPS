"""
Integration and End-to-End Tests for StegoForge pipeline.
"""

from __future__ import annotations

import wave
import zipfile
from pathlib import Path
from PIL import Image
import pytest
from typer.testing import CliRunner

from stegoforge.cli.commands import app
from stegoforge.cli.orchestrator import analyze_operation, embed_operation, extract_operation
from stegoforge.core.exceptions import AuthenticationError


@pytest.fixture
def sample_png(tmp_path: Path) -> Path:
    p = tmp_path / "carrier.png"
    img = Image.new("RGB", (120, 120), color=(100, 150, 200))
    img.save(p, "PNG")
    return p


@pytest.fixture
def sample_wav(tmp_path: Path) -> Path:
    p = tmp_path / "carrier.wav"
    with wave.open(str(p), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(b"\x00\x00" * 44100)
    return p


@pytest.fixture
def sample_docx(tmp_path: Path) -> Path:
    p = tmp_path / "carrier.docx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document></w:document>')
    return p


def test_e2e_png_aes_gcm(sample_png: Path, tmp_path: Path):
    secret_text = b"Classified secret message #42! Sensitive operations plan."
    passphrase = "UltraSecurePassphrase_999!"
    out_file = tmp_path / "stego_result.png"

    # 1. Embed with AES-256-GCM
    res_embed = embed_operation(
        carrier_path=sample_png,
        method_name="lsb-spatial",
        cipher_name="aes-256-gcm",
        payload=secret_text,
        passphrase=passphrase,
        output_path=out_file,
        verify=True,
    )
    assert res_embed.success is True
    assert res_embed.integrity_tag != ""

    # 2. Analyze the stego file -> should detect StegoForge payload
    report = analyze_operation(out_file)
    assert report["has_stegoforge_payload"] is True

    # 3. Extract with auto-detect method
    extracted, res_extract = extract_operation(
        stego_path=out_file,
        passphrase=passphrase,
        method_name=None,  # Auto-detect
    )
    assert res_extract.success is True
    assert extracted == secret_text
    assert res_extract.integrity_tag == res_embed.integrity_tag


def test_e2e_wrong_passphrase_fails(sample_png: Path, tmp_path: Path):
    secret_text = b"Secret data"
    out_file = tmp_path / "stego.png"

    embed_operation(
        carrier_path=sample_png,
        method_name="lsb-spatial",
        cipher_name="aes-256-gcm",
        payload=secret_text,
        passphrase="correct_passphrase",
        output_path=out_file,
        verify=True,
    )

    with pytest.raises(AuthenticationError):
        extract_operation(
            stego_path=out_file,
            passphrase="wrong_passphrase",
            method_name=None,
        )


def test_e2e_wav_chacha20(sample_wav: Path, tmp_path: Path):
    secret_text = b"Audio covert channel payload transmission verified."
    passphrase = "WavPassphrase123"
    out_file = tmp_path / "stego_audio.wav"

    embed_operation(
        carrier_path=sample_wav,
        method_name="lsb-sample",
        cipher_name="chacha20-poly1305",
        payload=secret_text,
        passphrase=passphrase,
        output_path=out_file,
        verify=True,
    )

    extracted, res = extract_operation(
        stego_path=out_file,
        passphrase=passphrase,
        method_name=None,
    )
    assert extracted == secret_text


def test_e2e_docx_base85(sample_docx: Path, tmp_path: Path):
    secret_text = b"Office Open XML covert data stream."
    out_file = tmp_path / "stego_doc.docx"

    embed_operation(
        carrier_path=sample_docx,
        method_name="ooxml-part",
        cipher_name="base85",
        payload=secret_text,
        output_path=out_file,
        verify=True,
    )

    extracted, res = extract_operation(
        stego_path=out_file,
        passphrase="",
        method_name=None,
    )
    assert extracted == secret_text


def test_cli_runner_embed_and_extract(sample_png: Path, tmp_path: Path, monkeypatch):
    runner = CliRunner()
    monkeypatch.setenv("TEST_PASS", "CliSecretPass123")
    out_stego = tmp_path / "cli_stego.png"
    out_payload = tmp_path / "cli_extracted.txt"

    # Embed command
    result_embed = runner.invoke(app, [
        "embed",
        "-i", str(sample_png),
        "-o", str(out_stego),
        "-m", "lsb-spatial",
        "-c", "aes-256-gcm",
        "--payload-text", "Hello from Typer CLI test!",
        "--passphrase-env", "TEST_PASS",
        "--yes",
    ])
    assert result_embed.exit_code == 0
    assert "Embedding Successful" in result_embed.output

    # Extract command
    result_extract = runner.invoke(app, [
        "extract",
        "-i", str(out_stego),
        "-o", str(out_payload),
        "--passphrase-env", "TEST_PASS",
    ])
    assert result_extract.exit_code == 0
    assert "Extraction Successful" in result_extract.output
    assert out_payload.read_text(encoding="utf-8") == "Hello from Typer CLI test!"
