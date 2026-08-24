"""
Unit and integration tests for StegoForge Advanced Features:
- Visual Quality Analysis (PSNR, SSIM, MSE)
- Defensive Steganalysis (Entropy, Chi-Square, Signatures)
- Digital Watermarking (HMAC-SHA256, Embed, Verify, Tamper Detection)
- Explainable Algorithm Recommender & Capacity Calculator
- Stego Lab Benchmarking
- Multi-Payload & Compressed Full Pipeline Round-Trips
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
from PIL import Image
import pytest

from stegoforge.cli.lab import run_stego_lab
from stegoforge.cli.orchestrator import (
    embed_operation,
    extract_operation,
    steganalysis_operation,
    watermark_embed_operation,
    watermark_verify_operation,
)
from stegoforge.core.bundle import PayloadObject, create_payload_from_text
from stegoforge.core.detection import detect
from stegoforge.core.quality import (
    analyze_image_quality,
    compute_mse,
    compute_psnr,
    compute_ssim,
)
from stegoforge.core.recommender import evaluate_and_recommend
from stegoforge.core.steganalysis import (
    calculate_block_entropy,
    calculate_shannon_entropy,
    scan_known_stego_signatures,
)
from stegoforge.core.watermark import (
    create_watermark_envelope,
    parse_and_verify_watermark,
)


# ---------------------------------------------------------------------------
# Visual Quality Tests
# ---------------------------------------------------------------------------

def test_visual_quality_identical_images():
    arr = np.ones((50, 50, 3), dtype=np.uint8) * 128
    mse = compute_mse(arr, arr)
    psnr = compute_psnr(arr, arr)
    ssim = compute_ssim(arr, arr)

    assert mse == 0.0
    assert psnr >= 100.0
    assert ssim == 1.0


def test_visual_quality_perturbed_images(tmp_path: Path):
    c_path = tmp_path / "carrier.png"
    s_path = tmp_path / "stego.png"

    img1 = Image.new("RGB", (60, 60), color=(100, 150, 200))
    img1.save(c_path)

    # Slight perturbation (1 LSB flip)
    arr = np.array(img1)
    arr[0, 0, 0] ^= 1
    Image.fromarray(arr).save(s_path)

    metrics = analyze_image_quality(c_path, s_path)
    assert metrics["psnr_db"] > 45.0
    assert metrics["ssim"] > 0.999
    assert metrics["changed_pixels_count"] == 1


# ---------------------------------------------------------------------------
# Defensive Steganalysis Tests
# ---------------------------------------------------------------------------

def test_shannon_entropy():
    zeros = b"\x00" * 1000
    assert calculate_shannon_entropy(zeros) == 0.0

    # Uniform random bytes should have entropy close to 8.0
    uniform = bytes(range(256)) * 10
    assert calculate_shannon_entropy(uniform) >= 7.99


def test_signature_scanner():
    data = b"Some innocent prefix... SGF1\x01\x01... trailing"
    sigs = scan_known_stego_signatures(data)
    assert len(sigs) >= 1
    assert "StegoForge" in sigs[0]


def test_steganalysis_on_stego_file(tmp_path: Path):
    carrier = tmp_path / "cover.png"
    img = Image.new("RGB", (80, 80), color=(80, 120, 160))
    img.save(carrier, "PNG")

    stego = tmp_path / "stego.png"
    embed_operation(
        carrier_path=carrier,
        method_name="lsb-spatial",
        cipher_name="aes-256-gcm",
        payload=b"High entropy secret payload " * 10,
        passphrase="secure-passphrase",
        output_path=stego,
    )

    report = steganalysis_operation(stego)
    assert report.file_size > 0
    assert report.global_entropy > 0.0
    assert report.suspicion_score >= 0


# ---------------------------------------------------------------------------
# Digital Watermarking Tests
# ---------------------------------------------------------------------------

def test_watermark_generation_and_verification():
    owner = "ACME Cyber Defense"
    key = "super-secret-signing-key-123"
    desc = "Proprietary Threat Intelligence Report"

    wm_env = create_watermark_envelope(owner, key, desc)
    report = parse_and_verify_watermark(wm_env, key)

    assert report.detected is True
    assert report.signature_valid is True
    assert report.owner == owner
    assert report.description == desc
    assert report.tampered is False


def test_watermark_wrong_key_fails():
    wm_env = create_watermark_envelope("OwnerA", "keyA", "Desc")
    report = parse_and_verify_watermark(wm_env, "wrong-key")

    assert report.detected is True
    assert report.signature_valid is False
    assert report.tampered is True


def test_watermark_carrier_embed_and_verify(tmp_path: Path):
    carrier = tmp_path / "asset.png"
    img = Image.new("RGB", (100, 100), color=(50, 100, 150))
    img.save(carrier, "PNG")

    watermarked_out = tmp_path / "watermarked_asset.png"
    out_path, method_used = watermark_embed_operation(
        carrier_path=carrier,
        owner="Security Operations Center",
        secret_key="ops-watermark-key",
        description="Confidential SOC Assessment",
        output_path=watermarked_out,
    )

    assert out_path.exists()

    rep = watermark_verify_operation(
        stego_path=watermarked_out,
        secret_key="ops-watermark-key",
    )
    assert rep.detected is True
    assert rep.signature_valid is True
    assert rep.owner == "Security Operations Center"


# ---------------------------------------------------------------------------
# Recommender & Capacity Calculator Tests
# ---------------------------------------------------------------------------

def test_recommender_png_carrier(tmp_path: Path):
    carrier = tmp_path / "test.png"
    img = Image.new("RGB", (200, 200), color=(100, 100, 100))
    img.save(carrier, "PNG")

    profile = detect(carrier)
    rec = evaluate_and_recommend(profile, payload_size_bytes=500, security_goal="high")

    assert rec.fits is True
    assert rec.recommended_method == "lsb-spatial"
    assert rec.recommended_cipher == "aes-256-gcm"
    assert rec.safety_margin_pct > 0.0
    assert "Lossless" in rec.explanation or "LSB" in rec.explanation


# ---------------------------------------------------------------------------
# Stego Lab Benchmark Tests
# ---------------------------------------------------------------------------

def test_stego_lab_run(tmp_path: Path):
    carrier = tmp_path / "lab_carrier.png"
    img = Image.new("RGB", (100, 100), color=(120, 140, 160))
    img.save(carrier, "PNG")

    results = run_stego_lab(carrier)
    assert len(results) >= 1
    # At least lsb-spatial or eof-append should PASS
    passing = [r for r in results if r["integrity"] == "PASS"]
    assert len(passing) >= 1


# ---------------------------------------------------------------------------
# Multi-Payload Bundle + Compression End-to-End Round Trip
# ---------------------------------------------------------------------------

def test_multi_payload_bundle_with_compression(tmp_path: Path):
    carrier = tmp_path / "carrier.png"
    img = Image.new("RGB", (150, 150), color=(70, 90, 110))
    img.save(carrier, "PNG")

    p1 = create_payload_from_text("Sensitive report content: " * 20, name="report.txt")
    p2 = create_payload_from_text('{"token": "xyz987"}', name="config.json")

    stego = tmp_path / "multi_stego.png"
    out_dir = tmp_path / "unpacked_output"

    res = embed_operation(
        carrier_path=carrier,
        method_name="lsb-spatial",
        cipher_name="aes-256-gcm",
        payload=[p1, p2],
        passphrase="bundle-test-passphrase",
        output_path=stego,
        compression="auto",
    )
    assert res.success is True

    recovered, ext_res = extract_operation(
        stego_path=stego,
        passphrase="bundle-test-passphrase",
        output_dir=out_dir,
    )
    assert ext_res.success is True
    assert isinstance(recovered, list)
    assert len(recovered) == 2
    assert recovered[0].name == "report.txt"
    assert recovered[0].data == p1.data
    assert recovered[1].name == "config.json"
    assert recovered[1].data == p2.data

    # Verify extracted on disk
    assert (out_dir / "report.txt").read_bytes() == p1.data
    assert (out_dir / "config.json").read_bytes() == p2.data
