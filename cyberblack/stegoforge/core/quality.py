"""
StegoForge Visual Quality & Distortion Analysis Engine.

Calculates PSNR (Peak Signal-to-Noise Ratio), SSIM (Structural Similarity Index),
MSE (Mean Squared Error), and histogram divergence between original carrier and stego assets.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image


def compute_mse(arr1: np.ndarray, arr2: np.ndarray) -> float:
    """Compute Mean Squared Error between two numpy image arrays."""
    if arr1.shape != arr2.shape:
        raise ValueError(f"Array shapes must match: {arr1.shape} vs {arr2.shape}")
    diff = arr1.astype(np.float64) - arr2.astype(np.float64)
    return float(np.mean(diff**2))


def compute_psnr(arr1: np.ndarray, arr2: np.ndarray, max_val: float = 255.0) -> float:
    """
    Compute Peak Signal-to-Noise Ratio in dB.
    Returns 100.0 dB if images are identical (infinite PSNR capped for reporting).
    """
    mse = compute_mse(arr1, arr2)
    if mse == 0:
        return 100.0
    return float(20.0 * math.log10(max_val) - 10.0 * math.log10(mse))


def compute_ssim(arr1: np.ndarray, arr2: np.ndarray) -> float:
    """
    Compute Structural Similarity Index (SSIM) between two image arrays.
    Returns float in range [-1, 1], where 1.0 indicates perfect structural identity.
    """
    if arr1.shape != arr2.shape:
        raise ValueError(f"Array shapes must match: {arr1.shape} vs {arr2.shape}")

    # Convert to grayscale if 3D
    if arr1.ndim == 3:
        # standard RGB to Luminance weights
        if arr1.shape[2] >= 3:
            img1 = 0.2989 * arr1[:, :, 0] + 0.5870 * arr1[:, :, 1] + 0.1140 * arr1[:, :, 2]
            img2 = 0.2989 * arr2[:, :, 0] + 0.5870 * arr2[:, :, 1] + 0.1140 * arr2[:, :, 2]
        else:
            img1 = arr1[:, :, 0].astype(np.float64)
            img2 = arr2[:, :, 0].astype(np.float64)
    else:
        img1 = arr1.astype(np.float64)
        img2 = arr2.astype(np.float64)

    # Constants for numerical stability
    k1 = 0.01
    k2 = 0.03
    l = 255.0
    c1 = (k1 * l) ** 2
    c2 = (k2 * l) ** 2

    mu1 = np.mean(img1)
    mu2 = np.mean(img2)
    var1 = np.var(img1)
    var2 = np.var(img2)
    cov12 = np.mean((img1 - mu1) * (img2 - mu2))

    numerator = (2.0 * mu1 * mu2 + c1) * (2.0 * cov12 + c2)
    denominator = (mu1**2 + mu2**2 + c1) * (var1 + var2 + c2)

    ssim_val = float(numerator / denominator)
    return max(-1.0, min(1.0, ssim_val))


def analyze_image_quality(carrier_path: Path | str, stego_path: Path | str) -> dict[str, Any]:
    """
    Perform full image distortion and quality assessment.

    Args:
        carrier_path: Original clean carrier image file.
        stego_path: Embedded stego image file.

    Returns:
        dict containing psnr_db, ssim, mse, max_pixel_diff, modified_pixels_pct, distortion_rating.
    """
    c_path = Path(carrier_path).resolve()
    s_path = Path(stego_path).resolve()

    if not c_path.exists() or not s_path.exists():
        raise FileNotFoundError("Carrier or stego file not found for quality analysis")

    with Image.open(c_path) as c_img, Image.open(s_path) as s_img:
        c_arr = np.array(c_img.convert("RGB"), dtype=np.uint8)
        s_arr = np.array(s_img.convert("RGB"), dtype=np.uint8)

    if c_arr.shape != s_arr.shape:
        return {
            "error": "Image dimensions or color channels do not match",
            "psnr_db": 0.0,
            "ssim": 0.0,
            "distortion_rating": "HIGH",
        }

    mse = compute_mse(c_arr, s_arr)
    psnr = compute_psnr(c_arr, s_arr)
    ssim = compute_ssim(c_arr, s_arr)

    diff = np.abs(c_arr.astype(int) - s_arr.astype(int))
    max_diff = int(np.max(diff))
    changed_pixels = int(np.count_nonzero(np.sum(diff, axis=2)))
    total_pixels = c_arr.shape[0] * c_arr.shape[1]
    pct_changed = float((changed_pixels / total_pixels) * 100.0) if total_pixels > 0 else 0.0

    # Categorize distortion
    if psnr >= 50.0 and ssim >= 0.999:
        rating = "NEGLIGIBLE / INVISIBLE"
    elif psnr >= 40.0 and ssim >= 0.99:
        rating = "VERY LOW"
    elif psnr >= 30.0 and ssim >= 0.95:
        rating = "LOW TO MODERATE"
    else:
        rating = "NOTICEABLE / HIGH"

    return {
        "psnr_db": round(psnr, 2),
        "ssim": round(ssim, 4),
        "mse": round(mse, 4),
        "max_pixel_diff": max_diff,
        "changed_pixels_count": changed_pixels,
        "changed_pixels_pct": round(pct_changed, 2),
        "distortion_rating": rating,
    }
