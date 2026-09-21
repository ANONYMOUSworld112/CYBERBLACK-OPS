"""
StegoForge LSB Spatial Image Method Plugin.

Spatial-domain Least Significant Bit embedding for lossless images
(PNG, BMP, GIF).
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import numpy as np
from PIL import Image

from stegoforge.core.contracts import CarrierProfile, ENVELOPE_HEADER_SIZE, MethodID
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method


class LsbSpatialMethod(MethodPlugin):
    """LSB Spatial — Lossless image steganography (PNG/BMP/GIF)."""

    name: ClassVar[str] = "LSB Spatial"
    method_id: ClassVar[MethodID] = MethodID.LSB_SPATIAL
    applicable_types: ClassVar[list[str]] = ["image/png", "image/bmp", "image/gif"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        width = carrier.format_details.get("width", 0)
        height = carrier.format_details.get("height", 0)
        channels = carrier.format_details.get("channels", 3)
        usable_channels = min(channels, 3)  # Use up to 3 channels (RGB)
        total_bits = width * height * usable_channels
        usable_bytes = (total_bits // 8) - ENVELOPE_HEADER_SIZE
        return max(0, usable_bytes)

    def embed(
        self,
        carrier_path: Path | str,
        envelope: bytes,
        out_path: Path | str,
    ) -> None:
        carrier_path = Path(carrier_path)
        out_path = Path(out_path)
        try:
            with Image.open(carrier_path) as img:
                fmt = img.format or "PNG"
                if fmt == "GIF" or img.mode == "P":
                    img_work = img.convert("RGB")
                elif img.mode not in ("RGB", "RGBA"):
                    img_work = img.convert("RGB")
                else:
                    img_work = img.copy()

                arr = np.array(img_work)
                orig_shape = arr.shape

                # Flatten array
                flat_arr = arr.reshape(-1)

                # For RGBA, use only RGB channels (indices 0, 1, 2 of each 4-byte chunk)
                if len(orig_shape) == 3 and orig_shape[2] == 4:
                    num_pixels = orig_shape[0] * orig_shape[1]
                    pixel_indices = np.arange(num_pixels)[:, None] * 4 + np.array([0, 1, 2])
                    channel_indices = pixel_indices.flatten()
                else:
                    channel_indices = np.arange(len(flat_arr))

                bits = np.unpackbits(np.frombuffer(envelope, dtype=np.uint8))
                if len(bits) > len(channel_indices):
                    raise CapacityExceededError(
                        len(envelope),
                        len(channel_indices) // 8 - ENVELOPE_HEADER_SIZE,
                        self.name,
                    )

                target_indices = channel_indices[: len(bits)]
                flat_arr[target_indices] = (flat_arr[target_indices] & np.uint8(0xFE)) | bits.astype(np.uint8)

                res_arr = flat_arr.reshape(orig_shape)
                res_img = Image.fromarray(res_arr, mode=img_work.mode)

                save_fmt = "PNG" if fmt == "GIF" else (fmt or "PNG")
                res_img.save(out_path, format=save_fmt)
        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during image LSB embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with Image.open(stego_path) as img:
                if img.mode not in ("RGB", "RGBA"):
                    img_work = img.convert("RGB")
                else:
                    img_work = img

                arr = np.array(img_work)
                orig_shape = arr.shape
                flat_arr = arr.reshape(-1)

                if len(orig_shape) == 3 and orig_shape[2] == 4:
                    num_pixels = orig_shape[0] * orig_shape[1]
                    pixel_indices = np.arange(num_pixels)[:, None] * 4 + np.array([0, 1, 2])
                    channel_indices = pixel_indices.flatten()
                else:
                    channel_indices = np.arange(len(flat_arr))

                lsbs = flat_arr[channel_indices] & 1
                packed = np.packbits(lsbs)
                return bytes(packed)
        except Exception as e:
            raise StegoForgeError(f"Error during image LSB extract: {e}") from e


lsb_spatial_instance = LsbSpatialMethod()
register_method(lsb_spatial_instance)
