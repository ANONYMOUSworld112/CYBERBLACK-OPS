"""
StegoForge Audio Sample LSB Method Plugin.

Spatial-domain Least Significant Bit embedding for uncompressed PCM WAV audio.
"""

from __future__ import annotations

import wave
from pathlib import Path
from typing import ClassVar

import numpy as np

from stegoforge.core.contracts import CarrierProfile, ENVELOPE_HEADER_SIZE, MethodID
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method


class LsbSampleMethod(MethodPlugin):
    """LSB Sample — Uncompressed WAV PCM audio steganography."""

    name: ClassVar[str] = "LSB Sample"
    method_id: ClassVar[MethodID] = MethodID.LSB_SAMPLE
    applicable_types: ClassVar[list[str]] = ["audio/x-wav", "audio/wav"]

    def capacity_bytes(self, carrier: CarrierProfile) -> int:
        n_frames = carrier.format_details.get("n_frames", 0)
        channels = carrier.format_details.get("channels", 1)
        total_samples = n_frames * channels
        usable_bytes = (total_samples // 8) - ENVELOPE_HEADER_SIZE
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
            with wave.open(str(carrier_path), "rb") as wf:
                params = wf.getparams()
                frames = wf.readframes(params.nframes)

            if params.sampwidth == 2:
                samples = np.frombuffer(frames, dtype=np.int16).copy()
            elif params.sampwidth == 1:
                samples = np.frombuffer(frames, dtype=np.uint8).copy()
            else:
                raise StegoForgeError(
                    f"Unsupported sample width: {params.sampwidth * 8}-bit (only 8-bit and 16-bit supported)"
                )

            bits = np.unpackbits(np.frombuffer(envelope, dtype=np.uint8))
            if len(bits) > len(samples):
                raise CapacityExceededError(
                    len(envelope),
                    len(samples) // 8 - ENVELOPE_HEADER_SIZE,
                    self.name,
                )

            mask = np.int16(~1) if params.sampwidth == 2 else np.uint8(0xFE)
            samples[: len(bits)] = (samples[: len(bits)] & mask) | bits.astype(samples.dtype)

            with wave.open(str(out_path), "wb") as wf_out:
                wf_out.setparams(params)
                wf_out.writeframes(samples.tobytes())

        except CapacityExceededError:
            raise
        except Exception as e:
            raise StegoForgeError(f"Error during audio LSB embed: {e}") from e

    def extract(self, stego_path: Path | str) -> bytes:
        stego_path = Path(stego_path)
        try:
            with wave.open(str(stego_path), "rb") as wf:
                params = wf.getparams()
                frames = wf.readframes(params.nframes)

            if params.sampwidth == 2:
                samples = np.frombuffer(frames, dtype=np.int16)
            elif params.sampwidth == 1:
                samples = np.frombuffer(frames, dtype=np.uint8)
            else:
                raise StegoForgeError(
                    f"Unsupported sample width: {params.sampwidth * 8}-bit"
                )

            lsbs = (samples & 1).astype(np.uint8)
            packed = np.packbits(lsbs)
            return bytes(packed)
        except Exception as e:
            raise StegoForgeError(f"Error during audio LSB extract: {e}") from e


lsb_sample_instance = LsbSampleMethod()
register_method(lsb_sample_instance)
