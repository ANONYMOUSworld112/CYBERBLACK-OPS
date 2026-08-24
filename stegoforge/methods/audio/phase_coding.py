from __future__ import annotations

import wave
import numpy as np
from typing import Dict, Any

from stegoforge.core.contracts import CarrierProfile, MethodID, MethodOption
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method

class PhaseCodingMethod(MethodPlugin):
    """Phase Coding (WAV)"""
    
    @property
    def method_id(self) -> MethodID:
        return MethodID.PHASE_CODING
        
    @property
    def name(self) -> str:
        return "Phase Coding"
        
    @property
    def applicable_types(self) -> list[str]:
        return ["audio/x-wav", "audio/wav"]

    def capacity_bytes(self, profile: CarrierProfile, options: Dict[MethodOption, Any] | None = None) -> int:
        n_frames = profile.format_details.get("n_frames", 0)
        frame_rate = profile.format_details.get("sample_rate", 44100)
        segment_size = frame_rate // 8 # 0.125s
        return n_frames // (segment_size * 8)

    def embed(self, carrier_path: str, envelope: bytes, output_path: str, options: Dict[MethodOption, Any] | None = None) -> None:
        try:
            with wave.open(carrier_path, "rb") as audio:
                params = audio.getparams()
                frames = audio.readframes(params.nframes)
                
            samples = np.frombuffer(frames, dtype=np.int16).copy()
            frame_rate = params.framerate
            segment_size = frame_rate // 8
            
            bits = np.unpackbits(np.frombuffer(envelope, dtype=np.uint8))
            
            if len(bits) * segment_size > len(samples):
                raise CapacityExceededError("Audio too short for Phase Coding data.")
                
            # Very simplified phase coding: we embed the whole bitstream into the phase of the first segment
            # Real phase coding uses multiple segments and phase difference matrices to maintain continuity.
            first_segment = samples[:segment_size].astype(np.float32)
            spectrum = np.fft.fft(first_segment)
            magnitude = np.abs(spectrum)
            phase = np.angle(spectrum)
            
            # Encode bits in the phase of the first segment's lower frequencies
            for i, bit in enumerate(bits):
                if i < len(phase) // 2:
                    phase[i] = np.pi if bit == 1 else 0.0
                    phase[-i] = -phase[i] # conjugate symmetry
            
            new_spectrum = magnitude * np.exp(1j * phase)
            new_first_segment = np.fft.ifft(new_spectrum).real
            
            out_samples = samples.copy().astype(np.float32)
            out_samples[:segment_size] = new_first_segment
            
            out_samples = np.clip(out_samples, -32768, 32767).astype(np.int16)
            
            with wave.open(output_path, "wb") as audio_out:
                audio_out.setparams(params)
                audio_out.writeframes(out_samples.tobytes())
                
        except Exception as e:
            if isinstance(e, CapacityExceededError):
                raise
            raise StegoForgeError(f"Error during Phase Coding embed: {e}")

    def extract(self, carrier_path: str, options: Dict[MethodOption, Any] | None = None) -> bytes:
        try:
            with wave.open(carrier_path, "rb") as audio:
                params = audio.getparams()
                frames = audio.readframes(params.nframes)
                
            samples = np.frombuffer(frames, dtype=np.int16)
            frame_rate = params.framerate
            segment_size = frame_rate // 8
            
            first_segment = samples[:segment_size]
            spectrum = np.fft.fft(first_segment)
            phase = np.angle(spectrum)
            
            # Read phases
            bits = []
            for p in phase:
                if len(bits) >= (segment_size // 2) * 8: # Cap to avoid blowing up memory
                    break
                bits.append(1 if p > np.pi/2 or p < -np.pi/2 else 0)
                
            bits = np.array(bits, dtype=np.uint8)
            packed = np.packbits(bits)
            return bytes(packed)
        except Exception as e:
            raise StegoForgeError(f"Error during Phase Coding extract: {e}")

# Register singleton
register_method(PhaseCodingMethod())
