from __future__ import annotations

import wave
import numpy as np
from typing import Dict, Any

from stegoforge.core.contracts import CarrierProfile, MethodID, MethodOption
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.methods.base import MethodPlugin, register_method

class EchoHideMethod(MethodPlugin):
    """Echo Hiding (WAV)"""
    
    @property
    def method_id(self) -> MethodID:
        return MethodID.ECHO_HIDE
        
    @property
    def name(self) -> str:
        return "Echo Hide"
        
    @property
    def applicable_types(self) -> list[str]:
        return ["audio/x-wav", "audio/wav"]

    def capacity_bytes(self, profile: CarrierProfile, options: Dict[MethodOption, Any] | None = None) -> int:
        n_frames = profile.format_details.get("n_frames", 0)
        frame_rate = profile.format_details.get("sample_rate", 44100)
        segment_size = frame_rate // 8 # About 0.125s
        return n_frames // (segment_size * 8)

    def embed(self, carrier_path: str, envelope: bytes, output_path: str, options: Dict[MethodOption, Any] | None = None) -> None:
        try:
            with wave.open(carrier_path, "rb") as audio:
                params = audio.getparams()
                frames = audio.readframes(params.nframes)
                
            if params.sampwidth != 2:
                raise StegoForgeError("Echo Hiding only supports 16-bit PCM WAV.")
                
            samples = np.frombuffer(frames, dtype=np.int16).copy()
            frame_rate = params.framerate
            
            segment_size = frame_rate // 8
            delay_0 = int(0.0005 * frame_rate) # 0.5ms
            delay_1 = int(0.0015 * frame_rate) # 1.5ms
            decay = 0.4
            
            bits = np.unpackbits(np.frombuffer(envelope, dtype=np.uint8))
            
            if len(bits) * segment_size > len(samples):
                raise CapacityExceededError("Audio too short for Echo Hiding data.")
            
            out_samples = np.zeros_like(samples, dtype=np.float32)
            
            # Simple segmented echo addition
            for i, bit in enumerate(bits):
                start = i * segment_size
                end = start + segment_size
                if end > len(samples):
                    break
                    
                delay = delay_1 if bit == 1 else delay_0
                
                segment = samples[start:end].astype(np.float32)
                echo_segment = np.zeros_like(segment)
                if delay < len(segment):
                    echo_segment[delay:] = segment[:-delay]
                
                out_samples[start:end] = segment + decay * echo_segment
                
            # Copy remaining unmodified samples
            rem_start = len(bits) * segment_size
            if rem_start < len(samples):
                out_samples[rem_start:] = samples[rem_start:]
                
            # Normalize to prevent clipping
            out_samples = np.clip(out_samples, -32768, 32767).astype(np.int16)
            
            with wave.open(output_path, "wb") as audio_out:
                audio_out.setparams(params)
                audio_out.writeframes(out_samples.tobytes())
                
        except Exception as e:
            if isinstance(e, CapacityExceededError):
                raise
            raise StegoForgeError(f"Error during Echo Hiding embed: {e}")

    def extract(self, carrier_path: str, options: Dict[MethodOption, Any] | None = None) -> bytes:
        try:
            with wave.open(carrier_path, "rb") as audio:
                params = audio.getparams()
                frames = audio.readframes(params.nframes)
                
            samples = np.frombuffer(frames, dtype=np.int16).astype(np.float32)
            frame_rate = params.framerate
            
            segment_size = frame_rate // 8
            delay_0 = int(0.0005 * frame_rate)
            delay_1 = int(0.0015 * frame_rate)
            
            num_segments = len(samples) // segment_size
            bits = []
            
            for i in range(num_segments):
                start = i * segment_size
                end = start + segment_size
                segment = samples[start:end]
                
                # Simple Autocorrelation analysis
                # Real cepstrum is better, but auto-correlation is requested/sufficient for mockup
                corr = np.correlate(segment, segment, mode='full')
                corr = corr[len(corr)//2:] # Take positive lags
                
                if delay_0 < len(corr) and delay_1 < len(corr):
                    val_0 = corr[delay_0]
                    val_1 = corr[delay_1]
                    bits.append(1 if val_1 > val_0 else 0)
                else:
                    bits.append(0)
            
            bits = np.array(bits, dtype=np.uint8)
            packed = np.packbits(bits)
            return bytes(packed)
        except Exception as e:
            raise StegoForgeError(f"Error during Echo Hiding extract: {e}")

# Register singleton
register_method(EchoHideMethod())
