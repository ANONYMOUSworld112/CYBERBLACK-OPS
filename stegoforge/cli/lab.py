"""
StegoForge Research Laboratory & Benchmark Subsystem.

Allows operators and researchers to benchmark, stress-test, and compare
multiple steganographic methods against carrier media: measuring capacity,
embedding throughput, extraction latency, PSNR/SSIM quality distortion,
and integrity verification.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from stegoforge.core.advisor import get_available_methods
from stegoforge.core.detection import detect
from stegoforge.core.quality import analyze_image_quality
from stegoforge.methods.base import get_method

console = Console()


def run_stego_lab(
    carrier_path: Path | str,
    probe_payload: bytes | None = None,
) -> list[dict[str, Any]]:
    """
    Execute comparative laboratory benchmark across all compatible methods for a carrier.

    Args:
        carrier_path: Path to carrier file.
        probe_payload: Optional custom payload bytes to embed.

    Returns:
        List of benchmark metric dictionaries.
    """
    path = Path(carrier_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Carrier not found: {path}")

    profile = detect(path)
    available = get_available_methods(profile)

    if not available:
        console.print(f"[bold red]No available steganography plugins for MIME: {profile.mime_type}[/bold red]")
        return []

    # Default probe payload: 256 bytes test pattern
    test_data = probe_payload or (b"StegoForge-Lab-Probe-Data-" + (b"X" * 230))

    results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        for opt in available:
            method = get_method(opt.plugin_name)
            if method is None:
                continue

            cap = method.capacity_bytes(profile)
            if cap < len(test_data):
                results.append(
                    {
                        "name": opt.name,
                        "plugin": opt.plugin_name,
                        "capacity": cap,
                        "embed_ms": 0.0,
                        "extract_ms": 0.0,
                        "psnr_db": 0.0,
                        "ssim": 0.0,
                        "integrity": "INSUFFICIENT CAPACITY",
                        "status": "SKIP",
                    }
                )
                continue

            stego_out = tmp_path / f"stego_{opt.plugin_name}_{path.name}"
            from stegoforge.core.contracts import CipherID
            from stegoforge.core.envelope import pack
            test_envelope = pack(
                method_id=method.method_id,
                cipher_id=CipherID.AES_256_GCM,
                salt=b"0123456789abcdef",
                nonce=b"123456789012",
                ciphertext=test_data,
            )

            embed_start = time.perf_counter()
            try:
                method.embed(path, test_envelope, stego_out)
                embed_ms = (time.perf_counter() - embed_start) * 1000.0
            except Exception as e:
                results.append(
                    {
                        "name": opt.name,
                        "plugin": opt.plugin_name,
                        "capacity": cap,
                        "embed_ms": 0.0,
                        "extract_ms": 0.0,
                        "psnr_db": 0.0,
                        "ssim": 0.0,
                        "integrity": f"FAIL ({e})",
                        "status": "ERROR",
                    }
                )
                continue

            extract_start = time.perf_counter()
            try:
                extracted = method.extract(stego_out)
                extract_ms = (time.perf_counter() - extract_start) * 1000.0
                integrity_pass = extracted[: len(test_envelope)] == test_envelope
                integrity_str = "PASS" if integrity_pass else "HASH MISMATCH"
            except Exception as e:
                extract_ms = (time.perf_counter() - extract_start) * 1000.0
                integrity_str = f"EXTRACT FAIL ({e})"

            # Image visual quality distortion calculation if image
            psnr_val = 0.0
            ssim_val = 0.0
            if profile.mime_type.startswith("image/"):
                try:
                    q = analyze_image_quality(path, stego_out)
                    psnr_val = q.get("psnr_db", 0.0)
                    ssim_val = q.get("ssim", 0.0)
                except Exception:
                    pass

            results.append(
                {
                    "name": opt.name,
                    "plugin": opt.plugin_name,
                    "capacity": cap,
                    "embed_ms": round(embed_ms, 2),
                    "extract_ms": round(extract_ms, 2),
                    "psnr_db": round(psnr_val, 2),
                    "ssim": round(ssim_val, 4),
                    "integrity": integrity_str,
                    "status": "OK" if integrity_str == "PASS" else "FAIL",
                }
            )

    return results


def display_lab_report(carrier_path: Path, results: list[dict[str, Any]]) -> None:
    """Render a rich terminal table for the laboratory report."""
    console.print(
        Panel(
            f"[bold cyan]StegoForge Research Lab — Algorithm Comparative Benchmark[/bold cyan]\n"
            f"[dim]Carrier:[/dim] [bold yellow]{carrier_path.name}[/bold yellow]",
            border_style="cyan",
        )
    )

    table = Table(border_style="bright_blue", title="Algorithm Comparison Matrix")
    table.add_column("Method", style="bold")
    table.add_column("Max Capacity", justify="right")
    table.add_column("Embed Time", justify="right")
    table.add_column("Extract Time", justify="right")
    table.add_column("PSNR (dB)", justify="right")
    table.add_column("SSIM", justify="right")
    table.add_column("Integrity Round-Trip", justify="center")

    for r in results:
        cap_str = f"{r['capacity']:,} B" if r["capacity"] < 10**12 else "Unlimited"
        psnr_str = f"{r['psnr_db']} dB" if r["psnr_db"] > 0 else "N/A"
        ssim_str = f"{r['ssim']}" if r["ssim"] > 0 else "N/A"
        integ_style = "[bold green]PASS[/bold green]" if r["integrity"] == "PASS" else f"[bold red]{r['integrity']}[/bold red]"

        table.add_row(
            r["name"],
            cap_str,
            f"{r['embed_ms']} ms",
            f"{r['extract_ms']} ms",
            psnr_str,
            ssim_str,
            integ_style,
        )

    console.print(table)
    console.print()
