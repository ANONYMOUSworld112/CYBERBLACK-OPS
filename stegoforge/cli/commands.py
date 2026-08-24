"""
StegoForge Typer CLI Commands.

Provides scriptable commands and launches interactive wizard when no args given.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from stegoforge.ciphers.base import get_all_ciphers, get_cipher
from stegoforge.cli.banner import check_acknowledgment, show_banner, show_banner_and_require_ack
from stegoforge.cli.lab import display_lab_report, run_stego_lab
from stegoforge.cli.orchestrator import (
    analyze_operation,
    embed_operation,
    extract_operation,
    steganalysis_operation,
    watermark_embed_operation,
    watermark_verify_operation,
)
from stegoforge.core.bundle import PayloadObject, create_payload_from_file, create_payload_from_text
from stegoforge.core.detection import detect
from stegoforge.core.exceptions import StegoForgeError
from stegoforge.core.recommender import evaluate_and_recommend
from stegoforge.methods.base import get_all_methods

console = Console()
app = typer.Typer(
    name="stegoforge",
    help="StegoForge - Universal Terminal-Based Steganography, Steganalysis & Encoding Platform",
    no_args_is_help=False,
    invoke_without_command=True,
)

plugins_app = typer.Typer(help="Manage and inspect format/cipher plugins")
app.add_typer(plugins_app, name="plugins")

watermark_app = typer.Typer(help="Digital watermarking & asset authenticity")
app.add_typer(watermark_app, name="watermark")


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """StegoForge entry point."""
    if not check_acknowledgment():
        show_banner_and_require_ack()

    if ctx.invoked_subcommand is None:
        show_banner()
        from stegoforge.cli.wizard import main_wizard

        main_wizard()


@app.command(name="embed")
def embed_command(
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="Carrier file path", exists=True, file_okay=True, dir_okay=False
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path (default: stego_<carrier>)"
    ),
    method: str = typer.Option(
        ..., "--method", "-m", help="Steganography method (e.g. lsb-spatial, eof-append, etc.)"
    ),
    cipher: str = typer.Option(
        "aes-256-gcm", "--cipher", "-c", help="Cipher algorithm (default: aes-256-gcm)"
    ),
    compress: str = typer.Option(
        "auto", "--compress", "-z", help="Compression mode: auto, deflate, lzma, bzip2, none (default: auto)"
    ),
    payload_file: Optional[Path] = typer.Option(
        None, "--payload-file", help="Single file to embed", exists=True, file_okay=True
    ),
    payload_text: Optional[str] = typer.Option(
        None, "--payload-text", help="Inline text string to embed"
    ),
    multi_payload: Optional[List[Path]] = typer.Option(
        None, "--multi-payload", "-p", help="Multiple payload files to bundle and embed"
    ),
    passphrase_env: Optional[str] = typer.Option(
        None, "--passphrase-env", help="Name of env var containing passphrase (for CI/scripts)"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip confirmation prompts"
    ),
    verify: bool = typer.Option(
        True, "--verify/--no-verify", help="Self-verify by extracting payload after embedding"
    ),
    cipher_lab: bool = typer.Option(
        False, "--cipher-lab", help="Enable educational/weak ciphers"
    ),
    no_log: bool = typer.Option(
        False, "--no-log", help="Disable audit logging"
    ),
) -> None:
    """Embed single or multi-payload data into a carrier file."""
    if not payload_file and payload_text is None and not multi_payload:
        console.print("[bold red]Error:[/bold red] Provide either --payload-file, --payload-text, or --multi-payload.")
        raise typer.Exit(1)

    payload_input: bytes | list[PayloadObject]
    if multi_payload:
        payload_objects = []
        for p in multi_payload:
            payload_objects.append(create_payload_from_file(p))
        payload_input = payload_objects
    elif payload_text is not None:
        payload_input = payload_text.encode("utf-8")
    else:
        assert payload_file is not None
        payload_input = payload_file.read_bytes()

    # Retrieve passphrase
    passphrase = ""
    cipher_obj = get_cipher(cipher)
    if cipher_obj and cipher_obj.requires_passphrase:
        if passphrase_env:
            passphrase = os.environ.get(passphrase_env, "")
            if not passphrase:
                console.print(f"[bold red]Error:[/bold red] Environment variable '{passphrase_env}' is empty or unset.")
                raise typer.Exit(1)
        else:
            import getpass

            passphrase = getpass.getpass("Enter passphrase: ")
            if not passphrase:
                console.print("[bold red]Error:[/bold red] Passphrase is required for this cipher.")
                raise typer.Exit(1)

    out_path = output_file or input_file.with_name(f"stego_{input_file.name}")

    try:
        res = embed_operation(
            carrier_path=input_file,
            method_name=method,
            cipher_name=cipher,
            payload=payload_input,
            passphrase=passphrase,
            output_path=out_path,
            compression=compress,
            verify=verify,
            no_log=no_log,
            cipher_lab=cipher_lab,
        )
        console.print(Panel(
            f"[bold green][OK] Embedding Successful[/bold green]\n\n"
            f"- [cyan]Carrier:[/cyan] {input_file.name}\n"
            f"- [cyan]Method:[/cyan] {res.method_name}\n"
            f"- [cyan]Cipher:[/cyan] {res.cipher_name}\n"
            f"- [cyan]Payload Size:[/cyan] {res.payload_size:,} bytes\n"
            f"- [cyan]Integrity Tag:[/cyan] [bold yellow]{res.integrity_tag}[/bold yellow]\n"
            f"- [cyan]Output File:[/cyan] {res.output_path}\n"
            f"- [cyan]Details:[/cyan] {res.message}",
            title="StegoForge Embed Result",
            border_style="green",
        ))
    except StegoForgeError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command(name="extract")
def extract_command(
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="Stego file path", exists=True, file_okay=True, dir_okay=False
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Path to save extracted payload (prints to stdout if omitted)"
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--out-dir", "-d", help="Directory to unpack multi-payload bundle files into"
    ),
    method: Optional[str] = typer.Option(
        None, "--method", "-m", help="Steganography method (auto-detect if omitted)"
    ),
    passphrase_env: Optional[str] = typer.Option(
        None, "--passphrase-env", help="Name of env var containing passphrase"
    ),
    no_log: bool = typer.Option(
        False, "--no-log", help="Disable audit logging"
    ),
) -> None:
    """Extract and reconstruct hidden payload(s) from a stego file."""
    passphrase = ""
    if passphrase_env:
        passphrase = os.environ.get(passphrase_env, "")
    else:
        import getpass

        passphrase = getpass.getpass("Enter passphrase (or press Enter if none): ")

    try:
        payload, res = extract_operation(
            stego_path=input_file,
            passphrase=passphrase,
            method_name=method,
            output_dir=output_dir,
            no_log=no_log,
        )

        if isinstance(payload, list):
            table = Table(title=f"Extracted Bundle Items ({len(payload)} files)", border_style="green")
            table.add_column("Filename", style="bold cyan")
            table.add_column("MIME Type")
            table.add_column("Size", justify="right")
            table.add_column("SHA-256", style="dim")

            for item in payload:
                table.add_row(item.name, item.mime_type, f"{item.size:,} B", item.sha256[:16] + "...")
            console.print(table)

            if output_dir:
                console.print(f"[bold green]Unpacked all files into directory: {output_dir}[/bold green]")
            elif output_file:
                output_file.write_bytes(payload[0].data)
                console.print(f"[bold green]Saved first bundle item to: {output_file}[/bold green]")
        elif output_file:
            output_file.write_bytes(payload)
            console.print(Panel(
                f"[bold green][OK] Extraction Successful[/bold green]\n\n"
                f"- [cyan]Method:[/cyan] {res.method_name}\n"
                f"- [cyan]Cipher:[/cyan] {res.cipher_name}\n"
                f"- [cyan]Payload Size:[/cyan] {res.payload_size:,} bytes\n"
                f"- [cyan]Integrity Tag:[/cyan] [bold yellow]{res.integrity_tag}[/bold yellow]\n"
                f"- [cyan]Saved To:[/cyan] {output_file}",
                title="StegoForge Extract Result",
                border_style="green",
            ))
        else:
            try:
                text_payload = payload.decode("utf-8")
                console.print(Panel(
                    text_payload,
                    title=f"Extracted Payload ({res.payload_size:,} bytes | Tag: {res.integrity_tag})",
                    border_style="green",
                ))
            except UnicodeDecodeError:
                console.print(f"[bold yellow]Extracted {len(payload):,} bytes of binary data (Tag: {res.integrity_tag}). Use -o to save to file.[/bold yellow]")

    except StegoForgeError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command(name="analyze")
def analyze_command(
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="File to analyze", exists=True, file_okay=True, dir_okay=False
    ),
    no_log: bool = typer.Option(
        False, "--no-log", help="Disable audit logging"
    ),
) -> None:
    """Analyze a file: report format, steganographic capacities, and payload signatures."""
    try:
        report = analyze_operation(input_file, no_log=no_log)

        table = Table(title=f"Carrier Profile: {input_file.name}", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")

        table.add_row("File Path", report["file_path"])
        table.add_row("MIME Type", report["mime_type"])
        table.add_row("File Size", f"{report['size_bytes']:,} bytes")
        if report["extension_mismatch"]:
            table.add_row("Extension Mismatch", "[bold yellow]Yes (extension does not match magic bytes)[/bold yellow]")

        for k, v in report["format_details"].items():
            table.add_row(f"Format Detail ({k})", str(v))

        console.print(table)

        m_table = Table(title="Available Steganography Methods & Capacities", border_style="green")
        m_table.add_column("Method", style="bold cyan")
        m_table.add_column("Capacity", justify="right")
        m_table.add_column("Notes", style="dim")

        for opt in report["available_methods"]:
            cap_str = f"{opt.capacity_bytes:,} bytes" if opt.capacity_bytes < 10**12 else "Unlimited (EOF)"
            m_table.add_row(opt.name, cap_str, opt.notes)

        console.print(m_table)

        if report["has_stegoforge_payload"]:
            console.print(Panel(
                f"[bold yellow][!] StegoForge Payload Detected![/bold yellow]\n"
                f"Detected method: [cyan]{report['detected_method']}[/cyan]\n"
                f"Run `stegoforge extract -i {input_file}` to extract it.",
                border_style="yellow",
            ))
        else:
            console.print("[dim]No existing StegoForge payload detected in this file.[/dim]")

    except StegoForgeError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command(name="steganalysis")
def steganalysis_command(
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="Carrier or stego file to inspect", exists=True, file_okay=True
    ),
) -> None:
    """Defensive forensic steganalysis: Shannon entropy, Chi-Square, trailing bytes, anomaly risk scoring."""
    rep = steganalysis_operation(input_file)

    score_color = "green" if rep.suspicion_score < 25 else ("yellow" if rep.suspicion_score < 60 else "red")
    console.print(Panel(
        f"[bold {score_color}]Steganalysis Suspicion Score: {rep.suspicion_score} / 100 ({rep.risk_level})[/bold {score_color}]\n"
        f"[dim]Confidence:[/dim] {rep.confidence_pct}%\n"
        f"[dim]Target:[/dim] {input_file.name} ({rep.file_size:,} bytes | {rep.mime_type})",
        title="Defensive Steganalysis Report",
        border_style=score_color,
    ))

    stat_table = Table(title="Statistical & Forensic Metrics", border_style="cyan")
    stat_table.add_column("Metric", style="bold")
    stat_table.add_column("Value")
    stat_table.add_column("Assessment", style="dim")

    stat_table.add_row(
        "Global Shannon Entropy",
        f"{rep.global_entropy:.3f} bits/byte",
        "Normal" if rep.global_entropy < 7.9 else "[bold yellow]High (Potential Encryption/Compression)[/bold yellow]",
    )
    stat_table.add_row(
        "Block Entropy (Mean / Std)",
        f"{rep.block_entropy_mean:.3f} / {rep.block_entropy_std:.3f}",
        "Uniform" if rep.block_entropy_std < 1.0 else "[bold yellow]Non-uniform dense regions[/bold yellow]",
    )
    stat_table.add_row(
        "Trailing EOF Bytes",
        f"{rep.trailing_bytes:,} bytes",
        "Clean" if rep.trailing_bytes == 0 else "[bold red]Appended payload detected[/bold red]",
    )
    stat_table.add_row(
        "LSB Randomness Anomaly",
        f"{rep.lsb_anomaly_score:.3f}",
        "Natural" if rep.lsb_anomaly_score < 0.9 else "[bold yellow]Artificial bit-plane randomization[/bold yellow]",
    )
    console.print(stat_table)

    if rep.findings:
        f_table = Table(title="Forensic Findings & Evidence", border_style="yellow")
        f_table.add_column("#", justify="right", style="bold")
        f_table.add_column("Finding", style="yellow")
        for i, f in enumerate(rep.findings, 1):
            f_table.add_row(str(i), f)
        console.print(f_table)

    if rep.recommendations:
        r_table = Table(title="Actionable SOC / Forensics Recommendations", border_style="green")
        r_table.add_column("#", justify="right", style="bold")
        r_table.add_column("Recommendation", style="green")
        for i, r in enumerate(rep.recommendations, 1):
            r_table.add_row(str(i), r)
        console.print(r_table)


@app.command(name="recommend")
def recommend_command(
    carrier_file: Path = typer.Option(
        ..., "--carrier", "-c", help="Carrier file path", exists=True, file_okay=True
    ),
    payload_size: int = typer.Option(
        1024, "--size", "-s", help="Payload size in bytes (default: 1024 B)"
    ),
    security: str = typer.Option(
        "high", "--security", help="Security goal: high (AES-GCM), stream (ChaCha20), lab"
    ),
) -> None:
    """Pre-flight capacity check and explainable algorithm recommendation."""
    profile = detect(carrier_file)
    rec = evaluate_and_recommend(profile, payload_size, security_goal=security)

    color = "green" if rec.fits else "red"
    console.print(Panel(
        f"[bold {color}]Algorithm Recommendation: {rec.recommended_method.upper()}[/bold {color}]\n\n"
        f"- [cyan]Carrier:[/cyan] {rec.carrier_name} ({rec.carrier_mime})\n"
        f"- [cyan]Recommended Cipher:[/cyan] {rec.recommended_cipher}\n"
        f"- [cyan]Recommended Compression:[/cyan] {rec.recommended_compression}\n"
        f"- [cyan]Required Capacity:[/cyan] {rec.required_capacity_bytes:,} bytes\n"
        f"- [cyan]Available Capacity:[/cyan] {rec.available_capacity_bytes:,} bytes\n"
        f"- [cyan]Safety Margin:[/cyan] {rec.safety_margin_pct}%\n"
        f"- [cyan]Expected Distortion:[/cyan] {rec.expected_distortion}\n"
        f"- [cyan]Robustness:[/cyan] {rec.robustness}\n\n"
        f"[bold]Rationale:[/bold] {rec.explanation}",
        title="Capacity & Recommendation Engine",
        border_style=color,
    ))


@app.command(name="lab")
def lab_command(
    carrier_file: Path = typer.Option(
        ..., "--carrier", "-c", help="Carrier file to benchmark", exists=True, file_okay=True
    ),
) -> None:
    """Run Stego Lab benchmark comparing all compatible algorithms on carrier."""
    results = run_stego_lab(carrier_file)
    display_lab_report(carrier_file, results)


@watermark_app.command(name="embed")
def watermark_embed_command(
    carrier_file: Path = typer.Option(
        ..., "--carrier", "-i", help="Carrier file to watermark", exists=True, file_okay=True
    ),
    owner: str = typer.Option(
        ..., "--owner", help="Owner identity / organization string"
    ),
    key: str = typer.Option(
        ..., "--key", "-k", help="Secret signing key for cryptographic watermark HMAC"
    ),
    description: str = typer.Option(
        "", "--desc", help="Optional asset copyright or license description"
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output watermarked file"
    ),
    method: Optional[str] = typer.Option(
        None, "--method", "-m", help="Specific steg method (auto-selected if omitted)"
    ),
) -> None:
    """Embed a cryptographically signed watermark into an asset."""
    out_path, used_m = watermark_embed_operation(
        carrier_path=carrier_file,
        owner=owner,
        secret_key=key,
        description=description,
        output_path=output_file,
        method_name=method,
    )
    console.print(Panel(
        f"[bold green][OK] Watermark Successfully Embedded[/bold green]\n\n"
        f"- [cyan]Owner:[/cyan] {owner}\n"
        f"- [cyan]Method Used:[/cyan] {used_m}\n"
        f"- [cyan]Output File:[/cyan] {out_path}\n"
        f"- [cyan]Signature Scheme:[/cyan] HMAC-SHA256",
        title="StegoForge Watermark Embed",
        border_style="green",
    ))


@watermark_app.command(name="verify")
def watermark_verify_command(
    stego_file: Path = typer.Option(
        ..., "--input", "-i", help="Watermarked asset file", exists=True, file_okay=True
    ),
    key: str = typer.Option(
        ..., "--key", "-k", help="Secret signing key"
    ),
) -> None:
    """Verify cryptographic watermark signature and authenticity in an asset."""
    rep = watermark_verify_operation(stego_path=stego_file, secret_key=key)

    if rep.detected and rep.signature_valid:
        console.print(Panel(
            f"[bold green][OK] Authentic Watermark Confirmed[/bold green]\n\n"
            f"- [cyan]Owner:[/cyan] [bold]{rep.owner}[/bold]\n"
            f"- [cyan]Timestamp:[/cyan] {rep.timestamp}\n"
            f"- [cyan]Description:[/cyan] {rep.description or 'N/A'}\n"
            f"- [cyan]Integrity:[/cyan] Valid (Zero Tampering Detected)",
            title="Watermark Verification: VALID",
            border_style="green",
        ))
    elif rep.detected and rep.tampered:
        console.print(Panel(
            f"[bold red][FAIL] Watermark Tampered or Invalid Key[/bold red]\n\n"
            f"- [cyan]Owner Claimed:[/cyan] {rep.owner}\n"
            f"- [cyan]Timestamp:[/cyan] {rep.timestamp}\n"
            f"- [cyan]Details:[/cyan] {rep.details}",
            title="Watermark Verification: TAMPERED / INVALID KEY",
            border_style="red",
        ))
    else:
        console.print(Panel(
            f"[yellow]{rep.details}[/yellow]",
            title="Watermark Verification: NOT FOUND",
            border_style="yellow",
        ))


@app.command(name="methods")
def methods_command(
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="Carrier file to inspect", exists=True, file_okay=True
    ),
) -> None:
    """List valid steganography methods for a carrier file."""
    analyze_command(input_file=input_file, no_log=True)


@plugins_app.command(name="list")
def list_plugins_command() -> None:
    """List all installed method and cipher plugins."""
    methods = get_all_methods()
    ciphers = get_all_ciphers()

    m_table = Table(title="Registered Steganography Method Plugins", border_style="cyan")
    m_table.add_column("Registry Key", style="bold")
    m_table.add_column("Name")
    m_table.add_column("Applicable Types")

    for key, m in methods.items():
        m_table.add_row(key, m.name, ", ".join(m.applicable_types))

    console.print(m_table)

    c_table = Table(title="Registered Cipher Plugins", border_style="magenta")
    c_table.add_column("Registry Key", style="bold")
    c_table.add_column("Name")
    c_table.add_column("Security Tier")
    c_table.add_column("Requires Passphrase")

    for key, c in ciphers.items():
        tier_style = "bold green" if c.security_tier == "strong" else ("yellow" if c.security_tier == "encoding_only" else "red")
        c_table.add_row(key, c.name, f"[{tier_style}]{c.security_tier}[/{tier_style}]", str(c.requires_passphrase))

    console.print(c_table)
