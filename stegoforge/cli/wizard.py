"""
StegoForge Interactive TUI Wizard (Rich + questionary).

Implements interactive operator journeys for embedding, extracting,
capacity calculation, forensic steganalysis, digital watermarking, and laboratory research.
"""

from __future__ import annotations

import sys
from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from stegoforge.ciphers.base import get_all_ciphers, get_cipher
from stegoforge.cli.lab import display_lab_report, run_stego_lab
from stegoforge.cli.orchestrator import (
    analyze_operation,
    embed_operation,
    extract_operation,
    steganalysis_operation,
    watermark_embed_operation,
    watermark_verify_operation,
)
from stegoforge.core.advisor import get_available_methods
from stegoforge.core.bundle import PayloadObject, create_payload_from_file, create_payload_from_text
from stegoforge.core.contracts import SecurityTier
from stegoforge.core.detection import detect
from stegoforge.core.exceptions import CapacityExceededError, StegoForgeError
from stegoforge.core.recommender import evaluate_and_recommend

console = Console()


def main_wizard() -> None:
    """Main interactive wizard menu."""
    while True:
        choice = questionary.select(
            "Select an operation to perform:",
            choices=[
                "1. Embed data into carrier (Single or Multi-Payload)",
                "2. Extract hidden payload from stego file",
                "3. Carrier format & capacity analysis",
                "4. Defensive steganalysis forensic scan",
                "5. Digital watermarking (Embed / Verify)",
                "6. Stego Lab (Comparative algorithm benchmark)",
                "7. Algorithm recommendation & capacity check",
                "8. List installed plugins",
                "9. Exit",
            ],
        ).ask()

        if choice is None or choice.startswith("9"):
            console.print("[dim]Goodbye.[/dim]")
            break
        elif choice.startswith("1"):
            embed_wizard()
        elif choice.startswith("2"):
            extract_wizard()
        elif choice.startswith("3"):
            analyze_wizard()
        elif choice.startswith("4"):
            steganalysis_wizard()
        elif choice.startswith("5"):
            watermark_wizard()
        elif choice.startswith("6"):
            lab_wizard()
        elif choice.startswith("7"):
            recommend_wizard()
        elif choice.startswith("8"):
            list_plugins_wizard()


def embed_wizard() -> None:
    """Interactive Embed Wizard with Multi-Payload and Compression support."""
    console.print(Panel("[bold cyan]StegoForge — Embed Wizard[/bold cyan]", border_style="cyan"))

    carrier_input = questionary.text("Enter path to input carrier file:").ask()
    if not carrier_input:
        return

    carrier_path = Path(carrier_input).expanduser().resolve()
    if not carrier_path.exists() or not carrier_path.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {carrier_path}")
        return

    try:
        profile = detect(carrier_path)
    except StegoForgeError as e:
        console.print(f"[bold red]Detection Error:[/bold red] {e}")
        return

    table = Table(title=f"Carrier Detected: {carrier_path.name}", border_style="green")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("MIME Type", profile.mime_type)
    table.add_row("File Size", f"{profile.size_bytes:,} bytes")
    for k, v in profile.format_details.items():
        table.add_row(k.capitalize(), str(v))
    console.print(table)

    available_methods = get_available_methods(profile)
    if not available_methods:
        console.print("[bold red]No steganographic methods available for this file type.[/bold red]")
        return

    method_choices = [
        questionary.Choice(
            title=f"{m.name:<18} (Capacity: {m.capacity_bytes:,} B) — {m.notes[:45]}...",
            value=m.plugin_name,
        )
        if m.capacity_bytes < 10**12
        else questionary.Choice(
            title=f"{m.name:<18} (Capacity: Unlimited) — {m.notes[:45]}...",
            value=m.plugin_name,
        )
        for m in available_methods
    ]

    chosen_method_key = questionary.select(
        "Select steganography embedding method:",
        choices=method_choices,
    ).ask()
    if not chosen_method_key:
        return

    # Payload selection
    payload_type = questionary.select(
        "Payload mode:",
        choices=[
            "1. Single inline text message",
            "2. Single file from disk",
            "3. Multi-payload bundle (multiple files)",
        ],
    ).ask()
    if not payload_type:
        return

    payload_input: bytes | list[PayloadObject]
    if payload_type.startswith("1"):
        payload_str = questionary.text("Enter message to conceal:").ask()
        if payload_str is None:
            return
        payload_input = payload_str.encode("utf-8")
        payload_size_est = len(payload_input)
    elif payload_type.startswith("2"):
        p_path_str = questionary.text("Enter path to payload file:").ask()
        if not p_path_str:
            return
        p_path = Path(p_path_str).expanduser().resolve()
        if not p_path.is_file():
            console.print(f"[bold red]Payload file not found:[/bold red] {p_path}")
            return
        payload_input = p_path.read_bytes()
        payload_size_est = len(payload_input)
    else:
        # Multi-payload
        files_input = questionary.text("Enter comma-separated file paths to bundle:").ask()
        if not files_input:
            return
        bundle_objects = []
        for raw_p in files_input.split(","):
            p_clean = Path(raw_p.strip()).expanduser().resolve()
            if p_clean.is_file():
                bundle_objects.append(create_payload_from_file(p_clean))
            else:
                console.print(f"[yellow]Warning: Skipping missing file {p_clean}[/yellow]")
        if not bundle_objects:
            console.print("[bold red]No valid files provided for bundle.[/bold red]")
            return
        payload_input = bundle_objects
        payload_size_est = sum(p.size for p in bundle_objects)

    # Compression selection
    comp_choice = questionary.select(
        "Select compression layer:",
        choices=["auto (Recommended)", "deflate", "lzma", "bzip2", "none"],
    ).ask()
    compression_mode = comp_choice.split()[0] if comp_choice else "auto"

    # Cipher selection
    ciphers = get_all_ciphers()
    cipher_choices = []
    for k, c in ciphers.items():
        if c.security_tier == SecurityTier.STRONG:
            cipher_choices.append(questionary.Choice(title=f"[Strong] {c.name}", value=k))
    for k, c in ciphers.items():
        if c.security_tier == SecurityTier.ENCODING_ONLY:
            cipher_choices.append(questionary.Choice(title=f"[Encoding only] {c.name}", value=k))

    chosen_cipher_key = questionary.select(
        "Select cipher layer (AES-256-GCM recommended):",
        choices=cipher_choices,
    ).ask()
    if not chosen_cipher_key:
        return

    chosen_cipher = ciphers[chosen_cipher_key]

    passphrase = ""
    if chosen_cipher.requires_passphrase:
        passphrase = questionary.password("Enter passphrase for encryption:").ask()
        if not passphrase:
            console.print("[bold red]Passphrase is required.[/bold red]")
            return
        confirm_pass = questionary.password("Confirm passphrase:").ask()
        if passphrase != confirm_pass:
            console.print("[bold red]Passphrases do not match. Aborting.[/bold red]")
            return

    default_out = str(carrier_path.with_name(f"stego_{carrier_path.name}"))
    out_input = questionary.text("Output file path:", default=default_out).ask()
    if not out_input:
        return
    out_path = Path(out_input).expanduser().resolve()

    console.print(Panel(
        f"• Carrier: [cyan]{carrier_path.name}[/cyan]\n"
        f"• Method: [cyan]{chosen_method_key}[/cyan]\n"
        f"• Cipher: [cyan]{chosen_cipher.name}[/cyan]\n"
        f"• Compression: [cyan]{compression_mode}[/cyan]\n"
        f"• Payload Size: [bold]{payload_size_est:,} bytes[/bold]\n"
        f"• Output Path: [cyan]{out_path}[/cyan]",
        title="Operation Confirmation",
        border_style="yellow",
    ))

    if not Confirm.ask("Proceed with embedding?"):
        console.print("[yellow]Cancelled.[/yellow]")
        return

    try:
        res = embed_operation(
            carrier_path=carrier_path,
            method_name=chosen_method_key,
            cipher_name=chosen_cipher_key,
            payload=payload_input,
            passphrase=passphrase,
            output_path=out_path,
            compression=compression_mode,
            verify=True,
        )

        console.print(Panel(
            f"[bold green]✓ Embedding & Verification Successful![/bold green]\n\n"
            f"• Output File: [cyan]{res.output_path}[/cyan]\n"
            f"• Payload Size: {res.payload_size:,} bytes\n"
            f"• Integrity Tag: [bold yellow]{res.integrity_tag}[/bold yellow]\n"
            f"• Method: {res.method_name}\n"
            f"• Cipher: {res.cipher_name}\n"
            f"• Details: {res.message}",
            border_style="green",
        ))

    except CapacityExceededError as e:
        console.print(f"[bold red]Capacity Exceeded:[/bold red] {e}")
    except StegoForgeError as e:
        console.print(f"[bold red]Embedding Error:[/bold red] {e}")


def extract_wizard() -> None:
    """Interactive Extract Wizard with automatic bundle unpacking."""
    console.print(Panel("[bold cyan]StegoForge — Extract Wizard[/bold cyan]", border_style="cyan"))

    stego_input = questionary.text("Enter path to stego file:").ask()
    if not stego_input:
        return

    stego_path = Path(stego_input).expanduser().resolve()
    if not stego_path.exists() or not stego_path.is_file():
        console.print(f"[bold red]File not found:[/bold red] {stego_path}")
        return

    passphrase = questionary.password("Enter passphrase (or leave blank if none):").ask()
    if passphrase is None:
        return

    try:
        payload, res = extract_operation(
            stego_path=stego_path,
            passphrase=passphrase,
            method_name=None,
        )

        console.print(Panel(
            f"[bold green]✓ Extraction & Verification Successful![/bold green]\n\n"
            f"• Detected Method: [cyan]{res.method_name}[/cyan]\n"
            f"• Detected Cipher: [cyan]{res.cipher_name}[/cyan]\n"
            f"• Payload Size: {res.payload_size:,} bytes\n"
            f"• Integrity Tag: [bold yellow]{res.integrity_tag}[/bold yellow]",
            border_style="green",
        ))

        if isinstance(payload, list):
            table = Table(title=f"Extracted Bundle Files ({len(payload)} items)", border_style="cyan")
            table.add_column("Filename", style="bold cyan")
            table.add_column("MIME Type")
            table.add_column("Size", justify="right")
            table.add_column("SHA-256", style="dim")

            for item in payload:
                table.add_row(item.name, item.mime_type, f"{item.size:,} B", item.sha256[:16] + "...")
            console.print(table)

            dest_dir_str = questionary.text("Enter destination directory to save extracted files:").ask()
            if dest_dir_str:
                dest_dir = Path(dest_dir_str).expanduser().resolve()
                dest_dir.mkdir(parents=True, exist_ok=True)
                for item in payload:
                    (dest_dir / item.name).write_bytes(item.data)
                console.print(f"[bold green]Successfully saved {len(payload)} files to {dest_dir}[/bold green]")
        else:
            try:
                text_preview = payload.decode("utf-8")
                console.print(Panel(text_preview[:1000], title="Payload Preview", border_style="cyan"))
            except UnicodeDecodeError:
                console.print("[dim]Payload is binary data.[/dim]")

            save_choice = questionary.select(
                "What would you like to do with the extracted payload?",
                choices=["Save to file", "Done"],
            ).ask()

            if save_choice == "Save to file":
                save_path_str = questionary.text("Enter path to save extracted file:").ask()
                if save_path_str:
                    save_path = Path(save_path_str).expanduser().resolve()
                    save_path.write_bytes(payload)
                    console.print(f"[bold green]Saved extracted payload to {save_path}[/bold green]")

    except StegoForgeError as e:
        console.print(f"[bold red]Extraction Failed:[/bold red] {e}")


def analyze_wizard() -> None:
    """Interactive Carrier Analysis Wizard."""
    console.print(Panel("[bold cyan]StegoForge — Carrier Analysis[/bold cyan]", border_style="cyan"))

    file_input = questionary.text("Enter path to file to analyze:").ask()
    if not file_input:
        return

    file_path = Path(file_input).expanduser().resolve()
    if not file_path.exists() or not file_path.is_file():
        console.print(f"[bold red]File not found:[/bold red] {file_path}")
        return

    try:
        report = analyze_operation(file_path)

        table = Table(title=f"File: {file_path.name}", border_style="cyan")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_row("MIME Type", report["mime_type"])
        table.add_row("Size", f"{report['size_bytes']:,} bytes")
        for k, v in report["format_details"].items():
            table.add_row(k.capitalize(), str(v))
        console.print(table)

        m_table = Table(title="Supported Embedding Methods for this Carrier", border_style="green")
        m_table.add_column("Method", style="bold cyan")
        m_table.add_column("Estimated Max Capacity", justify="right")
        m_table.add_column("Notes", style="dim")

        for opt in report["available_methods"]:
            cap_str = f"{opt.capacity_bytes:,} bytes" if opt.capacity_bytes < 10**12 else "Unlimited (EOF)"
            m_table.add_row(opt.name, cap_str, opt.notes)
        console.print(m_table)

        if report["has_stegoforge_payload"]:
            console.print(Panel(
                f"[bold yellow]⚠ StegoForge Payload Detected![/bold yellow]\n"
                f"Embedding method: [cyan]{report['detected_method']}[/cyan]",
                border_style="yellow",
            ))
        else:
            console.print("[dim]No existing StegoForge payload detected.[/dim]")

    except StegoForgeError as e:
        console.print(f"[bold red]Analysis Error:[/bold red] {e}")


def steganalysis_wizard() -> None:
    """Interactive Steganalysis Wizard."""
    console.print(Panel("[bold cyan]StegoForge — Defensive Forensic Steganalysis[/bold cyan]", border_style="cyan"))

    file_input = questionary.text("Enter path to file to inspect:").ask()
    if not file_input:
        return

    file_path = Path(file_input).expanduser().resolve()
    if not file_path.is_file():
        console.print(f"[bold red]File not found:[/bold red] {file_path}")
        return

    from stegoforge.cli.commands import steganalysis_command
    steganalysis_command(input_file=file_path)


def watermark_wizard() -> None:
    """Interactive Watermarking Wizard."""
    console.print(Panel("[bold cyan]StegoForge — Digital Watermarking[/bold cyan]", border_style="cyan"))

    action = questionary.select(
        "Watermark operation:",
        choices=["1. Embed watermark signature into asset", "2. Verify watermark in asset"],
    ).ask()
    if not action:
        return

    if action.startswith("1"):
        c_in = questionary.text("Carrier file path:").ask()
        if not c_in:
            return
        carrier_path = Path(c_in).expanduser().resolve()
        owner = questionary.text("Owner identity / organization:").ask()
        key = questionary.password("Secret signing key:").ask()
        desc = questionary.text("Description / metadata (optional):").ask() or ""

        if not owner or not key:
            console.print("[bold red]Owner and secret key are required.[/bold red]")
            return

        from stegoforge.cli.commands import watermark_embed_command
        watermark_embed_command(
            carrier_file=carrier_path,
            owner=owner,
            key=key,
            description=desc,
            output_file=None,
            method=None,
        )
    else:
        s_in = questionary.text("Watermarked file path:").ask()
        if not s_in:
            return
        stego_path = Path(s_in).expanduser().resolve()
        key = questionary.password("Secret signing key:").ask()
        if not key:
            return

        from stegoforge.cli.commands import watermark_verify_command
        watermark_verify_command(stego_file=stego_path, key=key)


def lab_wizard() -> None:
    """Interactive Stego Lab Wizard."""
    console.print(Panel("[bold cyan]StegoForge — Research Laboratory & Benchmark[/bold cyan]", border_style="cyan"))

    file_input = questionary.text("Enter path to carrier file to benchmark:").ask()
    if not file_input:
        return

    file_path = Path(file_input).expanduser().resolve()
    if not file_path.is_file():
        console.print(f"[bold red]File not found:[/bold red] {file_path}")
        return

    results = run_stego_lab(file_path)
    display_lab_report(file_path, results)


def recommend_wizard() -> None:
    """Interactive Algorithm Recommendation Wizard."""
    console.print(Panel("[bold cyan]StegoForge — Recommendation Engine[/bold cyan]", border_style="cyan"))

    file_input = questionary.text("Carrier file path:").ask()
    if not file_input:
        return
    carrier_path = Path(file_input).expanduser().resolve()
    if not carrier_path.is_file():
        console.print(f"[bold red]File not found:[/bold red] {carrier_path}")
        return

    size_str = questionary.text("Estimated payload size in bytes:", default="1024").ask()
    payload_size = int(size_str) if size_str and size_str.isdigit() else 1024

    from stegoforge.cli.commands import recommend_command
    recommend_command(carrier_file=carrier_path, payload_size=payload_size, security="high")


def list_plugins_wizard() -> None:
    """List all registered plugins in TUI."""
    from stegoforge.cli.commands import list_plugins_command
    list_plugins_command()
