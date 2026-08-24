import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()

STEGOFORGE_BANNER = """
  ____  _                   _   _____                    
 / ___|| |_ ___  __ _  ___ | | |  ___|__  _ __ __ _  ___ 
 \\___ \\| __/ _ \\/ _` |/ _ \\| | | |_ / _ \\| '__/ _` |/ _ \\
  ___) | ||  __/ (_| | (_) | | |  _| (_) | | | (_| |  __/
 |____/ \\__\\___|\\__, |\\___/|_| |_|  \\___/|_|  \\__, |\\___|
                |___/                         |___/      
"""

LEGAL_NOTICE = """
[bold red]LEGAL AND ETHICAL USE NOTICE[/bold red]

StegoForge is a powerful steganography engine designed for educational, research, and authorized data protection purposes. 

[bold yellow]BY USING THIS SOFTWARE, YOU ACKNOWLEDGE AND AGREE THAT:[/bold yellow]
1. You will only use StegoForge on systems, networks, and files for which you have explicit, authorized permission.
2. You will not use this tool for malicious purposes, including but not limited to malware concealment, unauthorized data exfiltration, or any activities that violate local, state, national, or international laws.
3. The authors and maintainers of StegoForge assume NO liability for any misuse of this tool or damage caused by its application.
4. You bear full responsibility for your actions and the consequences of using this software.
"""

def get_ack_path() -> Path:
    home = Path.home()
    sf_dir = home / ".stegoforge"
    return sf_dir / ".acknowledged"

def check_acknowledgment() -> bool:
    return get_ack_path().exists()

def show_banner():
    console.print(f"[bold cyan]{STEGOFORGE_BANNER}[/bold cyan]")

def show_banner_and_require_ack():
    show_banner()
    if not check_acknowledgment():
        console.print(Panel(LEGAL_NOTICE, title="First-Run Notice", border_style="red"))
        console.print("Type [bold green]'I understand'[/bold green] to acknowledge and proceed:")
        
        while True:
            try:
                response = input("> ").strip()
                if response == "I understand":
                    ack_path = get_ack_path()
                    ack_path.parent.mkdir(parents=True, exist_ok=True)
                    ack_path.touch()
                    console.print("[green]Acknowledgment saved. Welcome to StegoForge.[/green]\\n")
                    break
                else:
                    console.print("[red]Invalid response. Please type 'I understand' to proceed or Ctrl+C to exit.[/red]")
            except KeyboardInterrupt:
                console.print("\\n[yellow]Setup cancelled. Exiting.[/yellow]")
                import sys
                sys.exit(1)
