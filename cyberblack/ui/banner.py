from __future__ import annotations

import platform
from datetime import datetime

from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich import box

from ..util import local_ip
from .components import console

_ASCII_ART = r"""
[bold cyan] ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██████╗ ██╗      █████╗  ██████╗██╗  ██╗[/bold cyan]
[bold cyan]██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝[/bold cyan]
[bold cyan]██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██████╔╝██║     ███████║██║     █████╔╝ [/bold cyan]
[bold cyan]██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ [/bold cyan]
[bold cyan]╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗[/bold cyan]
[bold cyan] ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold cyan]"""

VERSION = "2.1.0"


def show_banner() -> None:
    console.print(_ASCII_ART)

    info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    info.add_column(style="bold cyan")
    info.add_column(style="white")
    info.add_row("Version", f"{VERSION}  |  Advanced Cybersecurity Terminal Toolkit")
    info.add_row("Platform", f"{platform.system()} {platform.release()}")
    info.add_row("Your IP", local_ip())
    info.add_row("Date", datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
    info.add_row("Scope", "SOC Analyst . Pentester . CEH . OSCP . eJPT . OSINT")
    console.print(Align.center(info))
    console.print()

    console.print(
        Panel(
            "[bold red]LEGAL:[/bold red] For [bold]AUTHORIZED TESTING & EDUCATION ONLY[/bold]. "
            "Always get written permission before testing any system.",
            style="red",
            padding=(0, 2),
        )
    )
    console.print()
