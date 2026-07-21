from __future__ import annotations

import socket
import time
from datetime import datetime

import psutil
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich import box

from .components import console
from ..util import clear_screen, fmt_bytes, local_ip


def network_monitor() -> None:
    clear_screen()
    console.print(Panel(
        "[bold green]LIVE NETWORK MONITOR[/bold green]\n[dim]Ctrl+C to stop[/dim]",
        border_style="green",
    ))

    try:
        prev = psutil.net_io_counters(pernic=True)
        with Live(refresh_per_second=1, screen=True) as live:
            while True:
                now = datetime.now().strftime("%H:%M:%S")
                renderables = []

                renderables.append(Panel(
                    f"[bold green]NETWORK MONITOR[/bold green]   [dim]{now}  |  Ctrl+C to stop[/dim]",
                    border_style="green",
                ))

                curr = psutil.net_io_counters(pernic=True)
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()

                it = Table(title="[bold cyan]Network Interfaces[/bold cyan]", box=box.ROUNDED, border_style="cyan", padding=(0, 1))
                it.add_column("Interface", style="bold white", width=12)
                it.add_column("IPv4", style="yellow", width=18)
                it.add_column("MAC", style="dim", width=20)
                it.add_column("Recv", style="bright_green", width=14, justify="right")
                it.add_column("Sent", style="bright_red", width=14, justify="right")
                it.add_column("Recv Rate", style="bold green", width=14, justify="right")
                it.add_column("Sent Rate", style="bold red", width=14, justify="right")
                it.add_column("Up", width=5, justify="center")

                for iface, ctr in curr.items():
                    ipv4 = mac = "--"
                    for a in addrs.get(iface, []):
                        if str(a.family) in ("AddressFamily.AF_INET", "2"):
                            ipv4 = a.address
                        if str(a.family) in ("AddressFamily.AF_PACKET", "17"):
                            mac = a.address
                    p = prev.get(iface)
                    rb_s = f"{fmt_bytes(ctr.bytes_recv - p.bytes_recv)}/s" if p else "--"
                    sb_s = f"{fmt_bytes(ctr.bytes_sent - p.bytes_sent)}/s" if p else "--"
                    is_up = stats.get(iface)
                    up = "[green]UP[/green]" if (is_up and is_up.isup) else "[red]DOWN[/red]"
                    it.add_row(iface, ipv4, mac, fmt_bytes(ctr.bytes_recv), fmt_bytes(ctr.bytes_sent), rb_s, sb_s, up)
                renderables.append(it)
                prev = curr

                conns = psutil.net_connections(kind="inet")
                active = [c for c in conns if c.status == "ESTABLISHED"]
                ct = Table(title=f"[bold cyan]Active Connections ({len(active)})[/bold cyan]", box=box.SIMPLE, padding=(0, 1))
                ct.add_column("PID", style="yellow", width=8, justify="right")
                ct.add_column("Proto", style="dim", width=7)
                ct.add_column("Local", style="white", width=24)
                ct.add_column("Remote", style="bright_cyan", width=24)
                ct.add_column("Status", style="bright_green", width=14)
                for c in active[:15]:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "--"
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "--"
                    proto = "TCP" if c.type == 1 else "UDP"
                    ct.add_row(str(c.pid or "--"), proto, laddr, raddr, c.status or "--")
                if len(active) > 15:
                    ct.add_row("...", "...", f"... {len(active) - 15} more ...", "", "")
                renderables.append(ct)

                listening = [c for c in conns if c.status == "LISTEN"]
                lt = Table(title=f"[bold yellow]Listening Ports ({len(listening)})[/bold yellow]", box=box.SIMPLE, padding=(0, 1))
                lt.add_column("Port", style="bold yellow", width=8, justify="right")
                lt.add_column("PID", style="dim", width=8, justify="right")
                lt.add_column("Address", style="white", width=20)
                for c in listening[:10]:
                    lt.add_row(str(c.laddr.port if c.laddr else "--"), str(c.pid or "--"), str(c.laddr.ip if c.laddr else "--"))
                renderables.append(lt)

                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory()
                renderables.append(
                    f"  [bold]CPU[/bold] [cyan]{cpu:5.1f}%[/cyan]  "
                    f"[bold]RAM[/bold] [cyan]{ram.percent:5.1f}%[/cyan]  "
                    f"[bold]Local IP[/bold] [yellow]{local_ip()}[/yellow]  "
                    f"[bold]Hostname[/bold] [white]{socket.gethostname()}[/white]"
                )

                live.update(Group(*renderables))

    except KeyboardInterrupt:
        console.print("\n[yellow]Network monitor stopped.[/yellow]")
        time.sleep(1)
