from __future__ import annotations

from typing import Any, Iterable, Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import RiskLevel
from .. import registry

console = Console()

STATUS_INSTALLED = "[bold bright_green]INSTALLED[/bold bright_green]"
STATUS_MISSING = "[bold red]NOT INSTALLED[/bold red]"


def status_badge(binary: str) -> str:
    return STATUS_INSTALLED if registry.is_installed(binary) else STATUS_MISSING


def risk_badge(risk: RiskLevel) -> str:
    return f"[{risk.color}]{risk.value.title()}[/{risk.color}]"


def build_table(
    *,
    columns: Sequence[tuple[str, dict[str, Any]]],
    rows: Iterable[Sequence[str]],
    title: str | None = None,
    box_style: box.Box = box.ROUNDED,
    border_style: str = "cyan",
    show_lines: bool = False,
    show_header: bool = True,
) -> Table:
    table = Table(
        title=title,
        box=box_style,
        border_style=border_style,
        padding=(0, 1),
        show_lines=show_lines,
        show_header=show_header,
    )
    for header, kwargs in columns:
        table.add_column(header, **kwargs)
    for row in rows:
        table.add_row(*row)
    return table


def build_panel(renderable: Any, *, title: str | None = None, border_style: str = "cyan") -> Panel:
    return Panel(renderable, title=title, border_style=border_style, padding=(0, 2))
