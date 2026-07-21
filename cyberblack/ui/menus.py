from __future__ import annotations

from rich import box
from rich.align import Align
from rich.rule import Rule
from rich.table import Table

from ..models import Tool, ToolCategory
from ..registry import ToolRegistry, is_installed
from .banner import show_banner
from .components import build_table, build_panel, console, status_badge, risk_badge
from ..util import clear_screen


def show_main_menu(registry: ToolRegistry) -> None:
    clear_screen()
    show_banner()

    columns = [
        ("ID", {"style": "bold yellow", "width": 4, "justify": "center"}),
        ("Icon", {"width": 4, "justify": "center"}),
        ("Category", {"style": "bold white", "width": 30}),
        ("Description", {"style": "dim white", "width": 42}),
    ]
    rows = []
    for cat in registry.categories:
        installed = sum(1 for t in cat.tools if is_installed(t.binary))
        total = len(cat.tools)
        rows.append((
            cat.id,
            cat.icon,
            f"[{cat.color}]{cat.name}[/{cat.color}] [green]{installed}/{total}[/green]",
            cat.description,
        ))
    rows.append(("N", "", "[bold green]Network Monitor[/bold green]", "Real-time monitor your own device's network traffic"))
    rows.append(("C", "", "[bold yellow]Check Installed Tools[/bold yellow]", "See which tools are installed / missing"))
    rows.append(("0", "", "[bold red]Exit[/bold red]", "Quit CyberBlack"))

    table = build_table(
        columns=columns,
        rows=rows,
        title="[bold cyan]SELECT A CATEGORY[/bold cyan]",
        box_style=box.DOUBLE_EDGE,
        border_style="cyan",
        title_style="bold cyan",
        show_lines=True,
    )
    console.print(Align.center(table))
    console.print()


def show_category_menu(category: ToolCategory) -> None:
    clear_screen()

    header = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    header.add_column(style=f"bold {category.color}")
    header.add_column(style="white")
    header.add_row(f"{category.icon}  {category.name}", category.description)
    console.print(build_panel(header, border_style=category.color))

    columns = [
        ("ID", {"style": "bold yellow", "width": 4, "justify": "center"}),
        ("Tool", {"style": "bold white", "width": 22}),
        ("Tagline", {"style": "dim white", "width": 44}),
        ("Risk", {"width": 10, "justify": "center"}),
        ("Status", {"width": 14, "justify": "center"}),
    ]
    rows = []
    for i, tool in enumerate(category.tools, 1):
        rows.append((
            str(i),
            tool.name,
            tool.tagline,
            risk_badge(tool.risk),
            status_badge(tool.binary),
        ))
    rows.append(("0", "[dim]Back[/dim]", "", "", ""))

    table = build_table(
        columns=columns,
        rows=rows,
        box_style=box.ROUNDED,
        border_style=category.color,
        show_lines=True,
    )
    console.print(table)
    console.print()


def show_tool_detail(tool: Tool, category_color: str = "cyan") -> None:
    clear_screen()

    console.print(build_panel(
        f"[bold white]{tool.name}[/bold white]  --  [italic]{tool.tagline}[/italic]\n"
        f"[dim]{tool.description}[/dim]",
        title=f"[bold {category_color}]TOOL INFO[/bold {category_color}]",
        border_style=category_color,
    ))

    meta = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    meta.add_column(style="bold cyan", width=16)
    meta.add_column(style="white")
    meta.add_row("Risk Level", risk_badge(tool.risk))
    meta.add_row("Status", status_badge(tool.binary))
    meta.add_row("Install", f"[yellow]{tool.install}[/yellow]")
    meta.add_row("Syntax", f"[green]{tool.syntax}[/green]")
    console.print(meta)
    console.print(Rule(style="dim"))

    console.print(f"\n[bold yellow]  KEY FLAGS & OPTIONS[/bold yellow]")
    console.print(build_table(
        columns=[("Flag", {"style": "bold green", "width": 28}), ("Description", {"style": "white", "width": 52})],
        rows=[(f.flag, f.description) for f in tool.flags],
        box_style=box.SIMPLE,
    ))
    console.print(Rule(style="dim"))

    console.print(f"\n[bold yellow]  USAGE EXAMPLES[/bold yellow]")
    console.print(build_table(
        columns=[("#", {"style": "bold yellow", "width": 4, "justify": "right"}), ("Description", {"style": "bold white", "width": 28}), ("Command", {"style": "bold green", "width": 52})],
        rows=[(str(i), e.description, e.command) for i, e in enumerate(tool.examples, 1)],
        box_style=box.SIMPLE,
    ))
    console.print(Rule(style="dim"))

    console.print(f"\n[bold yellow]  PRO TIPS[/bold yellow]")
    for tip in tool.tips:
        console.print(f"   [cyan]*[/cyan] {tip}")
    console.print()

    console.print(build_panel(
        "[bold yellow][R][/bold yellow] Run command   "
        "[bold yellow][E][/bold yellow] Run an example   "
        "[bold yellow][I][/bold yellow] Install tool   "
        "[bold yellow][B][/bold yellow] Back",
        border_style="dim",
    ))


def check_installed_tools(registry: ToolRegistry) -> None:
    clear_screen()
    console.print(build_panel("[bold yellow]TOOL INSTALLATION STATUS[/bold yellow]", border_style="yellow"))

    for category in registry.categories:
        rows = []
        for tool in category.tools:
            rows.append((
                tool.name,
                tool.binary,
                status_badge(tool.binary),
                tool.install,
            ))
        table = build_table(
            columns=[("Tool", {"style": "white", "width": 20}), ("Binary", {"style": "dim", "width": 20}), ("Status", {"width": 16, "justify": "center"}), ("Install", {"style": "dim yellow", "width": 38})],
            rows=rows,
            title=f"{category.icon} {category.name}",
            box_style=box.SIMPLE,
            title_style=f"bold {category.color}",
        )
        console.print(table)

    input("\n  Press ENTER to return to menu...")
