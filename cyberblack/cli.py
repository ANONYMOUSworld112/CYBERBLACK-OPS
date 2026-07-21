from __future__ import annotations

import time

from rich.prompt import Prompt

from .models import Tool, ToolCategory
from .registry import ToolRegistry, load_registry, refresh_status_cache
from .runner import run_trusted, run_freeform
from .ui.menus import (
    show_main_menu,
    show_category_menu,
    show_tool_detail,
    check_installed_tools,
)
from .ui.monitor import network_monitor
from .ui.components import console


def tool_action_loop(tool: Tool, category_color: str) -> None:
    while True:
        show_tool_detail(tool, category_color)
        choice = Prompt.ask("[bold cyan]Action[/bold cyan]", default="b").strip().lower()

        match choice:
            case "b":
                break
            case "r":
                cmd = Prompt.ask("\n[bold green]Enter command to run[/bold green]")
                confirm = Prompt.ask(
                    f"[bold yellow]Run '{cmd}'? This executes on your system.[/bold yellow] [y/N]",
                    default="n",
                ).lower()
                if confirm == "y":
                    result = run_freeform(cmd, confirmed=True)
                    if not result.ok and not result.interrupted:
                        console.print(f"\n[yellow]Exited with code {result.exit_code}[/yellow]")
                else:
                    console.print("[yellow]Command cancelled.[/yellow]")
                console.print()
                input("  Press ENTER to continue...")
            case "e":
                console.print("\n[bold yellow]Select example number:[/bold yellow]")
                for i, example in enumerate(tool.examples, 1):
                    console.print(f"  [yellow]{i}[/yellow]. {example.description}")
                try:
                    n = int(Prompt.ask("Example #")) - 1
                    if 0 <= n < len(tool.examples):
                        ex = tool.examples[n]
                        console.print(f"\n[dim]Command: {ex.command}[/dim]")
                        confirm = Prompt.ask("Run this command? [Y/n]", default="y").lower()
                        if confirm == "y":
                            result = run_trusted(ex.command)
                            if not result.ok and not result.interrupted:
                                console.print(f"\n[yellow]Exited with code {result.exit_code}[/yellow]")
                        input("\n  Press ENTER to continue...")
                except (ValueError, IndexError):
                    console.print("[red]Invalid selection.[/red]")
                    time.sleep(1)
            case "i":
                cmd = tool.install
                confirm = Prompt.ask(
                    f"Install {tool.name}? This runs: {cmd} [y/N]", default="n"
                ).lower()
                if confirm == "y":
                    result = run_trusted(cmd)
                    if result.ok:
                        refresh_status_cache()
                input("\n  Press ENTER to continue...")
            case _:
                console.print("[red]Unknown action.[/red]")
                time.sleep(0.5)


def category_loop(registry: ToolRegistry, category: ToolCategory) -> None:
    while True:
        show_category_menu(category)
        choice = Prompt.ask("[bold cyan]Select tool[/bold cyan]", default="0").strip()

        if choice == "0":
            break

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(category.tools):
                tool_action_loop(category.tools[idx], category.color)
            else:
                console.print("[red]Invalid selection.[/red]")
                time.sleep(0.8)
        except ValueError:
            console.print("[red]Please enter a number.[/red]")
            time.sleep(0.8)


def main() -> None:
    try:
        registry = load_registry()
    except Exception as exc:
        console.print(f"[bold red]Failed to load tool registry:[/bold red] {exc}")
        return

    while True:
        show_main_menu(registry)
        choice = Prompt.ask("[bold cyan]Select category[/bold cyan]", default="0").strip().lower()

        match choice:
            case "0":
                console.print("\n[bold cyan]  Thank you for using CyberBlack. Stay ethical. Stay legal.[/bold cyan]\n")
                break
            case "n":
                network_monitor()
            case "c":
                check_installed_tools(registry)
            case _:
                cat = registry.category_by_id(choice)
                if cat is not None:
                    category_loop(registry, cat)
                else:
                    console.print("[red]Invalid selection -- enter 1-10, N, C, or 0.[/red]")
                    time.sleep(0.8)


if __name__ == "__main__":
    main()
