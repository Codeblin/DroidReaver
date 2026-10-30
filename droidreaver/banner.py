"""ASCII art banner and terminal theme for DroidReaver."""

from __future__ import annotations

import os
from functools import wraps
from typing import Callable, TypeVar

from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text

from droidreaver import __version__

F = TypeVar("F", bound=Callable)

# Theme palette (classic hacker / Android pentest)
C_PRIMARY = "#00ff41"      # matrix green
C_SECONDARY = "#00d4ff"    # cyber cyan
C_ACCENT = "#ff0055"       # hot magenta
C_WARN = "#ffb000"         # amber
C_DIM = "#3a6652"          # muted green
C_GLOW = "#39ff14"         # neon

LOGO = r"""
  ____  ____   ___ ___ ____
 |  _ \|  _ \ / _ \_ _|  _ \
 | | | | |_) | | | | || | | |
 | |_| |  _ <| |_| | || |_| |
 |____/|_| \_\\___/___|____/

  ____  _____    _ __     _______ ____
 |  _ \| ____|  / \\ \   / / ____|  _ \
 | |_) |  _|   / _ \\ \ / /|  _| | |_) |
 |  _ <| |___ / ___ \\ V / | |___|  _ <
 |_| \_\_____/_/   \_\_/  |_____|_| \_\
"""

SIGNAL_PANEL = r"""
   /----------------------\
   | apk  -> map -> hook  |
   | adb  :: frida :: js  |
   | jadx :: apktool      |
   \----------------------/
        \__ mobile lab __/
"""

CIRCUIT_FOOTER = (
    "[ adb ]---[ frida ]---[ jadx ]---[ objection ]---[ apktool ]"
)

TAGLINE = "ANDROID PENTEST ENVIRONMENT"


def banner_enabled() -> bool:
    val = os.environ.get("DROIDREAVER_NO_BANNER", "").lower()
    return val not in ("1", "true", "yes")


def _colorize_logo(art: str) -> Text:
    result = Text()
    lines = art.strip("\n").splitlines()
    for i, line in enumerate(lines):
        if i > 0:
            result.append("\n")
        if not line:
            continue
        color = C_SECONDARY if i < 5 else C_PRIMARY
        result.append(line, style=Style(color=color, bold=True))
    return result


def _colorize_panel(art: str) -> Text:
    result = Text()
    lines = art.strip("\n").splitlines()
    for i, line in enumerate(lines):
        if i > 0:
            result.append("\n")
        style = Style(color=C_WARN if i in (1, 2, 3) else C_DIM, bold=i in (1, 2, 3))
        result.append(line, style=style)
    return result


def render_banner(*, compact: bool = False, version: str = __version__) -> RenderableType:
    if compact:
        line = Text()
        line.append("[dr] ", style=Style(color=C_ACCENT, bold=True))
        line.append("Droid", style=Style(color=C_SECONDARY, bold=True))
        line.append("Reaver", style=Style(color=C_PRIMARY, bold=True))
        line.append(f"  v{version}  ", style=Style(color=C_DIM))
        line.append("|", style=Style(color=C_DIM))
        line.append(" android pentest environment ", style=Style(color=C_GLOW, italic=True))
        return Panel(
            line,
            border_style=Style(color=C_DIM),
            padding=(0, 1),
        )

    hero = Table.grid(padding=(0, 3))
    hero.add_column(no_wrap=True)
    hero.add_column(no_wrap=True)
    hero.add_row(_colorize_logo(LOGO), _colorize_panel(SIGNAL_PANEL))
    hero_lockup = Align(hero, align="center")
    identity = Text(justify="center")
    identity.append(":: ", style=Style(color=C_ACCENT, bold=True))
    identity.append(TAGLINE, style=Style(color=C_GLOW, bold=True))
    identity.append(" ::", style=Style(color=C_ACCENT, bold=True))
    metadata = Text(justify="center")
    metadata.append(f"v{version}", style=Style(color=C_WARN, bold=True))
    metadata.append("  //  ", style=Style(color=C_DIM))
    metadata.append("APK WORKFLOW", style=Style(color=C_SECONDARY))
    metadata.append("  //  ", style=Style(color=C_DIM))
    metadata.append("MOBILE SECURITY", style=Style(color=C_PRIMARY))
    footer = Text(CIRCUIT_FOOTER, style=Style(color=C_DIM), justify="center")

    stack = Group(
        Panel(
            Group(hero_lockup, Text(""), identity, metadata, Text(""), footer),
            border_style=Style(color=C_PRIMARY),
            padding=(1, 2),
            title="[bold bright_green][ DROIDREAVER ][/]",
            title_align="center",
        ),
        Rule("[dim]environment online[/]", style=Style(color=C_DIM)),
    )
    return stack


def print_banner(console: Console | None = None, *, compact: bool = False) -> None:
    if not banner_enabled():
        return
    con = console or Console()
    con.print(render_banner(compact=compact))
    con.print()


def with_banner(*, compact: bool = True) -> Callable[[F], F]:
    """Decorator to print banner before a CLI command."""

    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            print_banner(compact=compact)
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def status_table(title: str = "Tool Status") -> Table:
    table = Table(
        title=f"[bold bright_cyan]{title}[/]",
        title_style=Style(color=C_SECONDARY, bold=True),
        show_header=True,
        header_style=f"bold {C_PRIMARY}",
        border_style=C_DIM,
        row_styles=[Style(color="white"), Style(color=C_DIM)],
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("Tool", style=f"bold {C_GLOW}")
    table.add_column("Category", style=C_SECONDARY)
    table.add_column("Installed", style="white")
    table.add_column("Latest", style=C_WARN)
    table.add_column("Status", justify="center")
    return table


def doctor_table() -> Table:
    table = Table(
        title="[bold]DroidReaver Doctor[/]",
        title_style=Style(color=C_ACCENT, bold=True),
        show_header=True,
        header_style=f"bold {C_PRIMARY}",
        border_style=C_DIM,
    )
    table.add_column("Check", style=f"bold {C_SECONDARY}")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="white")
    return table


def info_panel(title: str, content: str) -> Panel:
    return Panel(
        content,
        title=f"[bold {C_PRIMARY}]{title}[/]",
        border_style=Style(color=C_SECONDARY),
        padding=(1, 2),
    )
