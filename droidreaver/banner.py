"""ASCII art banner and terminal theme for DroidReaver."""

from __future__ import annotations

import os
from functools import wraps
from pathlib import Path
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

LOGO = Path(__file__).with_name("banner_art.txt").read_text(encoding="utf-8")

CIRCUIT_FOOTER = (
    "[ adb ]---[ frida ]---[ jadx ]---[ objection ]---[ apktool ]"
)

TAGLINE = "ANDROID PENTEST ENVIRONMENT"
# Full ASCII plus panel chrome needs about this many columns; below that we
# crop, and below _COMPACT_WIDTH we switch to the one-line header.
_COMPACT_WIDTH = 56
_PANEL_CHROME = 8


def banner_enabled() -> bool:
    val = os.environ.get("DROIDREAVER_NO_BANNER", "").lower()
    return val not in ("1", "true", "yes")


def _is_wordmark_line(line: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return False
    if "!" in stripped:
        return True
    return stripped.startswith("@") and "#" not in stripped


def _style_for_face_char(ch: str) -> Style:
    if ch in ":. ":
        return Style(color=C_DIM)
    if ch in "@%#":
        return Style(color=C_PRIMARY, bold=True)
    if ch in "*+=":
        return Style(color=C_GLOW, bold=True)
    return Style(color=C_PRIMARY)


def _style_for_wordmark_char(ch: str) -> Style:
    if ch in "@":
        return Style(color=C_PRIMARY, bold=True)
    if ch in "!":
        return Style(color=C_GLOW, bold=True)
    if ch in ":":
        return Style(color=C_PRIMARY)
    return Style(color=C_DIM)


def _stamp(line: str, text: str, *, align: str = "center") -> tuple[str, int]:
    width = max(len(line), len(text) + 4)
    if align == "right":
        start = max(0, width - len(text) - 2)
    elif align == "left":
        start = 2 if width > len(text) + 2 else 0
    else:
        start = max(0, (width - len(text)) // 2)
    base = line.ljust(width)
    end = start + len(text)
    if end > len(base):
        base = base.ljust(end)
    return base[:start] + text + base[end:], start


def _compose_logo(
    art: str,
    version: str,
    *,
    max_width: int | None = None,
) -> tuple[list[str], dict[int, tuple[int, str, Style]], int]:
    lines = [line.rstrip() for line in art.strip("\n").splitlines()]
    face_end = next((i for i, line in enumerate(lines) if _is_wordmark_line(line)), len(lines))
    stamps: dict[int, tuple[int, str, Style]] = {}

    def apply(index: int, text: str, style: Style, *, align: str = "center") -> None:
        if max_width is not None and len(text) > max_width:
            return
        stamped, start = _stamp(lines[index], text, align=align)
        if max_width is not None and len(stamped) > max_width:
            stamped = stamped[:max_width]
            if start >= max_width:
                return
            text = text[: max(0, max_width - start)]
        lines[index] = stamped
        stamps[index] = (start, text, style)

    apply(6, f"v{version}", Style(color=C_WARN, bold=True), align="right")
    chin = [i for i in range(face_end - 2, face_end) if i >= 0]
    if chin:
        apply(chin[0], f":: {TAGLINE} ::", Style(color=C_GLOW, bold=True))
    if len(chin) > 1:
        apply(chin[1], "APK WORKFLOW  //  MOBILE SECURITY", Style(color=C_SECONDARY, bold=True))

    gaps = [i for i in range(face_end, len(lines)) if not lines[i].strip()]
    if gaps:
        apply(gaps[0], CIRCUIT_FOOTER, Style(color=C_DIM))

    if max_width is not None:
        lines = [line[:max_width] for line in lines]

    return lines, stamps, face_end


def _colorize_logo(art: str, *, version: str, max_width: int | None = None) -> Text:
    result = Text(no_wrap=True, overflow="crop")
    lines, stamps, face_end = _compose_logo(art, version, max_width=max_width)

    for i, line in enumerate(lines):
        if i > 0:
            result.append("\n")
        stamp = stamps.get(i)
        stamp_range = range(stamp[0], stamp[0] + len(stamp[1])) if stamp else range(0)
        wordmark = i >= face_end
        for j, ch in enumerate(line):
            if stamp and j in stamp_range:
                result.append(ch, style=stamp[2])
            elif wordmark:
                result.append(ch, style=_style_for_wordmark_char(ch))
            else:
                result.append(ch, style=_style_for_face_char(ch))
    return result


def _compact_banner(version: str) -> RenderableType:
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


def render_banner(
    *,
    compact: bool = False,
    version: str = __version__,
    width: int | None = None,
) -> RenderableType:
    if compact or (width is not None and width < _COMPACT_WIDTH):
        return _compact_banner(version)

    inner = None if width is None else max(20, width - _PANEL_CHROME)
    hero_lockup = Align(
        _colorize_logo(LOGO, version=version, max_width=inner),
        align="center",
    )
    padding = (0, 1) if width is not None and width < 80 else (1, 2)
    stack = Group(
        Panel(
            hero_lockup,
            border_style=Style(color=C_PRIMARY),
            padding=padding,
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
    con.print(render_banner(compact=compact, width=con.size.width))
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
