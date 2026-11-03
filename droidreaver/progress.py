"""Rich progress indicators for long-running CLI operations."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Generator

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

UpdateFn = Callable[[str | None], None]
AdvanceFn = Callable[[int], None]

_tls = threading.local()


def _live_depth() -> int:
    return getattr(_tls, "depth", 0)


def _enter_live() -> None:
    _tls.depth = _live_depth() + 1


def _exit_live() -> None:
    _tls.depth = max(0, _live_depth() - 1)


def _spinner_columns(*, show_bar: bool) -> list:
    cols: list = [
        SpinnerColumn(style="bright_green"),
        TextColumn("[progress.description]{task.description}"),
    ]
    if show_bar:
        cols.extend(
            [
                BarColumn(bar_width=28, style="#3a6652", complete_style="#00ff41"),
                TaskProgressColumn(),
            ]
        )
    cols.append(TimeElapsedColumn())
    return cols


@contextmanager
def work_spinner(
    message: str,
    console: Console | None = None,
) -> Generator[UpdateFn, None, None]:
    """Indeterminate spinner for a single blocking operation.

    Nested calls (e.g. push-server inside ``fix``) must not start a second
    Rich Live display — that flickers two spinners hundreds of times a second.
    """
    con = console or Console()

    if _live_depth() > 0:
        con.print(f"[dim]{message}[/]")

        def nested_update(description: str | None = None) -> None:
            if description and description != message:
                con.print(f"[dim]{description}[/]")

        yield nested_update
        return

    def update(description: str | None = None) -> None:
        progress.update(task, description=description or message)

    _enter_live()
    try:
        with Progress(
            *_spinner_columns(show_bar=False),
            console=con,
            transient=True,
        ) as progress:
            task = progress.add_task(message, total=None)
            yield update
    finally:
        _exit_live()


@contextmanager
def work_progress(
    message: str,
    total: int,
    console: Console | None = None,
) -> Generator[tuple[UpdateFn, AdvanceFn], None, None]:
    """Spinner + progress bar for counted work."""
    con = console or Console()

    def update(description: str | None = None) -> None:
        progress.update(task, description=description or message)

    def advance(step: int = 1) -> None:
        progress.advance(task, step)

    _enter_live()
    try:
        with Progress(
            *_spinner_columns(show_bar=True),
            console=con,
            transient=True,
        ) as progress:
            task = progress.add_task(message, total=total)
            yield update, advance
    finally:
        _exit_live()
