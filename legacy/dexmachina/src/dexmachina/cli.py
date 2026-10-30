"""Deprecated DexMachina CLI wrapper for DroidReaver."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any

NOTICE = (
    "DexMachina has been renamed to DroidReaver. "
    "Install and use the maintained package with: pip install droidreaver"
)


def print_deprecation_notice() -> None:
    print(f"WARNING: {NOTICE}", file=sys.stderr)


def main(
    args: Sequence[str] | None = None,
    prog_name: str = "dexmachina",
    **extra: Any,
) -> Any:
    print_deprecation_notice()
    from droidreaver.cli import main as droidreaver_main

    return droidreaver_main(args=args, prog_name=prog_name, **extra)
