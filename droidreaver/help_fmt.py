"""Categorized --help output for the DroidReaver CLI."""

from __future__ import annotations

from collections import defaultdict

import click

from droidreaver.runtime import list_runnable_tools
from droidreaver.utils import human_category

# Core commands in display order (not tool dispatchers).
CORE_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Get started",
        (
            "init",
            "up",
            "console",
            "shell",
            "profile",
            "lock",
            "restore",
        ),
    ),
    (
        "Environment",
        (
            "status",
            "doctor",
            "fix",
            "install",
            "get",
            "update",
            "sync",
            "use",
            "versions",
            "env",
            "pin",
            "unpin",
        ),
    ),
    (
        "Device",
        (
            "device",
            "push-server",
        ),
    ),
    (
        "Presets",
        (
            "hook",
            "bypass",
        ),
    ),
    (
        "Arsenal",
        (
            "arsenal",
            "run",
            "info",
        ),
    ),
    ("Configuration", ("config",)),
)

CATEGORY_ORDER: tuple[str, ...] = (
    "dynamic_analysis",
    "static_analysis",
    "traffic_interception",
    "device_adb",
    "apk_manipulation",
    "automated_scanners",
    "data_storage",
    "network",
)


class DroidReaverGroup(click.Group):
    """Click group that renders --help in categorized sections."""

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        by_name: dict[str, click.Command] = {}
        for name in self.list_commands(ctx):
            cmd = self.get_command(ctx, name)
            if cmd is not None and not cmd.hidden:
                by_name[name] = cmd

        listed: set[str] = set()

        for section_title, command_names in CORE_SECTIONS:
            rows: list[tuple[str, str]] = []
            for name in command_names:
                cmd = by_name.get(name)
                if cmd is None:
                    continue
                rows.append((name, cmd.get_short_help_str() or ""))
                listed.add(name)
            if rows:
                with formatter.section(section_title):
                    formatter.write_dl(rows)

        by_category: dict[str, list[tuple[str, str]]] = defaultdict(list)
        seen_tools: set[str] = set()

        for inv in list_runnable_tools():
            if inv.tool.name in seen_tools:
                continue
            seen_tools.add(inv.tool.name)

            cmd = by_name.get(inv.name) or by_name.get(inv.tool.name)
            if cmd is None:
                continue

            aliases = sorted(
                i.name
                for i in list_runnable_tools()
                if i.tool.name == inv.tool.name and i.name != inv.tool.name
            )
            help_text = inv.tool.description or f"Run {inv.tool.display_name}"
            if aliases:
                alias_preview = ", ".join(aliases[:5])
                if len(aliases) > 5:
                    alias_preview += ", …"
                help_text = f"{help_text}  [aliases: {alias_preview}]"

            by_category[inv.tool.category].append((inv.tool.name, help_text))
            listed.add(inv.tool.name)
            listed.update(aliases)

        for category in CATEGORY_ORDER:
            rows = sorted(by_category.get(category, []), key=lambda r: r[0])
            if not rows:
                continue
            title = f"Arsenal — {human_category(category)}"
            with formatter.section(title):
                formatter.write_dl(rows)

        orphan_rows: list[tuple[str, str]] = []
        for name in sorted(by_name):
            if name not in listed:
                cmd = by_name[name]
                orphan_rows.append((name, cmd.get_short_help_str() or ""))
        if orphan_rows:
            with formatter.section("Other"):
                formatter.write_dl(orphan_rows)

        with formatter.section("Tip"):
            formatter.write_text(
                "Run any tool directly: droidreaver frida -U   ·   "
                "Full tool list: droidreaver arsenal"
            )
