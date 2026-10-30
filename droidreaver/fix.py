"""Automated repair planner and executor — works with doctor findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from droidreaver.config import config_path_of, get_pinned_version, is_ignored, load_config
from droidreaver.device import push_frida_server
from droidreaver.doctor import CheckResult, run_doctor
from droidreaver.installer import (
    InstallError,
    get_tool_status,
    get_tool_version,
    install_tools,
    sync_pin_group,
    update_pin_group,
    update_tool,
)
from droidreaver.progress import work_progress
from droidreaver.registry import FRIDA_PIN_GROUP, get_tool, list_tools
from droidreaver.utils import which

console = Console()

# Core toolkit for the pentest environment vision (safe auto-install on fix)
CORE_ENV_TOOLS: tuple[str, ...] = (
    "adb",
    "frida",
    "frida-tools",
    "objection",
    "jadx",
    "apktool",
    "mitmproxy",
)

FIX_CATEGORIES = frozenset({"frida", "server", "adb", "reinstall", "missing", "updates", "bootstrap"})

# Impact levels shown in the fix plan (scope/disruption — not a security score).
RISK_LEVELS: dict[str, dict[str, str]] = {
    "low": {
        "title": "Low impact",
        "short": "One tool or device; easily reversed",
        "detail": (
            "Installs or touches a single component. Uses pip, a GitHub release, "
            "or adb push. Unlikely to affect unrelated tools."
        ),
        "examples": "Install adb, push frida-server, reinstall one broken tool",
    },
    "medium": {
        "title": "Medium impact",
        "short": "Multiple packages or version bumps together",
        "detail": (
            "Changes versions across a pin group or updates several registry tools. "
            "May take longer and could temporarily break hooks until sync completes."
        ),
        "examples": "Sync frida pin group, update outdated tools (--aggressive)",
    },
    "high": {
        "title": "High impact / manual",
        "short": "Requires you — not run automatically",
        "detail": (
            "OS-level installs, hardware setup, or commercial tools DroidReaver cannot "
            "install for you. Listed in the plan but never applied without your action."
        ),
        "examples": "Upgrade Python, install JDK/Node.js, connect a USB device",
    },
}


@dataclass
class FixAction:
    """A single repair step."""

    id: str
    category: str
    title: str
    description: str
    risk: str  # low, medium, high — see RISK_LEVELS (impact scope, not security)
    automated: bool
    source_check: str
    apply: Callable[[dict], None] | None = None
    manual_hint: str | None = None
    risk_detail: str | None = None  # action-specific impact note; overrides level short text


@dataclass
class FixResult:
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    manual: list[str] = field(default_factory=list)


def _apply_install_frida(config: dict) -> None:
    install_tools(["frida"], config, force=True)


def _apply_sync_frida_group(config: dict) -> None:
    pinned = get_pinned_version(config, "frida")
    sync_pin_group("frida", config, target_frida=pinned, force=True)


def _apply_install_adb(config: dict) -> None:
    install_tools(["adb"], config, force=True)


def _apply_push_server(config: dict) -> None:
    push_frida_server(config)


def _make_reinstall(tool_name: str) -> Callable[[dict], None]:
    def _apply(config: dict) -> None:
        install_tools([tool_name], config, force=True)

    return _apply


def _make_install_tool(tool_name: str) -> Callable[[dict], None]:
    def _apply(config: dict) -> None:
        install_tools([tool_name], config, force=True)

    return _apply


def _make_update_tool(tool_name: str) -> Callable[[dict], None]:
    def _apply(config: dict) -> None:
        tool = get_tool(tool_name)
        if tool.pin_with:
            update_pin_group(tool_name, config, force=True)
        else:
            update_tool(tool_name, config, force=True)

    return _apply


def build_fix_plan(
    config: dict,
    checks: list[CheckResult],
    *,
    aggressive: bool = False,
    bootstrap: bool = False,
    only: set[str] | None = None,
) -> list[FixAction]:
    """Build an ordered, deduplicated fix plan from doctor results."""
    actions: list[FixAction] = []
    seen: set[str] = set()

    def add(action: FixAction) -> None:
        if action.id in seen:
            return
        if only and action.category not in only:
            return
        seen.add(action.id)
        actions.append(action)

    # Map doctor checks → fix actions
    for check in checks:
        if check.status not in ("fail", "warn"):
            continue

        if check.name == "ADB" and check.status == "fail":
            add(
                FixAction(
                    id="install-adb",
                    category="adb",
                    title="Install Android platform tools (adb)",
                    description="Install adb so devices and frida-server can be managed",
                    risk="low",
                    risk_detail="Downloads platform-tools; no other tools affected",
                    automated=True,
                    source_check=check.name,
                    apply=_apply_install_adb,
                )
            )

        elif check.name == "Frida pin group":
            if "No frida group" in check.message or "not installed" in check.message.lower():
                add(
                    FixAction(
                        id="install-frida-group",
                        category="frida",
                        title="Install Frida and pin-group tools",
                        description="Install frida, frida-tools, objection (dependency order)",
                        risk="low",
                        risk_detail="Fresh install; pulls frida + dependencies via pip",
                        automated=True,
                        source_check=check.name,
                        apply=_apply_install_frida,
                    )
                )
            elif "Version mismatch" in check.message or "runtime installed" in check.message:
                pinned = get_pinned_version(config, "frida")
                desc = (
                    f"Reinstall pin group at pinned version {pinned}"
                    if pinned
                    else "Update entire frida pin group to latest matching version"
                )
                add(
                    FixAction(
                        id="sync-frida-group",
                        category="frida",
                        title="Sync frida pin group versions",
                        description=desc,
                        risk="medium",
                        risk_detail=(
                            "Reinstalls frida, frida-tools, objection, r2frida "
                            "(+ medusa if available) to one version"
                        ),
                        automated=True,
                        source_check=check.name,
                        apply=_apply_sync_frida_group,
                    )
                )

        elif check.name == "Frida server" and check.status == "warn":
            if "Not running" in check.message or "frida-ps failed" in check.message:
                add(
                    FixAction(
                        id="push-frida-server",
                        category="server",
                        title="Push and start frida-server on device",
                        description="Download matching frida-server and push via adb",
                        risk="low",
                        risk_detail="Device only; local frida version unchanged",
                        automated=True,
                        source_check=check.name,
                        apply=_apply_push_server,
                    )
                )
            elif "not installed" in check.message.lower():
                add(
                    FixAction(
                        id="install-frida-for-server",
                        category="frida",
                        title="Install local frida before pushing server",
                        description="frida CLI must be installed to determine server version",
                        risk="low",
                        risk_detail="Installs frida via pip; required before push-server",
                        automated=True,
                        source_check=check.name,
                        apply=_apply_install_frida,
                    )
                )

        elif check.fix_tool and check.status == "warn":
            tool_name = check.fix_tool
            if is_ignored(config, tool_name):
                continue
            tool = get_tool(tool_name)
            add(
                FixAction(
                    id=f"reinstall-{tool_name}",
                    category="reinstall",
                    title=f"Reinstall {tool.display_name}",
                    description=check.message,
                    risk="low",
                    risk_detail=f"Reinstalls {tool.display_name} only (--force)",
                    automated=True,
                    source_check=check.name,
                    apply=_make_reinstall(tool_name),
                )
            )

        elif check.automated is False and check.fix and check.status in ("fail", "warn"):
            add(
                FixAction(
                    id=f"manual-{check.name.lower().replace(' ', '-')}",
                    category="manual",
                    title=f"Manual: {check.name}",
                    description=check.message,
                    risk="high",
                    risk_detail=RISK_LEVELS["high"]["short"],
                    automated=False,
                    source_check=check.name,
                    manual_hint=check.fix,
                )
            )

    # Bootstrap core pentest environment (missing auto-installable core tools)
    if bootstrap:
        for tool_name in CORE_ENV_TOOLS:
            if is_ignored(config, tool_name):
                continue
            tool = get_tool(tool_name)
            if tool.install_method == "manual":
                continue
            installed = get_tool_version(tool)
            binary_ok = tool.binary_name and which(tool.binary_name)
            if installed or binary_ok:
                continue
            add(
                FixAction(
                    id=f"bootstrap-{tool_name}",
                    category="bootstrap",
                    title=f"Install core tool: {tool.display_name}",
                    description="Part of the DroidReaver pentest environment baseline",
                    risk="low",
                    risk_detail=f"Adds {tool.display_name} to your core pentest kit",
                    automated=True,
                    source_check="bootstrap",
                    apply=_make_install_tool(tool_name),
                )
            )

    # Aggressive: update outdated non-manual tools
    if aggressive:
        for tool in list_tools():
            if is_ignored(config, tool.name):
                continue
            if tool.install_method == "manual":
                continue
            status = get_tool_status(tool, config)
            if status["status"] != "outdated":
                continue
            add(
                FixAction(
                    id=f"update-{tool.name}",
                    category="updates",
                    title=f"Update {tool.display_name}",
                    description=f"{status['installed']} → {status['latest']}",
                    risk="medium",
                    risk_detail=f"Bumps {tool.display_name} to latest release",
                    automated=True,
                    source_check="outdated scan",
                    apply=_make_update_tool(tool.name),
                )
            )

    # Execution order: adb → frida install → frida sync → reinstalls → bootstrap → server → updates
    order = {"adb": 0, "frida": 1, "reinstall": 2, "bootstrap": 3, "missing": 4, "server": 5, "updates": 6, "manual": 99}
    actions.sort(key=lambda a: (order.get(a.category, 50), a.title))
    return actions


def format_impact_cell(action: FixAction) -> str:
    """Render impact level + short explanation for the fix plan table."""
    level = RISK_LEVELS.get(action.risk, {})
    style = {"low": "green", "medium": "yellow", "high": "red"}.get(action.risk, "white")
    title = level.get("title", action.risk)
    short = action.risk_detail or level.get("short", "")
    return f"[{style}]{title}[/]\n[dim]{short}[/]"


def print_risk_legend() -> None:
    """Explain impact levels before the fix plan."""
    lines = [
        "[dim]Impact = how disruptive a fix is (not a security rating).[/]",
        "",
    ]
    for key in ("low", "medium", "high"):
        level = RISK_LEVELS[key]
        style = {"low": "green", "medium": "yellow", "high": "red"}[key]
        lines.append(
            f"[{style}]● {level['title']}[/] — {level['detail']}\n"
            f"   [dim]e.g. {level['examples']}[/]"
        )
    console.print(Panel("\n".join(lines), title="[bold]Impact levels[/]", border_style="#3a6652", padding=(1, 2)))
    console.print()


def print_fix_plan(plan: list[FixAction], *, show_legend: bool = True) -> None:
    auto = [a for a in plan if a.automated]
    manual = [a for a in plan if not a.automated]

    if show_legend:
        print_risk_legend()

    table = Table(
        title="[bold cyan]⚙ DroidReaver Fix Plan[/]",
        show_header=True,
        header_style="bold #00ff41",
        border_style="#3a6652",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Action", style="bold", min_width=28)
    table.add_column("Category", width=10)
    table.add_column("Impact", min_width=22)
    table.add_column("Mode", width=8)

    for i, action in enumerate(plan, 1):
        mode = "[green]auto[/]" if action.automated else "[dim]manual[/]"
        table.add_row(
            str(i),
            action.title,
            action.category,
            format_impact_cell(action),
            mode,
        )
        table.add_row("", f"[dim]{action.description}[/]", "", "", "")

    console.print(table)
    console.print(
        f"\n[bold]{len(auto)}[/] automated, [bold]{len(manual)}[/] manual step(s)"
    )

    if manual:
        console.print()
        hints = "\n".join(
            f"[cyan]▸[/] [bold]{a.title}:[/] {a.manual_hint or a.description}"
            for a in manual
        )
        console.print(
            Panel(hints, title="[yellow]Manual steps (not auto-applied)[/]", border_style="#3a6652")
        )


def apply_fix_plan(
    plan: list[FixAction],
    config: dict,
    *,
    dry_run: bool = False,
) -> FixResult:
    result = FixResult()
    automated = [a for a in plan if a.automated and a.apply]

    for action in plan:
        if not action.automated:
            result.manual.append(f"{action.title}: {action.manual_hint or action.description}")
            continue

    if dry_run:
        result.skipped = [a.title for a in automated]
        return result

    with work_progress(
        "[cyan]Applying fixes…[/]",
        total=len(automated),
        console=console,
    ) as (update, advance):
        for action in automated:
            update(f"[cyan]Fixing:[/] [bold]{action.title}[/]…")
            try:
                assert action.apply is not None
                action.apply(config)
                result.applied.append(action.title)
            except (InstallError, Exception) as e:
                result.failed.append((action.title, str(e)))
            advance()

    return result


def run_fix(
    config: dict,
    *,
    dry_run: bool = False,
    yes: bool = False,
    aggressive: bool = False,
    bootstrap: bool = False,
    only: set[str] | None = None,
    show_legend: bool = True,
) -> int:
    """Diagnose, plan, apply fixes, re-check. Returns exit code."""
    console.print("[bold cyan]Phase 1:[/] Diagnosing environment…")
    checks = run_doctor(config)
    plan = build_fix_plan(
        config,
        checks,
        aggressive=aggressive,
        bootstrap=bootstrap,
        only=only,
    )

    automated = [a for a in plan if a.automated]
    if not plan:
        console.print("\n[bold green]◈ Nothing to fix — environment looks good.[/]")
        return 0

    console.print()
    print_fix_plan(plan, show_legend=show_legend)

    if dry_run:
        console.print("\n[dim]Dry run — no changes applied.[/]")
        return 0

    if not automated:
        console.print("\n[yellow]Only manual steps remain. See hints above.[/]")
        return 1

    if not yes:
        console.print()
        if not click.confirm(
            f"Apply {len(automated)} automated fix(es)?",
            default=True,
        ):
            console.print("[dim]Aborted.[/]")
            return 0

    console.print()
    console.print("[bold cyan]Phase 2:[/] Applying fixes…")
    result = apply_fix_plan(plan, config, dry_run=False)

    if result.applied:
        console.print("\n[bold green]Applied:[/]")
        for title in result.applied:
            console.print(f"  [green]✓[/] {title}")

    if result.failed:
        console.print("\n[bold red]Failed:[/]")
        for title, err in result.failed:
            console.print(f"  [red]✗[/] {title}: {err}")

    if result.manual:
        console.print("\n[bold yellow]Still manual:[/]")
        for line in result.manual:
            console.print(f"  [yellow]▸[/] {line}")

    console.print("\n[bold cyan]Phase 3:[/] Re-checking environment…")
    config = load_config(config_path_of(config))
    post_checks = run_doctor(config)
    remaining = [c for c in post_checks if c.status in ("fail", "warn")]

    if not remaining and not result.failed:
        console.print("\n[bold green]◈ All automated issues resolved.[/]")
        return 0

    if remaining:
        console.print(f"\n[yellow]{len(remaining)} issue(s) still need attention:[/]")
        for c in remaining:
            color = "red" if c.status == "fail" else "yellow"
            console.print(f"  [{color}]•[/] {c.name}: {c.message}")

    return 1 if result.failed or remaining else 0
