"""Click CLI entrypoint for DroidReaver."""

from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import click
from rich.console import Console
from rich.panel import Panel


def _harden_stdio() -> None:
    """Avoid UnicodeEncodeError when stdout is piped on legacy Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


_harden_stdio()

from droidreaver import __version__
from droidreaver.banner import info_panel, print_banner, status_table
from droidreaver.bypass import BypassError, list_recipes, run_bypass
from droidreaver.config import (
    config_path_of,
    default_config_path,
    ensure_config,
    format_config_toml,
    load_config,
    pin_tool,
    save_config,
    set_config_value,
    unpin_tool,
)
from droidreaver.device import push_frida_server
from droidreaver.doctor import print_doctor_report
from droidreaver.fix import run_fix
from droidreaver.help_fmt import DroidReaverGroup
from droidreaver.installer import (
    InstallError,
    get_latest_version,
    get_tool_status,
    get_tool_version,
    install_tools,
    warm_version_cache,
    sync_pin_group,
    update_pin_group,
    update_tool,
)
from droidreaver.lockfile import lock_path, read_lock, restore_from_lock, write_lock
from droidreaver.profiles import (
    DEFAULT_PROFILE,
    profile_description,
    profile_names,
    resolve_profile,
)
from droidreaver.registry import (
    FRIDA_PIN_GROUP,
    TOOLS,
    get_pin_group,
    get_tool,
    list_tools,
    resolve_install_order,
)
from droidreaver.progress import work_progress, work_spinner
from droidreaver.runtime import (
    RunError,
    can_launch_interactive_shell,
    collect_tool_bin_paths,
    format_arsenal_row,
    launch_shell,
    list_runnable_tools,
    lookup_invocation,
    pick_user_shell,
    run_invocation,
    shell_path_hint,
)
from droidreaver.utils import human_category
from droidreaver.versions import (
    PinGroupSyncError,
    env_shell_hint,
    get_active_frida_version,
    get_usable_frida_version,
    print_sync_error,
    print_versions_report,
    resolve_frida_target,
    use_frida_version,
)
from droidreaver.workspace import find_git_root, init_workspace

console = Console()


def _resolve_tool_name(name: str) -> str | None:
    """Exact or case-insensitive registry lookup."""
    if name in TOOLS:
        return name
    lower = name.lower()
    for key in TOOLS:
        if key.lower() == lower:
            return key
    return None


def _suggest_tools(name: str, limit: int = 5) -> list[str]:
    """Fuzzy suggestions for unknown tool names."""
    q = name.lower()
    scored: list[tuple[int, str]] = []
    for key, tool in TOOLS.items():
        hay = f"{key} {tool.display_name}".lower()
        if q in hay:
            scored.append((0 if key.startswith(q) else 1, key))
    scored.sort(key=lambda x: (x[0], x[1]))
    return [k for _, k in scored[:limit]]


def _print_info_catalog(category: str | None) -> None:
    """List all registry tools when no tool name is given."""
    from rich.table import Table

    tools = list_tools(category)
    if not tools:
        console.print(f"[yellow]No tools in category:[/] {category}")
        console.print(
            "[dim]Categories:[/] dynamic_analysis, static_analysis, "
            "traffic_interception, device_adb, …"
        )
        return

    table = Table(
        title="[bold cyan]DroidReaver Tool Catalog[/]",
        show_header=True,
        header_style="bold #00ff41",
        border_style="#3a6652",
    )
    table.add_column("Name", style="bold #39ff14")
    table.add_column("Display name")
    table.add_column("Category")
    table.add_column("Install")

    for t in tools:
        table.add_row(t.name, t.display_name, human_category(t.category), t.install_method)

    console.print(table)
    console.print(
        f"\n[dim]{len(tools)} tools — details:[/] [cyan]droidreaver info <name>[/]  "
        f"[dim]e.g.[/] [cyan]droidreaver info frida[/]"
    )


def _load_cfg() -> dict:
    ensure_config()
    return load_config()


@click.group(cls=DroidReaverGroup, invoke_without_command=True)
@click.pass_context
@click.version_option(__version__, prog_name="droidreaver")
@click.option(
    "--no-banner",
    is_flag=True,
    default=False,
    help="Suppress ASCII banner (also: DROIDREAVER_NO_BANNER=1)",
)
def main(ctx: click.Context, no_banner: bool) -> None:
    """DroidReaver — Android pentesting tool manager."""
    if no_banner:
        import os

        os.environ["DROIDREAVER_NO_BANNER"] = "1"

    if ctx.invoked_subcommand is None:
        print_banner(console, compact=False)
        click.echo(ctx.get_help())


@main.command()
@click.option("--category", "-c", default=None, help="Filter by category")
@click.option(
    "--offline",
    is_flag=True,
    help="Skip latest-version lookups (no network; much faster)",
)
def status(category: str | None, offline: bool) -> None:
    """Show installed vs latest versions for all tools."""
    print_banner(console, compact=True)
    cfg = _load_cfg()
    tools = list_tools(category)
    warm_version_cache(cfg)

    table = status_table("DroidReaver Tool Status")

    status_icons = {
        "ok": "[bold green]▣ OK[/]",
        "outdated": "[bold yellow]▲ OUTDATED[/]",
        "missing": "[bold red]✗ MISSING[/]",
        "pinned": "[bold blue]◉ PINNED[/]",
        "manual": "[dim cyan]▤ MANUAL[/]",
    }

    rows: list[tuple | None] = [None] * len(tools)
    fetch_latest = not offline

    def _scan_tool(index: int, tool) -> tuple[int, tuple]:
        info = get_tool_status(tool, cfg, fetch_latest=fetch_latest)
        icon = status_icons.get(info["status"], info["status"])
        return index, (
            tool.display_name,
            human_category(tool.category),
            info["installed"] or "—",
            info["latest"] or "—",
            icon,
        )

    with work_progress(
        "[cyan]Scanning tool registry…[/]",
        total=len(tools),
        console=console,
    ) as (update, advance):
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_scan_tool, i, tool) for i, tool in enumerate(tools)]
            for future in as_completed(futures):
                index, row = future.result()
                update(f"[cyan]Checking[/] [bold]{row[0]}[/]…")
                rows[index] = row
                advance()

    for row in rows:
        if row is not None:
            table.add_row(*row)

    console.print(table)
    if offline:
        console.print(
            "[dim]Offline mode — latest versions skipped. "
            "Re-run without --offline to check for updates.[/]"
        )

    # Frida pin group summary
    from droidreaver.config import get_pinned_version
    from droidreaver.versions import FRIDA_COMPANIONS, get_active_frida_version

    frida_ver = get_tool_version(get_tool("frida"), cfg)
    active = get_active_frida_version(cfg)
    pinned = get_pinned_version(cfg, "frida")

    if frida_ver:
        parts = [f"frida={frida_ver}"]
        for name in FRIDA_COMPANIONS:
            v = get_tool_version(get_tool(name), cfg)
            if v:
                parts.append(f"{name}={v}")
        line = ", ".join(parts)
        extras = []
        if active:
            extras.append(f"active venv [bold]{active}[/]")
        if pinned:
            extras.append(f"pinned [bold]{pinned}[/]")
        suffix = f" ({', '.join(extras)})" if extras else ""
        console.print(f"\n[bold green]◈ Frida stack:[/] {line}{suffix}")
        console.print(
            "  [dim]Switch runtime:[/] [cyan]droidreaver use 17.11.0[/]  "
            "[dim]·[/]  [cyan]droidreaver sync frida[/]  "
            "[dim]·[/]  [cyan]droidreaver versions frida[/]"
        )
    else:
        console.print("\n[yellow]Frida not installed.[/] Try: [cyan]droidreaver use latest[/]")


@main.command("install")
@click.argument("tool", required=False, default=None)
@click.option("--all", "install_all", is_flag=True, help="Install all registry tools")
@click.option("--version", "ver", default=None, help="Pin version for this install")
@click.option("--force", is_flag=True, help="Override pin group conflicts")
def install_cmd(tool: str | None, install_all: bool, ver: str | None, force: bool) -> None:
    """Install a tool and its dependencies."""
    print_banner(console, compact=True)
    cfg = _load_cfg()

    if install_all:
        names = [
            t.name
            for t in TOOLS.values()
            if t.install_method != "manual"
        ]
        names = [n for n in names if n not in cfg.get("ignored", {}).get("tools", [])]
        console.print(f"Installing {len(names)} tools in dependency order...")
        try:
            install_tools(names, cfg, force=force)
        except InstallError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)
        return

    if not tool:
        console.print("[red]Specify a tool name or use --all[/]")
        sys.exit(1)

    try:
        get_tool(tool)
    except KeyError:
        console.print(f"[red]Unknown tool:[/] {tool}")
        sys.exit(1)

    group = get_pin_group(tool)
    if ver and len(group) > 1 and not force:
        from droidreaver.installer import check_pin_group_conflict

        conflicts = check_pin_group_conflict(tool, ver, cfg)
        if conflicts:
            console.print("[yellow]Warning:[/] This version may break the pin group:")
            for c in conflicts:
                console.print(f"  • {c}")
            console.print("Use [cyan]--force[/] to proceed anyway.")

    order = resolve_install_order([tool])
    console.print(f"Install order: {' → '.join(order)}")
    try:
        install_tools([tool], cfg, version=ver, force=force)
    except InstallError as e:
        console.print(f"[red]Error:[/] {e}")
        sys.exit(1)


@main.command("update")
@click.argument("tool", required=False, default=None)
@click.option("--all", "update_all", is_flag=True, help="Update all tools")
@click.option("--force", is_flag=True, help="Force update even if pin group fails partially")
def update_cmd(tool: str | None, update_all: bool, force: bool) -> None:
    """Update tool(s) to latest versions."""
    print_banner(console, compact=True)
    cfg = _load_cfg()

    if update_all:
        names = [
            t.name
            for t in TOOLS.values()
            if t.install_method not in ("manual",)
        ]
        updated = []
        processed_pin_groups: set[frozenset[str]] = set()
        order = [
            name
            for name in resolve_install_order(names)
            if get_tool(name).install_method != "manual"
        ]
        with work_progress(
            "[cyan]Updating tools…[/]",
            total=len(order),
            console=console,
        ) as (update, advance):
            for name in order:
                t = get_tool(name)
                update(f"[cyan]Updating[/] [bold]{t.display_name}[/]…")
                if t.pin_with:
                    group_key = frozenset(get_pin_group(name))
                    if group_key in processed_pin_groups:
                        advance()
                        continue
                    processed_pin_groups.add(group_key)
                    try:
                        results = update_pin_group(name, cfg, force=force)
                        for n, old, new in results:
                            if old != new:
                                updated.append(f"{n} {old or '?'} → {new}")
                    except InstallError as e:
                        console.print(f"[yellow]Skipped pin group ({name}):[/] {e}")
                    advance()
                    continue
                try:
                    old, new = update_tool(name, cfg, force=force)
                    if old != new:
                        updated.append(f"{name} {old or '?'} → {new}")
                except InstallError as e:
                    console.print(f"[yellow]Skipped {name}:[/] {e}")
                advance()
        if updated:
            console.print("[green]Updated:[/]")
            for line in updated:
                console.print(f"  • {line}")
        else:
            console.print("[dim]All tools up to date.[/]")
        return

    if not tool:
        console.print("[red]Specify a tool or use --all[/]")
        sys.exit(1)

    try:
        t = get_tool(tool)
    except KeyError:
        console.print(f"[red]Unknown tool:[/] {tool}")
        sys.exit(1)

    if t.pin_with:
        members = [m for m in get_pin_group(tool) if get_tool(m).install_method != "manual"]
        with work_spinner(f"[cyan]Resolving target frida runtime…[/]", console=console):
            target = resolve_frida_target(cfg, None)
        console.print(
            Panel(
                f"[bold]Target frida runtime:[/] {target}\n\n"
                "• [bold]frida[/] → installed at exactly this version\n"
                "• [bold]frida-tools, objection, r2frida[/] → upgraded to pip-compatible releases "
                "(they use [italic]different[/] version numbers)\n"
                "• [bold]medusa[/] → optional, best-effort\n\n"
                f"[dim]Members:[/] {', '.join(members)}\n\n"
                "Prefer nvm-style venvs? Use [cyan]droidreaver use {target}[/] instead.".format(
                    target=target
                ),
                title="Sync frida pin group",
                border_style="#3a6652",
            )
        )
        try:
            with work_spinner(f"[cyan]Syncing frida stack…[/]", console=console):
                results = sync_pin_group(tool, cfg, force=force)
            for n, old, new in results:
                if old == new:
                    console.print(f"[dim]–[/] {n}: already OK ({old or '—'})")
                else:
                    console.print(f"[green]✓[/] {n}: {old or '?'} → {new}")
        except PinGroupSyncError as e:
            print_sync_error(e)
            sys.exit(1)
        except InstallError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)
    else:
        try:
            with work_spinner(f"[cyan]Updating[/] [bold]{tool}[/]…", console=console):
                old, new = update_tool(tool, cfg, force=force)
            if old == new:
                console.print(f"[dim]{tool} already at latest ({old})[/]")
            else:
                console.print(f"[green]✓[/] {tool}: {old or '?'} → {new}")
        except InstallError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)


@main.command("sync")
@click.argument("tool", default="frida")
@click.option("--version", "ver", default=None, help="Frida runtime version (default: pin or latest)")
@click.option("--force", is_flag=True, help="Reinstall even if frida runtime already matches")
def sync_cmd(tool: str, ver: str | None, force: bool) -> None:
    """Sync a pin group to a frida runtime version (+ compatible companions)."""
    print_banner(console, compact=True)
    try:
        t = get_tool(tool)
    except KeyError:
        console.print(f"[red]Unknown tool:[/] {tool}")
        sys.exit(1)
    if not t.pin_with:
        console.print(f"[red]{tool} is not part of a pin group. Use update instead.[/]")
        sys.exit(1)
    cfg = _load_cfg()
    target = resolve_frida_target(cfg, ver)
    console.print(f"[bold]Syncing[/] frida pin group to runtime [cyan]{target}[/]")
    try:
        with work_spinner("[cyan]Syncing…[/]", console=console):
            results = sync_pin_group(tool, cfg, target_frida=ver, force=force)
        for n, old, new in results:
            if old == new:
                console.print(f"[dim]–[/] {n}: {old or '—'}")
            else:
                console.print(f"[green]✓[/] {n}: {old or '?'} → {new}")
    except PinGroupSyncError as e:
        print_sync_error(e)
        sys.exit(1)


@main.command("use")
@click.argument("version")
@click.option("--force", is_flag=True, help="Recreate venv and reinstall")
@click.option("--no-pin", is_flag=True, help="Do not write version to [pins] in config")
def use_cmd(version: str, force: bool, no_pin: bool) -> None:
    """Select frida runtime version (like nvm use) — isolated venv per version."""
    print_banner(console, compact=True)
    cfg = _load_cfg()
    try:
        with work_spinner(f"[cyan]Setting up frida {version}…[/]", console=console):
            venv = use_frida_version(cfg, version, force=force, pin=not no_pin)
    except PinGroupSyncError as e:
        print_sync_error(e)
        sys.exit(1)
    cfg = _load_cfg()
    from droidreaver.versions import get_active_frida_version

    active = get_active_frida_version(cfg)
    console.print(f"\n[green]✓[/] Now using frida runtime [bold]{active}[/]")
    console.print(f"  venv: [dim]{venv}[/]")
    console.print(
        Panel(
            env_shell_hint(cfg),
            title="Add to your shell (so frida/objection use this venv)",
            border_style="#00ff41",
        )
    )
    console.print(
        "\n[dim]Device:[/] [cyan]droidreaver push-server[/] after switching runtime"
    )


@main.command("versions")
@click.argument("tool", default="frida", required=False)
def versions_cmd(tool: str) -> None:
    """Show installed, pinned, active, and available versions."""
    print_banner(console, compact=True)
    if tool != "frida":
        console.print("[yellow]Only 'frida' pin group supported for now.[/]")
    cfg = _load_cfg()
    print_versions_report(cfg)


@main.command("env")
@click.option("--frida-only", is_flag=True, help="Only the active frida venv (legacy)")
def env_cmd(frida_only: bool) -> None:
    """Print shell commands to put all DroidReaver tools on PATH."""
    cfg = _load_cfg()
    hint = env_shell_hint(cfg) if frida_only else shell_path_hint(cfg)
    console.print(Panel(hint, title="DroidReaver environment", border_style="#3a6652"))


@main.command("shell")
def shell_cmd() -> None:
    """Open a subshell with every installed tool already on PATH."""
    cfg = _load_cfg()
    paths = collect_tool_bin_paths(cfg)
    if not paths:
        console.print(
            "[yellow]No tools installed yet.[/] Run [cyan]droidreaver up[/] first."
        )
        sys.exit(1)

    if not can_launch_interactive_shell():
        # No real TTY (piped/redirected/non-interactive runner). An interactive
        # subshell would exit immediately, so guide the user instead.
        console.print(
            "[yellow]No interactive terminal detected[/] - can't open a subshell here."
        )
        console.print(
            "Run this in a normal terminal, or add the tools to your current "
            "session with:\n"
        )
        console.print(shell_path_hint(cfg))
        sys.exit(1)

    shell_argv = pick_user_shell()
    shell_name = os.path.basename(shell_argv[0])
    console.print(
        Panel(
            "Tools on PATH for this session:\n"
            + "\n".join(f"  [green]•[/] {p}" for p in paths)
            + f"\n\n[dim]Launching[/] [cyan]{shell_name}[/] "
            + "[dim]- look for the[/] [green][DroidReaver][/] [dim]prompt.[/]\n"
            + "[dim]Type[/] [cyan]exit[/] [dim]to leave the DroidReaver shell.[/]",
            title="[bold #00ff41]⚔ DroidReaver shell[/]",
            border_style="#00ff41",
        )
    )
    code = launch_shell(cfg)
    sys.exit(code)


@main.command("console")
@click.option("--device", "-d", "serial", default=None, help="ADB device serial to target")
def console_cmd(serial: str | None) -> None:
    """Interactive pentest console (REPL) for a connected device.

    A DroidReaver shell with first-class verbs: devices, apps, target,
    ready, hook/bypass, objection, proxy, logcat, screenshot, adb, run…

    \b
    Example:
      droidreaver console
      droidreaver> devices
      droidreaver> target com.example.app
      droidreaver> ready
      droidreaver> hook
    """
    from droidreaver.console import run_console

    cfg = _load_cfg()
    sys.exit(run_console(cfg, serial=serial))


@main.command(
    "run",
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
    },
)
@click.argument("tool")
@click.pass_context
def run_cmd(ctx: click.Context, tool: str) -> None:
    """Run a pentest tool through DroidReaver (explicit dispatch).

    Pass tool flags after the tool name:

      droidreaver run objection -g com.example.app explore

    Same as: droidreaver objection -g com.example.app explore
    """
    cfg = _load_cfg()
    try:
        code = run_invocation(tool, list(ctx.args), cfg)
    except RunError as e:
        console.print(f"[red]{e}[/]")
        console.print("[dim]List runners:[/] [cyan]droidreaver arsenal[/]")
        sys.exit(1)
    sys.exit(code)


@main.command("arsenal")
def arsenal_cmd() -> None:
    """List all tool CLIs available through droidreaver (direct or via run)."""
    from rich.table import Table

    print_banner(console, compact=True)
    cfg = _load_cfg()
    invocations = list_runnable_tools()

    table = Table(
        title="[bold red]⚔ DroidReaver Arsenal[/] — runnable CLIs",
        header_style="bold #00ff41",
        border_style="#3a6652",
    )
    table.add_column("Command", style="bold #39ff14")
    table.add_column("Registry tool")
    table.add_column("Status")
    table.add_column("Example")

    for inv in invocations:
        _, _, status = format_arsenal_row(inv, cfg)
        example = inv.usage_hint or f"droidreaver {inv.name} --help"
        table.add_row(
            inv.name,
            inv.tool.name,
            status,
            example,
        )

    console.print(table)
    console.print(
        f"\n[dim]{len(invocations)} dispatchers · "
        "invoke directly: [cyan]droidreaver frida --version[/]  "
        "or: [cyan]droidreaver run objection explore[/]"
    )


def _bypass_options(func):
    """Shared options for bypass subcommands."""
    func = click.option(
        "-n",
        "--name",
        "package",
        required=False,
        default=None,
        help="Package identifier from frida-ps -Uai (Identifier column)",
    )(func)
    func = click.option(
        "-F",
        "--foremost",
        is_flag=True,
        help="Attach to the app currently open on screen (no package needed)",
    )(func)
    func = click.option(
        "-s",
        "-f",
        "--spawn",
        is_flag=True,
        help="Spawn the app (cold start). Auto-used if the app is not running.",
    )(func)
    func = click.option("-S", "--serial", default=None, help="ADB device serial")(func)
    func = click.option(
        "-N",
        "--network",
        is_flag=True,
        help="Connect to Frida over the network instead of USB",
    )(func)
    func = click.option(
        "--objection",
        "force_objection",
        is_flag=True,
        help="Force Objection (default when installed)",
    )(func)
    func = click.option(
        "--frida",
        "force_frida",
        is_flag=True,
        help="Force bundled Frida scripts instead of Objection",
    )(func)
    return func


def _resolve_bypass_engine(force_objection: bool, force_frida: bool) -> str:
    if force_objection and force_frida:
        raise click.ClickException("Use only one of --objection or --frida.")
    if force_objection:
        return "objection"
    if force_frida:
        return "frida"
    return "auto"


def _run_bypass_cmd(recipe_id: str, package: str | None, **kwargs) -> None:
    foremost = kwargs.get("foremost", False)
    if foremost and not package:
        package = ""
    elif not package:
        raise click.ClickException(
            "Missing -n / --name. List targets with: droidreaver frida-ps -Uai\n"
            "Or use --foremost to hook the app on screen."
        )
    cfg = _load_cfg()
    engine = _resolve_bypass_engine(kwargs.pop("force_objection"), kwargs.pop("force_frida"))
    print_banner(console, compact=True)
    try:
        code = run_bypass(
            cfg,
            recipe_id,  # type: ignore[arg-type]
            package,
            engine=engine,  # type: ignore[arg-type]
            **kwargs,
        )
    except BypassError as e:
        console.print(f"[red]{e}[/]")
        sys.exit(1)
    sys.exit(code)


@main.group("bypass", invoke_without_command=True)
@_bypass_options
@click.pass_context
def bypass_group(
    ctx: click.Context,
    package: str | None,
    foremost: bool,
    spawn: bool,
    serial: str | None,
    network: bool,
    force_objection: bool,
    force_frida: bool,
) -> None:
    """Bypass presets — SSL pinning, root detection, or both.

    Uses Objection when available, otherwise bundled Frida scripts.
    Session stays open until you press Ctrl+C.

    \b
    Quick start (both bypasses — recommended):
      droidreaver bypass -n com.example.app --spawn
      droidreaver hook -n com.example.app --spawn
      droidreaver bypass all -n com.example.app --spawn

    \b
    Individual bypasses:
      droidreaver bypass ssl -n com.example.app
      droidreaver bypass root -n com.example.app
    """
    if ctx.invoked_subcommand is not None:
        return

    if package is not None or foremost:
        _run_bypass_cmd(
            "all",
            package,
            spawn=spawn,
            serial=serial,
            network=network,
            force_objection=force_objection,
            force_frida=force_frida,
            foremost=foremost,
        )
        return

    from rich.table import Table

    print_banner(console, compact=True)
    table = Table(
        title="[bold cyan]DroidReaver Bypass Presets[/]",
        header_style="bold #00ff41",
        border_style="#3a6652",
    )
    table.add_column("Command", style="bold #39ff14")
    table.add_column("What it does")
    for recipe in list_recipes():
        label = recipe.id
        if recipe.id == "all":
            label = "all / both  (default)"
        table.add_row(f"bypass {label}", recipe.summary)
    console.print(table)
    console.print(
        "\n[bold]Quick start (SSL + root):[/]\n"
        "  [cyan]droidreaver bypass -n com.example.app --spawn[/]\n"
        "  [cyan]droidreaver hook -n com.example.app --spawn[/]\n\n"
        "[dim]Requires frida-server:[/] [cyan]droidreaver push-server[/]"
    )


@bypass_group.command("all")
@_bypass_options
def bypass_all(
    package: str | None,
    foremost: bool,
    spawn: bool,
    serial: str | None,
    network: bool,
    force_objection: bool,
    force_frida: bool,
) -> None:
    """SSL pinning + root detection bypass together (default test setup)."""
    _run_bypass_cmd(
        "all",
        package,
        spawn=spawn,
        serial=serial,
        network=network,
        force_objection=force_objection,
        force_frida=force_frida,
        foremost=foremost,
    )


@bypass_group.command("both")
@_bypass_options
def bypass_both(
    package: str | None,
    foremost: bool,
    spawn: bool,
    serial: str | None,
    network: bool,
    force_objection: bool,
    force_frida: bool,
) -> None:
    """Alias for bypass all — SSL + root detection bypass."""
    _run_bypass_cmd(
        "all",
        package,
        spawn=spawn,
        serial=serial,
        network=network,
        force_objection=force_objection,
        force_frida=force_frida,
        foremost=foremost,
    )


@main.command("hook")
@_bypass_options
def hook_cmd(
    package: str | None,
    foremost: bool,
    spawn: bool,
    serial: str | None,
    network: bool,
    force_objection: bool,
    force_frida: bool,
) -> None:
    """Start a test hook: SSL pinning + root detection bypass (shorthand).

    Same as: droidreaver bypass -n <package> --spawn

    \b
    Examples:
      droidreaver hook -n com.example.app --spawn
      droidreaver hook --foremost
    """
    _run_bypass_cmd(
        "all",
        package,
        spawn=spawn,
        serial=serial,
        network=network,
        force_objection=force_objection,
        force_frida=force_frida,
        foremost=foremost,
    )


@bypass_group.command("ssl")
@_bypass_options
def bypass_ssl(
    package: str | None,
    foremost: bool,
    spawn: bool,
    serial: str | None,
    network: bool,
    force_objection: bool,
    force_frida: bool,
) -> None:
    """Universal SSL / certificate pinning bypass."""
    _run_bypass_cmd(
        "ssl",
        package,
        spawn=spawn,
        serial=serial,
        network=network,
        force_objection=force_objection,
        force_frida=force_frida,
        foremost=foremost,
    )


@bypass_group.command("root")
@_bypass_options
def bypass_root(
    package: str | None,
    foremost: bool,
    spawn: bool,
    serial: str | None,
    network: bool,
    force_objection: bool,
    force_frida: bool,
) -> None:
    """Universal root-detection bypass (hide su / root checks from the app)."""
    _run_bypass_cmd(
        "root",
        package,
        spawn=spawn,
        serial=serial,
        network=network,
        force_objection=force_objection,
        force_frida=force_frida,
        foremost=foremost,
    )


@main.command("pin")
@click.argument("tool")
@click.argument("version")
def pin_cmd(tool: str, version: str) -> None:
    """Lock a tool (and its pin group) to a specific version."""
    try:
        get_tool(tool)
    except KeyError:
        console.print(f"[red]Unknown tool:[/] {tool}")
        sys.exit(1)

    cfg = _load_cfg()
    group = get_pin_group(tool)
    new_cfg = pin_tool(cfg, tool, version)
    path = save_config(new_cfg)
    console.print(f"[green]✓[/] Pinned frida [bold]runtime[/] to [bold]{version}[/]")
    console.print(
        "  [dim]Pin saves the version; install it with:[/] "
        f"[cyan]droidreaver use {version}[/] or [cyan]droidreaver sync frida[/]"
    )
    if len(group) > 1:
        console.print(f"  Companions (frida-tools, objection, …) follow automatically")
    console.print(f"  Config saved to {path}")


@main.command("unpin")
@click.argument("tool")
def unpin_cmd(tool: str) -> None:
    """Remove version lock for a tool."""
    try:
        get_tool(tool)
    except KeyError:
        console.print(f"[red]Unknown tool:[/] {tool}")
        sys.exit(1)

    cfg = _load_cfg()
    new_cfg = unpin_tool(cfg, tool)
    path = save_config(new_cfg)
    console.print(f"[green]✓[/] Unpinned {tool} (config: {path})")


@main.command("push-server")
@click.option("--device", "-d", default=None, help="ADB device serial")
@click.option("--no-start", is_flag=True, help="Do not start frida-server after push")
def push_server_cmd(device: str | None, no_start: bool) -> None:
    """Push matching frida-server binary to connected device(s)."""
    print_banner(console, compact=True)
    cfg = _load_cfg()
    try:
        push_frida_server(cfg, serial=device, start=not no_start)
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
        sys.exit(1)


@main.command("doctor")
def doctor_cmd() -> None:
    """Run environment health checks."""
    print_banner(console, compact=True)
    cfg = _load_cfg()
    code = print_doctor_report(cfg)
    sys.exit(code)


@main.command("fix")
@click.option("--dry-run", is_flag=True, help="Show fix plan without applying")
@click.option("--yes", "-y", is_flag=True, help="Apply fixes without confirmation")
@click.option(
    "--aggressive",
    is_flag=True,
    help="Also update all outdated tools (medium impact; slow, network-heavy)",
)
@click.option(
    "--bootstrap",
    is_flag=True,
    help="Install missing core pentest tools (adb, frida, jadx, apktool, …)",
)
@click.option(
    "--only",
    default=None,
    help="Comma-separated categories: frida,server,adb,reinstall,bootstrap,updates",
)
@click.option(
    "--no-legend",
    is_flag=True,
    help="Hide the impact-level explanation panel",
)
def fix_cmd(
    dry_run: bool,
    yes: bool,
    aggressive: bool,
    bootstrap: bool,
    only: str | None,
    no_legend: bool,
) -> None:
    """Diagnose and automatically repair common environment issues.

    Each planned fix shows an \bIMPACT level (low / medium / high) describing
    how disruptive the change is — not a security score. See the legend in the
    fix plan output, or run: droidreaver fix --dry-run
    """
    print_banner(console, compact=True)
    cfg = _load_cfg()
    only_set = None
    if only:
        only_set = {c.strip() for c in only.split(",") if c.strip()}
        unknown = only_set - {"frida", "server", "adb", "reinstall", "bootstrap", "updates", "missing"}
        if unknown:
            console.print(f"[red]Unknown fix categories:[/] {', '.join(sorted(unknown))}")
            sys.exit(1)
    code = run_fix(
        cfg,
        dry_run=dry_run,
        yes=yes,
        aggressive=aggressive,
        bootstrap=bootstrap,
        only=only_set,
        show_legend=not no_legend,
    )
    sys.exit(code)


@main.command("info")
@click.argument("tool", required=False, default=None)
@click.option("--category", "-c", default=None, help="Filter catalog by category")
def info_cmd(tool: str | None, category: str | None) -> None:
    """Show detailed information about a tool (or list all tools)."""
    print_banner(console, compact=True)

    if not tool:
        _print_info_catalog(category)
        return

    # Allow partial match: "jadx" matches, or suggest close names
    resolved = _resolve_tool_name(tool)
    if resolved is None:
        console.print(f"[red]Unknown tool:[/] {tool}")
        suggestions = _suggest_tools(tool)
        if suggestions:
            console.print("[dim]Did you mean:[/] " + ", ".join(f"[cyan]{s}[/]" for s in suggestions))
        console.print("\n[dim]List all tools:[/] [cyan]droidreaver info[/]")
        sys.exit(1)

    t = get_tool(resolved)
    cfg = _load_cfg()
    installed = get_tool_version(t, cfg)
    with work_spinner(f"[cyan]Fetching release info for[/] [bold]{resolved}[/]…", console=console):
        latest = get_latest_version(t)
    pinned = cfg.get("pins", {}).get("frida") if t.pin_with else cfg.get("pins", {}).get(t.name)

    lines = [
        f"[bold]{t.display_name}[/] ({t.name})",
        f"Category: {human_category(t.category)}",
        f"Install method: {t.install_method}",
    ]
    if t.description:
        lines.append(f"Description: {t.description}")
    if t.pip_package:
        lines.append(f"pip package: {t.pip_package}")
    if t.github_repo:
        lines.append(f"GitHub: https://github.com/{t.github_repo}")
    if t.manual_url:
        lines.append(f"URL: {t.manual_url}")
    if t.depends_on:
        lines.append(f"Depends on: {', '.join(t.depends_on)}")
    if t.pin_with:
        lines.append(f"Pin group: {', '.join(t.pin_with)}")
    lines.append(f"Installed: {installed or '—'}")
    lines.append(f"Latest: {latest or '—'}")
    if pinned:
        lines.append(f"Pinned: {pinned}")
    if t.notes:
        lines.append(f"\n[bold yellow]Notes:[/] {t.notes}")

    console.print(info_panel(t.display_name, "\n".join(lines)))


@main.group("config", invoke_without_command=True)
@click.pass_context
def config_group(ctx: click.Context) -> None:
    """View or modify droidreaver.toml."""
    if ctx.invoked_subcommand is None:
        path = ensure_config()
        cfg = load_config(path)
        console.print(Panel(format_config_toml(cfg), title=str(path)))


@config_group.command("show")
def config_show() -> None:
    """Print current configuration."""
    path = ensure_config()
    cfg = load_config(path)
    console.print(Panel(format_config_toml(cfg), title=str(path)))


@config_group.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a settings value."""
    cfg = _load_cfg()
    new_cfg = set_config_value(cfg, key, value)
    path = save_config(new_cfg)
    console.print(f"[green]✓[/] Set {key} = {value} ({path})")


@config_group.command("path")
def config_path_cmd() -> None:
    """Print config file path."""
    console.print(str(default_config_path()))


@main.command("init")
@click.option(
    "--profile",
    "-p",
    default=DEFAULT_PROFILE,
    type=click.Choice(profile_names()),
    help="Default environment profile to record in config",
)
@click.option("--force", is_flag=True, help="Overwrite an existing droidreaver.toml")
@click.option("--dir", "target", default=None, help="Workspace directory (default: git root or cwd)")
def init_cmd(profile: str, force: bool, target: str | None) -> None:
    """Set up a repo-local DroidReaver workspace (config + .gitignore + tools dir)."""
    from pathlib import Path

    print_banner(console, compact=True)
    target_dir = Path(target).resolve() if target else None
    result = init_workspace(target_dir, profile=profile, force=force)

    lines = []
    if result.created_config:
        lines.append(f"[green]✓[/] Created config: [bold]{result.config_path}[/]")
    else:
        lines.append(f"[dim]Config already exists:[/] {result.config_path}")
    lines.append(f"[green]✓[/] Tools directory: [bold]{result.tools_dir}[/]")
    if result.gitignore_added:
        lines.append(
            f"[green]✓[/] Updated .gitignore (+{len(result.gitignore_added)}): "
            + ", ".join(result.gitignore_added)
        )
    else:
        lines.append("[dim].gitignore already covers .droidreaver/[/]")
    lines.append(f"[dim]Default profile:[/] [cyan]{result.profile}[/]")

    console.print(Panel("\n".join(lines), title="[bold]Workspace ready[/]", border_style="#00ff41"))
    console.print(
        "\nNext: [cyan]droidreaver up[/]  (install the profile + frida)  ·  "
        "[cyan]droidreaver shell[/]  (enter a ready environment)"
    )


def _setup_frida(cfg: dict, version: str | None) -> str | None:
    """Create/select the frida venv; returns active version or None on failure."""
    try:
        target = version or "latest"
        with work_spinner(f"[cyan]Setting up frida runtime ({target})…[/]", console=console):
            use_frida_version(cfg, target, pin=True)
    except PinGroupSyncError as e:
        console.print(f"[yellow]Frida setup skipped:[/] {e}")
        return None
    return get_active_frida_version(load_config(config_path_of(cfg)))


@main.command("up")
@click.option(
    "--profile",
    "-p",
    default=None,
    type=click.Choice(profile_names()),
    help="Profile to install (default: config profile or 'dynamic')",
)
@click.option("--frida-version", default=None, help="Frida runtime version (default: pinned/latest)")
@click.option("--no-frida", is_flag=True, help="Skip frida venv setup")
@click.option("--yes", "-y", is_flag=True, help="Run non-interactively (CI/headless)")
@click.option("--no-lock", is_flag=True, help="Do not write droidreaver.lock.toml")
def up_cmd(
    profile: str | None,
    frida_version: str | None,
    no_frida: bool,
    yes: bool,
    no_lock: bool,
) -> None:
    """Build or converge the environment; existing compatible tools are skipped."""
    print_banner(console, compact=True)

    # Auto-init a repo-local workspace when inside a git repo with no config yet.
    git_root = find_git_root()
    if git_root and not (git_root / "droidreaver.toml").exists():
        result = init_workspace(git_root, profile=profile or DEFAULT_PROFILE)
        if result.created_config:
            console.print(f"[green]✓[/] Initialized workspace at [bold]{result.config_path}[/]")

    cfg = _load_cfg()
    chosen = profile or cfg.get("settings", {}).get("profile") or DEFAULT_PROFILE
    try:
        tools = resolve_profile(chosen)
    except KeyError:
        console.print(f"[red]Unknown profile:[/] {chosen}")
        sys.exit(1)

    ignored = set(cfg.get("ignored", {}).get("tools", []))
    tools = [t for t in tools if t not in ignored]

    # Frida stack pip members come from the venv; don't double-install globally.
    if not no_frida:
        install_list = [
            t
            for t in tools
            if not (t in FRIDA_PIN_GROUP and get_tool(t).install_method == "pip")
        ]
    else:
        install_list = tools

    console.print(
        Panel(
            f"Profile: [bold cyan]{chosen}[/] — {profile_description(chosen)}\n"
            f"Tools: {', '.join(tools) if tools else '—'}\n"
            f"Frida runtime: {'skipped' if no_frida else (frida_version or 'pinned/latest')}",
            title="[bold]Environment plan[/]",
            border_style="#3a6652",
        )
    )
    if not yes and not click.confirm("Build this environment?", default=True):
        console.print("[dim]Aborted.[/]")
        return

    install_failures: list[tuple[str, str]] = []
    if install_list:
        try:
            install_failures = install_tools(install_list, cfg, continue_on_error=True)
        except InstallError as e:
            console.print(f"[red]Install error:[/] {e}")

    active = None
    if not no_frida:
        active = _setup_frida(cfg, frida_version)

    cfg = _load_cfg()
    if not no_lock:
        path = write_lock(cfg)
        console.print(f"[green]✓[/] Wrote lockfile: [dim]{path}[/]")

    border = "#00ff41"
    if install_failures:
        summary = ["[bold yellow]◈ Environment built with some failures.[/]"]
        if active:
            summary.append(f"  frida runtime: [bold]{active}[/]")
        summary.append("")
        summary.append("[yellow]Could not install:[/]")
        for name, err in install_failures:
            first_line = err.splitlines()[0] if err else "unknown error"
            summary.append(f"  [red]✗[/] {name}: {first_line}")
        summary.append("")
        summary.append("[dim]Retry one tool:[/] [cyan]droidreaver get <tool>[/]")
        border = "#d7af00"
    else:
        summary = ["[bold green]◈ Environment ready.[/]"]
        if active:
            summary.append(f"  frida runtime: [bold]{active}[/]")
    console.print(Panel("\n".join(summary), border_style=border))
    console.print(
        "\nUse your tools:\n"
        "  [cyan]droidreaver shell[/]            enter a subshell with everything on PATH\n"
        "  [cyan]droidreaver env[/]              print PATH setup for your shell\n"
        "  [cyan]droidreaver device ready[/]     push frida-server to a connected device\n"
        "  [cyan]droidreaver status --offline[/] see what's installed"
    )


@main.group("profile", invoke_without_command=True)
@click.pass_context
def profile_group(ctx: click.Context) -> None:
    """List or inspect environment profiles."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(profile_list)


@profile_group.command("list")
def profile_list() -> None:
    """Show available environment profiles."""
    from rich.table import Table

    table = Table(
        title="[bold cyan]DroidReaver Profiles[/]",
        header_style="bold #00ff41",
        border_style="#3a6652",
    )
    table.add_column("Profile", style="bold #39ff14")
    table.add_column("Tools", justify="right")
    table.add_column("Description")
    for name in profile_names():
        tools = resolve_profile(name)
        table.add_row(name, str(len(tools)), profile_description(name))
    console.print(table)
    console.print("\nBuild one: [cyan]droidreaver up --profile dynamic[/]")


@profile_group.command("show")
@click.argument("name", type=click.Choice(profile_names()))
def profile_show(name: str) -> None:
    """Show the tools in a profile and whether they're installed."""
    from rich.table import Table

    cfg = _load_cfg()
    warm_version_cache(cfg)
    tools = resolve_profile(name)
    table = Table(
        title=f"[bold cyan]Profile: {name}[/] — {profile_description(name)}",
        header_style="bold #00ff41",
        border_style="#3a6652",
    )
    table.add_column("Tool", style="bold #39ff14")
    table.add_column("Category")
    table.add_column("Installed")
    for tool_name in tools:
        t = get_tool(tool_name)
        ver = get_tool_version(t, cfg)
        installed = f"[green]{ver}[/]" if ver else "[red]—[/]"
        table.add_row(tool_name, human_category(t.category), installed)
    console.print(table)


@main.command("lock")
def lock_cmd() -> None:
    """Write droidreaver.lock.toml capturing the current installed kit."""
    cfg = _load_cfg()
    warm_version_cache(cfg)
    path = write_lock(cfg)
    console.print(f"[green]✓[/] Lockfile written: [bold]{path}[/]")
    console.print("[dim]Commit it so teammates can reproduce with[/] [cyan]droidreaver restore[/]")


@main.command("restore")
@click.option("--yes", "-y", is_flag=True, help="Run non-interactively")
def restore_cmd(yes: bool) -> None:
    """Install tools/frida exactly as recorded in droidreaver.lock.toml."""
    print_banner(console, compact=True)
    cfg = _load_cfg()
    lock = read_lock(cfg)
    if not lock:
        console.print(
            f"[yellow]No lockfile found at[/] {lock_path(cfg)}\n"
            "Create one with: [cyan]droidreaver lock[/]"
        )
        sys.exit(1)

    tools = lock.get("tools", {})
    frida = (lock.get("frida") or {}).get("active")
    console.print(
        Panel(
            f"Tools: {', '.join(tools) if tools else '—'}\n"
            f"Frida runtime: {frida or '—'}",
            title="[bold]Restore from lockfile[/]",
            border_style="#3a6652",
        )
    )
    if not yes and not click.confirm("Restore this environment?", default=True):
        console.print("[dim]Aborted.[/]")
        return

    restored, failures = restore_from_lock(cfg, lock)
    for name in restored:
        console.print(f"[green]✓[/] {name}")
    for name, err in failures:
        console.print(f"[red]✗[/] {name}: {err}")
    if failures:
        sys.exit(1)
    console.print("\n[bold green]◈ Environment restored.[/] Enter it: [cyan]droidreaver shell[/]")


@main.command("get")
@click.argument("tool")
@click.option("--version", "ver", default=None, help="Pin version for this install")
@click.option("--force", is_flag=True, help="Reinstall / override pin group conflicts")
def get_cmd(tool: str, ver: str | None, force: bool) -> None:
    """Download a tool, put it on PATH, and verify it's runnable (alias of install)."""
    print_banner(console, compact=True)
    resolved = _resolve_tool_name(tool)
    if resolved is None:
        console.print(f"[red]Unknown tool:[/] {tool}")
        suggestions = _suggest_tools(tool)
        if suggestions:
            console.print("[dim]Did you mean:[/] " + ", ".join(f"[cyan]{s}[/]" for s in suggestions))
        sys.exit(1)

    cfg = _load_cfg()
    order = resolve_install_order([resolved])
    console.print(f"Install order: {' → '.join(order)}")
    try:
        install_tools([resolved], cfg, version=ver, force=force)
    except InstallError as e:
        console.print(f"[red]Error:[/] {e}")
        sys.exit(1)

    # Verify the tool is now resolvable on the DroidReaver PATH.
    inv = lookup_invocation(resolved) or lookup_invocation(get_tool(resolved).binary_name or "")
    if inv:
        _, _, status = format_arsenal_row(inv, _load_cfg())
        if "ready" in status:
            console.print(f"[green]✓[/] [bold]{resolved}[/] is ready. Run it: [cyan]droidreaver {inv.name}[/]")
        else:
            console.print(
                f"[yellow]Installed, but '{resolved}' isn't on PATH yet.[/]\n"
                "Enter a ready shell: [cyan]droidreaver shell[/]  ·  or print PATH: [cyan]droidreaver env[/]"
            )
    if read_lock(cfg) is not None:
        write_lock(_load_cfg())


@main.group("device", invoke_without_command=True)
@click.pass_context
def device_group(ctx: click.Context) -> None:
    """Device helpers — list devices, get frida-ready."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(device_list)


@device_group.command("list")
def device_list() -> None:
    """List connected ADB devices."""
    from droidreaver.device import DeviceError, list_devices

    cfg = _load_cfg()
    try:
        devices = list_devices(cfg)
    except DeviceError as e:
        console.print(f"[red]{e}[/]")
        sys.exit(1)
    if not devices:
        console.print("[yellow]No devices connected.[/] Enable USB debugging and reconnect.")
        return
    console.print("[bold]Connected devices:[/]")
    for d in devices:
        console.print(f"  [green]•[/] {d}")


@device_group.command("root-server")
@click.option("--device", "-d", "serial", default=None, help="ADB device serial")
def device_root_server(serial: str | None) -> None:
    """Restart frida-server as root (required for attach on rooted phones)."""
    from droidreaver.device import (
        DEFAULT_FRIDA_SERVER_PATH,
        device_has_su,
        frida_server_status,
        print_frida_attach_troubleshooting,
        restart_frida_server,
    )

    cfg = _load_cfg()
    if not device_has_su(cfg, serial):
        console.print(
            "[red]adb shell su failed[/] — device does not appear rooted, or Magisk denied su.\n"
            "Grant root to [bold]Shell[/] or [bold]ADB[/] in Magisk Superuser settings."
        )
        sys.exit(1)

    console.print(
        "[dim]Watch your phone — approve the Magisk/superuser prompt if it appears.[/]\n"
    )
    status = restart_frida_server(cfg, serial=serial, verbose=True)
    if status.running and status.runs_as_root:
        console.print("[bold green]◈ frida-server is running as root.[/] You can hook now.")
        return

    console.print("[red]Could not start frida-server as root.[/]")
    print_frida_attach_troubleshooting(cfg, serial=serial)
    console.print(
        "\n[bold]Manual fallback[/] (run in your terminal, approve Magisk on phone):\n"
        f"  [cyan]adb shell su -c \"pkill frida-server; {DEFAULT_FRIDA_SERVER_PATH} -D &\"[/]\n"
        f"  [cyan]adb shell su -c \"cat /proc/$(pidof frida-server)/status | grep Uid\"[/]"
    )
    sys.exit(1)


@device_group.command("ready")
@click.option("--device", "-d", "serial", default=None, help="ADB device serial")
@click.option("--frida-version", default=None, help="Frida runtime to ensure active")
def device_ready(serial: str | None, frida_version: str | None) -> None:
    """Get a device frida-ready: ensure runtime, push frida-server, verify."""
    from droidreaver.device import DeviceError, list_devices

    print_banner(console, compact=True)
    cfg = _load_cfg()

    # 1) Device present?
    try:
        devices = list_devices(cfg)
    except DeviceError as e:
        console.print(f"[red]ADB error:[/] {e}")
        sys.exit(1)
    if not devices:
        console.print("[red]No devices connected.[/] Plug in a device with USB debugging enabled.")
        sys.exit(1)
    console.print(f"[green]✓[/] Device(s): {', '.join(devices)}")

    # 2) Ensure a frida runtime is active and usable.
    active = get_usable_frida_version(cfg)
    if not active or frida_version:
        active = _setup_frida(cfg, frida_version)
        cfg = _load_cfg()
    if not active:
        console.print(
            "[red]Could not establish a frida runtime.[/] "
            "Try: [cyan]droidreaver use latest[/]\n"
            "[dim]If you still see a bogus version like 9.9.9, delete[/] "
            "[cyan]%USERPROFILE%\\.droidreaver\\cache[/]"
        )
        sys.exit(1)
    console.print(f"[green]✓[/] Frida runtime: [bold]{active}[/]")

    # 3) Push frida-server.
    try:
        push_frida_server(cfg, serial=serial, start=True)
    except Exception as e:  # noqa: BLE001 - report and exit
        console.print(f"[red]push-server failed:[/] {e}")
        sys.exit(1)

    from droidreaver.device import frida_server_status, print_frida_attach_troubleshooting

    status = frida_server_status(cfg, serial)
    if status.device_rooted and not status.runs_as_root:
        console.print(
            "\n[red]frida-server is running but NOT as root[/] — hooks will fail.\n"
            "[dim]Approve the Magisk prompt on the phone, then run:[/] "
            "[cyan]droidreaver device root-server[/]"
        )
        print_frida_attach_troubleshooting(cfg, serial=serial)
        sys.exit(1)

    # 4) Verify with frida-ps -U.
    try:
        code = run_invocation("frida-ps", ["-U"], cfg, passthrough=False)
    except RunError:
        code = 1
    if code == 0:
        console.print("\n[bold green]◈ Device is frida-ready.[/] Try: [cyan]droidreaver hook --foremost[/]")
    else:
        console.print(
            "\n[yellow]frida-server pushed, but frida-ps -U didn't list processes.[/] "
            "Give it a moment, then retry: [cyan]droidreaver frida-ps -U[/]"
        )


def _register_tool_runners() -> None:
    """Register each runnable tool as a top-level droidreaver subcommand."""
    seen: set[str] = set()
    for inv in list_runnable_tools():
        if inv.name in seen:
            continue
        seen.add(inv.name)

        def make_tool_command(invocation_name: str, display: str):
            @click.command(
                name=invocation_name,
                add_help_option=False,
                context_settings={
                    "ignore_unknown_options": True,
                    "allow_extra_args": True,
                },
                help=inv.tool.description or f"Run {inv.tool.display_name}",
            )
            @click.pass_context
            def _tool_runner(ctx: click.Context) -> None:
                cfg = ensure_config()
                cfg_data = load_config(cfg)
                try:
                    code = run_invocation(
                        invocation_name,
                        list(ctx.args),
                        cfg_data,
                    )
                except RunError as e:
                    console.print(f"[red]{e}[/]")
                    sys.exit(1)
                sys.exit(code)

            return _tool_runner

        cmd = make_tool_command(inv.name, inv.tool.display_name)
        main.add_command(cmd)


_register_tool_runners()


if __name__ == "__main__":
    main()
