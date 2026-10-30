"""Frida version management — nvm-style venvs and pin-group sync."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from droidreaver.config import get_pinned_version, pin_tool, save_config
from droidreaver.registry import FRIDA_PIN_GROUP, get_pin_group, get_tool
from droidreaver.utils import (
    compare_versions,
    detect_platform,
    fetch_pypi_latest_version,
    load_pip_package_versions,
    parse_version,
    pypi_version_exists,
    run_cmd,
    versions_match,
)

console = Console()

# Tools that must be installed at the exact frida runtime version (PyPI version == frida version).
FRIDA_EXACT: frozenset[str] = frozenset({"frida"})

# Pip tools that depend on frida but have their own package versions — upgrade after frida is set.
FRIDA_COMPANIONS: frozenset[str] = frozenset({"frida-tools", "objection"})

# Optional companions — skip on failure (need radare2, manual clone, etc.).
FRIDA_COMPANIONS_OPTIONAL: frozenset[str] = frozenset({"r2frida"})

# Optional / separate versioning — best-effort only during sync.
FRIDA_OPTIONAL: frozenset[str] = frozenset({"medusa"})


@dataclass
class SyncStep:
    tool: str
    action: str  # install, skip, failed
    detail: str
    old: str | None = None
    new: str | None = None


@dataclass
class PinGroupSyncError(Exception):
    """Pin group sync failed with structured context for the CLI."""

    message: str
    target_frida: str
    steps: list[SyncStep] = field(default_factory=list)
    cause: str | None = None

    def __str__(self) -> str:
        return self.message


def venvs_root() -> Path:
    return Path.home() / ".droidreaver" / "venvs"


def frida_venv_path(frida_version: str) -> Path:
    safe = frida_version.replace("/", "-")
    return venvs_root() / f"frida-{safe}"


def _venv_python(venv: Path) -> Path:
    if detect_platform() == "windows":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _venv_bin_dir(venv: Path) -> Path:
    if detect_platform() == "windows":
        return venv / "Scripts"
    return venv / "bin"


def get_active_frida_version(config: dict) -> str | None:
    active = config.get("active", {})
    if isinstance(active, dict) and active.get("frida"):
        return str(active["frida"])
    return get_pinned_version(config, "frida")


def get_usable_frida_version(config: dict) -> str | None:
    """Active/pinned frida only when the venv exists and the version is on PyPI."""
    ver = get_active_frida_version(config)
    if ver and frida_runtime_ready(ver):
        return ver
    return None


def frida_runtime_ready(version: str) -> bool:
    """True when the version exists on PyPI and its venv has a frida CLI."""
    ver = version.lstrip("v")
    if not pypi_version_exists("frida", ver):
        return False
    bindir = _venv_bin_dir(frida_venv_path(ver))
    for name in ("frida", "frida.exe", "frida.cmd", "frida.bat"):
        if (bindir / name).is_file():
            return True
    return False


def frida_environment_ready(version: str) -> bool:
    """True when the complete managed Frida environment is already usable."""
    version = version.lstrip("v")
    venv = frida_venv_path(version)
    py = _venv_python(venv)
    if not py.is_file():
        return False

    bindir = _venv_bin_dir(venv)
    if not any((bindir / name).is_file() for name in ("frida", "frida.exe", "frida.cmd", "frida.bat")):
        return False

    packages = load_pip_package_versions(python=str(py), use_cache=False)
    installed_frida = packages.get("frida")
    return bool(
        installed_frida
        and versions_match(installed_frida, version)
        and "frida-tools" in packages
        and "objection" in packages
    )


def set_active_frida_version(config: dict, version: str) -> dict:
    import copy

    data = copy.deepcopy(config)
    data.setdefault("active", {})["frida"] = version.lstrip("v")
    return data


def list_frida_venvs() -> list[str]:
    root = venvs_root()
    if not root.exists():
        return []
    versions: list[str] = []
    for p in sorted(root.iterdir()):
        if p.is_dir() and p.name.startswith("frida-"):
            versions.append(p.name.removeprefix("frida-"))
    return versions


def fetch_frida_pypi_versions(limit: int = 15) -> list[str]:
    try:
        resp = requests.get("https://pypi.org/pypi/frida/json", timeout=20)
        resp.raise_for_status()
        releases = list(resp.json().get("releases", {}).keys())
        releases.sort(key=lambda v: parse_version(v) or v, reverse=True)
        return releases[:limit]
    except requests.RequestException:
        return []


def resolve_frida_target(config: dict, explicit: str | None = None) -> str:
    if explicit and explicit.lower() != "latest":
        target = explicit.lstrip("v")
        if not pypi_version_exists("frida", target):
            latest = fetch_pypi_latest_version("frida")
            hint = f" Latest on PyPI: {latest}." if latest else ""
            raise PinGroupSyncError(
                f"Frida {target} is not published on PyPI.{hint}\n"
                "Run: droidreaver use latest",
                target_frida=target,
            )
        return target

    pinned = get_pinned_version(config, "frida")
    if pinned:
        pinned = pinned.lstrip("v")
        if pypi_version_exists("frida", pinned):
            return pinned
        console.print(
            f"[yellow]Pinned frida {pinned} is not on PyPI — using latest instead.[/]"
        )

    latest = fetch_pypi_latest_version("frida")
    if not latest:
        raise PinGroupSyncError(
            "Could not determine target frida version from PyPI.",
            target_frida="?",
        )
    return latest.lstrip("v")


def _pip_in_venv(venv: Path, *args: str) -> None:
    py = _venv_python(venv)
    if not py.exists():
        raise PinGroupSyncError(
            f"venv python missing at {py}",
            target_frida="?",
        )
    cmd = [str(py), "-m", "pip", "install", *args]
    result = run_cmd(cmd)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "pip failed").strip()
        raise PinGroupSyncError(err, target_frida="?")


def ensure_frida_venv(frida_version: str, *, force: bool = False) -> Path:
    """Create venv and install frida stack (nvm-style isolated environment)."""
    frida_version = frida_version.lstrip("v")
    venv = frida_venv_path(frida_version)

    if not force and frida_environment_ready(frida_version):
        console.print(
            f"[dim]↷ Frida environment {frida_version} already ready — skipped[/]"
        )
        return venv

    if not pypi_version_exists("frida", frida_version):
        latest = fetch_pypi_latest_version("frida")
        hint = f" Latest on PyPI: {latest}." if latest else ""
        raise PinGroupSyncError(
            f"Frida {frida_version} is not published on PyPI.{hint}\n"
            "Run: droidreaver use latest\n"
            "If this persists, clear stale cache: delete %USERPROFILE%\\.droidreaver\\cache "
            "(or ~/.droidreaver/cache on Unix).",
            target_frida=frida_version,
        )

    venvs_root().mkdir(parents=True, exist_ok=True)

    if not venv.exists():
        result = run_cmd([sys.executable, "-m", "venv", str(venv)])
        if result.returncode != 0:
            raise PinGroupSyncError(
                f"Failed to create venv at {venv}:\n{(result.stderr or result.stdout or '').strip()}",
                target_frida=frida_version,
            )

    # Exact frida version, then let pip resolve compatible companions.
    frida_spec = f"frida=={frida_version}"
    upgrade = ["--upgrade"] if force else []
    _pip_in_venv(venv, frida_spec, *upgrade)
    for pkg in ("frida-tools", "objection"):
        _pip_in_venv(venv, pkg, *upgrade)

    for pkg in ("r2frida",):
        try:
            _pip_in_venv(venv, pkg, *upgrade)
        except PinGroupSyncError:
            pass

    return venv


def use_frida_version(
    config: dict,
    version: str,
    *,
    force: bool = False,
    pin: bool = True,
) -> Path:
    """Like nvm use: select frida version, create venv if needed, pin in config."""
    if version.lower() == "latest":
        version = resolve_frida_target(config, None)
    else:
        version = version.lstrip("v")

    venv = ensure_frida_venv(version, force=force)
    data = set_active_frida_version(config, version)
    if pin:
        data = pin_tool(data, "frida", version)
    save_config(data)
    return venv


def env_shell_hint(config: dict) -> str:
    """Printable instructions to activate the active frida venv."""
    ver = get_active_frida_version(config)
    if not ver:
        return "No active frida version. Run: droidreaver use <version>  (e.g. droidreaver use 17.11.0)"

    venv = frida_venv_path(ver)
    bindir = _venv_bin_dir(venv)
    if detect_platform() == "windows":
        return (
            f"# Active frida {ver} venv:\n"
            f"set PATH={bindir};%PATH%\n"
            f"# Or in PowerShell:\n"
            f'$env:PATH = "{bindir};$env:PATH"'
        )
    return (
        f"# Active frida {ver} venv:\n"
        f'export PATH="{bindir}:$PATH"'
    )


def print_versions_report(config: dict) -> None:
    """Show frida versions: active, pinned, venvs on disk, group state, PyPI recent."""
    from droidreaver.installer import get_latest_version, get_tool_version

    pinned = get_pinned_version(config, "frida")
    active = get_active_frida_version(config)
    latest = get_latest_version(get_tool("frida"))
    venvs = list_frida_venvs()
    recent = fetch_frida_pypi_versions(8)

    console.print(Panel(
        "[bold]Frida version model[/]\n\n"
        "Only the [bold]frida[/] pip package uses the runtime version (e.g. 17.11.0).\n"
        "[bold]frida-tools[/] and [bold]objection[/] have their own package versions but "
        "must be compatible with the frida runtime you select.\n\n"
        "Think [bold]nvm[/]: [cyan]droidreaver use 17.11.0[/] creates an isolated venv and "
        "sets it active. Switch anytime with [cyan]droidreaver use 16.2.0[/].",
        title="How versions work",
        border_style="#3a6652",
    ))

    meta = Table(show_header=False, border_style="#3a6652")
    meta.add_column("Key", style="cyan")
    meta.add_column("Value")
    meta.add_row("Active (nvm)", active or "—")
    meta.add_row("Pinned in config", pinned or "—")
    meta.add_row("Latest on PyPI", latest or "—")
    meta.add_row("Venvs on disk", ", ".join(venvs) if venvs else "—")
    meta.add_row("Recent PyPI releases", ", ".join(recent[:6]) if recent else "—")
    console.print(meta)
    console.print()

    table = Table(title="Frida pin group — installed versions", border_style="#3a6652")
    table.add_column("Tool")
    table.add_column("Installed")
    table.add_column("Notes")

    for name in FRIDA_PIN_GROUP:
        tool = get_tool(name)
        if tool.install_method == "manual":
            continue
        ver = get_tool_version(tool)
        note = ""
        if name in FRIDA_EXACT:
            note = "must match active frida runtime"
        elif name in FRIDA_COMPANIONS:
            note = "own pip version; must be compatible with frida"
        elif name in FRIDA_OPTIONAL:
            note = "separate versioning; optional"
        table.add_row(tool.display_name, ver or "—", note)

    console.print(table)
    console.print()
    console.print("[dim]Commands:[/]")
    console.print("  [cyan]droidreaver use 17.11.0[/]     switch/create venv (like nvm use)")
    console.print("  [cyan]droidreaver use latest[/]     use latest frida release")
    console.print("  [cyan]droidreaver pin frida X[/]    lock config without reinstall")
    console.print("  [cyan]droidreaver env[/]            print PATH to activate active venv")
    console.print("  [cyan]droidreaver sync frida[/]     align global pip install to target")


def print_sync_error(err: PinGroupSyncError) -> None:
    lines = [
        f"[bold red]{err.message}[/]",
        "",
        f"Target frida runtime: [bold]{err.target_frida}[/]",
    ]
    if err.cause:
        lines.extend(["", "[bold]Underlying error:[/]", f"[dim]{err.cause}[/]"])
    if err.steps:
        lines.append("")
        lines.append("[bold]Steps:[/]")
        for s in err.steps:
            icon = {"install": "[green]✓[/]", "skip": "[dim]–[/]", "failed": "[red]✗[/]"}.get(
                s.action, "?"
            )
            lines.append(f"  {icon} {s.tool}: {s.detail}")

    lines.extend([
        "",
        "[bold]What to do:[/]",
        "  1. [cyan]droidreaver use {ver}[/]  — nvm-style venv (recommended)".format(
            ver=err.target_frida
        ),
        "  2. [cyan]droidreaver sync frida[/]  — fix global pip install",
        "  3. [cyan]droidreaver versions frida[/]  — inspect group + available releases",
        "  4. [cyan]droidreaver pin frida {ver}[/]  — lock version, then use/sync".format(
            ver=err.target_frida
        ),
    ])
    console.print(Panel("\n".join(lines), title="[red]Pin group sync failed[/]", border_style="red"))
