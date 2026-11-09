"""Inventory and dispatch tests for every arsenal tool.

Structural tests always run. Live probes skip when the binary is not installed
so CI stays green and a local `pytest tests/test_arsenal.py -rs` lists gaps.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from droidreaver.cli import main
from droidreaver.config import DEFAULT_CONFIG_NAME, META_KEY
from droidreaver.help_fmt import CORE_SECTIONS
from droidreaver.registry import TOOLS, Tool, list_tools
from droidreaver.runtime import (
    INVOCATION_META,
    RESERVED_COMMANDS,
    RunError,
    format_arsenal_row,
    list_runnable_tools,
    lookup_invocation,
    prepare_dispatch_args,
    resolve_executable,
    run_invocation,
)
from droidreaver.utils import PROBE_CMD_TIMEOUT

INVOCATIONS = list_runnable_tools()
INVOCATION_IDS = [inv.name for inv in INVOCATIONS]
TOOLS_LIST = list_tools()
TOOL_IDS = [tool.name for tool in TOOLS_LIST]

# Manual GUI / commercial packages: listed in the catalog, not dispatched.
MANUAL_NO_CLI = frozenset(
    name
    for name, tool in TOOLS.items()
    if tool.install_method == "manual" and not tool.binary_name
)

# Registry entries that currently have no version_cmd. Shrink this set when
# a tool gains a real probe — do not add new names without a reason.
KNOWN_NO_VERSION_CMD = frozenset(
    {
        "apksigner",
        "burp-suite",
        "drozer",
        "enjarify",
        "ghidra",
        "httptoolkit",
        "mobsf",
        "pidcat",
        "sqlitebrowser",
        "uber-apk-signer",
        "wireshark",
        "zipalign",
    }
)

# Do not spawn these even if installed (GUI / long-running servers).
LIVE_SPAWN_SKIP = frozenset(
    {
        "fastboot",  # `fastboot version` waits on USB
        "mitmproxy",
        "mitmweb",
        "mobsf",
        "scrcpy",
        "sqlitebrowser",
    }
)

# Safe to fetch in CI / DROIDREAVER_ARSENAL_INSTALL=all (no apt, brew, pip, git, GUI).
AUTO_INSTALL_METHODS = frozenset({"github_release", "direct"})

INSTALL_METHOD_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "pip": ("pip_package",),
    "npm": ("npm_package",),
    "github_release": ("github_repo",),
    "git": ("github_repo",),
    "direct": ("download_url_template",),
    "apt": ("apt_package",),
    "brew": ("brew_package",),
    "manual": (),
}


def _home_cfg() -> dict:
    """Product cache: ~/.droidreaver/tools (never committed)."""
    root = Path.home() / ".droidreaver"
    return {
        "settings": {"install_dir": str(root / "tools")},
        "pins": {},
        "ignored": {"tools": []},
        "active": {},
        META_KEY: {"root": str(root), "path": str(root / DEFAULT_CONFIG_NAME)},
    }


def parse_arsenal_install_spec(raw: str | None = None) -> set[str] | None:
    """Tool names to install before live probes.

    None — do not install (skip missing).
    Env ``DROIDREAVER_ARSENAL_INSTALL``: ``gitleaks,adb`` or ``all``.
    """
    spec = (os.environ.get("DROIDREAVER_ARSENAL_INSTALL", "") if raw is None else raw).strip()
    if not spec:
        return None
    if spec.lower() in {"1", "true", "all", "*"}:
        return {
            tool.name
            for tool in TOOLS.values()
            if tool.install_method in AUTO_INSTALL_METHODS
        }
    return {part.strip() for part in spec.split(",") if part.strip()}


def _cfg(root: Path) -> dict:
    return {
        "settings": {"install_dir": ".droidreaver/tools"},
        "pins": {},
        "ignored": {"tools": []},
        "active": {},
        META_KEY: {"root": str(root), "path": str(root / "droidreaver.toml")},
    }


def _probe_args(inv) -> list[str]:
    cmd = inv.tool.version_cmd
    if cmd:
        parts = cmd.split()
        return parts[1:] if len(parts) > 1 else ["--help"]
    return ["--help"]


# --- Catalog integrity -------------------------------------------------------


def test_arsenal_is_not_empty():
    assert INVOCATIONS, "arsenal produced no runnable invocations"


def test_every_dispatchable_tool_has_an_invocation():
    missing = []
    for tool in TOOLS_LIST:
        if tool.name in MANUAL_NO_CLI:
            continue
        if lookup_invocation(tool.name) is None and (
            not tool.binary_name or lookup_invocation(tool.binary_name) is None
        ):
            missing.append(tool.name)
    assert missing == [], f"tools missing from arsenal: {missing}"


def test_manual_gui_tools_are_not_in_arsenal():
    names = {inv.name for inv in INVOCATIONS}
    leaked = sorted(name for name in MANUAL_NO_CLI if name in names)
    assert leaked == [], f"manual GUI tools should not be dispatched: {leaked}"


def test_arsenal_names_do_not_shadow_core_commands():
    names = {inv.name for inv in INVOCATIONS}
    overlap = sorted(names & RESERVED_COMMANDS)
    assert overlap == [], f"arsenal names collide with core CLI: {overlap}"


def test_invocation_names_are_unique():
    seen: dict[str, str] = {}
    dupes = []
    for inv in INVOCATIONS:
        key = inv.name.lower()
        if key in seen:
            dupes.append(f"{inv.name} ({inv.tool.name} vs {seen[key]})")
        seen[key] = inv.tool.name
    assert dupes == [], f"duplicate arsenal names: {dupes}"


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_lookup_roundtrip(inv):
    found = lookup_invocation(inv.name)
    assert found is not None
    assert found.name == inv.name
    assert found.tool.name == inv.tool.name
    assert found.executable
    assert found.executable == inv.executable


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_invocation_points_at_registered_tool(inv):
    assert inv.tool.name in TOOLS
    assert TOOLS[inv.tool.name] is inv.tool or TOOLS[inv.tool.name].name == inv.tool.name


@pytest.mark.parametrize("tool", TOOLS_LIST, ids=TOOL_IDS)
def test_tool_has_required_install_fields(tool: Tool):
    assert tool.install_method in INSTALL_METHOD_REQUIREMENTS, (
        f"{tool.name}: unknown install_method {tool.install_method!r}"
    )
    missing = [
        field
        for field in INSTALL_METHOD_REQUIREMENTS[tool.install_method]
        if not getattr(tool, field)
    ]
    assert missing == [], f"{tool.name}: missing {missing} for {tool.install_method}"
    if tool.install_method == "brew":
        assert tool.brew_package
    if tool.install_method == "manual":
        assert tool.manual_url or tool.binary_name, (
            f"{tool.name}: manual tool needs manual_url or binary_name"
        )


@pytest.mark.parametrize("tool", TOOLS_LIST, ids=TOOL_IDS)
def test_version_cmd_gaps_are_explicit(tool: Tool):
    if tool.version_cmd:
        assert tool.name not in KNOWN_NO_VERSION_CMD, (
            f"{tool.name} now has version_cmd; remove it from KNOWN_NO_VERSION_CMD"
        )
        return
    assert tool.name in KNOWN_NO_VERSION_CMD, (
        f"{tool.name} has no version_cmd — add a probe or list it in KNOWN_NO_VERSION_CMD"
    )


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_meta_requires_args_implies_usage_hint(inv):
    meta = INVOCATION_META.get(inv.name, {})
    if meta.get("requires_args"):
        assert inv.requires_args
        assert inv.usage_hint, f"{inv.name} requires args but has no usage_hint"


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_prepare_dispatch_args_never_drops_user_args(inv):
    args = ["--sentinel", "value"]
    assert prepare_dispatch_args(inv, args) == args


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_prepare_dispatch_empty_args(inv):
    forwarded = prepare_dispatch_args(inv, [])
    if inv.requires_args:
        assert forwarded == ["--help"]
    else:
        assert forwarded == []


# --- Click wiring ------------------------------------------------------------


def _cli_context():
    return main.make_context("droidreaver", [], resilient_parsing=True)


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_click_registers_every_arsenal_command(inv):
    cmd = main.get_command(_cli_context(), inv.name)
    assert cmd is not None, f"{inv.name} is not a droidreaver subcommand"
    expected = inv.tool.description or f"Run {inv.tool.display_name}"
    assert cmd.help == expected, (
        f"{inv.name} help is {cmd.help!r}, expected {expected!r} "
        "(late-binding closure in _register_tool_runners?)"
    )


@pytest.mark.parametrize("section, names", CORE_SECTIONS)
def test_core_help_sections_exist(section, names):
    for name in names:
        assert main.get_command(_cli_context(), name) is not None, (
            f"core command {name!r} from section {section!r} is missing"
        )


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_cli_forwards_args_to_run_invocation(inv):
    runner = CliRunner()
    with patch("droidreaver.cli.ensure_config"), patch(
        "droidreaver.cli.load_config", return_value={}
    ), patch("droidreaver.cli.run_invocation", return_value=0) as run:
        result = runner.invoke(main, [inv.name, "--help", "--flag", "x"])
    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert run.call_args[0][0] == inv.name
    assert run.call_args[0][1] == ["--help", "--flag", "x"]


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_run_subcommand_forwards_every_tool(inv):
    runner = CliRunner()
    with patch("droidreaver.cli._load_cfg", return_value={}), patch(
        "droidreaver.cli.run_invocation", return_value=0
    ) as run:
        result = runner.invoke(main, ["run", inv.name, "--version"])
    assert result.exit_code == 0, result.output
    run.assert_called_once_with(inv.name, ["--version"], {})


def test_run_unknown_tool_exits_nonzero():
    runner = CliRunner()
    with patch("droidreaver.cli._load_cfg", return_value={}):
        result = runner.invoke(main, ["run", "not-a-real-tool-xyz"])
    assert result.exit_code != 0
    assert "Unknown" in result.output or "not-a-real-tool-xyz" in result.output


def test_arsenal_lists_every_invocation(tmp_path):
    runner = CliRunner()
    cfg = _cfg(tmp_path)
    with patch("droidreaver.cli._load_cfg", return_value=cfg), patch(
        "droidreaver.cli.print_banner"
    ):
        result = runner.invoke(main, ["arsenal"])
    assert result.exit_code == 0, result.output
    missing = [inv.name for inv in INVOCATIONS if inv.name not in result.output]
    assert missing == [], f"arsenal table missing: {missing}"


@pytest.mark.parametrize("tool", TOOLS_LIST, ids=TOOL_IDS)
def test_info_lists_every_registry_tool(tool: Tool):
    runner = CliRunner()
    with patch("droidreaver.cli.print_banner"), patch(
        "droidreaver.cli.get_latest_version", return_value=None
    ), patch("droidreaver.cli.get_tool_version", return_value=None), patch(
        "droidreaver.cli._load_cfg", return_value={"pins": {}}
    ), patch("droidreaver.cli.work_spinner") as spinner:
        spinner.return_value.__enter__.return_value = None
        spinner.return_value.__exit__.return_value = None
        result = runner.invoke(main, ["info", tool.name])
    assert result.exit_code == 0, result.output
    assert tool.display_name in result.output or tool.name in result.output
    assert tool.install_method in result.output


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_arsenal_row_missing_when_unresolvable(inv, tmp_path):
    cfg = _cfg(tmp_path)
    with patch("droidreaver.runtime.resolve_executable", side_effect=RunError("missing")):
        name, tool_name, status = format_arsenal_row(inv, cfg)
    assert name == inv.name
    assert tool_name == inv.tool.name
    assert "missing" in status


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_arsenal_row_ready_when_resolvable(inv, tmp_path):
    cfg = _cfg(tmp_path)
    with patch("droidreaver.runtime.resolve_executable", return_value=["/bin/true"]):
        name, tool_name, status = format_arsenal_row(inv, cfg)
    assert name == inv.name
    assert tool_name == inv.tool.name
    assert "ready" in status


def test_run_invocation_unknown_rejected():
    with pytest.raises(RunError, match="Unknown"):
        run_invocation("not-a-real-tool-xyz", [], {})


@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_run_invocation_builds_argv(inv, tmp_path):
    cfg = _cfg(tmp_path)
    with patch(
        "droidreaver.runtime.resolve_executable", return_value=["tool-bin"]
    ) as resolve, patch("droidreaver.runtime.subprocess.run") as run:
        run.return_value.returncode = 0
        code = run_invocation(inv.name, ["--flag"], cfg, passthrough=True)
    assert code == 0
    resolve.assert_called_once()
    argv = run.call_args[0][0]
    assert argv[0] == "tool-bin"
    assert argv[-1] == "--flag"


# --- Live probes (real ~/.droidreaver/tools cache; skip if missing) ----------


def test_parse_arsenal_install_spec_empty(monkeypatch):
    monkeypatch.delenv("DROIDREAVER_ARSENAL_INSTALL", raising=False)
    assert parse_arsenal_install_spec() is None
    assert parse_arsenal_install_spec("") is None
    assert parse_arsenal_install_spec("gitleaks, adb") == {"gitleaks", "adb"}
    assert "gitleaks" in parse_arsenal_install_spec("all")
    assert "adb" in parse_arsenal_install_spec("all")
    assert "nmap" not in parse_arsenal_install_spec("all")


@pytest.fixture(scope="session")
def arsenal_live_cfg():
    """Shared DroidReaver home install dir; optional pre-install via env."""
    cfg = _home_cfg()
    wanted = parse_arsenal_install_spec()
    if wanted:
        from droidreaver.installer import install_tools

        install_tools(sorted(wanted), cfg, continue_on_error=True)
    return cfg


@pytest.mark.arsenal_live
@pytest.mark.parametrize("inv", INVOCATIONS, ids=INVOCATION_IDS)
def test_live_tool_probe(inv, arsenal_live_cfg):
    """Probe binaries from ~/.droidreaver/tools (or PATH). Skip if missing."""
    if inv.name in LIVE_SPAWN_SKIP or inv.tool.name in LIVE_SPAWN_SKIP:
        pytest.skip(f"{inv.name} is GUI/long-running or blocks; not spawned")
    cfg = arsenal_live_cfg
    wanted = parse_arsenal_install_spec()
    try:
        prefix = resolve_executable(cfg, inv.tool, inv.executable)
    except RunError:
        if wanted and (inv.tool.name in wanted or inv.name in wanted):
            pytest.fail(
                f"{inv.name} was requested via DROIDREAVER_ARSENAL_INSTALL "
                "but is still missing"
            )
        pytest.skip(f"{inv.name} not installed")

    args = _probe_args(inv)
    try:
        result = subprocess.run(
            prefix + args,
            capture_output=True,
            text=True,
            timeout=PROBE_CMD_TIMEOUT,
            env={**os.environ, "DROIDREAVER_SHELL": "1"},
        )
    except FileNotFoundError:
        pytest.skip(f"{inv.name} binary vanished")
    except subprocess.TimeoutExpired:
        pytest.fail(f"{inv.name} hung on {' '.join(args)} after {PROBE_CMD_TIMEOUT}s")

    combined = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 127, f"{inv.name} command not found: {combined[:400]}"
    if result.returncode not in (0, 1, 2, 3, 4):
        pytest.fail(
            f"{inv.name} probe exit {result.returncode}: {combined[:500]}"
        )
