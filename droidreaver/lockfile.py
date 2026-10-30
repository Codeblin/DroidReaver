"""Reproducible environment lockfile — capture and restore the installed kit."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

import tomli_w

from droidreaver import __version__
from droidreaver.config import config_root, get_setting, install_dir
from droidreaver.registry import TOOLS, get_tool

LOCK_NAME = "droidreaver.lock.toml"
INSTALL_METADATA_NAME = ".droidreaver-install.json"


def lock_path(config: dict) -> Path:
    """Lockfile sits next to the config (repo root for project configs)."""
    return config_root(config) / LOCK_NAME


def _read_install_metadata(config: dict, tool_name: str) -> dict[str, Any] | None:
    path = install_dir(config) / tool_name / INSTALL_METADATA_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def build_lock(config: dict) -> dict[str, Any]:
    """Snapshot currently installed tools + active frida runtime."""
    from droidreaver.installer import get_tool_version
    from droidreaver.versions import get_active_frida_version

    tools: dict[str, Any] = {}
    for name, tool in TOOLS.items():
        if tool.install_method == "manual":
            continue
        version = get_tool_version(tool, config)
        if version:
            entry: dict[str, Any] = {"version": version, "method": tool.install_method}
            metadata = _read_install_metadata(config, name)
            if metadata and metadata.get("sha256"):
                entry["integrity"] = {
                    "sha256": str(metadata["sha256"]),
                    "verified": bool(metadata.get("verified")),
                }
                if metadata.get("source_url"):
                    entry["source_url"] = str(metadata["source_url"])
            tools[name] = entry

    lock: dict[str, Any] = {
        "meta": {
            "droidreaver_version": __version__,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "tools": tools,
    }

    profile = get_setting(config, "profile")
    if profile:
        lock["meta"]["profile"] = profile

    active = get_active_frida_version(config)
    if active:
        lock["frida"] = {"active": active}

    return lock


def write_lock(config: dict) -> Path:
    path = lock_path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        tomli_w.dump(build_lock(config), f)
    return path


def read_lock(config: dict) -> dict[str, Any] | None:
    path = lock_path(config)
    if not path.exists():
        return None
    with path.open("rb") as f:
        return tomllib.load(f)


def restore_from_lock(config: dict, lock: dict[str, Any]) -> tuple[list[str], list[tuple[str, str]]]:
    """Install tools/frida recorded in a lockfile.

    Returns (restored_tool_names, failures[(name, error)]).
    """
    from droidreaver.installer import InstallError, install_tool
    from droidreaver.versions import use_frida_version

    restored: list[str] = []
    failures: list[tuple[str, str]] = []

    frida_active = (lock.get("frida") or {}).get("active")
    locked_tools: dict[str, Any] = lock.get("tools", {})

    # Frida stack comes from the active venv if one was locked.
    frida_stack = set(get_tool("frida").pin_with) if frida_active else set()

    if frida_active:
        try:
            use_frida_version(config, str(frida_active), pin=True)
            restored.append(f"frida (runtime {frida_active})")
        except Exception as e:  # noqa: BLE001 - surface as a failure row
            failures.append(("frida", str(e)))

    for name, info in locked_tools.items():
        if name not in TOOLS:
            continue
        tool = get_tool(name)
        if tool.install_method == "manual":
            continue
        if name in frida_stack and tool.install_method == "pip":
            # Provided by the frida venv already.
            continue
        version = info.get("version") if isinstance(info, dict) else None
        integrity = info.get("integrity", {}) if isinstance(info, dict) else {}
        expected_sha256 = (
            integrity.get("sha256")
            if isinstance(integrity, dict) and tool.install_method in ("direct", "github_release")
            else None
        )
        try:
            pin = version if tool.install_method in ("pip", "github_release") else None
            install_tool(name, config, version=pin, expected_sha256=expected_sha256)
            restored.append(f"{name} {version or ''}".strip())
        except InstallError as e:
            failures.append((name, str(e)))

    return restored, failures
