"""TOML configuration read/write and version pinning."""

from __future__ import annotations

import copy
import os
import shutil
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w

from droidreaver.registry import get_pin_group, get_pin_group_leader, get_tool

DEFAULT_CONFIG_NAME = "droidreaver.toml"
DEFAULT_TEMPLATE = "droidreaver.toml.default"
META_KEY = "_meta"


def _package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_config_path() -> Path:
    """Project-local (searching up to the repo root) or user config path."""
    cwd = Path.cwd()
    for d in (cwd, *cwd.parents):
        candidate = d / DEFAULT_CONFIG_NAME
        if candidate.exists():
            return candidate
        if (d / ".git").exists():
            break
    return Path.home() / ".droidreaver" / DEFAULT_CONFIG_NAME


def ensure_config(path: Path | None = None) -> Path:
    """Create config from template if missing."""
    cfg_path = path or default_config_path()
    if cfg_path.exists():
        return cfg_path

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    template = _package_root() / DEFAULT_TEMPLATE
    if template.exists():
        shutil.copy(template, cfg_path)
    else:
        bundled = Path(__file__).resolve().parent.parent / DEFAULT_TEMPLATE
        if bundled.exists():
            shutil.copy(bundled, cfg_path)
        else:
            cfg_path.write_text(
                '[settings]\nadb_path = "adb"\njava_path = "java"\n'
                'install_dir = "~/.droidreaver/tools"\nauto_push_frida_server = false\n\n'
                "[pins]\n\n[ignored]\ntools = []\n",
                encoding="utf-8",
            )
    return cfg_path


def load_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = ensure_config(path) if path is None else path
    if not cfg_path.exists():
        cfg = _empty_config()
        cfg[META_KEY] = {"root": str(cfg_path.parent), "path": str(cfg_path)}
        return cfg
    with cfg_path.open("rb") as f:
        data = tomllib.load(f)
    cfg = _normalize_config(data)
    cfg[META_KEY] = {"root": str(cfg_path.parent), "path": str(cfg_path)}
    return cfg


def _empty_config() -> dict[str, Any]:
    return {
        "settings": {
            "adb_path": "adb",
            "java_path": "java",
            "install_dir": "~/.droidreaver/tools",
            "auto_push_frida_server": False,
        },
        "pins": {},
        "ignored": {"tools": []},
        "active": {},
    }


def _normalize_config(data: dict[str, Any]) -> dict[str, Any]:
    base = _empty_config()
    for section in ("settings", "pins", "ignored", "active"):
        if section in data:
            if isinstance(data[section], dict):
                base[section].update(data[section])
            else:
                base[section] = data[section]
    return base


def _strip_meta(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k != META_KEY}


def save_config(data: dict[str, Any], path: Path | None = None) -> Path:
    if path is None:
        meta = data.get(META_KEY, {})
        path = Path(meta["path"]) if meta.get("path") else default_config_path()
    cfg_path = path
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with cfg_path.open("wb") as f:
        tomli_w.dump(_strip_meta(data), f)
    return cfg_path


def get_setting(config: dict[str, Any], key: str, default: Any = None) -> Any:
    return config.get("settings", {}).get(key, default)


def config_root(config: dict[str, Any]) -> Path:
    """Directory the config file lives in — base for repo-local relative paths."""
    meta = config.get(META_KEY, {})
    root = meta.get("root")
    if root:
        return Path(root)
    return Path.home() / ".droidreaver"


def config_path_of(config: dict[str, Any]) -> Path:
    meta = config.get(META_KEY, {})
    if meta.get("path"):
        return Path(meta["path"])
    return default_config_path()


def is_project_config(config: dict[str, Any]) -> bool:
    """True when the active config is repo-local (not the home fallback)."""
    return config_root(config) != (Path.home() / ".droidreaver")


def expand_path(config: dict[str, Any], key: str) -> Path:
    raw = str(get_setting(config, key, "") or "")
    expanded = os.path.expanduser(raw)
    p = Path(expanded)
    if p.is_absolute():
        return p.resolve()
    # Relative paths resolve against the config's directory (repo-local layout).
    return (config_root(config) / p).resolve()


def install_dir(config: dict[str, Any]) -> Path:
    p = expand_path(config, "install_dir")
    p.mkdir(parents=True, exist_ok=True)
    return p


def is_ignored(config: dict[str, Any], tool_name: str) -> bool:
    ignored = config.get("ignored", {}).get("tools", [])
    return tool_name in ignored


def get_pinned_version(config: dict[str, Any], tool_name: str) -> str | None:
    pins = config.get("pins", {})
    if tool_name in pins:
        return str(pins[tool_name])
    group = get_pin_group(tool_name)
    if len(group) > 1:
        leader = get_pin_group_leader(group)
        if leader in pins:
            return str(pins[leader])
    return None


def pin_tool(config: dict[str, Any], tool_name: str, version: str) -> dict[str, Any]:
    get_tool(tool_name)  # validate
    data = copy.deepcopy(config)
    group = get_pin_group(tool_name)
    leader = get_pin_group_leader(group)
    pins = data.setdefault("pins", {})
    # Pin group leader only; comment in toml is lost on round-trip
    pins[leader] = version
    # Remove redundant pins for group members
    for member in group:
        if member != leader and member in pins:
            del pins[member]
    return data


def unpin_tool(config: dict[str, Any], tool_name: str) -> dict[str, Any]:
    get_tool(tool_name)
    data = copy.deepcopy(config)
    group = get_pin_group(tool_name)
    leader = get_pin_group_leader(group)
    pins = data.setdefault("pins", {})
    if leader in pins:
        del pins[leader]
    if tool_name in pins:
        del pins[tool_name]
    return data


def set_config_value(config: dict[str, Any], key: str, value: str) -> dict[str, Any]:
    data = copy.deepcopy(config)
    settings = data.setdefault("settings", {})
    # Coerce booleans and paths
    if value.lower() in ("true", "false"):
        settings[key] = value.lower() == "true"
    else:
        settings[key] = value
    return data


def format_config_toml(config: dict[str, Any]) -> str:
    import io

    buf = io.BytesIO()
    tomli_w.dump(_strip_meta(config), buf)
    return buf.getvalue().decode("utf-8")
