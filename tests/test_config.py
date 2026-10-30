"""Tests for TOML config and pin group logic."""

from pathlib import Path

import pytest

from droidreaver.config import (
    format_config_toml,
    get_pinned_version,
    load_config,
    pin_tool,
    save_config,
    set_config_value,
    unpin_tool,
)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    cfg = tmp_path / "droidreaver.toml"
    cfg.write_text(
        '[settings]\nadb_path = "adb"\ninstall_dir = "/tmp/tools"\n\n[pins]\n\n[ignored]\ntools = []\n',
        encoding="utf-8",
    )
    return cfg


def test_load_and_save_config(config_path: Path):
    data = load_config(config_path)
    assert data["settings"]["adb_path"] == "adb"
    data["settings"]["java_path"] = "/usr/bin/java"
    save_config(data, config_path)
    reloaded = load_config(config_path)
    assert reloaded["settings"]["java_path"] == "/usr/bin/java"


def test_pin_frida_group(config_path: Path):
    data = load_config(config_path)
    data = pin_tool(data, "objection", "16.1.4")
    save_config(data, config_path)
    reloaded = load_config(config_path)
    assert reloaded["pins"]["frida"] == "16.1.4"
    assert get_pinned_version(reloaded, "objection") == "16.1.4"
    assert get_pinned_version(reloaded, "r2frida") == "16.1.4"


def test_unpin_frida_group(config_path: Path):
    data = load_config(config_path)
    data = pin_tool(data, "frida", "16.1.4")
    data = unpin_tool(data, "objection")
    assert "frida" not in data["pins"]


def test_set_config_value(config_path: Path):
    data = load_config(config_path)
    data = set_config_value(data, "auto_push_frida_server", "true")
    assert data["settings"]["auto_push_frida_server"] is True


def test_format_config_toml(config_path: Path):
    data = load_config(config_path)
    text = format_config_toml(data)
    assert "[settings]" in text
    assert "adb_path" in text
