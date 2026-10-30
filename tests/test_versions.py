"""Tests for frida version sync logic."""

from unittest.mock import patch

import pytest

from droidreaver import versions
from droidreaver.versions import (
    FRIDA_COMPANIONS,
    FRIDA_EXACT,
    ensure_frida_venv,
    frida_environment_ready,
    resolve_frida_target,
)


def test_frida_exact_vs_companions():
    assert "frida" in FRIDA_EXACT
    assert "frida-tools" in FRIDA_COMPANIONS
    assert "frida" not in FRIDA_COMPANIONS


def test_resolve_frida_target_pinned():
    cfg = {"pins": {"frida": "16.1.4"}, "settings": {}, "ignored": {"tools": []}, "active": {}}
    assert resolve_frida_target(cfg, None) == "16.1.4"


def test_resolve_frida_target_explicit():
    cfg = {"pins": {}, "settings": {}, "ignored": {"tools": []}, "active": {}}
    assert resolve_frida_target(cfg, "17.11.0") == "17.11.0"


def test_frida_environment_ready_requires_complete_stack(tmp_path, monkeypatch):
    venv = tmp_path / "frida-17.11.0"
    bindir = venv / "bin"
    bindir.mkdir(parents=True)
    python = bindir / "python"
    python.write_text("", encoding="utf-8")
    (bindir / "frida").write_text("", encoding="utf-8")

    monkeypatch.setattr(versions, "frida_venv_path", lambda _version: venv)
    monkeypatch.setattr(versions, "_venv_python", lambda _venv: python)
    monkeypatch.setattr(versions, "_venv_bin_dir", lambda _venv: bindir)
    monkeypatch.setattr(
        versions,
        "load_pip_package_versions",
        lambda **_kwargs: {
            "frida": "17.11.0",
            "frida-tools": "14.0.0",
            "objection": "1.12.0",
        },
    )

    assert frida_environment_ready("17.11.0") is True


def test_ensure_frida_venv_skips_ready_environment(tmp_path, monkeypatch):
    venv = tmp_path / "frida-17.11.0"
    monkeypatch.setattr(versions, "frida_venv_path", lambda _version: venv)
    monkeypatch.setattr(versions, "frida_environment_ready", lambda _version: True)
    monkeypatch.setattr(
        versions,
        "pypi_version_exists",
        lambda *_args: pytest.fail("ready environment should not query PyPI"),
    )

    assert ensure_frida_venv("17.11.0") == venv
