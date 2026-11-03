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
    with patch("droidreaver.versions.pypi_version_exists", return_value=True):
        assert resolve_frida_target(cfg, None) == "16.1.4"


def test_resolve_frida_target_explicit():
    cfg = {"pins": {}, "settings": {}, "ignored": {"tools": []}, "active": {}}
    with patch("droidreaver.versions.pypi_version_exists", return_value=True):
        assert resolve_frida_target(cfg, "17.11.0") == "17.11.0"


def test_resolve_frida_target_latest_ignores_pin():
    cfg = {
        "pins": {"frida": "17.25.1"},
        "settings": {},
        "ignored": {"tools": []},
        "active": {"frida": "17.25.1"},
    }
    with patch("droidreaver.versions.pypi_version_exists", return_value=True):
        with patch(
            "droidreaver.versions.fetch_pypi_latest_version",
            return_value="17.25.2",
        ):
            assert resolve_frida_target(cfg, "latest") == "17.25.2"
            assert resolve_frida_target(cfg, None) == "17.25.1"


def test_use_frida_version_latest_ignores_pin():
    cfg = {
        "pins": {"frida": "17.25.1"},
        "settings": {},
        "ignored": {"tools": []},
        "active": {"frida": "17.25.1"},
    }
    with patch(
        "droidreaver.versions.fetch_pypi_latest_version",
        return_value="17.25.2",
    ):
        with patch("droidreaver.versions.ensure_frida_venv") as ensure:
            with patch("droidreaver.versions.save_config"):
                with patch("droidreaver.versions.pin_tool", side_effect=lambda c, *_a, **_k: c):
                    versions.use_frida_version(cfg, "latest")
    ensure.assert_called_once_with("17.25.2", force=False)


def test_update_pin_group_uses_latest_venv_not_pin():
    from droidreaver.installer import update_pin_group

    cfg = {
        "pins": {"frida": "17.25.1"},
        "settings": {},
        "ignored": {"tools": []},
        "active": {"frida": "17.25.1"},
    }
    with patch(
        "droidreaver.versions.resolve_frida_target",
        return_value="17.25.2",
    ):
        with patch("droidreaver.versions.use_frida_version") as use:
            results = update_pin_group("frida", cfg)

    use.assert_called_once()
    assert use.call_args.args[1] == "17.25.2"
    assert results == [("frida", "17.25.1", "17.25.2")]


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
