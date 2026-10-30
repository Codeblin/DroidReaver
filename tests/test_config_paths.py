"""Tests for repo-local (config-relative) path resolution."""

from pathlib import Path

from droidreaver.config import (
    META_KEY,
    config_root,
    expand_path,
    is_project_config,
)


def _cfg(root: Path, install_dir: str) -> dict:
    return {
        "settings": {"install_dir": install_dir},
        "pins": {},
        "ignored": {"tools": []},
        "active": {},
        META_KEY: {"root": str(root), "path": str(root / "droidreaver.toml")},
    }


def test_relative_install_dir_resolves_against_config_root(tmp_path):
    cfg = _cfg(tmp_path, ".droidreaver/tools")
    assert expand_path(cfg, "install_dir") == (tmp_path / ".droidreaver" / "tools").resolve()


def test_absolute_install_dir_preserved(tmp_path):
    abs_dir = tmp_path / "somewhere" / "tools"
    cfg = _cfg(tmp_path, str(abs_dir))
    assert expand_path(cfg, "install_dir") == abs_dir.resolve()


def test_home_path_expands(tmp_path):
    cfg = _cfg(tmp_path, "~/.droidreaver/tools")
    assert expand_path(cfg, "install_dir") == (Path.home() / ".droidreaver" / "tools").resolve()


def test_config_root_falls_back_to_home_without_meta():
    cfg = {"settings": {}}
    assert config_root(cfg) == Path.home() / ".droidreaver"


def test_is_project_config(tmp_path):
    project = _cfg(tmp_path, ".droidreaver/tools")
    assert is_project_config(project)
    home_cfg = {"settings": {}}
    assert not is_project_config(home_cfg)
