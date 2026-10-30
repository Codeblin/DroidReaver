"""Tests for repo-local workspace init and .gitignore management."""

from droidreaver.workspace import (
    GITIGNORE_ENTRIES,
    find_git_root,
    init_workspace,
    update_gitignore,
)


def test_init_creates_config_and_dirs(tmp_path):
    result = init_workspace(tmp_path, profile="minimal")
    assert result.created_config
    assert result.config_path == tmp_path / "droidreaver.toml"
    assert result.config_path.exists()
    assert (tmp_path / ".droidreaver" / "tools").is_dir()

    body = result.config_path.read_text(encoding="utf-8")
    assert 'install_dir = ".droidreaver/tools"' in body
    assert 'profile = "minimal"' in body


def test_init_is_idempotent(tmp_path):
    init_workspace(tmp_path, profile="minimal")
    second = init_workspace(tmp_path, profile="dynamic")
    assert not second.created_config  # config preserved
    assert second.gitignore_added == []  # entries already present


def test_init_force_overwrites_config(tmp_path):
    init_workspace(tmp_path, profile="minimal")
    forced = init_workspace(tmp_path, profile="static", force=True)
    assert forced.created_config
    assert 'profile = "static"' in forced.config_path.read_text(encoding="utf-8")


def test_update_gitignore_adds_entries_once(tmp_path):
    gi = tmp_path / ".gitignore"
    gi.write_text("node_modules/\n", encoding="utf-8")

    _, added = update_gitignore(tmp_path)
    assert set(added) == set(GITIGNORE_ENTRIES)

    _, added_again = update_gitignore(tmp_path)
    assert added_again == []

    content = gi.read_text(encoding="utf-8")
    for entry in GITIGNORE_ENTRIES:
        assert content.count(entry) == 1
    assert "node_modules/" in content


def test_find_git_root(tmp_path):
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert find_git_root(sub) == tmp_path
