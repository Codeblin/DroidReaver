"""Tests for version comparison utilities."""

from droidreaver.utils import (
    compare_versions,
    find_git,
    normalize_version,
    parse_version,
    versions_match,
)


def test_parse_version_from_output():
    assert parse_version("16.1.4") == "16.1.4"
    assert parse_version("frida 16.1.4") == "16.1.4"
    assert parse_version("Version 2.9.0") == "2.9.0"
    assert parse_version("v3.0.1-beta") == "3.0.1"


def test_compare_versions_ordering():
    assert compare_versions("16.1.4", "16.2.0") == -1
    assert compare_versions("16.2.0", "16.1.4") == 1
    assert compare_versions("16.1.4", "16.1.4") == 0


def test_versions_match_with_v_prefix():
    assert versions_match("16.1.4", "v16.1.4")
    assert not versions_match("16.1.4", "16.2.0")


def test_normalize_version():
    assert normalize_version("v16.1.4") == "16.1.4"


def test_compare_none_returns_none():
    assert compare_versions(None, "1.0") is None
    assert compare_versions("1.0", None) is None


def test_find_git_returns_path_or_none():
    # On CI/dev machines git may or may not exist; function must not crash.
    result = find_git()
    assert result is None or result.lower().endswith(("git", "git.exe"))
