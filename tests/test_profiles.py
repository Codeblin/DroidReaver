"""Tests for environment profiles."""

import pytest

from droidreaver.profiles import (
    PROFILES,
    profile_description,
    profile_names,
    resolve_profile,
)
from droidreaver.registry import TOOLS


def test_minimal_profile_tools():
    assert resolve_profile("minimal") == ["adb", "frida", "frida-tools"]


def test_profile_names_includes_full():
    names = profile_names()
    assert "full" in names
    assert set(PROFILES).issubset(set(names))


def test_full_profile_excludes_manual_tools():
    full = resolve_profile("full")
    assert full, "full profile should not be empty"
    for name in full:
        assert TOOLS[name].install_method != "manual"


def test_full_profile_has_no_duplicates():
    full = resolve_profile("full")
    assert len(full) == len(set(full))


def test_resolve_profile_case_insensitive():
    assert resolve_profile("DYNAMIC") == resolve_profile("dynamic")


def test_unknown_profile_raises():
    with pytest.raises(KeyError):
        resolve_profile("nope")


def test_profile_description_present():
    for name in profile_names():
        assert profile_description(name)
