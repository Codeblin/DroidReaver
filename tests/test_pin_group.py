"""Tests for pin group conflict detection."""

from unittest.mock import patch

from droidreaver.installer import check_pin_group_conflict, force_version_match


def test_force_version_match():
    assert force_version_match("16.1.4", "v16.1.4")
    assert not force_version_match("16.1.4", "16.2.0")


def test_pin_conflict_empty_when_no_installed():
    cfg = {"pins": {}, "settings": {}, "ignored": {"tools": []}}
    with patch("droidreaver.installer.get_tool_version", return_value=None):
        warnings = check_pin_group_conflict("frida", "16.2.0", cfg)
    assert warnings == []


def test_pin_conflict_detects_mismatch():
    cfg = {"pins": {}, "settings": {}, "ignored": {"tools": []}}

    def fake_version(tool):
        return "16.1.4" if tool.name == "objection" else None

    with patch("droidreaver.installer.get_tool_version", side_effect=fake_version):
        warnings = check_pin_group_conflict("frida", "16.2.0", cfg)
    assert any("objection" in w for w in warnings)
