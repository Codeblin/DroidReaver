"""Tests for banner module."""

import os

from rich.console import Console

from droidreaver.banner import banner_enabled, render_banner


def test_banner_enabled_default():
    os.environ.pop("DROIDREAVER_NO_BANNER", None)
    assert banner_enabled() is True


def test_banner_disabled_via_env():
    os.environ["DROIDREAVER_NO_BANNER"] = "1"
    try:
        assert banner_enabled() is False
    finally:
        os.environ.pop("DROIDREAVER_NO_BANNER", None)


def test_render_banner_compact():
    rendered = render_banner(compact=True)
    console = Console(record=True, color_system=None, width=100)
    console.print(rendered)
    output = console.export_text()
    assert "DroidReaver" in output
    assert "DROIDFORGE" not in output


def test_render_banner_full():
    rendered = render_banner(compact=False, width=160)
    console = Console(record=True, color_system=None, width=160)
    console.print(rendered)
    output = console.export_text()
    assert "ANDROID PENTEST ENVIRONMENT" in output
    assert "DROIDREAVER" in output
    assert "APK WORKFLOW" in output
    assert "MOBILE SECURITY" in output
    assert "frida" in output
    assert "@@@@@@@@@@@@@@@@" in output
    assert "DROIDFORGE" not in output


def test_render_banner_narrow_falls_back_to_compact():
    rendered = render_banner(compact=False, width=40)
    console = Console(record=True, color_system=None, width=40)
    console.print(rendered)
    output = console.export_text()
    assert "DroidReaver" in output
    assert "ANDROID PENTEST ENVIRONMENT" not in output
    assert "@@@@@@@@@@@@@@@@" not in output
