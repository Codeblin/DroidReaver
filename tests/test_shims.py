"""Tests for Windows readline shim."""

import sys

from droidreaver.shims.readline_win import install_readline_shim


def test_readline_shim_registers_on_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    sys.modules.pop("readline", None)
    install_readline_shim()
    import readline

    assert readline.__doc__
    readline.parse_and_bind("tab: complete")
    readline.set_completer(lambda *_: None)
    sys.modules.pop("readline", None)


def test_readline_shim_noop_on_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    install_readline_shim()
    # Should not inject stub on non-Windows unless import fails naturally.
