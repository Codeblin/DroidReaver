"""Tests for the interactive DroidReaver console (REPL)."""

import subprocess
from types import SimpleNamespace

import droidreaver.console as console_mod
from droidreaver.console import DroidReaverConsole


def _make(monkeypatch, devices=None, apps=None):
    """Build a console with device/app lookups stubbed out (no real ADB)."""
    monkeypatch.setattr(console_mod, "list_devices", lambda cfg: list(devices or []))
    monkeypatch.setattr(
        console_mod, "list_android_apps", lambda cfg, serial=None: list(apps or [])
    )
    return DroidReaverConsole(config={}, serial=None)


def test_prompt_reflects_state(monkeypatch):
    c = _make(monkeypatch)
    assert "no-device" in c.prompt
    assert "no-target" in c.prompt
    c.serial = "emulator-5554"
    c.package = "com.example.app"
    c._update_prompt()
    assert "emulator-5554" in c.prompt
    assert "com.example.app" in c.prompt


def test_empty_line_is_noop(monkeypatch):
    c = _make(monkeypatch)
    assert c.emptyline() is False


def test_exit_stops_loop(monkeypatch):
    c = _make(monkeypatch)
    assert c.do_exit("") is True
    assert c.do_quit("") is True
    assert c.do_EOF("") is True


def test_guards_do_not_stop_loop(monkeypatch):
    c = _make(monkeypatch)
    for line in ["hook", "bypass", "objection", "adb shell", "proxy 1.2.3.4:8080", "pull /x"]:
        assert not c.onecmd(line), f"{line!r} should not stop the loop"


def test_use_rejects_unconnected_device(monkeypatch):
    c = _make(monkeypatch, devices=["emulator-5554"])
    c.onecmd("use nonexistent")
    assert c.serial is None
    c.onecmd("use emulator-5554")
    assert c.serial == "emulator-5554"


def test_devices_auto_selects_single(monkeypatch):
    c = _make(monkeypatch, devices=["emulator-5554"])
    c.do_devices("")
    assert c.serial == "emulator-5554"


def test_target_exact_match(monkeypatch):
    class App:
        def __init__(self, ident, name, pid=None):
            self.identifier = ident
            self.name = name
            self.pid = pid

        @property
        def running(self):
            return self.pid is not None

    apps = [App("com.example.app", "Example"), App("com.other.app", "Other")]
    c = _make(monkeypatch, apps=apps)
    c.do_target("com.example.app")
    assert c.package == "com.example.app"


def test_target_falls_back_to_literal_when_no_apps(monkeypatch):
    c = _make(monkeypatch, apps=[])
    c.do_target("com.manual.pkg")
    assert c.package == "com.manual.pkg"


def test_adb_reverse_is_bounded_and_uses_selected_device(monkeypatch):
    c = _make(monkeypatch, devices=["device-123"])
    c.serial = "device-123"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(console_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(console_mod, "adb_path", lambda cfg: "adb")
    c.do_adb("reverse tcp:8080 tcp:8080")

    argv, kwargs = calls[0]
    assert argv[-3:] == ["reverse", "tcp:8080", "tcp:8080"]
    assert "device-123" in argv
    assert kwargs["timeout"] == 15


def test_adb_reverse_timeout_returns_to_console(monkeypatch):
    c = _make(monkeypatch, devices=["device-123"])
    c.serial = "device-123"

    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(console_mod.subprocess, "run", timeout)
    monkeypatch.setattr(console_mod, "adb_path", lambda cfg: "adb")
    assert c.do_adb("reverse tcp:8080 tcp:8080") is None
