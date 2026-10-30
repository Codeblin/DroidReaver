"""Tests for device / frida-server helpers."""

from unittest.mock import patch

from droidreaver.device import (
    FridaServerStatus,
    adb_path,
    device_has_su,
    get_local_frida_version,
    frida_server_user,
    restart_frida_server,
)


def test_adb_path_finds_managed_platform_tools(tmp_path, monkeypatch):
    tools = tmp_path / ".droidreaver" / "tools"
    adb = tools / "adb" / "bin" / "adb"
    adb.parent.mkdir(parents=True)
    adb.write_text("#!/bin/sh\n", encoding="utf-8")
    cfg = {"settings": {"adb_path": "adb", "install_dir": str(tools)}}

    monkeypatch.setattr("droidreaver.device.which", lambda _name: None)
    monkeypatch.setattr("droidreaver.device.detect_platform", lambda: "linux")

    assert adb_path(cfg) == str(adb)


def test_device_has_su_true():
    cfg = {"settings": {"adb_path": "adb"}}
    with patch("droidreaver.device.adb_path", return_value="adb"):
        with patch("droidreaver.device.run_cmd") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "uid=0(root) gid=0(root)"
            assert device_has_su(cfg) is True


def test_get_local_frida_version_uses_droidreaver_env(monkeypatch):
    captured = {}

    def fake_env(config):
        return {"PATH": "/tmp/frida-venv/bin"}

    def fake_run(cmd, *, env=None, timeout=None, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = env
        captured["timeout"] = timeout

        class Result:
            returncode = 0
            stdout = "17.15.5\n"
            stderr = ""

        return Result()

    monkeypatch.setattr("droidreaver.runtime.build_run_env", fake_env)
    monkeypatch.setattr("droidreaver.device.run_cmd", fake_run)

    assert get_local_frida_version({"active": {"frida": "17.15.5"}}) == "17.15.5"
    assert captured["cmd"] == "frida --version"
    assert captured["env"] == {"PATH": "/tmp/frida-venv/bin"}


def test_frida_server_user_reads_root_uid():
    cfg = {"settings": {"adb_path": "adb"}}
    with patch("droidreaver.device.frida_server_pid", return_value="1234"):
        with patch("droidreaver.device.adb_path", return_value="adb"):
            with patch("droidreaver.device.run_cmd") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = "Uid:\t0\t0\t0\t0\n"
                assert frida_server_user(cfg) == "root"


def test_restart_frida_server_uses_su_when_rooted():
    cfg = {"settings": {"adb_path": "adb"}}
    with patch("droidreaver.device.adb_path", return_value="adb"):
        with patch("droidreaver.device.device_has_su", return_value=True):
            with patch("droidreaver.device._kill_frida_server"):
                with patch("droidreaver.device.run_cmd") as mock_run:
                    with patch("droidreaver.device.frida_server_status") as status:
                        status.side_effect = [
                            FridaServerStatus(running=True, user="shell", device_rooted=True),
                            FridaServerStatus(running=True, user="root", device_rooted=True),
                        ]
                        result = restart_frida_server(cfg)

    assert result.runs_as_root
    su_calls = [c for c in mock_run.call_args_list if "su" in c.args[0]]
    assert su_calls
