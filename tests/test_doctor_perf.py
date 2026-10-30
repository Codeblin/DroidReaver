"""Tests for fast doctor broken-install scanning."""

from unittest.mock import patch

from droidreaver.doctor import check_broken_installs, check_frida_server_match
from droidreaver.registry import get_tool


def test_check_broken_installs_skips_version_cmd_probes():
    config = {"settings": {"install_dir": "~/.droidreaver/tools"}, "pins": {}, "ignored": {"tools": []}}
    tool = get_tool("jadx")

    def installed_side_effect(tool_arg, _config, _pip_versions):
        if tool_arg.name == "jadx":
            return True, "1.5.0"
        return False, None

    with patch("droidreaver.installer._merged_pip_versions", return_value={}):
        with patch("droidreaver.doctor.collect_tool_bin_paths", return_value=[]):
            with patch("droidreaver.doctor._tool_installed_fast", side_effect=installed_side_effect):
                with patch("droidreaver.doctor._binary_resolvable", return_value=False):
                    with patch("droidreaver.installer.get_installed_version") as mock_version:
                        results = check_broken_installs(config)

    assert len(results) == 1
    assert results[0].name == tool.display_name
    mock_version.assert_not_called()


def test_check_broken_installs_no_issue_when_binary_resolvable():
    config = {"settings": {"install_dir": "~/.droidreaver/tools"}, "pins": {}, "ignored": {"tools": []}}

    with patch("droidreaver.installer._merged_pip_versions", return_value={"frida": "17.0.0"}):
        with patch("droidreaver.doctor.collect_tool_bin_paths", return_value=[]):
            with patch("droidreaver.doctor._binary_resolvable", return_value=True):
                results = check_broken_installs(config)

    assert results == []


def test_frida_server_check_uses_managed_run_env():
    config = {"settings": {"install_dir": "~/.droidreaver/tools"}, "active": {"frida": "17.0.0"}}
    captured = {}

    def fake_run(cmd, *, env=None, timeout=None, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = env

        class Result:
            returncode = 0
            stdout = "ok"
            stderr = ""

        return Result()

    with patch("droidreaver.doctor.list_devices", return_value=["emulator-5554"]):
        with patch("droidreaver.doctor.get_local_frida_version", return_value="17.0.0") as local:
            with patch("droidreaver.doctor.check_frida_server_running", return_value=True):
                with patch(
                    "droidreaver.doctor.frida_server_status",
                    return_value=type("Status", (), {"device_rooted": True, "runs_as_root": True})(),
                ):
                    with patch("droidreaver.doctor.build_run_env", return_value={"PATH": "/tmp/frida"}):
                        with patch("droidreaver.doctor.run_cmd", side_effect=fake_run):
                            result = check_frida_server_match(config)

    assert result.status == "ok"
    local.assert_called_once_with(config)
    assert captured["cmd"] == "frida-ps -U"
    assert captured["env"] == {"PATH": "/tmp/frida"}
