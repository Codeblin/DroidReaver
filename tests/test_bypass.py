"""Tests for bypass presets."""

from pathlib import Path
from unittest.mock import patch

import pytest

from droidreaver.bypass import (
    RECIPES,
    AndroidApp,
    MEDUSA_ROOT_SPEC,
    ResolvedTarget,
    build_frida_argv,
    build_objection_argv,
    choose_engine,
    list_android_apps,
    resolve_android_target,
    run_bypass,
    script_path,
)

FRIDA_PS_SAMPLE = """\
  PID  Name       Identifier
-----  ---------  -------------------
14935  Anchored   com.example.anchored
    -  APKrypt    com.example.apkrypt
"""


def test_recipes_defined():
    assert "ssl" in RECIPES
    assert "root" in RECIPES
    assert "all" in RECIPES
    assert RECIPES["root"].frida_scripts == (MEDUSA_ROOT_SPEC,)
    assert MEDUSA_ROOT_SPEC in RECIPES["all"].frida_scripts
    assert RECIPES["all"].objection_commands == ("android sslpinning disable",)


def test_bundled_scripts_exist():
    cfg = {}
    assert script_path("ssl_pinning_bypass.js", cfg).is_file()
    assert script_path(MEDUSA_ROOT_SPEC, cfg).is_file()


def test_list_android_apps_parses_frida_ps():
    cfg = {}
    with patch("droidreaver.bypass.run_cmd") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = FRIDA_PS_SAMPLE
        with patch("droidreaver.bypass.resolve_executable", return_value=["frida-ps"]):
            with patch("droidreaver.bypass._tool_ready", return_value=True):
                apps = list_android_apps(cfg)
    assert len(apps) == 2
    assert apps[0].identifier == "com.example.anchored"
    assert apps[0].pid == 14935
    assert apps[1].identifier == "com.example.apkrypt"
    assert apps[1].pid is None


def test_resolve_target_attach_running():
    cfg = {}
    apps = [
        AndroidApp(14935, "Anchored", "com.example.anchored"),
        AndroidApp(None, "APKrypt", "com.example.apkrypt"),
    ]
    with patch("droidreaver.bypass.list_android_apps", return_value=apps):
        target = resolve_android_target(
            cfg, "com.example.anchored", spawn=False, serial=None, foremost=False
        )
    assert target.pid == 14935
    assert target.spawn is False


def test_resolve_target_auto_spawn_when_stopped():
    cfg = {}
    apps = [AndroidApp(None, "APKrypt", "com.example.apkrypt")]
    with patch("droidreaver.bypass.list_android_apps", return_value=apps):
        target = resolve_android_target(
            cfg, "com.example.apkrypt", spawn=False, serial=None, foremost=False
        )
    assert target.spawn is True
    assert target.identifier == "com.example.apkrypt"


def test_build_objection_argv_uses_pid_for_attach():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.example.app", "com.example.app", 1234, "App", False)
    with patch("droidreaver.bypass.resolve_executable", return_value=["objection"]):
        argv = build_objection_argv(
            cfg, recipe, target, serial=None, network=False, foremost=False
        )
    assert "-n" in argv and "1234" in argv
    assert "--spawn" not in argv


def test_build_objection_argv_spawn():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.example.app", "com.example.app", None, "App", True)
    with patch("droidreaver.bypass.resolve_executable", return_value=["objection"]):
        argv = build_objection_argv(
            cfg, recipe, target, serial="emulator-5554", network=False, foremost=False
        )
    assert "-S" in argv and "emulator-5554" in argv
    assert "--spawn" in argv
    assert "android sslpinning disable" in argv


def test_build_frida_argv_attach_by_identifier():
    cfg = {}
    recipe = RECIPES["all"]
    target = ResolvedTarget("com.example.app", "com.example.app", None, "App", False)
    with patch("droidreaver.bypass.resolve_executable", return_value=["frida"]):
        argv = build_frida_argv(
            cfg, recipe, target, serial=None, network=False, foremost=False
        )
    assert "-N" in argv and "com.example.app" in argv
    assert "-n" not in argv
    script_flags = [Path(p) for i, p in enumerate(argv) if argv[i - 1] == "-l"]
    assert len(script_flags) == 2


def test_build_frida_argv_prefers_identifier_over_pid():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.example.app", "com.example.app", 1234, "App", False)
    with patch("droidreaver.bypass.resolve_executable", return_value=["frida"]):
        argv = build_frida_argv(
            cfg, recipe, target, serial=None, network=False, foremost=False
        )
    assert "-N" in argv and "com.example.app" in argv
    assert "-p" not in argv


def test_build_frida_argv_serial_uses_only_device_id_transport():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.example.app", "com.example.app", None, "App", True)
    with patch("droidreaver.bypass.resolve_executable", return_value=["frida"]):
        argv = build_frida_argv(
            cfg,
            recipe,
            target,
            serial="device-123",
            network=False,
            foremost=False,
        )
    assert argv.count("-D") == 1
    assert "device-123" in argv
    assert "-U" not in argv
    assert "-R" not in argv


def test_build_frida_argv_network_uses_remote_transport_only():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.example.app", "com.example.app", None, "App", True)
    with patch("droidreaver.bypass.resolve_executable", return_value=["frida"]):
        argv = build_frida_argv(
            cfg,
            recipe,
            target,
            serial="ignored-device",
            network=True,
            foremost=False,
        )
    assert "-R" in argv
    assert "-D" not in argv
    assert "-U" not in argv


def test_choose_engine_prefers_objection_for_ssl():
    cfg = {}
    with patch("droidreaver.bypass._tool_ready", side_effect=lambda _c, tool, _e: tool == "objection"):
        assert choose_engine(cfg, "auto", "ssl") == "objection"


def test_choose_engine_uses_frida_for_root():
    cfg = {}
    with patch("droidreaver.bypass._medusa_root_available", return_value=True):
        with patch("droidreaver.bypass._tool_ready", side_effect=lambda _c, tool, _e: tool == "frida"):
            assert choose_engine(cfg, "auto", "root") == "frida"


def test_run_bypass_force_stops_before_spawn():
    cfg = {}
    apps = [AndroidApp(None, "TalentCards", "com.talentcards.android")]
    with patch("droidreaver.bypass.list_android_apps", return_value=apps):
        with patch("droidreaver.bypass.choose_engine", return_value="frida"):
            with patch("droidreaver.bypass._tool_ready", return_value=True):
                with patch("droidreaver.bypass.preflight"):
                    with patch("droidreaver.bypass.force_stop_app") as stop:
                        with patch("droidreaver.bypass._run_frida_session", return_value=(0, 1.0)):
                            code = run_bypass(
                                cfg,
                                "all",
                                "com.talentcards.android",
                                spawn=True,
                            )
    assert code == 0
    stop.assert_called_once_with(cfg, "com.talentcards.android", serial=None)


def test_run_bypass_spawn_failure_falls_back_to_attach():
    cfg = {}
    apps_stopped = [AndroidApp(None, "TalentCards", "com.talentcards.android")]
    attach_target = ResolvedTarget(
        "com.talentcards.android",
        "com.talentcards.android",
        None,
        "TalentCards",
        False,
    )
    with patch("droidreaver.bypass.list_android_apps", return_value=apps_stopped):
        with patch("droidreaver.bypass.choose_engine", return_value="frida"):
            with patch("droidreaver.bypass._tool_ready", return_value=True):
                with patch("droidreaver.bypass.preflight"):
                    with patch("droidreaver.bypass.force_stop_app"):
                        with patch("droidreaver.bypass.launch_app"):
                            with patch(
                                "droidreaver.bypass._wait_for_running_app",
                                return_value=attach_target,
                            ):
                                with patch(
                                    "droidreaver.bypass._run_frida_session",
                                    side_effect=[(1, 0.5), (0, 5.0)],
                                ) as run_sess:
                                    code = run_bypass(
                                        cfg,
                                        "all",
                                        "com.talentcards.android",
                                        spawn=True,
                                    )
    assert code == 0
    assert run_sess.call_count == 2
