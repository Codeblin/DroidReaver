"""Tests for bypass presets."""

from pathlib import Path
from unittest.mock import patch

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
  PID  Name              Identifier
-----  ----------------  --------------------------------
14935  droidreavervault  com.codeblin.droidreavervault
    -  droidreavervault  com.codeblin.droidreavervault.debug
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


def test_ssl_script_covers_common_stacks():
    text = Path(__file__).resolve().parents[1].joinpath(
        "droidreaver", "scripts", "ssl_pinning_bypass.js"
    ).read_text(encoding="utf-8")
    for marker in (
        "SSLContext",
        "TrustManagerImpl",
        "CertificatePinner",
        "NetworkSecurityTrustManager",
        "WebViewClient",
        "SSL_CTX_set_custom_verify",
        "findExport",
        "trustkit",
    ):
        assert marker in text, marker


def test_list_android_apps_parses_frida_ps():
    from droidreaver.bypass import _parse_frida_ps_apps

    apps = _parse_frida_ps_apps(FRIDA_PS_SAMPLE)
    assert len(apps) == 2
    assert apps[0].identifier == "com.codeblin.droidreavervault"
    assert apps[0].pid == 14935
    assert apps[1].identifier == "com.codeblin.droidreavervault.debug"
    assert apps[1].pid is None


def test_list_android_apps_uses_adb_pm_and_ps():
    cfg = {}
    with patch("droidreaver.bypass.list_installed_packages", return_value=["com.codeblin.droidreavervault"]):
        with patch("droidreaver.bypass.process_name_pids", return_value={"com.codeblin.droidreavervault": 42}):
            apps = list_android_apps(cfg)
    assert apps[0].identifier == "com.codeblin.droidreavervault"
    assert apps[0].pid == 42


def test_resolve_target_attach_running():
    cfg = {}
    with patch("droidreaver.bypass.pidof_package", return_value=14935):
        target = resolve_android_target(
            cfg, "com.codeblin.droidreavervault", spawn=False, serial=None, foremost=False
        )
    assert target.pid == 14935
    assert target.spawn is False


def test_resolve_target_stays_attach_when_stopped():
    cfg = {}
    with patch("droidreaver.bypass.pidof_package", return_value=None):
        target = resolve_android_target(
            cfg, "com.codeblin.droidreavervault.debug", spawn=False, serial=None, foremost=False
        )
    assert target.spawn is False
    assert target.pid is None
    assert target.identifier == "com.codeblin.droidreavervault.debug"


def test_run_bypass_launches_then_attaches_when_stopped():
    cfg = {}
    running = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", 99, "app", False)
    with patch("droidreaver.bypass.pidof_package", return_value=None):
        with patch("droidreaver.bypass.choose_engine", return_value="frida"):
            with patch("droidreaver.bypass._tool_ready", return_value=True):
                with patch("droidreaver.bypass.preflight"):
                    with patch("droidreaver.bypass.launch_app") as launch:
                        with patch(
                            "droidreaver.bypass._wait_for_running_app",
                            return_value=running,
                        ):
                            with patch("droidreaver.bypass.relax_selinux"):
                              with patch(
                                  "droidreaver.bypass._run_frida_session",
                                  return_value=(0, 5.0),
                              ) as run_sess:
                                code = run_bypass(cfg, "all", "com.codeblin.droidreavervault", spawn=False)
    assert code == 0
    launch.assert_called_once()
    argv = run_sess.call_args[0][0]
    assert "-N" in argv and "com.codeblin.droidreavervault" in argv
    assert "-f" not in argv
    assert "-U" in argv


def test_build_objection_argv_uses_pid_for_attach():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", 1234, "App", False)
    with patch("droidreaver.bypass.resolve_executable", return_value=["objection"]):
        argv = build_objection_argv(
            cfg, recipe, target, serial=None, network=False, foremost=False
        )
    assert "-n" in argv and "1234" in argv
    assert "--spawn" not in argv


def test_build_objection_argv_spawn():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", None, "App", True)
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
    target = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", None, "App", False)
    with patch("droidreaver.bypass.resolve_executable", return_value=["frida"]):
        argv = build_frida_argv(
            cfg, recipe, target, serial=None, network=False, foremost=False
        )
    assert "-N" in argv and "com.codeblin.droidreavervault" in argv
    assert "-n" not in argv
    script_flags = [Path(p) for i, p in enumerate(argv) if argv[i - 1] == "-l"]
    assert len(script_flags) == 2


def test_build_frida_argv_prefers_package_over_pid():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", 1234, "App", False)
    with patch("droidreaver.bypass.resolve_executable", return_value=["frida"]):
        argv = build_frida_argv(
            cfg, recipe, target, serial=None, network=False, foremost=False
        )
    assert "-N" in argv and "com.codeblin.droidreavervault" in argv
    assert "-p" not in argv


def test_build_frida_argv_serial_uses_only_device_id_transport():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", None, "App", True)
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
    assert "-H" not in argv


def test_build_frida_argv_network_uses_remote_transport_only():
    cfg = {}
    recipe = RECIPES["ssl"]
    target = ResolvedTarget("com.codeblin.droidreavervault", "com.codeblin.droidreavervault", None, "App", True)
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
    apps = [AndroidApp(None, "droidreavervault", "com.codeblin.droidreavervault")]
    with patch("droidreaver.bypass.pidof_package", return_value=None):
        with patch("droidreaver.bypass.list_android_apps", return_value=apps):
          with patch("droidreaver.bypass.choose_engine", return_value="frida"):
            with patch("droidreaver.bypass._tool_ready", return_value=True):
                with patch("droidreaver.bypass.preflight"):
                    with patch("droidreaver.bypass.force_stop_app") as stop:
                        with patch("droidreaver.bypass.relax_selinux"):
                          with patch("droidreaver.bypass._run_frida_session", return_value=(0, 1.0)):
                            code = run_bypass(
                                cfg,
                                "all",
                                "com.codeblin.droidreavervault",
                                spawn=True,
                            )
    assert code == 0
    stop.assert_called_once_with(cfg, "com.codeblin.droidreavervault", serial=None)


def test_run_bypass_spawn_failure_falls_back_to_attach():
    cfg = {}
    apps_stopped = [AndroidApp(None, "droidreavervault", "com.codeblin.droidreavervault")]
    attach_target = ResolvedTarget(
        "com.codeblin.droidreavervault",
        "com.codeblin.droidreavervault",
        None,
        "droidreavervault",
        False,
    )
    with patch("droidreaver.bypass.pidof_package", return_value=None):
            with patch("droidreaver.bypass.choose_engine", return_value="frida"):
                with patch("droidreaver.bypass._tool_ready", return_value=True):
                    with patch("droidreaver.bypass.preflight"):
                        with patch("droidreaver.bypass.force_stop_app"):
                            with patch("droidreaver.bypass.relax_selinux"):
                              with patch("droidreaver.bypass.list_android_apps", return_value=apps_stopped):
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
                                            "com.codeblin.droidreavervault",
                                            spawn=True,
                                        )
    assert code == 0
    assert run_sess.call_count == 2
