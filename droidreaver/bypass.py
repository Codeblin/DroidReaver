"""Predefined bypass presets — SSL pinning and root detection."""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from rich.console import Console

from droidreaver.device import force_stop_app, frida_server_status, launch_app, print_frida_attach_troubleshooting
from droidreaver.medusa_modules import MEDUSA_ROOT_SPEC, medusa_install_dir, resolve_bypass_script
from droidreaver.registry import get_tool
from droidreaver.runtime import RunError, build_run_env, resolve_executable
from droidreaver.utils import run_cmd, which

console = Console()

Engine = Literal["auto", "objection", "frida"]
RecipeId = Literal["ssl", "root", "all"]

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"

_FRIDA_PS_LINE = re.compile(
    r"^\s*(?P<pid>-|\d+)\s+(?P<name>.+?)\s{2,}(?P<identifier>\S+)\s*$"
)


@dataclass(frozen=True)
class AndroidApp:
    pid: int | None
    name: str
    identifier: str

    @property
    def running(self) -> bool:
        return self.pid is not None


@dataclass(frozen=True)
class ResolvedTarget:
    query: str
    identifier: str
    pid: int | None
    display_name: str
    spawn: bool


@dataclass(frozen=True)
class BypassRecipe:
    id: RecipeId
    title: str
    summary: str
    objection_commands: tuple[str, ...]
    frida_scripts: tuple[str, ...]


RECIPES: dict[RecipeId, BypassRecipe] = {
    "ssl": BypassRecipe(
        id="ssl",
        title="SSL Pinning Bypass",
        summary="Disable TLS certificate pinning so HTTPS traffic can be intercepted.",
        objection_commands=("android sslpinning disable",),
        frida_scripts=("ssl_pinning_bypass.js",),
    ),
    "root": BypassRecipe(
        id="root",
        title="Root Detection Bypass",
        summary="Medusa universal root/debug bypass (anti_root module).",
        objection_commands=(),  # Objection android root disable is too weak — Frida only.
        frida_scripts=(MEDUSA_ROOT_SPEC,),
    ),
    "all": BypassRecipe(
        id="all",
        title="SSL + Root Detection Bypass",
        summary="SSL bypass + Medusa universal root bypass — usual test setup.",
        objection_commands=("android sslpinning disable",),
        frida_scripts=(
            "ssl_pinning_bypass.js",
            MEDUSA_ROOT_SPEC,
        ),
    ),
}


class BypassError(Exception):
    """Bypass preset could not run."""


def list_android_apps(config: dict, *, serial: str | None = None) -> list[AndroidApp]:
    """Parse `frida-ps -Uai` into structured app rows."""
    if not _tool_ready(config, "frida-tools", "frida-ps"):
        return []

    env = build_run_env(config)
    argv = [resolve_executable(config, get_tool("frida-tools"), "frida-ps")[0], "-Uai"]
    if serial:
        argv = [
            resolve_executable(config, get_tool("frida-tools"), "frida-ps")[0],
            "-D",
            serial,
            "-ai",
        ]

    result = run_cmd(argv, env=env)
    if result.returncode != 0:
        return []

    apps: list[AndroidApp] = []
    for line in (result.stdout or "").splitlines():
        if line.startswith("PID") or line.startswith("---") or not line.strip():
            continue
        match = _FRIDA_PS_LINE.match(line)
        if not match:
            continue
        pid_raw = match.group("pid")
        pid = None if pid_raw == "-" else int(pid_raw)
        apps.append(
            AndroidApp(
                pid=pid,
                name=match.group("name").strip(),
                identifier=match.group("identifier").strip(),
            )
        )
    return apps


def _format_running_apps(apps: list[AndroidApp], limit: int = 8) -> str:
    running = [a for a in apps if a.running]
    if not running:
        return "  (no apps with an active Frida PID right now)"
    lines = []
    for app in running[:limit]:
        lines.append(f"  {app.identifier}  ({app.name})  pid={app.pid}")
    if len(running) > limit:
        lines.append(f"  … and {len(running) - limit} more")
    return "\n".join(lines)


def resolve_android_target(
    config: dict,
    query: str,
    *,
    spawn: bool,
    serial: str | None,
    foremost: bool,
) -> ResolvedTarget:
    """Match package/display name and decide attach PID vs spawn."""
    if foremost:
        return ResolvedTarget(
            query=query or "frontmost",
            identifier=query or "frontmost",
            pid=None,
            display_name="frontmost app",
            spawn=False,
        )

    apps = list_android_apps(config, serial=serial)
    q = query.strip()
    q_lc = q.lower()

    by_identifier = [a for a in apps if a.identifier.lower() == q_lc]
    if len(by_identifier) == 1:
        app = by_identifier[0]
        if spawn or not app.running:
            return ResolvedTarget(q, app.identifier, None, app.name, spawn=True)
        return ResolvedTarget(q, app.identifier, app.pid, app.name, spawn=False)

    by_name = [a for a in apps if a.name.lower() == q_lc]
    if len(by_name) == 1:
        app = by_name[0]
        if spawn or not app.running:
            return ResolvedTarget(q, app.identifier, None, app.name, spawn=True)
        return ResolvedTarget(q, app.identifier, app.pid, app.name, spawn=False)

    partial = [
        a
        for a in apps
        if q_lc in a.identifier.lower() or q_lc in a.name.lower()
    ]
    if len(partial) == 1:
        app = partial[0]
        if spawn or not app.running:
            return ResolvedTarget(q, app.identifier, None, app.name, spawn=True)
        return ResolvedTarget(q, app.identifier, app.pid, app.name, spawn=False)

    installed = [a for a in apps if a.identifier.lower() == q_lc or a.name.lower() == q_lc]
    if installed and not spawn:
        app = installed[0]
        raise BypassError(
            f"'{q}' is installed as [bold]{app.identifier}[/] but Frida sees no running PID.\n"
            "Open the app on the device, or cold-start it with [cyan]--spawn[/]:\n"
            f"  droidreaver bypass ssl -n {app.identifier} --spawn\n\n"
            "Apps Frida can attach to right now:\n"
            f"{_format_running_apps(apps)}"
        )

    hints = [f"  {a.identifier}  ({a.name})" + (f"  pid={a.pid}" if a.pid else "") for a in apps[:12]]
    hint_block = "\n".join(hints) if hints else "  (could not list apps — run: droidreaver frida-ps -Uai)"
    raise BypassError(
        f"Could not resolve target '{q}'.\n"
        "Use the exact package from [cyan]droidreaver frida-ps -Uai[/] "
        "(Identifier column).\n\n"
        f"Known apps on device:\n{hint_block}"
    )


def script_path(spec: str, config: dict) -> Path:
    try:
        return resolve_bypass_script(config, spec, SCRIPTS_DIR)
    except FileNotFoundError as e:
        raise BypassError(
            f"{e}\nInstall Medusa for the universal root module: droidreaver install medusa"
        ) from e


def _medusa_root_available(config: dict) -> bool:
    if medusa_install_dir(config):
        return True
    return (SCRIPTS_DIR / "medusa_universal_root.js").is_file()


def _tool_ready(config: dict, tool_name: str, executable: str) -> bool:
    tool = get_tool(tool_name)
    try:
        resolve_executable(config, tool, executable)
        return True
    except RunError:
        return False


def choose_engine(config: dict, engine: Engine, recipe_id: RecipeId = "ssl") -> Engine:
    if engine != "auto":
        if engine == "objection" and recipe_id == "root":
            raise BypassError(
                "Root bypass uses Medusa's universal module via Frida.\n"
                "Drop --objection or use: droidreaver bypass root -n <package> --spawn"
            )
        return engine
    if recipe_id in ("root", "all"):
        if not _medusa_root_available(config):
            raise BypassError(
                "Medusa root module required.\n"
                "Run: droidreaver install medusa"
            )
        if _tool_ready(config, "frida", "frida"):
            return "frida"
        raise BypassError("Root bypass requires Frida. Run: droidreaver install frida")
    if _tool_ready(config, "objection", "objection"):
        return "objection"
    if _tool_ready(config, "frida", "frida"):
        return "frida"
    raise BypassError(
        "Neither objection nor frida is installed.\n"
        "Install the stack: droidreaver install frida objection\n"
        "Then push server: droidreaver push-server"
    )


def preflight(config: dict, *, network: bool, serial: str | None = None) -> None:
    if network:
        return
    if not which("adb"):
        console.print("[yellow]Warning:[/] adb not found — ensure a device is reachable.")
        return

    status = frida_server_status(config, serial)
    if status.running and status.device_rooted and not status.runs_as_root:
        console.print(
            "[bold yellow]Warning:[/] frida-server is running as [bold]shell[/], not [bold]root[/].\n"
            "Attach will fail with [dim]unable to access process[/] on most apps.\n"
            "  [dim]Fix:[/] [cyan]droidreaver push-server[/]  "
            "[dim](restarts as root when su works)[/]\n"
        )
    elif status.running and not status.device_rooted:
        console.print(
            "[yellow]Warning:[/] device does not appear rooted — Frida attach to "
            "third-party apps usually fails.\n"
        )

    env = build_run_env(config)
    frida_ps = None
    if _tool_ready(config, "frida-tools", "frida-ps"):
        try:
            frida_ps = resolve_executable(config, get_tool("frida-tools"), "frida-ps")[0]
        except RunError:
            pass
    if frida_ps:
        transport = ["-D", serial] if serial else ["-U"]
        result = run_cmd([frida_ps, *transport], env=env)
        if result.returncode != 0:
            console.print(
                "[yellow]Warning:[/] frida-ps failed — is frida-server running?\n"
                "  [dim]Try:[/] [cyan]droidreaver push-server[/]"
            )


def build_objection_argv(
    config: dict,
    recipe: BypassRecipe,
    target: ResolvedTarget,
    *,
    serial: str | None,
    network: bool,
    foremost: bool,
) -> list[str]:
    tool = get_tool("objection")
    argv = list(resolve_executable(config, tool, "objection"))
    if network:
        argv.append("-N")
    elif serial:
        argv.extend(["-S", serial])
    if foremost:
        argv.append("-f")
    elif target.spawn:
        argv.extend(["-n", target.identifier, "--spawn", "--no-pause"])
    elif target.pid is not None:
        # Objection accepts numeric PID for attach — most reliable on Android.
        argv.extend(["-n", str(target.pid)])
    else:
        argv.extend(["-n", target.identifier])
    argv.append("start")
    for command in recipe.objection_commands:
        argv.extend(["--startup-command", command])
    return argv


def build_frida_argv(
    config: dict,
    recipe: BypassRecipe,
    target: ResolvedTarget,
    *,
    serial: str | None,
    network: bool,
    foremost: bool,
) -> list[str]:
    tool = get_tool("frida")
    argv = list(resolve_executable(config, tool, "frida"))
    if network:
        argv.append("-R")
    elif serial:
        argv.extend(["-D", serial])
    else:
        argv.append("-U")
    if foremost:
        argv.append("-F")
    elif target.spawn:
        # Frida 17+: auto-resumes after spawn; --no-pause was removed (--pause opts in).
        argv.extend(["-f", target.identifier])
    elif target.identifier and target.identifier != "frontmost":
        # Android: package identifier beats PID (PIDs churn; wrong process is common).
        argv.extend(["-N", target.identifier])
    elif target.pid is not None:
        argv.extend(["-p", str(target.pid)])
    else:
        argv.extend(["-N", target.identifier])
    for script_name in recipe.frida_scripts:
        argv.extend(["-l", str(script_path(script_name, config))])
    return argv


def print_recipe_banner(
    recipe: BypassRecipe,
    target: ResolvedTarget,
    engine: Engine,
) -> None:
    console.print(f"\n[bold cyan]◈ {recipe.title}[/]")
    console.print(f"[dim]{recipe.summary}[/]")
    mode = "spawn" if target.spawn else ("frontmost" if target.identifier == "frontmost" else "attach")
    console.print(
        f"[dim]Target:[/] [bold]{target.identifier}[/] ({target.display_name})  "
        f"[dim]Mode:[/] [bold]{mode}[/]  [dim]Engine:[/] [bold]{engine}[/]"
    )
    if target.pid is not None and not target.spawn:
        console.print(f"[dim]PID:[/] [bold]{target.pid}[/]")
    if engine == "objection":
        for cmd in recipe.objection_commands:
            console.print(f"  [dim]→[/] [cyan]{cmd}[/]")
    else:
        for script in recipe.frida_scripts:
            label = script.split("/")[-1] if script.startswith("medusa:") else script
            console.print(f"  [dim]→[/] [cyan]{label}[/]")
    console.print(
        "[dim]Session stays open — use the app, then Ctrl+C to stop.[/]\n"
    )


def _wait_for_running_app(
    config: dict,
    package: str,
    *,
    serial: str | None,
    timeout_s: float = 18.0,
) -> ResolvedTarget | None:
    """Poll frida-ps until the package is running, then return an attach target."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            target = resolve_android_target(
                config, package, spawn=False, serial=serial, foremost=False
            )
        except BypassError:
            target = None
        if target and target.pid is not None:
            # Attach by package (-N), not PID — more reliable after adb launch.
            return ResolvedTarget(
                target.query,
                target.identifier,
                None,
                target.display_name,
                spawn=False,
            )
        time.sleep(1.0)
    return None


def _print_attach_failure_help(package: str, serial: str | None, config: dict) -> None:
    print_frida_attach_troubleshooting(config, serial=serial, package=package)


def _print_spawn_failure_help(package: str, serial: str | None) -> None:
    serial_flag = f" -S {serial}" if serial else ""
    console.print(
        "\n[yellow]Spawn failed[/] — this app may block Frida cold start.\n\n"
        "[bold]Try attach mode[/] (open the app on the device first, no --spawn):\n"
        f"  [cyan]droidreaver hook -n {package}{serial_flag}[/]\n\n"
        "[bold]Or retry spawn[/] after a clean stop:\n"
        f"  [cyan]adb shell am force-stop {package}[/]\n"
        f"  [cyan]droidreaver hook -n {package} --spawn{serial_flag}[/]\n\n"
        "[bold]Or Objection[/] (sometimes works when Frida spawn does not):\n"
        f"  [cyan]droidreaver hook -n {package} --objection --spawn{serial_flag}[/]\n\n"
        "[dim]Physical devices and hardened apps often need attach, not spawn.[/]"
    )


def _run_frida_session(argv: list[str], env: dict) -> tuple[int, float]:
    """Run frida interactively; return exit code and elapsed seconds."""
    start = time.monotonic()
    code = subprocess.run(argv, env=env).returncode
    return code, time.monotonic() - start


def _attempt_attach_after_spawn_failure(
    config: dict,
    recipe: BypassRecipe,
    package: str,
    *,
    serial: str | None,
    network: bool,
) -> int | None:
    """Launch the app via adb and attach with the same scripts. Returns exit code or None."""
    console.print(
        "[yellow]Spawn failed[/] — switching to attach mode (package name, not PID)…"
    )

    apps = list_android_apps(config, serial=serial)
    running = next((a for a in apps if a.identifier == package and a.running), None)
    if not running:
        console.print("[dim]Launching app via adb…[/]")
        try:
            launch_app(config, package, serial=serial)
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]Could not launch {package}:[/] {e}")
            return None
    else:
        console.print(f"[dim]App already running (pid={running.pid}) — attaching…[/]")

    target = _wait_for_running_app(config, package, serial=serial)
    if not target:
        console.print(
            f"[red]Timed out waiting for {package} to start.[/] "
            "Open it manually on the device and retry without [cyan]--spawn[/]."
        )
        return None

    env = build_run_env(config)
    last_code = 1
    for attempt in range(3):
        if attempt:
            console.print(f"[dim]Attach retry {attempt + 1}/3…[/]")
            time.sleep(2.0)
        argv = build_frida_argv(
            config,
            recipe,
            target,
            serial=serial,
            network=network,
            foremost=False,
        )
        console.print(f"[dim]Running:[/] {' '.join(argv)}\n")
        code, elapsed = _run_frida_session(argv, env)
        last_code = code
        if code == 0:
            return code
        # Long session = user ran hooks and exited; don't retry.
        if elapsed > 12:
            return code

    _print_attach_failure_help(package, serial, config)
    return last_code


def run_bypass(
    config: dict,
    recipe_id: RecipeId,
    package: str,
    *,
    spawn: bool = False,
    serial: str | None = None,
    network: bool = False,
    engine: Engine = "auto",
    foremost: bool = False,
) -> int:
    recipe = RECIPES[recipe_id]
    chosen = choose_engine(config, engine, recipe_id)

    if chosen == "objection" and not recipe.objection_commands:
        raise BypassError(
            "This preset has no Objection commands. Use Frida (default for root/all)."
        )

    if chosen == "objection" and not _tool_ready(config, "objection", "objection"):
        raise BypassError("Objection not installed. Run: droidreaver install objection")
    if chosen == "frida" and not _tool_ready(config, "frida", "frida"):
        raise BypassError("Frida not installed. Run: droidreaver install frida")

    preflight(config, network=network, serial=serial)

    if foremost:
        target = resolve_android_target(
            config, package, spawn=False, serial=serial, foremost=True
        )
    else:
        target = resolve_android_target(
            config, package, spawn=spawn, serial=serial, foremost=False
        )
        if target.spawn and not spawn:
            console.print(
                "[yellow]App not running — switching to spawn mode.[/] "
                "[dim](Use [cyan]--spawn[/] explicitly next time.)[/]"
            )

    print_recipe_banner(recipe, target, chosen)
    env = build_run_env(config)

    if chosen == "objection":
        argv = build_objection_argv(
            config,
            recipe,
            target,
            serial=serial,
            network=network,
            foremost=foremost,
        )
        console.print(f"[dim]Running:[/] {' '.join(argv)}\n")
        try:
            return subprocess.run(argv, env=env).returncode
        except FileNotFoundError as e:
            raise BypassError(f"Executable not found: {e}") from e

    argv = build_frida_argv(
        config,
        recipe,
        target,
        serial=serial,
        network=network,
        foremost=foremost,
    )

    if target.spawn and not foremost:
        try:
            force_stop_app(config, target.identifier, serial=serial)
            console.print(
                f"[dim]Force-stopped[/] [bold]{target.identifier}[/] [dim]before spawn.[/]"
            )
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]Warning:[/] could not force-stop app: {e}")

    console.print(f"[dim]Running:[/] {' '.join(argv)}\n")

    try:
        if target.spawn and not foremost:
            code, elapsed = _run_frida_session(argv, env)
            if code == 0:
                return code
            # Immediate exit usually means spawn failed before hooks could run.
            if elapsed < 15:
                attach_code = _attempt_attach_after_spawn_failure(
                    config,
                    recipe,
                    target.identifier,
                    serial=serial,
                    network=network,
                )
                if attach_code is not None and attach_code == 0:
                    return attach_code
                if attach_code is None:
                    _print_spawn_failure_help(target.identifier, serial)
                return attach_code if attach_code is not None else code
            return code
        code, elapsed = _run_frida_session(argv, env)
        if code != 0 and elapsed < 15:
            print_frida_attach_troubleshooting(
                config, serial=serial, package=target.identifier
            )
        return code
    except FileNotFoundError as e:
        raise BypassError(f"Executable not found: {e}") from e


def list_recipes() -> list[BypassRecipe]:
    return list(RECIPES.values())
