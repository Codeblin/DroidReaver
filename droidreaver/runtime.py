"""Resolve and execute tool CLIs through DroidReaver."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from droidreaver.config import get_setting, install_dir
from droidreaver.registry import FRIDA_PIN_GROUP, TOOLS, Tool, get_tool
from droidreaver.utils import detect_platform, which
from droidreaver.versions import frida_venv_path, get_active_frida_version

_console = Console()

# DroidReaver commands — never shadow with tool runners.
RESERVED_COMMANDS = frozenset(
    {
        "status",
        "install",
        "update",
        "pin",
        "unpin",
        "push-server",
        "doctor",
        "info",
        "config",
        "fix",
        "sync",
        "use",
        "versions",
        "env",
        "run",
        "arsenal",
        "bypass",
        "hook",
        "init",
        "up",
        "shell",
        "console",
        "profile",
        "lock",
        "restore",
        "get",
        "device",
    }
)


@dataclass(frozen=True)
class Invocation:
    """Maps a CLI name the user types to a tool + executable basename."""

    name: str
    tool: Tool
    executable: str  # binary file name passed to exec
    requires_args: bool = False
    usage_hint: str | None = None


# Per-command dispatch hints (aliases share entries by name).
INVOCATION_META: dict[str, dict[str, str | bool]] = {
    "frida-kill": {
        "requires_args": True,
        "usage_hint": "droidreaver frida-kill -U <package|pid>",
        "summary": "Kill a process on a device via frida",
    },
    "frida-trace": {
        "requires_args": True,
        "usage_hint": "droidreaver frida-trace -U -i com.example.app",
        "summary": "Trace API calls in a process",
    },
    "apktool": {
        "requires_args": False,
        "usage_hint": "droidreaver apktool d app.apk",
        "summary": "Decode/rebuild APKs",
    },
    "jadx": {
        "requires_args": False,
        "usage_hint": "droidreaver jadx -d out app.apk",
        "summary": "Decompile APK/DEX to Java",
    },
    "objection": {
        "requires_args": False,
        "usage_hint": "droidreaver objection -g com.example.app explore",
        "summary": "Runtime mobile exploration (Objection)",
    },
}


class RunError(Exception):
    """Could not locate or launch a tool."""


def _is_frida_stack_tool(tool_name: str) -> bool:
    return tool_name in FRIDA_PIN_GROUP


def _tool_install_bin(config: dict, tool_name: str) -> Path:
    return install_dir(config) / tool_name / "bin"


def _find_binary_in_dir(directory: Path, name: str) -> Path | None:
    if not directory.is_dir():
        return None
    candidates = [name]
    if detect_platform() == "windows":
        candidates.extend([f"{name}.exe", f"{name}.bat", f"{name}.cmd"])
    for c in candidates:
        p = directory / c
        if p.is_file():
            return p
    return None


def frida_venv_bin(config: dict) -> Path | None:
    ver = get_active_frida_version(config)
    if not ver:
        return None
    venv = frida_venv_path(ver)
    if detect_platform() == "windows":
        scripts = venv / "Scripts"
        return scripts if scripts.is_dir() else None
    bindir = venv / "bin"
    return bindir if bindir.is_dir() else None


def collect_tool_bin_paths(config: dict) -> list[Path]:
    """All DroidReaver-managed bin directories (for PATH augmentation)."""
    paths: list[Path] = []
    venv_bin = frida_venv_bin(config)
    if venv_bin:
        paths.append(venv_bin)

    inst = install_dir(config)
    if inst.is_dir():
        for entry in inst.iterdir():
            if not entry.is_dir():
                continue
            bin_d = entry / "bin"
            if bin_d.is_dir():
                paths.append(bin_d)

    # Global shim dir for future use
    shim = Path.home() / ".droidreaver" / "bin"
    if shim.is_dir():
        paths.append(shim)

    return paths


def build_run_env(config: dict) -> dict[str, str]:
    """Environment with DroidReaver tool bins prepended to PATH."""
    env = os.environ.copy()
    prepend = collect_tool_bin_paths(config)
    if prepend:
        extra = os.pathsep.join(str(p) for p in prepend)
        env["PATH"] = extra + os.pathsep + env.get("PATH", "")
    java = get_setting(config, "java_path", "java")
    if java:
        env.setdefault("DROIDREAVER_JAVA", java)
    env["DROIDREAVER_SHELL"] = "1"
    return env


def shell_path_hint(config: dict) -> str:
    """Shell snippet to put ALL DroidReaver tool bins on PATH (not just frida)."""
    paths = collect_tool_bin_paths(config)
    if not paths:
        return (
            "No DroidReaver tools installed yet.\n"
            "Install some: droidreaver up   (or: droidreaver install <tool>)"
        )
    joined = os.pathsep.join(str(p) for p in paths)
    if detect_platform() == "windows":
        return (
            "# CMD:\n"
            f"set PATH={joined};%PATH%\n"
            "# PowerShell:\n"
            f'$env:PATH = "{joined};$env:PATH"\n'
            "# Or just open a ready shell:  droidreaver shell"
        )
    return (
        f'export PATH="{joined}:$PATH"\n'
        "# Or just open a ready shell:  droidreaver shell"
    )


def _windows_parent_shell_exe() -> str | None:
    """Best-effort: name of the cmd/powershell/pwsh process that launched us."""
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return None
        try:
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            procs: dict[int, tuple[int, str]] = {}
            if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
                return None
            while True:
                procs[entry.th32ProcessID] = (
                    entry.th32ParentProcessID,
                    entry.szExeFile.decode(errors="ignore"),
                )
                if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
        finally:
            kernel32.CloseHandle(snapshot)

        pid = os.getpid()
        for _ in range(10):
            info = procs.get(pid)
            if not info:
                break
            ppid, name = info
            low = name.lower()
            if low in ("cmd.exe", "powershell.exe", "pwsh.exe"):
                return low
            pid = ppid
    except Exception:  # noqa: BLE001 - detection is best-effort only
        return None
    return None


def _detect_shell_kind() -> str:
    """Return 'powershell' | 'pwsh' | 'cmd' | 'posix' for the user's shell."""
    if detect_platform() != "windows":
        return "posix"

    override = os.environ.get("DROIDREAVER_SHELL_EXE", "").lower()
    if "pwsh" in override:
        return "pwsh"
    if "powershell" in override:
        return "powershell"
    if "cmd" in override:
        return "cmd"

    parent = _windows_parent_shell_exe()
    if parent == "pwsh.exe":
        return "pwsh"
    if parent == "powershell.exe":
        return "powershell"
    if parent == "cmd.exe":
        return "cmd"

    if which("pwsh"):
        return "pwsh"
    if which("powershell"):
        return "powershell"
    return "cmd"


def pick_user_shell() -> list[str]:
    """Return argv for an interactive subshell that stays open with a clear prompt."""
    kind = _detect_shell_kind()

    if kind == "posix":
        shell = os.environ.get("SHELL") or which("bash") or "/bin/sh"
        return [shell]

    if kind == "cmd":
        comspec = os.environ.get("COMSPEC") or "cmd.exe"
        # /K keeps cmd open; custom prompt makes the DroidReaver shell obvious.
        return [comspec, "/K", "prompt [DroidReaver] $P$G"]

    exe = (which("pwsh") if kind == "pwsh" else which("powershell")) or which("pwsh") or "powershell"
    ps_prompt = (
        "function prompt { \"[DroidReaver] PS \" "
        "+ $executionContext.SessionState.Path.CurrentLocation + \"> \" }"
    )
    return [exe, "-NoLogo", "-NoExit", "-Command", ps_prompt]


def can_launch_interactive_shell() -> bool:
    """True when stdin/stdout are attached to a real terminal."""
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty())
    except (ValueError, OSError):
        return False


def launch_shell(config: dict) -> int:
    """Open an interactive subshell with DroidReaver tools on PATH."""
    env = build_run_env(config)
    argv = pick_user_shell()
    result = subprocess.run(argv, env=env)
    return result.returncode


def resolve_executable(config: dict, tool: Tool, executable: str) -> list[str]:
    """Return argv prefix to launch executable (may be multi-arg for java -m)."""
    # 1) Active frida venv (for frida stack tools and their aliases)
    if _is_frida_stack_tool(tool.name) or executable in _all_frida_stack_executables():
        vbin = frida_venv_bin(config)
        if vbin:
            found = _find_binary_in_dir(vbin, executable)
            if found:
                return [str(found)]

    # 2) DroidReaver install_dir/<tool>/bin/
    found = _find_binary_in_dir(_tool_install_bin(config, tool.name), executable)
    if found:
        return [str(found)]

    # 3) Augmented PATH
    env = build_run_env(config)
    path_val = env.get("PATH", "")
    for part in path_val.split(os.pathsep):
        if not part:
            continue
        found = _find_binary_in_dir(Path(part), executable)
        if found:
            return [str(found)]

    # 4) shutil.which with augmented env
    which_path = shutil.which(executable, path=env.get("PATH"))
    if which_path:
        return [which_path]

    # 5) python -m module
    module = tool.run_module or tool.pip_package
    if module and tool.install_method == "pip":
        return [sys.executable, "-m", module]

    # 6) java -jar in tool dir
    inst = install_dir(config) / tool.name
    if inst.is_dir():
        jars = list(inst.glob("*.jar"))
        if jars:
            java = get_setting(config, "java_path", "java") or "java"
            return [java, "-jar", str(jars[0])]

    raise RunError(
        f"Cannot find executable '{executable}' for {tool.display_name}.\n"
        f"Install it: droidreaver install {tool.name}\n"
        + (
            f"Or activate frida venv: droidreaver use <version> && droidreaver env\n"
            if _is_frida_stack_tool(tool.name)
            else ""
        )
    )


def _all_frida_stack_executables() -> set[str]:
    names: set[str] = set()
    for name in FRIDA_PIN_GROUP:
        tool = get_tool(name)
        if tool.binary_name:
            names.add(tool.binary_name)
        names.update(tool.cli_aliases)
    return names


def iter_invocations() -> list[Invocation]:
    """Every CLI name we can dispatch (tool names, binaries, aliases)."""
    seen: set[str] = set()
    invocations: list[Invocation] = []

    def add(name: str, tool: Tool, executable: str) -> None:
        key = name.lower()
        if key in seen or key in RESERVED_COMMANDS:
            return
        if tool.install_method == "manual" and not tool.binary_name:
            return
        seen.add(key)
        meta = INVOCATION_META.get(name, {})
        invocations.append(
            Invocation(
                name=name,
                tool=tool,
                executable=executable,
                requires_args=bool(meta.get("requires_args")),
                usage_hint=str(meta["usage_hint"]) if meta.get("usage_hint") else None,
            )
        )

    for tool in TOOLS.values():
        if tool.install_method == "manual" and not tool.binary_name:
            continue
        add(tool.name, tool, tool.binary_name or tool.name)
        if tool.binary_name and tool.binary_name != tool.name:
            add(tool.binary_name, tool, tool.binary_name)
        for alias in tool.cli_aliases:
            add(alias, tool, alias)

    invocations.sort(key=lambda i: i.name.lower())
    return invocations


def lookup_invocation(name: str) -> Invocation | None:
    q = name.lower()
    for inv in iter_invocations():
        if inv.name.lower() == q:
            return inv
    return None


def list_runnable_tools() -> list[Invocation]:
    return iter_invocations()


def print_dispatch_hint(inv: Invocation) -> None:
    """Show DroidReaver guidance when a tool is invoked without arguments."""
    meta = INVOCATION_META.get(inv.name, {})
    summary = meta.get("summary") or inv.tool.description or inv.tool.display_name
    lines = [
        f"[bold cyan]⚔ {inv.name}[/] — {summary}",
        "",
    ]
    if inv.requires_args:
        lines.append("[yellow]This command requires arguments.[/]")
    if inv.usage_hint:
        lines.append(f"[dim]Example:[/] [cyan]{inv.usage_hint}[/]")
    lines.append(f"[dim]Full help:[/] [cyan]droidreaver {inv.name} --help[/]")
    _console.print(Panel("\n".join(lines), border_style="#3a6652", padding=(0, 1)))


def prepare_dispatch_args(inv: Invocation, args: list[str]) -> list[str]:
    """If invoked bare and args are required, show hint and forward --help."""
    if args:
        return args
    if inv.requires_args or inv.usage_hint:
        print_dispatch_hint(inv)
    if inv.requires_args:
        return ["--help"]
    return args


def run_invocation(
    invocation: str,
    args: list[str],
    config: dict,
    *,
    passthrough: bool = True,
) -> int:
    """Execute tool CLI; returns exit code."""
    inv = lookup_invocation(invocation)
    if not inv:
        raise RunError(f"Unknown tool or alias: {invocation}")

    args = prepare_dispatch_args(inv, list(args))
    argv = resolve_executable(config, inv.tool, inv.executable) + args
    env = build_run_env(config)

    if passthrough:
        result = subprocess.run(argv, env=env)
        return result.returncode

    result = subprocess.run(argv, env=env, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def format_arsenal_row(inv: Invocation, config: dict) -> tuple[str, str, str]:
    """Return (name, tool, available?) for display."""
    try:
        resolve_executable(config, inv.tool, inv.executable)
        status = "[green]ready[/]"
    except RunError:
        status = "[red]missing[/]"
    return inv.name, inv.tool.name, status
