"""DroidReaver interactive console — a pentest REPL for a connected device.

This is a real interactive shell (like Objection's prompt) that keeps live
session state — selected device + target app — and exposes first-class
pentest verbs (apps, target, ready, bypass, objection, proxy, logcat, …).

Built on the stdlib ``cmd`` module so it needs no extra dependencies and
works on Windows/macOS/Linux.
"""

from __future__ import annotations

import cmd
import shlex
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from droidreaver.bypass import BypassError, list_android_apps, run_bypass
from droidreaver.device import (
    DeviceError,
    adb_path,
    check_frida_server_running,
    list_devices,
    push_frida_server,
)
from droidreaver.runtime import RunError, build_run_env, run_invocation
from droidreaver.versions import get_active_frida_version

console = Console()

BANNER = r"""
[bold #00ff41]⚔  DroidReaver Console[/]  [dim]— interactive Android pentest shell[/]
"""

_GREEN = "\033[92m"
_DIM = "\033[2m"
_RESET = "\033[0m"


class DroidReaverConsole(cmd.Cmd):
    """Interactive pentest REPL with live device + target state."""

    intro = ""  # printed manually so we can use rich
    doc_header = "Commands (type help <cmd>)"
    ruler = "-"

    def __init__(self, config: dict, serial: str | None = None) -> None:
        super().__init__()
        self.config = config
        self.serial: str | None = serial
        self.package: str | None = None
        self._update_prompt()

    # ------------------------------------------------------------------ #
    # prompt / lifecycle
    # ------------------------------------------------------------------ #
    def _update_prompt(self) -> None:
        dev = self.serial or "no-device"
        tgt = self.package or "no-target"
        self.prompt = f"{_GREEN}droidreaver{_RESET} {_DIM}[{dev} | {tgt}]{_RESET}> "

    def postcmd(self, stop: bool, line: str) -> bool:  # noqa: D401
        self._update_prompt()
        return stop

    def emptyline(self) -> bool:  # don't repeat last command on empty enter
        return False

    def default(self, line: str) -> None:
        console.print(
            f"[yellow]Unknown command:[/] {line.split()[0] if line.split() else line}. "
            "Type [cyan]help[/] to list commands."
        )

    def cmdloop(self, intro=None):  # noqa: ANN001 - match base signature
        """Run the loop but survive Ctrl+C instead of crashing out."""
        self._print_intro()
        while True:
            try:
                super().cmdloop(intro="")
                break
            except KeyboardInterrupt:
                console.print("\n[dim]^C — type[/] [cyan]exit[/] [dim]to quit the console.[/]")

    def _print_intro(self) -> None:
        console.print(Panel.fit(BANNER.strip(), border_style="#00ff41"))
        if self.serial:
            console.print(f"[green]✓[/] Device: [bold]{self.serial}[/]")
        else:
            self._auto_select_device(quiet=True)
        console.print(
            "[dim]Type[/] [cyan]help[/] [dim]for commands,[/] "
            "[cyan]status[/] [dim]for the session, or[/] "
            "[cyan]exit[/] [dim]to leave.[/]\n"
        )

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _adb_base(self) -> list[str]:
        adb = adb_path(self.config)
        cmd_base = [adb]
        if self.serial:
            cmd_base += ["-s", self.serial]
        return cmd_base

    def _auto_select_device(self, quiet: bool = False) -> None:
        try:
            devices = list_devices(self.config)
        except DeviceError as e:
            if not quiet:
                console.print(f"[red]{e}[/]")
            return
        if not devices:
            if not quiet:
                console.print(
                    "[yellow]No devices connected.[/] Start an emulator or plug in a device."
                )
            return
        if len(devices) == 1:
            self.serial = devices[0]
            console.print(f"[green]✓[/] Auto-selected device: [bold]{self.serial}[/]")
        else:
            console.print("[yellow]Multiple devices — pick one with[/] [cyan]use <serial>[/]:")
            for d in devices:
                console.print(f"  [green]•[/] {d}")

    def _require_device(self) -> bool:
        if self.serial:
            return True
        console.print("[red]No device selected.[/] Run [cyan]devices[/] then [cyan]use <serial>[/].")
        return False

    def _require_target(self) -> bool:
        if self.package:
            return True
        console.print(
            "[red]No target app set.[/] Run [cyan]apps[/] to list, then [cyan]target <package>[/]."
        )
        return False

    @staticmethod
    def _split(arg: str) -> list[str]:
        try:
            return shlex.split(arg)
        except ValueError:
            return arg.split()

    # ------------------------------------------------------------------ #
    # device / session
    # ------------------------------------------------------------------ #
    def do_devices(self, arg: str) -> None:
        """List connected ADB devices (auto-selects when only one)."""
        try:
            devices = list_devices(self.config)
        except DeviceError as e:
            console.print(f"[red]{e}[/]")
            return
        if not devices:
            console.print("[yellow]No devices connected.[/]")
            return
        console.print("[bold]Connected devices:[/]")
        for d in devices:
            marker = "[green]✓[/]" if d == self.serial else " "
            console.print(f"  {marker} {d}")
        if not self.serial and len(devices) == 1:
            self.serial = devices[0]
            console.print(f"[green]✓[/] Selected [bold]{self.serial}[/]")

    def do_use(self, arg: str) -> None:
        """use <serial> — select the active device."""
        serial = arg.strip()
        if not serial:
            console.print("[yellow]Usage:[/] use <serial>")
            return
        try:
            devices = list_devices(self.config)
        except DeviceError as e:
            console.print(f"[red]{e}[/]")
            return
        if serial not in devices:
            console.print(f"[red]{serial} not connected.[/] Available: {', '.join(devices) or 'none'}")
            return
        self.serial = serial
        console.print(f"[green]✓[/] Using [bold]{serial}[/]")

    def do_apps(self, arg: str) -> None:
        """apps [filter] — list installed apps (running ones are marked)."""
        filt = arg.strip().lower()
        apps = list_android_apps(self.config, serial=self.serial)
        if not apps:
            console.print(
                "[yellow]No apps listed.[/] Is frida-server running? Try [cyan]ready[/] first."
            )
            return
        if filt:
            apps = [a for a in apps if filt in a.identifier.lower() or filt in a.name.lower()]
        if not apps:
            console.print(f"[yellow]No apps match[/] '{filt}'.")
            return
        table = Table(header_style="bold #00ff41", border_style="#3a6652")
        table.add_column("State")
        table.add_column("Package", style="bold #39ff14")
        table.add_column("Name")
        table.add_column("PID")
        for a in sorted(apps, key=lambda x: (not x.running, x.identifier)):
            state = "[green]running[/]" if a.running else "[dim]stopped[/]"
            table.add_row(state, a.identifier, a.name, str(a.pid or "-"))
        console.print(table)

    def do_target(self, arg: str) -> None:
        """target <package|substring> — set the app you're testing."""
        query = arg.strip()
        if not query:
            if self.package:
                console.print(f"Current target: [bold]{self.package}[/]")
            else:
                console.print("[yellow]Usage:[/] target <package>")
            return
        apps = list_android_apps(self.config, serial=self.serial)
        exact = [a for a in apps if a.identifier.lower() == query.lower()]
        if exact:
            self.package = exact[0].identifier
        elif apps:
            partial = [
                a
                for a in apps
                if query.lower() in a.identifier.lower() or query.lower() in a.name.lower()
            ]
            if len(partial) == 1:
                self.package = partial[0].identifier
            elif len(partial) > 1:
                console.print("[yellow]Multiple matches — be more specific:[/]")
                for a in partial[:12]:
                    console.print(f"  [green]•[/] {a.identifier}  ({a.name})")
                return
            else:
                # No frida list available / no match — trust the user's package id.
                self.package = query
        else:
            self.package = query
        console.print(f"[green]✓[/] Target: [bold]{self.package}[/]")

    def do_status(self, arg: str) -> None:
        """status — show device, frida runtime, frida-server, and target."""
        active = get_active_frida_version(self.config)
        server = False
        if self.serial:
            try:
                server = check_frida_server_running(self.config, self.serial)
            except Exception:  # noqa: BLE001
                server = False
        lines = [
            f"Device        : {self.serial or '[yellow]none[/]'}",
            f"Target app    : {self.package or '[yellow]none[/]'}",
            f"Frida runtime : {active or '[yellow]none — run: droidreaver use latest[/]'}",
            f"frida-server  : {'[green]running[/]' if server else '[red]not running[/] (run: ready)'}",
        ]
        console.print(Panel("\n".join(lines), title="[bold]Session[/]", border_style="#3a6652"))

    do_info = do_status

    # ------------------------------------------------------------------ #
    # frida readiness
    # ------------------------------------------------------------------ #
    def do_ready(self, arg: str) -> None:
        """ready — push & start frida-server matching your local frida."""
        if not get_active_frida_version(self.config):
            console.print(
                "[yellow]No active frida runtime.[/] Set one first: "
                "[cyan]droidreaver use latest[/] (outside the console), then re-run [cyan]ready[/]."
            )
            return
        try:
            push_frida_server(self.config, serial=self.serial, start=True)
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]ready failed:[/] {e}")
            return
        console.print("[green]◈ Device is frida-ready.[/] Try [cyan]apps[/] then [cyan]hook[/].")

    def do_ps(self, arg: str) -> None:
        """ps — list running processes on the selected device."""
        try:
            transport = ["-D", self.serial] if self.serial else ["-U"]
            run_invocation("frida-ps", transport, self.config)
        except RunError as e:
            console.print(f"[red]{e}[/]")

    # ------------------------------------------------------------------ #
    # attacks
    # ------------------------------------------------------------------ #
    def _run_bypass(self, recipe: str, spawn: bool) -> None:
        if not self._require_target():
            return
        try:
            run_bypass(
                self.config,
                recipe,  # type: ignore[arg-type]
                self.package or "",
                spawn=spawn,
                serial=self.serial,
            )
        except (BypassError, RunError) as e:
            console.print(f"[red]{e}[/]")
        except KeyboardInterrupt:
            console.print("\n[dim]Bypass session ended.[/]")

    def do_hook(self, arg: str) -> None:
        """hook [--spawn] — SSL + root bypass; attach to a running target by default."""
        spawn = arg.strip().lower() in ("spawn", "--spawn")
        self._run_bypass("all", spawn=spawn)

    def do_bypass(self, arg: str) -> None:
        """bypass [ssl|root|all] [--spawn] — attach by default."""
        parts = self._split(arg.lower())
        spawn = "--spawn" in parts or "spawn" in parts
        parts = [part for part in parts if part not in ("--spawn", "spawn")]
        recipe = (parts[0] if parts else "all").lower()
        if recipe not in ("ssl", "root", "all", "both"):
            console.print(r"[yellow]Usage:[/] bypass \[ssl|root|all] [--spawn]")
            return
        if recipe == "both":
            recipe = "all"
        self._run_bypass(recipe, spawn=spawn)

    def do_objection(self, arg: str) -> None:
        """objection [extra args] — open Objection's explorer on the target."""
        if not self._require_target():
            return
        extra = self._split(arg)
        args = ["-g", self.package or "", "explore", *extra]
        try:
            run_invocation("objection", args, self.config)
        except RunError as e:
            console.print(f"[red]{e}[/]")
        except KeyboardInterrupt:
            console.print("\n[dim]Objection session ended.[/]")

    # ------------------------------------------------------------------ #
    # device interaction
    # ------------------------------------------------------------------ #
    def do_adb(self, arg: str) -> None:
        """adb <args...> — run adb against the selected device."""
        if not self._require_device():
            return
        args = self._split(arg)
        if not args:
            console.print("[yellow]Usage:[/] adb <args...>   e.g. adb shell getprop ro.build.version.release")
            return
        timeout = 15 if args[0] in ("reverse", "forward") else 60
        try:
            result = subprocess.run(
                self._adb_base() + args,
                env=build_run_env(self.config),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            console.print(
                f"[red]adb {args[0]} timed out after {timeout}s.[/] "
                "Check the USB connection with [cyan]devices[/] and retry."
            )
            return
        if result.returncode == 0:
            console.print("[green]✓[/] adb command completed.")
        else:
            console.print(f"[red]adb command failed (exit {result.returncode}).[/]")

    def do_adbshell(self, arg: str) -> None:
        """adbshell — drop into an interactive adb shell on the device."""
        if not self._require_device():
            return
        console.print("[dim]Entering adb shell — type[/] [cyan]exit[/] [dim]to return.[/]")
        subprocess.run(self._adb_base() + ["shell"], env=build_run_env(self.config))

    def do_logcat(self, arg: str) -> None:
        """logcat [filter] — stream device logs (Ctrl+C to stop)."""
        if not self._require_device():
            return
        args = self._split(arg)
        console.print("[dim]Streaming logcat — press Ctrl+C to stop.[/]")
        try:
            subprocess.run(self._adb_base() + ["logcat", *args], env=build_run_env(self.config))
        except KeyboardInterrupt:
            console.print("\n[dim]logcat stopped.[/]")

    def _run_settings(self, *settings_args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._adb_base() + ["shell", "settings", *settings_args],
            capture_output=True,
            text=True,
        )

    def _set_global_proxy(self, value: str) -> bool:
        """Set http_proxy; returns True on success."""
        res = self._run_settings("put", "global", "http_proxy", value)
        if res.returncode == 0 and "SecurityException" not in (res.stderr or ""):
            return True
        # Rooted devices: global settings often need su.
        su = subprocess.run(
            self._adb_base()
            + ["shell", "su", "-c", f"settings put global http_proxy {value}"],
            capture_output=True,
            text=True,
        )
        if su.returncode == 0 and "SecurityException" not in (su.stderr or ""):
            return True
        console.print(
            "[yellow]Could not set global proxy via adb[/] "
            "(needs WRITE_SECURE_SETTINGS or root).\n"
            "[bold]Set it manually on the phone:[/]\n"
            "  Settings → Wi‑Fi → your network → Proxy → Manual\n"
            f"  Host: [cyan]{value.rsplit(':', 1)[0]}[/]  "
            f"Port: [cyan]{value.rsplit(':', 1)[-1]}[/]"
        )
        return False

    def do_proxy(self, arg: str) -> None:
        """proxy <host:port> | off — set/clear the device global HTTP proxy."""
        if not self._require_device():
            return
        value = arg.strip()
        if not value:
            res = self._run_settings("get", "global", "http_proxy")
            console.print(f"Current proxy: [bold]{(res.stdout or '').strip() or 'none'}[/]")
            return
        if value.lower() in ("off", "none", "clear"):
            self._run_settings("put", "global", "http_proxy", ":0")
            self._run_settings("delete", "global", "http_proxy")
            subprocess.run(
                self._adb_base()
                + ["shell", "su", "-c", "settings delete global http_proxy"],
                capture_output=True,
            )
            console.print("[green]✓[/] Proxy cleared.")
            return
        if self._set_global_proxy(value):
            console.print(
                f"[green]✓[/] Proxy set to [bold]{value}[/]. "
                "[dim]Install your CA cert for HTTPS interception.[/]"
            )

    def do_screenshot(self, arg: str) -> None:
        """screenshot [file.png] — capture the device screen to a local PNG."""
        if not self._require_device():
            return
        out = Path(arg.strip() or "screenshot.png")
        res = subprocess.run(
            self._adb_base() + ["exec-out", "screencap", "-p"],
            capture_output=True,
        )
        if res.returncode != 0 or not res.stdout:
            console.print(f"[red]screencap failed:[/] {(res.stderr or b'').decode(errors='ignore')}")
            return
        out.write_bytes(res.stdout)
        console.print(f"[green]✓[/] Saved [bold]{out.resolve()}[/]")

    def do_pull(self, arg: str) -> None:
        """pull <remote> [local] — copy a file off the device."""
        if not self._require_device():
            return
        args = self._split(arg)
        if not args:
            console.print(r"[yellow]Usage:[/] pull <remote> \[local]")
            return
        subprocess.run(self._adb_base() + ["pull", *args], env=build_run_env(self.config))

    def do_push(self, arg: str) -> None:
        """push <local> <remote> — copy a file onto the device."""
        if not self._require_device():
            return
        args = self._split(arg)
        if len(args) < 2:
            console.print("[yellow]Usage:[/] push <local> <remote>")
            return
        subprocess.run(self._adb_base() + ["push", *args], env=build_run_env(self.config))

    def do_run(self, arg: str) -> None:
        """run <tool> [args...] — run any DroidReaver tool (frida, jadx, apktool, …)."""
        args = self._split(arg)
        if not args:
            console.print("[yellow]Usage:[/] run <tool> [args...]")
            return
        try:
            run_invocation(args[0], args[1:], self.config)
        except RunError as e:
            console.print(f"[red]{e}[/]")
        except KeyboardInterrupt:
            console.print("\n[dim]Stopped.[/]")

    # ------------------------------------------------------------------ #
    # misc
    # ------------------------------------------------------------------ #
    def do_clear(self, arg: str) -> None:
        """clear — clear the screen."""
        console.clear()

    do_cls = do_clear

    def do_exit(self, arg: str) -> bool:
        """exit — leave the DroidReaver console."""
        console.print("[dim]Leaving DroidReaver console.[/]")
        return True

    do_quit = do_exit

    def do_EOF(self, arg: str) -> bool:  # Ctrl+D / Ctrl+Z
        console.print("")
        return self.do_exit(arg)


def run_console(config: dict, serial: str | None = None) -> int:
    """Start the interactive DroidReaver console."""
    if not (sys.stdin and sys.stdin.isatty()):
        console.print(
            "[yellow]The console needs an interactive terminal.[/] "
            "Run [cyan]droidreaver console[/] directly in your terminal."
        )
        return 1
    DroidReaverConsole(config, serial=serial).cmdloop()
    return 0
