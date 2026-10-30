"""ADB wrapper and frida-server push logic."""

from __future__ import annotations

import os
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from rich.console import Console
from rich.progress import Progress

from droidreaver.config import get_setting, install_dir
from droidreaver.progress import work_spinner
from droidreaver.utils import PROBE_CMD_TIMEOUT, detect_platform, github_headers, parse_version, run_cmd, which

console = Console()

DEFAULT_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
# Map adb ABI names to frida-server arch suffixes
ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86": "x86",
    "x86_64": "x86_64",
}


class DeviceError(Exception):
    """Device operation failed."""


@dataclass(frozen=True)
class FridaServerStatus:
    running: bool
    user: str | None = None
    device_rooted: bool = False

    @property
    def runs_as_root(self) -> bool:
        return self.user == "root"


def _managed_binary(config: dict, tool_name: str, binary_name: str) -> str | None:
    bin_dir = install_dir(config) / tool_name / "bin"
    candidates = [binary_name]
    if detect_platform() == "windows":
        candidates.extend([f"{binary_name}.exe", f"{binary_name}.bat", f"{binary_name}.cmd"])
    for candidate in candidates:
        path = bin_dir / candidate
        if path.is_file():
            return str(path)
    return None


def adb_path(config: dict) -> str:
    custom = get_setting(config, "adb_path", "adb")
    if which(custom):
        return custom
    if which("adb"):
        return "adb"
    managed = _managed_binary(config, "adb", "adb")
    if managed:
        return managed
    raise DeviceError(
        "adb not found. Install platform-tools, run `droidreaver shell`, "
        "or set adb_path in droidreaver.toml"
    )


def _adb_cmd(config: dict, serial: str | None = None) -> list[str]:
    cmd = [adb_path(config)]
    if serial:
        cmd.extend(["-s", serial])
    return cmd


def force_stop_app(config: dict, package: str, *, serial: str | None = None) -> None:
    """Force-stop an Android app before a Frida cold spawn."""
    run_cmd(_adb_cmd(config, serial) + ["shell", "am", "force-stop", package])


def launch_app(config: dict, package: str, *, serial: str | None = None) -> None:
    """Launch an app via adb (MAIN/LAUNCHER intent)."""
    run_cmd(
        _adb_cmd(config, serial)
        + [
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ]
    )


def list_devices(config: dict) -> list[str]:
    adb = adb_path(config)
    result = run_cmd([adb, "devices"], timeout=PROBE_CMD_TIMEOUT)
    if result.returncode != 0:
        raise DeviceError(f"adb devices failed: {result.stderr}")
    devices: list[str] = []
    for line in (result.stdout or "").splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def get_device_arch(config: dict, serial: str | None = None) -> str:
    adb = adb_path(config)
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["shell", "getprop", "ro.product.cpu.abi"])
    result = run_cmd(cmd)
    if result.returncode != 0:
        raise DeviceError(f"Could not detect device architecture: {result.stderr}")
    abi = (result.stdout or "").strip()
    arch = ABI_MAP.get(abi)
    if not arch:
        raise DeviceError(
            f"Unsupported device ABI: {abi}. "
            f"Supported: {', '.join(ABI_MAP.keys())}"
        )
    return arch


def get_local_frida_version(config: dict | None = None) -> str:
    env = None
    if config is not None:
        from droidreaver.runtime import build_run_env

        env = build_run_env(config)

    result = run_cmd("frida --version", env=env, timeout=PROBE_CMD_TIMEOUT)
    if result.returncode != 0:
        raise DeviceError(
            "frida not installed locally. Run: droidreaver use latest"
        )
    ver = parse_version(result.stdout or result.stderr)
    if not ver:
        raise DeviceError("Could not parse local frida version")
    return ver


def download_frida_server(version: str, arch: str, dest: Path) -> Path:
    """Download frida-server binary matching version and arch."""
    filename = f"frida-server-{version}-android-{arch}"
    urls = [
        f"https://github.com/frida/frida/releases/download/{version}/{filename}.xz",
        f"https://github.com/frida/frida/releases/download/{version}/{filename}",
    ]

    dest.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None

    for url in urls:
        try:
            resp = requests.get(url, headers=github_headers(), stream=True, timeout=120)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            raw = dest.with_suffix(".download")
            with raw.open("wb") as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)

            if url.endswith(".xz"):
                try:
                    import lzma

                    data = lzma.open(raw).read()
                    out = dest
                    out.write_bytes(data)
                    raw.unlink()
                except ImportError:
                    raise DeviceError(
                        "Downloaded .xz frida-server but lzma module unavailable"
                    )
            else:
                raw.rename(dest)
            return dest
        except requests.RequestException as e:
            last_error = e
            continue

    raise DeviceError(
        f"Could not download frida-server {version} for {arch}. "
        f"Check that version exists at https://github.com/frida/frida/releases. "
        f"{last_error or ''}"
    )


def push_frida_server(
    config: dict,
    *,
    serial: str | None = None,
    start: bool = True,
    remote_path: str = "/data/local/tmp/frida-server",
) -> None:
    """Push matching frida-server to device."""
    frida_ver = get_local_frida_version(config)
    devices = list_devices(config)

    if not devices:
        raise DeviceError("No ADB devices connected. Connect a device and enable USB debugging.")

    targets = [serial] if serial else devices
    if serial and serial not in devices:
        raise DeviceError(f"Device {serial} not found. Connected: {', '.join(devices)}")

    adb = adb_path(config)

    for dev in targets:
        with work_spinner("[cyan]Detecting device architecture…[/]", console=console) as update:
            arch = get_device_arch(config, dev)
            update(f"[cyan]Device[/] [bold]{dev}[/] — [green]{arch}[/], frida [yellow]{frida_ver}[/]")

        with tempfile.TemporaryDirectory() as tmp:
            local_bin = Path(tmp) / "frida-server"
            with work_spinner(
                f"[cyan]Downloading frida-server {frida_ver} ({arch})…[/]",
                console=console,
            ):
                download_frida_server(frida_ver, arch, local_bin)

            if os.name != "nt":
                local_bin.chmod(local_bin.stat().st_mode | stat.S_IEXEC)

            cmd_base = [adb]
            if dev:
                cmd_base.extend(["-s", dev])

            # Push
            push_cmd = cmd_base + ["push", str(local_bin), remote_path]
            with work_spinner(f"[cyan]Pushing to {remote_path}…[/]", console=console):
                result = run_cmd(push_cmd)
            if result.returncode != 0:
                raise DeviceError(f"adb push failed: {result.stderr}")

            # chmod
            chmod_cmd = cmd_base + ["shell", f"chmod 755 {remote_path}"]
            run_cmd(chmod_cmd)

            console.print(f"[green]✓[/] Pushed frida-server {frida_ver} ({arch}) to {remote_path}")

            if start:
                with work_spinner("[cyan]Starting frida-server on device…[/]", console=console):
                    status = restart_frida_server(
                        config, serial=dev, remote_path=remote_path
                    )
                if not status.running:
                    raise DeviceError("frida-server did not start on device")
                if status.runs_as_root:
                    console.print("[green]✓[/] Started frida-server [bold]as root[/]")
                elif status.device_rooted:
                    console.print(
                        "[yellow]⚠[/] frida-server started but [bold]not as root[/] — "
                        "attach to apps will likely fail.\n"
                        f"  Run: [cyan]adb -s {dev} shell su -c "
                        f"'pkill frida-server; {remote_path} -D &'[/]"
                    )
                else:
                    console.print(
                        "[green]✓[/] Started frida-server [dim](device not rooted — "
                        "attach may only work on debuggable apps)[/]"
                    )

def get_remote_frida_server_version(config: dict, serial: str | None = None) -> str | None:
    """Try to detect frida-server version on device via frida-ps."""
    if not which("frida-ps"):
        return None
    cmd = "frida-ps -U"
    if serial:
        cmd = f"frida-ps -D {serial}"
    result = run_cmd(cmd)
    if result.returncode != 0:
        return None
    # frida-ps doesn't show server version directly; use frida CLI
    result = run_cmd("frida --version", timeout=PROBE_CMD_TIMEOUT)
    return parse_version(result.stdout) if result.returncode == 0 else None


def check_frida_server_running(config: dict, serial: str | None = None) -> bool:
    adb = adb_path(config)
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["shell", "pgrep frida-server"])
    result = run_cmd(cmd)
    return result.returncode == 0 and bool((result.stdout or "").strip())


def device_has_su(config: dict, serial: str | None = None) -> bool:
    """True when adb shell su can get uid 0 (device is rooted)."""
    result = run_cmd(
        _adb_cmd(config, serial) + ["shell", "su", "-c", "id"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    return result.returncode == 0 and "uid=0" in (result.stdout or "")


def _kill_frida_server(base: list[str]) -> None:
    run_cmd(
        base
        + [
            "shell",
            "su",
            "-c",
            "pkill -9 frida-server 2>/dev/null; killall frida-server 2>/dev/null; true",
        ]
    )
    run_cmd(base + ["shell", "pkill -9 frida-server 2>/dev/null || true"])


def _root_frida_start_strategies(remote_path: str) -> list[list[str]]:
    """ADB shell argv suffixes to try when starting frida-server as root."""
    return [
        ["su", "-c", f"chmod 755 {remote_path}; exec {remote_path} -D &"],
        ["su", "-c", f"nohup {remote_path} -D >/dev/null 2>&1 &"],
        ["su", "-mm", "-c", f"{remote_path} -D &"],
        ["su", "0", "sh", "-c", f"{remote_path} -D &"],
        ["su", "-c", f"({remote_path} -D &) &"],
        ["su", "-c", f"setsid {remote_path} -D &"],
    ]


def frida_server_pid(config: dict, serial: str | None = None) -> str | None:
    base = _adb_cmd(config, serial)
    for cmd in (
        base + ["shell", "pidof frida-server"],
        base + ["shell", "su", "-c", "pidof frida-server"],
    ):
        result = run_cmd(cmd, timeout=PROBE_CMD_TIMEOUT)
        if result.returncode != 0:
            continue
        pid = (result.stdout or "").strip().split()
        if pid:
            return pid[0]
    return None


def frida_server_user(config: dict, serial: str | None = None) -> str | None:
    """Return 'root' when frida-server runs as uid 0, else a uid label."""
    pid = frida_server_pid(config, serial)
    if not pid:
        return None
    base = _adb_cmd(config, serial)
    for cmd in (
        base + ["shell", f"cat /proc/{pid}/status"],
        base + ["shell", "su", "-c", f"cat /proc/{pid}/status"],
    ):
        result = run_cmd(cmd, timeout=PROBE_CMD_TIMEOUT)
        if result.returncode != 0:
            continue
        for line in (result.stdout or "").splitlines():
            if line.startswith("Uid:"):
                uid = line.split()[1]
                return "root" if uid == "0" else f"uid_{uid}"
    return None


def frida_server_status(config: dict, serial: str | None = None) -> FridaServerStatus:
    running = check_frida_server_running(config, serial)
    user = frida_server_user(config, serial) if running else None
    return FridaServerStatus(
        running=running,
        user=user,
        device_rooted=device_has_su(config, serial),
    )


def restart_frida_server(
    config: dict,
    *,
    serial: str | None = None,
    remote_path: str = DEFAULT_FRIDA_SERVER_PATH,
    verbose: bool = False,
) -> FridaServerStatus:
    """Kill any frida-server and start it (as root when su is available)."""
    base = _adb_cmd(config, serial)
    rooted = device_has_su(config, serial)

    _kill_frida_server(base)

    if not rooted:
        run_cmd(base + ["shell", f"{remote_path} -D &"])
        time.sleep(1.0)
        return frida_server_status(config, serial)

    for idx, strat in enumerate(_root_frida_start_strategies(remote_path), start=1):
        if verbose:
            console.print(f"[dim]Trying root start strategy {idx}/{len(_root_frida_start_strategies(remote_path))}…[/]")
        run_cmd(base + ["shell"] + strat)
        time.sleep(1.5)
        status = frida_server_status(config, serial)
        if status.running and status.runs_as_root:
            return status
        _kill_frida_server(base)

    # Last resort — may only work for debuggable apps.
    run_cmd(base + ["shell", f"{remote_path} -D &"])
    time.sleep(1.0)
    return frida_server_status(config, serial)


def print_frida_attach_troubleshooting(
    config: dict,
    *,
    serial: str | None = None,
    package: str | None = None,
) -> None:
    """Explain common causes of 'unable to access process' attach failures."""
    status = frida_server_status(config, serial)
    serial_flag = f" -s {serial}" if serial else ""
    pkg = package or "<package>"

    console.print(
        "\n[bold red]Frida attach failed[/] — [dim]unable to access process[/]\n"
    )

    if not status.running:
        console.print("[yellow]frida-server is not running.[/]")
        console.print(f"  [cyan]droidreaver device ready{serial_flag}[/]")
        return

    if status.device_rooted and not status.runs_as_root:
        console.print(
            "[yellow]Device is rooted but frida-server is NOT running as root.[/]\n"
            "This is the usual cause of [bold]unable to access process[/].\n"
        )
        console.print(
            "[bold]On the phone:[/] approve the [bold]Magisk/superuser[/] prompt when starting "
            "frida-server (set Magisk to prompt or grant permanent su to shell/adb).\n"
        )
        console.print("[bold]Fix — restart frida-server as root:[/]")
        console.print(
            f"  [cyan]droidreaver device root-server{serial_flag}[/]  "
            "[dim](tries multiple su strategies)[/]\n"
            f"  [cyan]adb{serial_flag} shell su -c "
            f"'pkill frida-server; {DEFAULT_FRIDA_SERVER_PATH} -D &'[/]\n"
            "  Manual check:\n"
            f"  [cyan]adb{serial_flag} shell su -c "
            f"\"cat /proc/$(pidof frida-server)/status | grep Uid\"[/]  "
            "[dim]→ must show Uid: 0[/]"
        )
    elif not status.device_rooted:
        console.print(
            "[yellow]Device does not appear rooted[/] (adb shell su failed).\n"
            "Frida can list apps but usually [bold]cannot attach[/] on a stock phone.\n\n"
            "[bold]Options:[/]\n"
            "  • Rooted device with Magisk\n"
            "  • Rooted emulator (Android Studio AVD / Genymotion)\n"
            "  • frida-gadget patched APK (advanced)\n"
        )
    else:
        console.print(
            "[yellow]frida-server runs as root but attach still failed.[/]\n"
            "Try opening the app first, then attach without [cyan]--spawn[/]:\n"
            f"  [cyan]droidreaver hook -n {pkg}{serial_flag}[/]\n"
            f"  [cyan]droidreaver objection -g {pkg} explore{serial_flag}[/]"
        )
