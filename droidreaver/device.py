"""ADB wrapper and frida-server push logic."""

from __future__ import annotations

import os
import stat
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
FRIDA_TCP_PORT = 27042
FRIDA_LISTEN = f"0.0.0.0:{FRIDA_TCP_PORT}"
FRIDA_HOST = f"127.0.0.1:{FRIDA_TCP_PORT}"
# Map adb ABI names to frida-server arch suffixes
ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86": "x86",
    "x86_64": "x86_64",
}
# 64-bit Android still runs 32-bit apps; those need a matching frida-server.
_COMPANION_ARCH = {"x86_64": "x86", "arm64": "arm"}


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
    """Launch an app via adb (MAIN/LAUNCHER), preferring `am start` over monkey."""
    base = _adb_cmd(config, serial)
    resolved = run_cmd(
        base + ["shell", "cmd", "package", "resolve-activity", "--brief", package],
        timeout=PROBE_CMD_TIMEOUT,
    )
    component = ""
    for line in reversed((resolved.stdout or "").splitlines()):
        line = line.strip()
        if "/" in line and not line.startswith("priority="):
            component = line
            break
    if component:
        run_cmd(base + ["shell", "am", "start", "-W", "-n", component], timeout=30)
        return
    run_cmd(
        base
        + [
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
        timeout=PROBE_CMD_TIMEOUT,
    )


def list_installed_packages(
    config: dict,
    serial: str | None = None,
    query: str | None = None,
) -> list[str]:
    """Fast `pm list packages` (optional substring filter)."""
    cmd = _adb_cmd(config, serial) + ["shell", "pm", "list", "packages"]
    if query:
        cmd.append(query)
    result = run_cmd(cmd, timeout=PROBE_CMD_TIMEOUT)
    if result.returncode != 0:
        return []
    packages: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            packages.append(line.split(":", 1)[1].strip())
    return packages


def pidof_package(config: dict, package: str, serial: str | None = None) -> int | None:
    """Return the app PID. Avoid `pidof -s` — some images reject that flag."""
    result = run_cmd(
        _adb_cmd(config, serial) + ["shell", "pidof", package],
        timeout=PROBE_CMD_TIMEOUT,
    )
    token = (result.stdout or "").strip().split()
    if result.returncode == 0 and token:
        try:
            return int(token[0])
        except ValueError:
            pass
    return process_name_pids(config, serial).get(package)


def process_name_pids(config: dict, serial: str | None = None) -> dict[str, int]:
    """Map process NAME -> PID from a single `ps -A`."""
    result = run_cmd(
        _adb_cmd(config, serial) + ["shell", "ps", "-A"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    if result.returncode != 0:
        return {}
    pids: dict[str, int] = {}
    for line in (result.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[-1]
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        pids[name] = pid
    return pids


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


def get_cpu_abilist(config: dict, serial: str | None = None) -> list[str]:
    result = run_cmd(
        _adb_cmd(config, serial) + ["shell", "getprop", "ro.product.cpu.abilist"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    return [part.strip() for part in (result.stdout or "").split(",") if part.strip()]


def get_needed_frida_arches(config: dict, serial: str | None = None) -> list[str]:
    """Primary ABI plus a 32-bit companion only when the image actually has that ABI."""
    primary = get_device_arch(config, serial)
    abilist = get_cpu_abilist(config, serial)
    arches = [primary]
    companion = _COMPANION_ARCH.get(primary)
    native_32 = {"x86", "armeabi-v7a", "armeabi"}
    if companion and any(abi in native_32 for abi in abilist):
        arches.append(companion)
    return arches


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


def cached_frida_server_path(version: str, arch: str) -> Path:
    return (
        Path.home()
        / ".droidreaver"
        / "cache"
        / "frida-server"
        / f"frida-server-{version}-android-{arch}"
    )


def download_frida_server(version: str, arch: str, dest: Path) -> Path:
    """Download frida-server binary matching version and arch. Reuses dest if present."""
    if dest.is_file() and dest.stat().st_size > 1024:
        return dest
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
            arches = get_needed_frida_arches(config, dev)
            update(
                f"[cyan]Device[/] [bold]{dev}[/] — [green]{' + '.join(arches)}[/], "
                f"frida [yellow]{frida_ver}[/]"
            )
        extra = (
            " [dim](32-bit apps need the 32-bit server)[/]"
            if len(arches) > 1
            else ""
        )
        console.print(
            f"[dim]Installing frida-server for[/] [bold]{' + '.join(arches)}[/]{extra}"
        )

        cmd_base = [adb]
        if dev:
            cmd_base.extend(["-s", dev])

        remote_paths: list[str] = []
        for arch in arches:
            dest = (
                remote_path
                if arch == arches[0]
                else f"{remote_path}-{arch}"
            )
            local_bin = cached_frida_server_path(frida_ver, arch)
            if local_bin.is_file() and local_bin.stat().st_size > 1024:
                console.print(f"[dim]Using cached frida-server {frida_ver} ({arch})[/]")
            else:
                with work_spinner(
                    f"[cyan]Downloading frida-server {frida_ver} ({arch})…[/]",
                    console=console,
                ):
                    download_frida_server(frida_ver, arch, local_bin)
            if os.name != "nt":
                local_bin.chmod(local_bin.stat().st_mode | stat.S_IEXEC)
            if _remote_file_size(cmd_base, dest) != local_bin.stat().st_size:
                with work_spinner(f"[cyan]Pushing {arch} to {dest}…[/]", console=console):
                    result = run_cmd(cmd_base + ["push", str(local_bin), dest])
                if result.returncode != 0:
                    raise DeviceError(f"adb push failed ({arch}): {result.stderr}")
                run_cmd(cmd_base + ["shell", f"chmod 755 {dest}"])
                console.print(f"[green]✓[/] Pushed frida-server {frida_ver} ({arch})")
            else:
                console.print(f"[dim]Device already has {arch} frida-server — skip push[/]")
            remote_paths.append(dest)

        if start:
            with work_spinner(
                "[cyan]Starting frida-server(s) as root…[/]",
                console=console,
            ):
                status = restart_frida_server(
                    config, serial=dev, remote_paths=remote_paths
                )
            if not status.running:
                raise DeviceError("frida-server did not start on device")
            if status.runs_as_root:
                console.print("[green]✓[/] Started frida-server [bold]as root[/]")
            elif status.device_rooted:
                console.print(
                    "[yellow]⚠[/] frida-server started but [bold]not as root[/]"
                )
            else:
                console.print("[green]✓[/] Started frida-server")

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


def _remote_file_size(cmd_base: list[str], remote_path: str) -> int | None:
    result = run_cmd(
        cmd_base + ["shell", f"wc -c < {remote_path} 2>/dev/null || echo"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    if result.returncode != 0:
        return None
    token = (result.stdout or "").strip().split()
    if not token:
        return None
    try:
        return int(token[0])
    except ValueError:
        return None


def check_frida_server_running(config: dict, serial: str | None = None) -> bool:
    adb = adb_path(config)
    cmd = [adb]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(["shell", "pgrep frida-server"])
    result = run_cmd(cmd)
    return result.returncode == 0 and bool((result.stdout or "").strip())


def _stdout_has_uid0(stdout: str | None) -> bool:
    return "uid=0" in (stdout or "")


def device_has_su(config: dict, serial: str | None = None) -> bool:
    """True when Magisk-style `adb shell su` can get uid 0."""
    result = run_cmd(
        _adb_cmd(config, serial) + ["shell", "su", "-c", "id"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    return result.returncode == 0 and _stdout_has_uid0(result.stdout)


def adbd_runs_as_root(config: dict, serial: str | None = None) -> bool:
    """True when `adb shell` itself is uid 0 (`adb root` on userdebug/emulator)."""
    result = run_cmd(
        _adb_cmd(config, serial) + ["shell", "id"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    return result.returncode == 0 and _stdout_has_uid0(result.stdout)


def try_adb_root(config: dict, serial: str | None = None) -> bool:
    """Best-effort `adb root` for AVDs / userdebug images. Harmless on production."""
    if adbd_runs_as_root(config, serial):
        return True
    run_cmd(_adb_cmd(config, serial) + ["root"], timeout=PROBE_CMD_TIMEOUT)
    time.sleep(0.8)
    run_cmd(_adb_cmd(config, serial) + ["wait-for-device"], timeout=PROBE_CMD_TIMEOUT)
    return adbd_runs_as_root(config, serial)


def device_is_rooted(config: dict, serial: str | None = None) -> bool:
    """True if Magisk su works or adbd is already uid 0 (emulator `adb root`)."""
    return device_has_su(config, serial) or adbd_runs_as_root(config, serial)


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
    run_cmd(base + ["shell", "pkill -9 -f frida-server 2>/dev/null || true"])


def wait_for_frida_tcp(*, timeout: float = 8.0) -> bool:
    """True when the host can connect to the forwarded frida-server port."""
    import socket

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", FRIDA_TCP_PORT), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def ensure_frida_tcp_forward(config: dict, serial: str | None = None) -> str:
    """Map host 127.0.0.1:27042 → device :27042. USB Frida on Windows often drops."""
    base = _adb_cmd(config, serial)
    run_cmd(base + ["forward", "--remove", f"tcp:{FRIDA_TCP_PORT}"], timeout=PROBE_CMD_TIMEOUT)
    result = run_cmd(
        base + ["forward", f"tcp:{FRIDA_TCP_PORT}", f"tcp:{FRIDA_TCP_PORT}"],
        timeout=PROBE_CMD_TIMEOUT,
    )
    if result.returncode != 0:
        console.print(
            f"[yellow]adb forward tcp:{FRIDA_TCP_PORT} failed:[/] "
            f"{(result.stderr or result.stdout or '').strip()}"
        )
    if not wait_for_frida_tcp():
        console.print(
            f"[yellow]Nothing is listening on {FRIDA_HOST} yet.[/] "
            "frida-server may have crashed — check [cyan]ready[/] output."
        )
    return FRIDA_HOST


def relax_selinux(config: dict, serial: str | None = None) -> None:
    run_cmd(_adb_cmd(config, serial) + ["shell", "setenforce", "0"], timeout=PROBE_CMD_TIMEOUT)


def _start_frida_daemon(base: list[str], remote_path: str) -> None:
    """Start one frida-server over USB (Frida's default Android transport)."""
    probe = run_cmd(base + ["shell", "ls", remote_path], timeout=PROBE_CMD_TIMEOUT)
    out = f"{probe.stdout or ''}{probe.stderr or ''}"
    if (isinstance(probe.returncode, int) and probe.returncode != 0) or "No such file" in out:
        console.print(f"[dim]Skip {remote_path} — binary is not on the device.[/]")
        return
    run_cmd(base + ["shell", "setenforce 0"], timeout=PROBE_CMD_TIMEOUT)
    log = "/data/local/tmp/frida-server.log"
    run_cmd(
        base
        + [
            "shell",
            f"nohup {remote_path} >>{log} 2>&1 </dev/null &",
        ],
        timeout=PROBE_CMD_TIMEOUT,
    )
    time.sleep(0.5)


def _root_frida_start_strategies(remote_path: str) -> list[list[str]]:
    """ADB shell argv suffixes to try when starting frida-server as root."""
    return [
        ["su", "-c", f"chmod 755 {remote_path}; exec {remote_path} &"],
        ["su", "-c", f"nohup {remote_path} >/dev/null 2>&1 &"],
        ["su", "-mm", "-c", f"{remote_path} &"],
        ["su", "0", "sh", "-c", f"{remote_path} &"],
        ["su", "-c", f"({remote_path} &) &"],
        ["su", "-c", f"setsid {remote_path} &"],
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
        device_rooted=device_is_rooted(config, serial),
    )


def restart_frida_server(
    config: dict,
    *,
    serial: str | None = None,
    remote_path: str = DEFAULT_FRIDA_SERVER_PATH,
    remote_paths: list[str] | None = None,
    verbose: bool = False,
) -> FridaServerStatus:
    """Kill existing servers and start each binary as root when possible."""
    base = _adb_cmd(config, serial)
    paths = remote_paths or [remote_path]
    adbd_root = try_adb_root(config, serial)
    has_su = device_has_su(config, serial)

    _kill_frida_server(base)

    primary = paths[0]
    if has_su:
        for idx, strat in enumerate(_root_frida_start_strategies(primary), start=1):
            if verbose:
                console.print(
                    f"[dim]Trying Magisk su start strategy "
                    f"{idx}/{len(_root_frida_start_strategies(primary))}…[/]"
                )
            run_cmd(base + ["shell"] + strat)
            time.sleep(1.5)
            status = frida_server_status(config, serial)
            if status.running and status.runs_as_root:
                for extra in paths[1:]:
                    _start_frida_daemon(base, extra)
                return status
            _kill_frida_server(base)

    if verbose:
        console.print("[dim]Starting frida-server via adb shell…[/]")
    for path in paths:
        _start_frida_daemon(base, path)
    time.sleep(0.8)
    return frida_server_status(config, serial)


def print_frida_attach_troubleshooting(
    config: dict,
    *,
    serial: str | None = None,
    package: str | None = None,
) -> None:
    """Explain common causes of Frida attach failures."""
    status = frida_server_status(config, serial)
    serial_flag = f" -s {serial}" if serial else ""
    pkg = package or "<package>"
    has_su = device_has_su(config, serial)

    console.print("\n[bold red]Frida attach failed[/]\n")

    if not status.running:
        console.print("[yellow]frida-server is not running.[/]")
        console.print(f"  [cyan]droidreaver device ready{serial_flag}[/]")
        return

    if status.device_rooted and not status.runs_as_root:
        console.print(
            "[yellow]Privilege is available but frida-server is NOT running as root.[/]\n"
            "This is the usual cause of [bold]unable to access process[/].\n"
        )
        console.print("[bold]Fix — restart frida-server as root:[/]")
        console.print(
            f"  [cyan]droidreaver device ready{serial_flag}[/]  "
            "[dim]or[/] [cyan]droidreaver device root-server{serial_flag}[/]\n"
        )
        if has_su:
            console.print(
                "[dim]On a Magisk phone, approve the superuser prompt for Shell/ADB.[/]\n"
                f"  [cyan]adb{serial_flag} shell su -c "
                f"'pkill frida-server; {DEFAULT_FRIDA_SERVER_PATH} -D &'[/]"
            )
        else:
            console.print(
                "[dim]On an emulator, `adb root` then start the server via adb shell:[/]\n"
                f"  [cyan]adb{serial_flag} root[/]\n"
                f"  [cyan]adb{serial_flag} shell "
                f"'pkill frida-server; {DEFAULT_FRIDA_SERVER_PATH} -D &'[/]"
            )
    elif not status.device_rooted:
        console.print(
            "[yellow]No root path detected[/] (`su` missing and `adb shell` is not uid 0).\n"
            "Frida can list apps but usually [bold]cannot attach[/] to third-party processes.\n\n"
            "[bold]Try, in order:[/]\n"
            f"  • Emulator (Google APIs / AOSP image): [cyan]adb{serial_flag} root[/] "
            f"then [cyan]droidreaver device ready{serial_flag}[/]\n"
            "  • Phone: Magisk, grant su to Shell/ADB, then [cyan]droidreaver device ready[/]\n"
            "  • Debuggable debug build of the target app (attach may work without root)\n"
        )
    else:
        console.print(
            "[yellow]Attach closed while frida-server stayed up.[/]\n"
            "Often a [bold]frida client / frida-server version mismatch[/]. "
            "Run [cyan]droidreaver update frida[/] then [cyan]ready[/] so both match.\n"
            "If versions already match, try [cyan]hook --spawn[/] or check [cyan]logcat[/].\n"
        )
        log = run_cmd(
            _adb_cmd(config, serial) + ["shell", "cat", "/data/local/tmp/frida-server.log"],
            timeout=PROBE_CMD_TIMEOUT,
        )
        text = (log.stdout or "").strip()
        if text:
            console.print("[dim]frida-server.log:[/]")
            console.print(text)
        alive = run_cmd(
            _adb_cmd(config, serial) + ["shell", "pidof", "frida-server"],
            timeout=PROBE_CMD_TIMEOUT,
        )
        console.print(
            f"[dim]frida-server pidof:[/] {(alive.stdout or alive.stderr or '').strip() or 'not running'}"
        )
