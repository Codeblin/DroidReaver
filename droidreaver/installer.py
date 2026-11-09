"""Install and update logic per tool type."""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Callable

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

from droidreaver.config import get_pinned_version, install_dir
from droidreaver.registry import Tool, get_pin_group, get_tool, resolve_install_order
from droidreaver.utils import (
    compare_versions,
    detect_cpu_arch,
    detect_platform,
    detect_system_package_manager,
    extract_release_version,
    fetch_pypi_latest_version,
    find_git,
    get_github_default_branch,
    get_installed_version,
    get_latest_github_release,
    github_headers,
    is_binary_available,
    load_pip_package_versions,
    normalize_pkg_name,
    npm_show_version,
    parse_version,
    pip_show_version,
    PROBE_CMD_TIMEOUT,
    run_cmd,
    versions_match,
    which,
)

console = Console()


class InstallError(Exception):
    """Installation failed with a user-facing message."""


class DownloadVerificationError(InstallError):
    """Downloaded artifact failed an integrity check."""


_latest_version_cache: dict[str, str | None] = {}


def _request_error_message(error: requests.RequestException) -> str:
    message = str(error)
    response = getattr(error, "response", None)
    if response is not None and response.status_code == 403 and "rate limit" in message.lower():
        message += (
            "\nGitHub API rate limit exceeded. Set GITHUB_TOKEN to a GitHub token "
            "with public_repo/read-only access, then retry."
        )
    return message


def _merged_pip_versions(config: dict | None) -> dict[str, str]:
    versions = load_pip_package_versions()
    if not config:
        return versions

    from droidreaver.versions import frida_venv_path, get_active_frida_version

    active = get_active_frida_version(config)
    if not active:
        return versions

    venv = frida_venv_path(active)
    from droidreaver.versions import _venv_python

    py = _venv_python(venv)
    if not py.is_file():
        return versions

    venv_versions = load_pip_package_versions(python=str(py), use_cache=False)
    return {**versions, **venv_versions}


def warm_version_cache(config: dict | None = None) -> None:
    """Pre-load pip package versions (one subprocess) before bulk scans."""
    _merged_pip_versions(config)


def _tool_has_install_artifacts(tool: Tool, config: dict | None) -> bool:
    if tool.binary_name and is_binary_available(tool.binary_name):
        return True
    if not config:
        return False
    inst_bin = install_dir(config) / tool.name / "bin"
    if inst_bin.is_dir() and any(inst_bin.iterdir()):
        return True
    return False


GIT_REF_MARKER = ".droidreaver-ref"


def _write_git_ref(tool_dir: Path, ref: str) -> None:
    (tool_dir / GIT_REF_MARKER).write_text(ref.strip() + "\n", encoding="utf-8")


def _normalize_git_version(ref: str) -> str:
    return extract_release_version({"tag_name": ref.strip()}) or ref.strip()


def _git_tool_version(tool_dir: Path) -> str | None:
    """Version for git/zip clones (Medusa has no --version CLI)."""
    if not tool_dir.is_dir():
        return None
    recorded = tool_dir / GIT_REF_MARKER
    if recorded.is_file():
        label = recorded.read_text(encoding="utf-8").strip()
        if label:
            return _normalize_git_version(label)
    git_exe = find_git()
    if git_exe and (tool_dir / ".git").exists():
        described = run_cmd(
            [git_exe, "-C", str(tool_dir), "describe", "--tags", "--always"],
            timeout=PROBE_CMD_TIMEOUT,
        )
        if described.returncode == 0:
            label = (described.stdout or "").strip()
            if label:
                return label
        short = run_cmd(
            [git_exe, "-C", str(tool_dir), "rev-parse", "--short", "HEAD"],
            timeout=PROBE_CMD_TIMEOUT,
        )
        if short.returncode == 0:
            label = (short.stdout or "").strip()
            if label:
                return label
    marker = tool_dir / ".droidreaver-source"
    if marker.is_file():
        kind = marker.read_text(encoding="utf-8").strip() or "clone"
        return kind
    if (tool_dir / "medusa.py").is_file() or (tool_dir / "bin").is_dir():
        return "installed"
    return None


def _resolve_git_ref(tool: Tool, version: str | None = None) -> str:
    """GitHub release tag shown as Latest, else the default branch."""
    if version:
        return version.strip()
    if not tool.github_repo:
        return "master"
    try:
        release = get_latest_github_release(tool.github_repo)
        tag = str(release.get("tag_name") or "").strip()
        if tag:
            return tag
    except requests.RequestException:
        pass
    try:
        return get_github_default_branch(tool.github_repo)
    except requests.RequestException:
        return "master"


def _git_ref_candidates(ref: str) -> list[str]:
    refs = [ref]
    if ref.startswith("v") and len(ref) > 1:
        refs.append(ref[1:])
    elif ref and ref[0].isdigit():
        refs.insert(0, f"v{ref}")
    seen: set[str] = set()
    out: list[str] = []
    for item in refs:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _git_fetch_and_checkout(git_exe: str, inst: Path, ref: str) -> bool:
    """Move a shallow clone onto a tag/branch (git pull does not do this)."""
    specs = []
    for candidate in _git_ref_candidates(ref):
        specs.extend(
            (
                candidate,
                f"refs/tags/{candidate}",
                f"refs/heads/{candidate}",
            )
        )
    for spec in specs:
        fetched = run_cmd(
            [git_exe, "-C", str(inst), "fetch", "--depth", "1", "origin", spec]
        )
        if fetched.returncode != 0:
            continue
        checked = run_cmd(
            [git_exe, "-C", str(inst), "checkout", "-f", "--detach", "FETCH_HEAD"]
        )
        if checked.returncode == 0:
            return True
    return False


def get_tool_version(tool: Tool, config: dict | None = None) -> str | None:
    """Get currently installed version for a tool."""
    if tool.install_method == "manual":
        return None

    if tool.install_method == "pip" and tool.pip_package:
        ver = _merged_pip_versions(config).get(normalize_pkg_name(tool.pip_package))
        if ver:
            return ver

    if tool.install_method == "npm" and tool.npm_package:
        ver = npm_show_version(tool.npm_package)
        if ver:
            return ver

    if tool.install_method == "git" and config is not None:
        git_ver = _git_tool_version(install_dir(config) / tool.name)
        if git_ver:
            return git_ver

    if tool.version_cmd or tool.binary_name:
        if not _tool_has_install_artifacts(tool, config):
            return None
        return get_installed_version(tool.version_cmd, tool.binary_name)

    return None


def installation_satisfied(
    tool: Tool,
    config: dict,
    target_version: str | None = None,
) -> tuple[bool, str | None]:
    """Return whether an existing install already satisfies this request.

    An unversioned request is satisfied by either a detectable version or
    managed/system install artifacts. A versioned request is only satisfied
    when the detected version matches, so pins still converge correctly.
    """
    installed = get_tool_version(tool, config)
    has_artifacts = _tool_has_install_artifacts(tool, config)

    if target_version:
        if installed and versions_match(installed, target_version):
            return True, installed
        return False, installed

    return bool(installed or has_artifacts), installed


def get_latest_version(tool: Tool, *, fetch: bool = True) -> str | None:
    """Fetch latest available version."""
    if not fetch:
        return None

    if tool.name in _latest_version_cache:
        return _latest_version_cache[tool.name]

    latest: str | None = None
    if tool.install_method == "manual":
        latest = None
    elif tool.install_method == "pip" and tool.pip_package:
        latest = fetch_pypi_latest_version(tool.pip_package)
    elif tool.github_repo:
        try:
            release = get_latest_github_release(tool.github_repo)
            latest = extract_release_version(release)
        except requests.RequestException:
            latest = None
    elif tool.install_method == "npm" and tool.npm_package:
        from droidreaver.utils import PIP_CMD_TIMEOUT

        result = run_cmd(f"npm view {tool.npm_package} version", timeout=PIP_CMD_TIMEOUT)
        if result.returncode == 0:
            latest = (result.stdout or "").strip() or None

    _latest_version_cache[tool.name] = latest
    return latest


def _pip_install(package: str, version: str | None, force: bool) -> None:
    spec = f"{package}=={version}" if version else package
    cmd = [sys.executable, "-m", "pip", "install", spec]
    if force:
        cmd.append("--force-reinstall")
    else:
        cmd.append("--upgrade")
    result = run_cmd(cmd)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "Unknown pip error").strip()
        raise InstallError(f"pip install failed for {package}:\n{err}")


def _pip_install_companion(package: str, force: bool) -> None:
    """Install/upgrade a pip package without pinning to frida's version number."""
    cmd = [sys.executable, "-m", "pip", "install", package, "--upgrade"]
    if force:
        cmd.append("--force-reinstall")
    result = run_cmd(cmd)
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "Unknown pip error").strip()
        raise InstallError(f"pip install failed for {package}:\n{err}")


def _npm_install(package: str, version: str | None) -> None:
    spec = f"{package}@{version}" if version else package
    result = run_cmd(f"npm install -g {spec}")
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "Unknown npm error").strip()
        raise InstallError(f"npm install failed for {package}:\n{err}")


def _apt_install(package: str) -> None:
    if not which("apt-get") and not which("apt"):
        raise InstallError("apt not found. Install manually or use a Debian/Ubuntu system.")
    try:
        is_root = os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        is_root = False
    sudo = "" if is_root else "sudo "
    result = run_cmd(f"{sudo}apt-get update && {sudo}apt-get install -y {package}")
    if result.returncode != 0:
        raise InstallError(f"apt install failed for {package}")


def _brew_install(package: str) -> None:
    if not which("brew"):
        raise InstallError("Homebrew not found.")
    result = run_cmd(f"brew install {package}")
    if result.returncode != 0:
        raise InstallError(f"brew install failed for {package}")


def _write_cli_wrapper(wrapper: Path, argv_prefix: list[str]) -> None:
    """Write a small launcher script into install_dir/.../bin/."""
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    if detect_platform() == "windows":
        if not wrapper.suffix:
            wrapper = wrapper.with_suffix(".bat")
        parts = " ".join(f'"{p}"' if " " in p else p for p in argv_prefix)
        wrapper.write_text(f"@echo off\n{parts} %*\n", encoding="utf-8")
    else:
        parts = " ".join(f'"{p}"' if " " in p else p for p in argv_prefix)
        wrapper.write_text(f"#!/bin/sh\nexec {parts} \"$@\"\n", encoding="utf-8")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)


def _write_medusa_launcher(inst: Path, bin_name: str) -> None:
    """Launcher that patches readline on Windows before starting medusa.py."""
    launcher = inst / "bin" / "medusa_launcher.py"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_text(
        '''\
"""DroidReaver Medusa launcher."""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if sys.platform == "win32":
    from droidreaver.shims.readline_win import install_readline_shim

    install_readline_shim()

sys.path.insert(0, str(ROOT))
runpy.run_path(str(ROOT / "medusa.py"), run_name="__main__")
''',
        encoding="utf-8",
    )
    wrapper = inst / "bin" / bin_name
    _write_cli_wrapper(wrapper, [sys.executable, str(launcher)])


def _finalize_python_repo_install(tool: Tool, inst: Path) -> None:
    """Install requirements and write bin/ wrapper for a cloned or zipped repo."""
    requirements = inst / "requirements.txt"
    if requirements.is_file():
        result = run_cmd([sys.executable, "-m", "pip", "install", "-r", str(requirements)])
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "pip failed").strip()
            raise InstallError(f"Failed to install {tool.name} requirements:\n{err}")

    entry = inst / f"{tool.name}.py"
    if not entry.is_file():
        candidates = list(inst.glob("*.py"))
        entry = next((p for p in candidates if p.stem.lower() == tool.name), None)
        if not entry and candidates:
            entry = candidates[0]
    if not entry or not entry.is_file():
        raise InstallError(
            f"Could not find entry script in {inst}. "
            f"Source fetch ok — check repo layout manually."
        )

    bin_name = tool.binary_name or tool.name
    if tool.name == "medusa":
        _write_medusa_launcher(inst, bin_name)
    else:
        wrapper = inst / "bin" / bin_name
        _write_cli_wrapper(wrapper, [sys.executable, str(entry)])
    console.print(f"[green]✓[/] {tool.display_name} installed at {inst}")
    console.print(f"  Run: [cyan]droidreaver {bin_name} --help[/]")
    if tool.name == "medusa" and detect_platform() == "windows":
        console.print(
            "[yellow]Note:[/] Medusa upstream lists limited functionality on Windows. "
            "Linux/macOS + rooted device is recommended."
        )


def _download_github_repo_zip(tool: Tool, inst: Path, ref: str | None = None) -> None:
    """Fetch a GitHub tag or branch as a zip (no git required)."""
    if not tool.github_repo:
        raise InstallError(f"No git repo defined for {tool.name}")
    target = ref or get_github_default_branch(tool.github_repo)
    urls: list[str] = []
    for candidate in _git_ref_candidates(target):
        urls.append(f"https://codeload.github.com/{tool.github_repo}/zip/refs/tags/{candidate}")
        urls.append(f"https://codeload.github.com/{tool.github_repo}/zip/refs/heads/{candidate}")
    last_error = "download failed"
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "source.zip"
        downloaded = False
        for url in urls:
            try:
                _download_file(url, zip_path)
                downloaded = True
                break
            except requests.RequestException as e:
                last_error = str(e)
                continue
        if not downloaded:
            raise InstallError(
                f"Could not download {tool.display_name} source for {target}: {last_error}"
            )
        extract_root = tmp_path / "extract"
        extract_root.mkdir()
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_root)
        children = [p for p in extract_root.iterdir() if p.is_dir()]
        if len(children) != 1:
            raise InstallError(
                f"Unexpected GitHub zip layout for {tool.name} "
                f"({len(children)} top-level folders)."
            )
        if inst.exists():
            shutil.rmtree(inst)
        shutil.move(str(children[0]), str(inst))
    (inst / ".droidreaver-source").write_text("zip\n", encoding="utf-8")
    _write_git_ref(inst, target)


def _clone_github_ref(git_exe: str, tool: Tool, inst: Path, ref: str) -> None:
    repo_url = f"https://github.com/{tool.github_repo}.git"
    last_err = "git clone failed"
    for candidate in _git_ref_candidates(ref):
        if inst.exists():
            shutil.rmtree(inst)
        inst.parent.mkdir(parents=True, exist_ok=True)
        result = run_cmd(
            [git_exe, "clone", "--depth", "1", "--branch", candidate, repo_url, str(inst)]
        )
        if result.returncode == 0:
            (inst / ".droidreaver-source").write_text("git\n", encoding="utf-8")
            _write_git_ref(inst, candidate)
            return
        last_err = (result.stderr or result.stdout or "git clone failed").strip()
    raise InstallError(f"git clone failed for {tool.name} ({ref}):\n{last_err}")


def _install_git_clone(
    tool: Tool,
    cfg: dict,
    *,
    force: bool = False,
    refresh: bool = False,
    version: str | None = None,
) -> None:
    """Clone or download a GitHub repo at the Latest release tag (or default branch)."""
    if not tool.github_repo:
        raise InstallError(f"No git repo defined for {tool.name}")

    inst = install_dir(cfg) / tool.name
    git_exe = find_git()
    bin_name = tool.binary_name or tool.name
    wrapper_sh = inst / "bin" / bin_name
    wrapper_bat = wrapper_sh.with_suffix(".bat")
    already_installed = (
        wrapper_sh.is_file()
        or wrapper_bat.is_file()
        or (inst / ".git").is_dir()
        or (inst / ".droidreaver-source").is_file()
    )
    ref = _resolve_git_ref(tool, version)

    if (inst / ".git").is_dir() and git_exe and not force:
        if _git_fetch_and_checkout(git_exe, inst, ref):
            _write_git_ref(inst, ref)
            _finalize_python_repo_install(tool, inst)
            return
        if not refresh:
            console.print(
                f"[yellow]Could not fetch {ref}; continuing with existing {tool.display_name} clone[/]"
            )
            _finalize_python_repo_install(tool, inst)
            return
        console.print(f"[yellow]Fetch of {ref} failed — recloning {tool.display_name}[/]")

    if already_installed and not force and not refresh:
        if tool.name == "medusa":
            _write_medusa_launcher(inst, bin_name)
        console.print(f"[dim]{tool.display_name} already installed at {inst}[/]")
        return

    if inst.exists() and (force or refresh):
        shutil.rmtree(inst)

    if git_exe:
        _clone_github_ref(git_exe, tool, inst, ref)
    else:
        console.print(
            "[yellow]git not found — downloading GitHub source zip instead.[/]"
        )
        console.print(
            "[dim]For easier updates, install Git: "
            "https://git-scm.com/download/win[/]"
        )
        inst.parent.mkdir(parents=True, exist_ok=True)
        _download_github_repo_zip(tool, inst, ref=ref)

    _finalize_python_repo_install(tool, inst)


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_sha256(path: Path, expected: str | None) -> str | None:
    actual = _sha256_file(path)
    if not expected:
        return actual
    if actual.lower() != expected.lower():
        raise DownloadVerificationError(
            f"Checksum mismatch for {path.name}:\n"
            f"  expected sha256: {expected.lower()}\n"
            f"  actual sha256:   {actual.lower()}\n"
            "The archive was not extracted. Retry the download or update the registry "
            "only after confirming the upstream release changed."
        )
    return actual


def _expected_download_sha256(tool: Tool, platform_key: str) -> str | None:
    expected = tool.download_sha256
    if isinstance(expected, dict):
        return expected.get(platform_key)
    return expected


def _install_metadata_path(tool_dir: Path) -> Path:
    return tool_dir / ".droidreaver-install.json"


def _write_install_metadata(
    tool_dir: Path,
    *,
    source_url: str,
    sha256_digest: str,
    verified: bool,
    version: str | None = None,
) -> None:
    metadata = {
        "source_url": source_url,
        "sha256": sha256_digest,
        "verified": verified,
    }
    if version:
        metadata["version"] = version
    _install_metadata_path(tool_dir).write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _download_file(
    url: str,
    dest: Path,
    progress: Progress | None = None,
    *,
    expected_sha256: str | None = None,
) -> str | None:
    resp = requests.get(url, headers=github_headers(), stream=True, timeout=120)
    resp.raise_for_status()
    total = int(resp.headers.get("content-length", 0))
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(f"{dest.name}.part")

    task = None
    if progress:
        task = progress.add_task(f"Downloading {dest.name}", total=total or None)

    written = 0
    with partial.open("wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                written += len(chunk)
                if progress and task is not None:
                    progress.update(task, advance=len(chunk))

    if total and written < total:
        partial.unlink(missing_ok=True)
        raise DownloadVerificationError(
            f"Incomplete download for {dest.name}: expected {total} bytes, got {written}."
        )

    try:
        digest = _verify_sha256(partial, expected_sha256)
    except DownloadVerificationError:
        partial.unlink(missing_ok=True)
        raise
    partial.replace(dest)
    return digest


def _os_tokens(plat: str) -> tuple[str, ...]:
    if plat == "windows":
        return ("windows", "win64", "win32", "_win")
    if plat == "macos":
        return ("darwin", "macos", "osx", "mac")
    return ("linux", "ubuntu")


def _arch_tokens(arch: str) -> tuple[str, ...]:
    if arch == "x64":
        return ("x64", "amd64", "x86_64", "win64")
    if arch == "arm64":
        return ("arm64", "aarch64")
    if arch == "x86":
        return ("x86", "i386", "i686", "win32", "x32", "386")
    return (arch,)


def _arch_conflicts(arch: str, name: str) -> bool:
    """True when the asset is clearly built for a different CPU."""
    if arch == "x64" and any(tok in name for tok in ("arm64", "aarch64", "armv", "_x32", "i386", "386")):
        return True
    if arch == "arm64" and any(tok in name for tok in ("x64", "amd64", "x86_64", "_x32", "i386")):
        return True
    if arch == "x86" and any(tok in name for tok in ("arm64", "aarch64", "x64", "amd64", "x86_64")):
        return True
    return False


def _asset_score(asset_name: str, plat: str, arch: str) -> int:
    n = asset_name.lower()
    archive = n.endswith((".zip", ".tar.gz", ".tgz", ".jar"))
    if not archive:
        return -1
    if not any(tok in n for tok in _os_tokens(plat)):
        return -1
    if _arch_conflicts(arch, n):
        return -1
    if any(tok in n for tok in _arch_tokens(arch)):
        return 3
    return 1


def _find_asset(release: dict, pattern: str | None, version: str) -> dict | None:
    assets = release.get("assets", [])
    if pattern:
        name = pattern.replace("{version}", version.lstrip("v"))
        for asset in assets:
            if asset["name"] == name or name in asset["name"]:
                return asset
    plat = detect_platform()
    arch = detect_cpu_arch()
    ranked: list[tuple[int, dict]] = []
    for asset in assets:
        score = _asset_score(str(asset.get("name", "")), plat, arch)
        if score > 0:
            ranked.append((score, asset))
    if ranked:
        ranked.sort(key=lambda item: item[0], reverse=True)
        return ranked[0][1]
    for asset in assets:
        n = str(asset.get("name", "")).lower()
        if n.endswith(".zip") or n.endswith(".tar.gz") or n.endswith(".jar"):
            return asset
    return None


def _find_checksum_asset(release: dict, artifact_name: str) -> dict | None:
    """Find a checksum asset that likely covers artifact_name."""
    assets = release.get("assets", [])
    exact_names = {
        f"{artifact_name}.sha256",
        f"{artifact_name}.sha256sum",
        f"{artifact_name}.sha256.txt",
    }
    for asset in assets:
        if asset.get("name") in exact_names:
            return asset

    checksum_tokens = ("sha256", "checksum", "checksums", "shasums")
    text_suffixes = (".txt", ".sha256", ".sha256sum", ".checksums", "SHA256SUMS")
    for asset in assets:
        name = str(asset.get("name", ""))
        lower = name.lower()
        if any(token in lower for token in checksum_tokens):
            return asset
        if name.endswith(text_suffixes):
            return asset
    return None


def _parse_checksum_text(text: str, artifact_name: str) -> str | None:
    """Parse common SHA-256 checksum file formats."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        normalized = line.replace("*", " ")
        parts = normalized.split()
        hashes = [p for p in parts if len(p) == 64 and all(c in "0123456789abcdefABCDEF" for c in p)]
        if not hashes:
            continue
        if artifact_name in parts or any(part.endswith("/" + artifact_name) for part in parts):
            return hashes[0]
        if len(parts) == 1:
            return hashes[0]
    return None


def _fetch_release_checksum(release: dict, artifact_name: str) -> str | None:
    checksum_asset = _find_checksum_asset(release, artifact_name)
    if not checksum_asset:
        return None
    url = checksum_asset.get("browser_download_url")
    if not url:
        return None
    try:
        resp = requests.get(url, headers=github_headers(), timeout=30)
        resp.raise_for_status()
    except requests.RequestException:
        return None
    return _parse_checksum_text(resp.text, artifact_name)


def _extract_archive(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()

    def safe_path(member_name: str) -> Path:
        target = (dest / member_name).resolve()
        if target != dest_root and dest_root not in target.parents:
            raise InstallError(
                f"Refusing to extract unsafe archive member outside destination: {member_name}"
            )
        return target

    name = archive.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive, "r") as zf:
            for member in zf.infolist():
                safe_path(member.filename)
            zf.extractall(dest)
    elif name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                safe_path(member.name)
            tf.extractall(dest)
    else:
        shutil.copy(archive, dest / archive.name)


def _platform_download_key() -> str:
    """Map the host platform to common archive URL tokens (windows/linux/darwin)."""
    plat = detect_platform()
    return {"windows": "windows", "linux": "linux", "macos": "darwin"}.get(plat, plat)


def _install_direct(
    tool: Tool,
    cfg: dict,
    progress: Progress | None = None,
    *,
    expected_sha256: str | None = None,
) -> None:
    """Install a tool from a direct archive URL (e.g. Google platform-tools)."""
    if not tool.download_url_template:
        raise InstallError(f"No download URL defined for {tool.name}")

    platform_key = _platform_download_key()
    url = tool.download_url_template.format(platform=platform_key)
    expected_sha256 = expected_sha256 or _expected_download_sha256(tool, platform_key)
    inst = install_dir(cfg)
    tool_dir = inst / tool.name
    tool_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / Path(url).name
        try:
            digest = _download_file(
                url,
                archive,
                progress,
                expected_sha256=expected_sha256,
            )
        except requests.RequestException as e:
            raise InstallError(f"Failed to download {tool.display_name} from {url}: {e}") from e
        extract_to = tool_dir / "extracted"
        if extract_to.exists():
            shutil.rmtree(extract_to)
        _extract_archive(archive, extract_to)
        _link_binaries(tool, extract_to, tool_dir)
        if digest:
            _write_install_metadata(
                tool_dir,
                source_url=url,
                sha256_digest=digest,
                verified=bool(expected_sha256),
            )

    console.print(f"[green]✓[/] {tool.display_name} installed at {tool_dir}")


def _install_github_release(
    tool: Tool,
    version: str | None,
    cfg: dict,
    progress: Progress | None = None,
    *,
    expected_sha256: str | None = None,
) -> None:
    if not tool.github_repo:
        raise InstallError(f"No GitHub repo defined for {tool.name}")

    if version:
        url = f"https://api.github.com/repos/{tool.github_repo}/releases/tags/v{version.lstrip('v')}"
        try:
            release = requests.get(url, headers=github_headers(), timeout=30).json()
            if "message" in release:
                url = f"https://api.github.com/repos/{tool.github_repo}/releases/tags/{version}"
                release = requests.get(url, headers=github_headers(), timeout=30).json()
        except requests.RequestException as e:
            raise InstallError(
                f"Failed to fetch release {version} for {tool.name}: {_request_error_message(e)}"
            ) from e
        ver = version.lstrip("v")
    else:
        try:
            release = get_latest_github_release(tool.github_repo)
        except requests.RequestException as e:
            raise InstallError(
                f"Could not fetch latest release for {tool.display_name} "
                f"(github.com/{tool.github_repo}): {_request_error_message(e)}"
            ) from e
        ver = extract_release_version(release)

    asset = _find_asset(release, tool.github_asset_pattern, ver)
    inst = install_dir(cfg)
    tool_dir = inst / tool.name
    tool_dir.mkdir(parents=True, exist_ok=True)

    if asset:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / asset["name"]
            checksum = expected_sha256 or _fetch_release_checksum(release, asset["name"])
            digest = _download_file(
                asset["browser_download_url"],
                archive,
                progress,
                expected_sha256=checksum,
            )
            extract_to = tool_dir / "extracted"
            if extract_to.exists():
                shutil.rmtree(extract_to)
            _extract_archive(archive, extract_to)
            _link_binaries(tool, extract_to, tool_dir)
            if digest:
                _write_install_metadata(
                    tool_dir,
                    source_url=asset["browser_download_url"],
                    sha256_digest=digest,
                    verified=bool(checksum),
                    version=ver,
                )
    elif tool.name == "medusa":
        raise InstallError(
            "Medusa uses git install — run: droidreaver install medusa"
        )
    else:
        raise InstallError(f"No suitable release asset found for {tool.name} v{ver}")


def _find_executable_in_tree(root: Path, name: str) -> Path | None:
    """Find an executable named `name` (with or without .exe) under root.

    Prefers an exact stem match so we don't grab e.g. AdbWinApi.dll for 'adb'.
    """
    candidates = [
        p
        for p in (*root.rglob(name), *root.rglob(f"{name}.exe"))
        if p.is_file()
    ]
    if not candidates:
        return None
    exact = [c for c in candidates if c.stem.lower() == name.lower()]
    return exact[0] if exact else candidates[0]


def _wrap_in_place(bin_dir: Path, wrapper_name: str, target: Path) -> None:
    """Write a launcher in bin_dir that runs `target` from its own directory.

    Running in place keeps sibling files (e.g. AdbWinApi.dll, scrcpy DLLs) next
    to the executable, which copying a lone binary would break.
    """
    if detect_platform() != "windows":
        try:
            target.chmod(target.stat().st_mode | stat.S_IEXEC)
        except OSError:
            pass
    _write_cli_wrapper(bin_dir / wrapper_name, [str(target)])


def _link_binaries(tool: Tool, extract_root: Path, tool_dir: Path) -> None:
    """Create wrapper scripts in tool_dir/bin for discovered binaries."""
    bin_dir = tool_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    if not tool.binary_name:
        return

    candidates = [c for c in extract_root.rglob(tool.binary_name + "*") if c.is_file()]
    if tool.binary_name.endswith(".jar") or any(c.suffix == ".jar" for c in candidates):
        jar = next((c for c in candidates if c.suffix == ".jar"), None)
        if not jar:
            jars = list(extract_root.rglob("*.jar"))
            jar = jars[0] if jars else None
        if jar:
            dest_jar = tool_dir / jar.name
            shutil.copy(jar, dest_jar)
            wrapper = bin_dir / tool.binary_name
            if detect_platform() == "windows":
                wrapper = bin_dir / f"{tool.binary_name}.bat"
                wrapper.write_text(
                    f'@echo off\njava -jar "{dest_jar}" %*\n',
                    encoding="utf-8",
                )
            else:
                wrapper.write_text(
                    f'#!/bin/sh\nexec java -jar "{dest_jar}" "$@"\n',
                    encoding="utf-8",
                )
                wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        return

    # Native binary: wrap it in place so bundled libraries stay alongside it.
    main = _find_executable_in_tree(extract_root, tool.binary_name)
    if main:
        _wrap_in_place(bin_dir, tool.binary_name, main)

    for alias in tool.cli_aliases:
        target = _find_executable_in_tree(extract_root, alias)
        if target:
            _wrap_in_place(bin_dir, alias, target)


def _install_system(tool: Tool, cfg: dict, progress: Progress | None = None) -> None:
    pm = detect_system_package_manager()
    pkg = tool.brew_package if pm == "brew" else tool.apt_package
    if not pkg:
        pkg = tool.apt_package or tool.brew_package
    if pm == "brew" and pkg:
        _brew_install(pkg)
        return
    if pm == "apt" and pkg:
        _apt_install(pkg)
        return

    # No usable package manager (e.g. Windows): fall back to a GitHub release.
    if tool.github_repo:
        console.print(
            f"[yellow]No system package manager for {tool.display_name}; "
            "trying a GitHub release instead.[/]"
        )
        _install_github_release(tool, None, cfg, progress)
        return

    hint = f"Install '{pkg}' with your OS package manager." if pkg else ""
    if tool.manual_url:
        hint += f" Or download: {tool.manual_url}"
    raise InstallError(
        f"{tool.display_name} needs a system package manager (apt/brew) which "
        f"isn't available here. {hint}".strip()
    )


def install_tool(
    tool_name: str,
    cfg: dict,
    *,
    version: str | None = None,
    force: bool = False,
    progress: Progress | None = None,
    expected_sha256: str | None = None,
) -> None:
    tool = get_tool(tool_name)

    if tool.install_method == "manual":
        url = tool.manual_url or "project website"
        raise InstallError(
            f"{tool.display_name} is a manual install (GUI/commercial or OS-specific).\n"
            f"  Download: {url}\n"
            f"  {tool.notes or ''}\n"
            f"  Hide it from reports: add '{tool.name}' to [ignored] tools in droidreaver.toml"
        )

    pinned = get_pinned_version(cfg, tool_name)
    target_version = version or pinned

    if tool.install_method == "pip" and tool.pip_package:
        if version and tool.name in {"frida-tools", "objection", "r2frida"}:
            # These packages do not share frida's version number on PyPI.
            _pip_install_companion(tool.pip_package, force)
        else:
            _pip_install(tool.pip_package, target_version, force)
        return

    if tool.install_method == "npm" and tool.npm_package:
        if not which("npm"):
            raise InstallError("Node.js/npm not found. Install Node.js first.")
        _npm_install(tool.npm_package, target_version)
        return

    if tool.install_method == "github_release":
        _install_github_release(
            tool,
            target_version,
            cfg,
            progress,
            expected_sha256=expected_sha256,
        )
        return

    if tool.install_method == "direct":
        _install_direct(tool, cfg, progress, expected_sha256=expected_sha256)
        return

    if tool.install_method == "git":
        _install_git_clone(tool, cfg, force=force, version=target_version)
        return

    if tool.install_method in ("apt", "brew"):
        _install_system(tool, cfg, progress)
        return

    raise InstallError(f"Unsupported install method '{tool.install_method}' for {tool.name}")


def _rmtree(path: Path) -> None:
    if not path.exists():
        return

    def _retry(func, p, _exc) -> None:
        os.chmod(p, stat.S_IWRITE)
        func(p)

    shutil.rmtree(path, onerror=_retry)


def _managed_pythons(cfg: dict) -> list[str]:
    from droidreaver.versions import frida_venv_path, get_active_frida_version

    pythons: list[str] = []
    ver = get_active_frida_version(cfg)
    if ver:
        venv = frida_venv_path(ver)
        for rel in ("Scripts/python.exe", "bin/python"):
            candidate = venv / rel
            if candidate.is_file():
                pythons.append(str(candidate))
                break
    pythons.append(sys.executable)
    # Preserve order, drop dupes
    seen: set[str] = set()
    unique: list[str] = []
    for py in pythons:
        if py not in seen:
            seen.add(py)
            unique.append(py)
    return unique


@dataclass
class UninstallResult:
    tool: str
    removed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def uninstall_tool(
    tool_name: str,
    cfg: dict,
    *,
    remove_venv: bool = True,
) -> UninstallResult:
    """Remove a DroidReaver-managed install. Does not apt/brew uninstall."""
    tool = get_tool(tool_name)
    result = UninstallResult(tool=tool.name)
    tool_dir = install_dir(cfg) / tool.name
    if tool_dir.exists():
        _rmtree(tool_dir)
        result.removed.append(str(tool_dir))

    if tool.name == "frida" and remove_venv:
        from droidreaver.versions import frida_venv_path, get_active_frida_version

        ver = get_active_frida_version(cfg)
        if ver:
            venv = frida_venv_path(ver)
            if venv.exists():
                _rmtree(venv)
                result.removed.append(str(venv))
            result.notes.append(
                f"Frida pin/active in config is unchanged ({ver}). "
                "Clear with: droidreaver unpin frida"
            )

    if tool.install_method == "pip" and tool.pip_package and tool.name != "frida":
        from droidreaver.utils import run_cmd

        for py in _managed_pythons(cfg):
            cmd = [py, "-m", "pip", "uninstall", "-y", tool.pip_package]
            pip_result = run_cmd(cmd)
            if pip_result.returncode == 0:
                result.notes.append(f"pip uninstall {tool.pip_package} ({py})")

    if tool.install_method in ("apt", "brew"):
        result.notes.append(
            f"System package not removed. Uninstall with apt/brew if you installed "
            f"{tool.display_name} that way."
        )
    if tool.install_method == "manual":
        result.notes.append(
            f"{tool.display_name} is a manual install — nothing for DroidReaver to delete."
        )
    if tool.install_method == "npm" and tool.npm_package:
        result.notes.append(
            f"Global npm package not removed. Run: npm uninstall -g {tool.npm_package}"
        )

    if not result.removed and not result.notes:
        result.notes.append(
            f"No managed files found for {tool.display_name} under {install_dir(cfg)}."
        )
    return result


def check_pin_group_conflict(
    tool_name: str,
    target_version: str,
    cfg: dict,
) -> list[str]:
    """Return warning messages if target_version breaks pin group sync."""
    warnings: list[str] = []
    group = get_pin_group(tool_name)
    if len(group) <= 1:
        return warnings

    for member in group:
        if member == tool_name:
            continue
        member_tool = get_tool(member)
        installed = get_tool_version(member_tool)
        pinned = get_pinned_version(cfg, member)
        expected = pinned or installed
        if expected and not force_version_match(target_version, expected):
            warnings.append(
                f"{member} is at {expected}, would conflict with {tool_name}@{target_version}"
            )
    return warnings


def force_version_match(a: str, b: str) -> bool:
    from droidreaver.utils import versions_match

    return versions_match(a, b)


def install_tools(
    tool_names: list[str],
    cfg: dict,
    *,
    version: str | None = None,
    force: bool = False,
    on_progress: Callable[[str], None] | None = None,
    continue_on_error: bool = False,
) -> list[tuple[str, str]]:
    """Install tools in dependency order.

    Returns a list of (tool_name, error) for failures. When ``continue_on_error``
    is False the first failure (other than under ``force``) is raised.
    """
    failures: list[tuple[str, str]] = []
    order = resolve_install_order(tool_names)

    with Progress(
        SpinnerColumn(style="bright_green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28, style="#3a6652", complete_style="#00ff41"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Preparing install…[/]", total=len(order))
        for name in order:
            tool = get_tool(name)
            if tool.install_method == "manual":
                console.print(f"[dim]Skipping manual tool: {tool.display_name}[/]")
                progress.advance(task)
                continue

            pinned = get_pinned_version(cfg, name)
            from droidreaver.versions import FRIDA_EXACT

            in_group = name in get_pin_group(tool_names[0])
            if name in FRIDA_EXACT and in_group:
                ver = version if version else pinned
            elif name in FRIDA_EXACT:
                ver = version or pinned
            else:
                ver = version if not in_group else None

            if not force:
                satisfied, installed = installation_satisfied(tool, cfg, ver)
                if satisfied:
                    detail = f" ({installed})" if installed else ""
                    console.print(
                        f"[dim]↷ {tool.display_name} already installed{detail} — skipped[/]"
                    )
                    progress.advance(task)
                    continue

            if not force and ver:
                conflicts = check_pin_group_conflict(name, ver, cfg)
                if conflicts:
                    raise InstallError(
                        "Pin group version conflict detected:\n"
                        + "\n".join(f"  • {w}" for w in conflicts)
                        + "\n\nUse --force to override or pin the group with: "
                        f"droidreaver pin {name} {ver}"
                    )

            desc = f"[cyan]Installing[/] [bold]{tool.display_name}[/]" + (f" [yellow]@{ver}[/]" if ver else "")
            progress.update(task, description=desc)
            if on_progress:
                on_progress(name)

            try:
                install_tool(name, cfg, version=ver, force=force, progress=progress)
                console.print(f"[green]✓[/] Installed {tool.display_name}")
            except InstallError as e:
                console.print(f"[red]✗[/] {tool.display_name}: {e}")
                failures.append((name, str(e)))
                if not force and not continue_on_error:
                    raise
            except Exception as e:  # noqa: BLE001 - keep one bad tool from aborting the run
                console.print(f"[red]✗[/] {tool.display_name}: unexpected error: {e}")
                failures.append((name, str(e)))
                if not force and not continue_on_error:
                    raise InstallError(f"{tool.display_name}: {e}") from e
            progress.advance(task)

    return failures


def update_tool(
    tool_name: str,
    cfg: dict,
    *,
    force: bool = False,
) -> tuple[str | None, str | None]:
    """Update tool; returns (old_version, new_version)."""
    tool = get_tool(tool_name)
    old = get_tool_version(tool, cfg)
    if tool.install_method == "git":
        _install_git_clone(tool, cfg, force=force, refresh=True, version=None)
        new = get_tool_version(tool, cfg)
        return old, new
    latest = get_latest_version(tool)
    if not latest:
        raise InstallError(f"Could not determine latest version for {tool.name}")
    if old and compare_versions(old, latest) == 0:
        return old, old
    install_tool(tool_name, cfg, version=latest, force=force)
    new = get_tool_version(tool, cfg) or latest
    return old, new


def sync_pin_group(
    tool_name: str,
    cfg: dict,
    *,
    target_frida: str | None = None,
    force: bool = False,
) -> list[tuple[str, str | None, str | None]]:
    """Align the frida pin group to a frida *runtime* version.

    Only ``frida`` is installed at the exact target version. Companion pip tools
    (frida-tools, objection, r2frida) are upgraded so pip resolves versions
    compatible with that runtime — they do NOT use the same version number.
    """
    from droidreaver.versions import (
        FRIDA_COMPANIONS,
        FRIDA_COMPANIONS_OPTIONAL,
        FRIDA_EXACT,
        FRIDA_OPTIONAL,
        PinGroupSyncError,
        SyncStep,
        resolve_frida_target,
    )

    group = get_pin_group(tool_name)
    target = resolve_frida_target(cfg, target_frida)
    steps: list[SyncStep] = []
    results: list[tuple[str, str | None, str | None]] = []

    def record(name: str, old: str | None, new: str | None, action: str, detail: str) -> None:
        steps.append(SyncStep(name, action, detail, old, new))
        results.append((name, old, new))

    order = resolve_install_order(list(group))

    for name in order:
        tool = get_tool(name)
        if tool.install_method == "manual":
            continue

        old = get_tool_version(tool)

        if name in FRIDA_EXACT:
            if not force and old and versions_match(old, target):
                record(name, old, old, "skip", f"already at frida runtime {target}")
                continue
            try:
                _pip_install(tool.pip_package or "frida", target, force)
                new = get_tool_version(tool) or target
                record(name, old, new, "install", f"frida runtime → {new}")
            except InstallError as e:
                steps.append(SyncStep(name, "failed", str(e), old, None))
                raise PinGroupSyncError(
                    f"Could not install frida runtime {target}.",
                    target_frida=target,
                    steps=steps,
                    cause=str(e),
                ) from e
            continue

        if name in FRIDA_COMPANIONS or name in FRIDA_COMPANIONS_OPTIONAL:
            try:
                _pip_install_companion(tool.pip_package or name, force)
                new = get_tool_version(tool)
                record(
                    name,
                    old,
                    new,
                    "install",
                    f"upgraded compatible release → {new or '?'} (frida runtime {target})",
                )
            except InstallError as e:
                if name in FRIDA_COMPANIONS_OPTIONAL:
                    record(name, old, old, "skip", f"optional, skipped: {e}")
                    continue
                steps.append(SyncStep(name, "failed", str(e), old, None))
                raise PinGroupSyncError(
                    f"Frida runtime is {target}, but {name} failed to install.",
                    target_frida=target,
                    steps=steps,
                    cause=str(e),
                ) from e
            continue

        if name in FRIDA_OPTIONAL:
            try:
                install_tool(name, cfg, version=None, force=force)
                new = get_tool_version(tool)
                record(name, old, new, "install", f"optional tool → {new or 'installed'}")
            except InstallError as e:
                record(name, old, old, "skip", f"optional, skipped: {e}")

    return results


def update_pin_group(
    tool_name: str,
    cfg: dict,
    *,
    force: bool = False,
) -> list[tuple[str, str | None, str | None]]:
    """Bump the frida pin group to the latest PyPI runtime (isolated venv)."""
    from droidreaver.versions import (
        PinGroupSyncError,
        get_active_frida_version,
        print_sync_error,
        resolve_frida_target,
        use_frida_version,
    )

    old = get_active_frida_version(cfg)
    target = resolve_frida_target(cfg, "latest")
    try:
        use_frida_version(cfg, target, force=force)
    except PinGroupSyncError as e:
        print_sync_error(e)
        raise InstallError(str(e)) from e
    return [("frida", old, target)]


def get_tool_status(tool: Tool, cfg: dict, *, fetch_latest: bool = True) -> dict:
    """Return status dict for a tool."""
    installed = get_tool_version(tool, cfg)
    latest = get_latest_version(tool, fetch=fetch_latest)
    pinned = get_pinned_version(cfg, tool.name)
    ignored = tool.name in cfg.get("ignored", {}).get("tools", [])

    if tool.install_method == "manual":
        status = "manual"
    elif installed is None and not _tool_has_install_artifacts(tool, cfg):
        status = "missing"
    elif pinned:
        status = "pinned"
    elif latest and installed and compare_versions(installed, latest) < 0:
        status = "outdated"
    elif installed or _tool_has_install_artifacts(tool, cfg):
        status = "ok"
    else:
        status = "missing"

    return {
        "tool": tool,
        "installed": installed,
        "latest": latest,
        "pinned": pinned,
        "status": status,
        "ignored": ignored,
    }
