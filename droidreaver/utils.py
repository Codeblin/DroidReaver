"""GitHub releases API, version comparison, and subprocess helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests
from packaging import version as pkg_version

CACHE_TTL_SECONDS = 3600
GITHUB_API = "https://api.github.com"
PYPI_API = "https://pypi.org/pypi"
PIP_CMD_TIMEOUT = 20
PROBE_CMD_TIMEOUT = 15

_pip_versions_cache: dict[str, str] | None = None
_pypi_latest_cache: dict[str, str | None] = {}
_pypi_releases_cache: dict[str, set[str]] = {}


def clear_version_caches() -> None:
    """Reset in-memory version caches (mainly for tests)."""
    global _pip_versions_cache
    _pip_versions_cache = None
    _pypi_latest_cache.clear()
    _pypi_releases_cache.clear()


def normalize_pkg_name(name: str) -> str:
    return name.lower().replace("_", "-")


def run_cmd(
    cmd: str | list[str],
    *,
    capture: bool = True,
    check: bool = False,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    if isinstance(cmd, str):
        shell = True
        args: str | list[str] = cmd
    else:
        shell = False
        args = cmd
    try:
        return subprocess.run(
            args,
            shell=shell,
            capture_output=capture,
            text=True,
            check=check,
            env=env,
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        return subprocess.CompletedProcess(
            args=args if isinstance(args, list) else [args],
            returncode=124,
            stdout=e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
            stderr=e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "command timed out"),
        )


def which(binary: str) -> str | None:
    return shutil.which(binary)


def find_git() -> str | None:
    """Locate git on PATH or common Windows install locations."""
    found = which("git")
    if found:
        return found
    if sys.platform != "win32":
        return None
    for base in (
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
    ):
        if not base:
            continue
        for sub in ("Git/cmd/git.exe", "Git/bin/git.exe"):
            candidate = Path(base) / sub
            if candidate.is_file():
                return str(candidate)
    return None


def get_github_default_branch(repo: str) -> str:
    """Return the repo's default branch (main/master)."""
    data = github_get(f"{GITHUB_API}/repos/{repo}")
    if isinstance(data, dict):
        branch = data.get("default_branch")
        if branch:
            return str(branch)
    return "main"


def parse_version(text: str | None) -> str | None:
    """Extract semver-like version from command output."""
    if not text:
        return None
    text = text.strip()
    # Common patterns: "16.1.4", "v16.1.4", "Version 2.9.0"
    match = re.search(r"v?(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.-]*)?)", text)
    if match:
        ver = match.group(1)
        # Strip trailing non-version suffixes
        ver = re.sub(r"[-_][a-zA-Z]+$", "", ver) if ver.count(".") >= 2 else ver
        return ver.lstrip("v")
    return None


def normalize_version(ver: str | None) -> str | None:
    if not ver:
        return None
    ver = ver.strip().lstrip("v")
    try:
        return str(pkg_version.parse(ver))
    except pkg_version.InvalidVersion:
        return ver


def compare_versions(a: str | None, b: str | None) -> int | None:
    """Return -1 if a<b, 0 if equal, 1 if a>b, None if incomparable."""
    if not a or not b:
        return None
    try:
        va = pkg_version.parse(a)
        vb = pkg_version.parse(b)
        if va < vb:
            return -1
        if va > vb:
            return 1
        return 0
    except pkg_version.InvalidVersion:
        if a == b:
            return 0
        return None


def versions_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    na = normalize_version(a)
    nb = normalize_version(b)
    if na and nb:
        return compare_versions(na, nb) == 0
    return a.strip().lstrip("v") == b.strip().lstrip("v")


def cache_dir() -> Path:
    d = Path.home() / ".droidreaver" / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_key(url: str) -> Path:
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    return cache_dir() / f"{h}.json"


def _read_cache(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - data.get("_cached_at", 0) > CACHE_TTL_SECONDS:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(path: Path, payload: dict[str, Any]) -> None:
    payload = {**payload, "_cached_at": time.time()}
    path.write_text(json.dumps(payload), encoding="utf-8")


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "droidreaver/0.1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_get(url: str, *, use_cache: bool = True) -> dict[str, Any] | list[Any]:
    cache_path = _cache_key(url)
    if use_cache:
        cached = _read_cache(cache_path)
        if cached and "body" in cached:
            return cached["body"]

    resp = requests.get(url, headers=github_headers(), timeout=30)
    resp.raise_for_status()
    body = resp.json()
    if use_cache:
        _write_cache(cache_path, {"body": body, "url": url})
    return body


def get_latest_github_release(repo: str) -> dict[str, Any]:
    url = f"{GITHUB_API}/repos/{repo}/releases/latest"
    try:
        return github_get(url)  # type: ignore[return-value]
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            # Some repos use tags only
            tags_url = f"{GITHUB_API}/repos/{repo}/tags"
            tags = github_get(tags_url)
            if tags:
                tag_name = tags[0]["name"]  # type: ignore[index]
                return {"tag_name": tag_name, "assets": []}
        raise


def extract_release_version(release: dict[str, Any]) -> str:
    tag = release.get("tag_name", "")
    return tag.lstrip("v")


def get_installed_version(
    version_cmd: str | None,
    binary_name: str | None = None,
    *,
    timeout: float | None = PROBE_CMD_TIMEOUT,
) -> str | None:
    if version_cmd:
        try:
            result = run_cmd(version_cmd, timeout=timeout)
            if result.returncode == 0 and result.stdout:
                return parse_version(result.stdout) or parse_version(result.stderr)
            if result.stderr:
                return parse_version(result.stderr)
        except (OSError, subprocess.SubprocessError):
            pass

    if binary_name and which(binary_name):
        try:
            result = run_cmd(f"{binary_name} --version", timeout=timeout)
            if result.returncode == 0:
                combined = (result.stdout or "") + (result.stderr or "")
                return parse_version(combined)
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def is_binary_available(binary_name: str | None) -> bool:
    if not binary_name:
        return False
    return which(binary_name) is not None


def load_pip_package_versions(
    *,
    python: str | None = None,
    use_cache: bool = True,
) -> dict[str, str]:
    """Return installed pip packages from a single pip list call."""
    global _pip_versions_cache

    if use_cache and python is None and _pip_versions_cache is not None:
        return _pip_versions_cache

    result = run_cmd(
        [python or sys.executable, "-m", "pip", "list", "--format=json"],
        timeout=PIP_CMD_TIMEOUT,
    )
    versions: dict[str, str] = {}
    if result.returncode == 0 and result.stdout:
        try:
            for entry in json.loads(result.stdout):
                name = entry.get("name", "")
                ver = entry.get("version", "")
                if name and ver:
                    versions[normalize_pkg_name(name)] = ver
        except (json.JSONDecodeError, TypeError):
            pass

    if use_cache and python is None:
        _pip_versions_cache = versions
    return versions


def fetch_pypi_latest_version(package: str) -> str | None:
    """Fetch latest PyPI release with disk + in-memory cache."""
    key = normalize_pkg_name(package)
    if key in _pypi_latest_cache:
        return _pypi_latest_cache[key]

    cache_path = _cache_key(f"pypi:{package}")
    cached = _read_cache(cache_path)
    if cached and cached.get("version"):
        ver = str(cached["version"])
        try:
            if pypi_version_exists(package, ver):
                _pypi_latest_cache[key] = ver
                return ver
        except requests.RequestException:
            pass

    try:
        resp = requests.get(f"{PYPI_API}/{package}/json", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        releases = _releases_from_pypi_json(data)
        _pypi_releases_cache[key] = releases
        ver = _latest_from_pypi_releases(releases, data)
        if not ver:
            _pypi_latest_cache[key] = None
            return None
        _write_cache(cache_path, {"version": ver, "package": package})
        _pypi_latest_cache[key] = ver
        return ver
    except (requests.RequestException, KeyError, TypeError):
        _pypi_latest_cache[key] = None
        return None


def _releases_from_pypi_json(data: dict[str, Any]) -> set[str]:
    return set(data.get("releases", {}).keys())


def _latest_from_pypi_releases(releases: set[str], data: dict[str, Any]) -> str | None:
    """Pick the highest published version (not info.version — avoids stale/wrong metadata)."""
    files_by_version = data.get("releases", {})
    candidates = [v for v in releases if files_by_version.get(v)]
    if not candidates:
        info_ver = data.get("info", {}).get("version")
        return str(info_ver) if info_ver else None
    candidates.sort(key=lambda v: pkg_version.parse(v), reverse=True)
    return candidates[0]


def pypi_version_exists(package: str, version: str) -> bool:
    """True when version is a real release on PyPI."""
    ver = version.lstrip("v")
    key = normalize_pkg_name(package)
    if key not in _pypi_releases_cache:
        try:
            resp = requests.get(f"{PYPI_API}/{package}/json", timeout=10)
            resp.raise_for_status()
            data = resp.json()
            _pypi_releases_cache[key] = _releases_from_pypi_json(data)
        except requests.RequestException:
            return False
    return ver in _pypi_releases_cache[key]


def pip_show_version(package: str) -> str | None:
    versions = load_pip_package_versions()
    found = versions.get(normalize_pkg_name(package))
    if found:
        return found

    result = run_cmd(
        [sys.executable, "-m", "pip", "show", package],
        timeout=PIP_CMD_TIMEOUT,
    )
    if result.returncode != 0:
        return None
    for line in (result.stdout or "").splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def npm_show_version(package: str) -> str | None:
    result = run_cmd(f"npm list -g {package} --depth=0", timeout=PIP_CMD_TIMEOUT)
    if result.returncode != 0:
        return None
    match = re.search(rf"{re.escape(package)}@(\S+)", result.stdout or "")
    return match.group(1) if match else None


def detect_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def detect_system_package_manager() -> str | None:
    if shutil.which("brew"):
        return "brew"
    if shutil.which("apt-get") or shutil.which("apt"):
        return "apt"
    return None


def human_category(category: str) -> str:
    return category.replace("_", " ").title()
