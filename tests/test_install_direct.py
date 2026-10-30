"""Tests for direct-download installs and install resilience."""

import tarfile
import zipfile
from pathlib import Path

import pytest

from droidreaver import installer
from droidreaver.config import META_KEY
from droidreaver.installer import InstallError, install_tools
from droidreaver.registry import Tool, get_tool


def _cfg(root: Path) -> dict:
    return {
        "settings": {"install_dir": ".droidreaver/tools"},
        "pins": {},
        "ignored": {"tools": []},
        "active": {},
        META_KEY: {"root": str(root), "path": str(root / "droidreaver.toml")},
    }


def test_adb_uses_direct_method_not_github():
    adb = get_tool("adb")
    assert adb.install_method == "direct"
    assert adb.github_repo is None
    assert adb.download_url_template and "{platform}" in adb.download_url_template


def test_platform_download_key_maps_known_platforms(monkeypatch):
    monkeypatch.setattr(installer, "detect_platform", lambda: "macos")
    assert installer._platform_download_key() == "darwin"
    monkeypatch.setattr(installer, "detect_platform", lambda: "windows")
    assert installer._platform_download_key() == "windows"
    monkeypatch.setattr(installer, "detect_platform", lambda: "linux")
    assert installer._platform_download_key() == "linux"


def test_install_direct_downloads_and_links(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    captured = {}

    def fake_download(url, dest, progress=None, *, expected_sha256=None):
        captured["url"] = url
        captured["sha256"] = expected_sha256
        dest.write_bytes(b"fake-zip")

    def fake_extract(archive, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "adb").write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(installer, "detect_platform", lambda: "linux")
    monkeypatch.setattr(installer, "_download_file", fake_download)
    monkeypatch.setattr(installer, "_extract_archive", fake_extract)

    installer._install_direct(get_tool("adb"), cfg)

    assert "platform-tools-latest-linux.zip" in captured["url"]
    bin_dir = tmp_path / ".droidreaver" / "tools" / "adb" / "bin"
    assert (bin_dir / "adb").is_file()


def test_install_direct_passes_platform_checksum(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    expected = "0" * 64
    tool = Tool(
        name="sample",
        display_name="Sample",
        category="device_adb",
        install_method="direct",
        download_url_template="https://example.invalid/sample-{platform}.zip",
        download_sha256={"linux": expected},
        binary_name="sample",
    )
    captured = {}

    def fake_download(url, dest, progress=None, *, expected_sha256=None):
        captured["url"] = url
        captured["sha256"] = expected_sha256
        dest.write_bytes(b"fake-zip")

    def fake_extract(archive, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "sample").write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(installer, "detect_platform", lambda: "linux")
    monkeypatch.setattr(installer, "_download_file", fake_download)
    monkeypatch.setattr(installer, "_extract_archive", fake_extract)

    installer._install_direct(tool, cfg)

    assert captured["url"].endswith("sample-linux.zip")
    assert captured["sha256"] == expected


def test_install_direct_writes_integrity_metadata(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    expected = "0" * 64
    digest = "0" * 64
    tool = Tool(
        name="sample",
        display_name="Sample",
        category="device_adb",
        install_method="direct",
        download_url_template="https://example.invalid/sample-{platform}.zip",
        download_sha256={"linux": expected},
        binary_name="sample",
    )

    def fake_download(url, dest, progress=None, *, expected_sha256=None):
        dest.write_bytes(b"fake-zip")
        return digest

    def fake_extract(archive, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "sample").write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(installer, "detect_platform", lambda: "linux")
    monkeypatch.setattr(installer, "_download_file", fake_download)
    monkeypatch.setattr(installer, "_extract_archive", fake_extract)

    installer._install_direct(tool, cfg)

    metadata = tmp_path / ".droidreaver" / "tools" / "sample" / ".droidreaver-install.json"
    text = metadata.read_text(encoding="utf-8")
    assert '"sha256": "0000000000000000000000000000000000000000000000000000000000000000"' in text
    assert '"verified": true' in text


def test_download_file_rejects_checksum_mismatch(tmp_path, monkeypatch):
    class Response:
        headers = {"content-length": "3"}

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"bad"

    monkeypatch.setattr(installer.requests, "get", lambda *args, **kwargs: Response())

    dest = tmp_path / "artifact.zip"
    with pytest.raises(installer.DownloadVerificationError, match="Checksum mismatch"):
        installer._download_file("https://example.invalid/a.zip", dest, expected_sha256="0" * 64)

    assert not dest.exists()
    assert not (tmp_path / "artifact.zip.part").exists()


def test_download_file_rejects_short_body(tmp_path, monkeypatch):
    class Response:
        headers = {"content-length": "4"}

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"bad"

    monkeypatch.setattr(installer.requests, "get", lambda *args, **kwargs: Response())

    dest = tmp_path / "artifact.zip"
    with pytest.raises(installer.DownloadVerificationError, match="Incomplete download"):
        installer._download_file("https://example.invalid/a.zip", dest)

    assert not dest.exists()
    assert not (tmp_path / "artifact.zip.part").exists()


def test_download_file_allows_decoded_body_larger_than_content_length(tmp_path, monkeypatch):
    class Response:
        headers = {"content-length": "3"}

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"abcd"

    monkeypatch.setattr(installer.requests, "get", lambda *args, **kwargs: Response())

    dest = tmp_path / "artifact.zip"
    digest = installer._download_file("https://example.invalid/a.zip", dest)

    assert dest.read_bytes() == b"abcd"
    assert digest == "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"


def test_download_file_returns_digest_without_expected_hash(tmp_path, monkeypatch):
    class Response:
        headers = {"content-length": "3"}

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"abc"

    monkeypatch.setattr(installer.requests, "get", lambda *args, **kwargs: Response())

    dest = tmp_path / "artifact.zip"
    digest = installer._download_file("https://example.invalid/a.zip", dest)

    assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert dest.read_bytes() == b"abc"


def test_extract_archive_rejects_zip_path_traversal(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.txt", "nope")

    with pytest.raises(InstallError, match="unsafe archive member"):
        installer._extract_archive(archive, tmp_path / "out")

    assert not (tmp_path / "evil.txt").exists()


def test_extract_archive_rejects_tar_path_traversal(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    payload = tmp_path / "payload.txt"
    payload.write_text("nope", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(payload, arcname="../evil.txt")

    with pytest.raises(InstallError, match="unsafe archive member"):
        installer._extract_archive(archive, tmp_path / "out")

    assert not (tmp_path / "evil.txt").exists()


def test_parse_checksum_text_matches_artifact_name():
    digest = "c" * 64
    text = f"{digest}  jadx-1.5.0.zip\n"

    assert installer._parse_checksum_text(text, "jadx-1.5.0.zip") == digest


def test_find_checksum_asset_prefers_exact_artifact_hash():
    release = {
        "assets": [
            {"name": "SHA256SUMS", "browser_download_url": "https://example.invalid/all"},
            {
                "name": "jadx-1.5.0.zip.sha256",
                "browser_download_url": "https://example.invalid/one",
            },
        ]
    }

    asset = installer._find_checksum_asset(release, "jadx-1.5.0.zip")

    assert asset is not None
    assert asset["browser_download_url"] == "https://example.invalid/one"


def test_find_executable_prefers_exact_stem(tmp_path):
    root = tmp_path / "platform-tools"
    root.mkdir()
    (root / "adb.exe").write_text("x", encoding="utf-8")
    (root / "AdbWinApi.dll").write_text("x", encoding="utf-8")

    found = installer._find_executable_in_tree(tmp_path, "adb")
    assert found is not None
    assert found.name == "adb.exe"  # not the DLL


def test_link_binaries_wraps_in_place_keeping_siblings(tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "detect_platform", lambda: "windows")
    extract_root = tmp_path / "extracted"
    pt = extract_root / "platform-tools"
    pt.mkdir(parents=True)
    (pt / "adb.exe").write_text("x", encoding="utf-8")
    (pt / "AdbWinApi.dll").write_text("x", encoding="utf-8")
    (pt / "fastboot.exe").write_text("x", encoding="utf-8")

    tool_dir = tmp_path / "adb"
    installer._link_binaries(get_tool("adb"), extract_root, tool_dir)

    bin_dir = tool_dir / "bin"
    adb_wrapper = bin_dir / "adb.bat"
    assert adb_wrapper.is_file()
    assert (bin_dir / "fastboot.bat").is_file()
    # Wrapper points at the in-place exe so sibling DLLs remain usable.
    assert "adb.exe" in adb_wrapper.read_text(encoding="utf-8")
    # The real exe is NOT copied out of its folder.
    assert not (bin_dir / "adb.exe").exists()


def test_install_tools_continue_on_error_collects_failures(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)

    def boom(name, config, *, version=None, force=False, progress=None):
        if name == "adb":
            raise InstallError("network down")

    monkeypatch.setattr(installer, "install_tool", boom)
    monkeypatch.setattr(installer, "installation_satisfied", lambda *_args: (False, None))

    failures = install_tools(["adb"], cfg, continue_on_error=True)
    assert failures == [("adb", "network down")]


def test_install_tools_wraps_unexpected_error(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)

    def boom(name, config, *, version=None, force=False, progress=None):
        raise RuntimeError("404 not found")

    monkeypatch.setattr(installer, "install_tool", boom)
    monkeypatch.setattr(installer, "installation_satisfied", lambda *_args: (False, None))

    # Non-InstallError must be wrapped, not propagated raw.
    with pytest.raises(InstallError):
        install_tools(["jadx"], cfg)


def test_install_tools_skips_satisfied_install(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    calls = []
    monkeypatch.setattr(
        installer,
        "installation_satisfied",
        lambda _tool, _cfg, _version: (True, "1.2.3"),
    )
    monkeypatch.setattr(
        installer,
        "install_tool",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert install_tools(["adb"], cfg) == []
    assert calls == []


def test_install_tools_reinstalls_version_mismatch(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    calls = []
    monkeypatch.setattr(
        installer,
        "installation_satisfied",
        lambda _tool, _cfg, _version: (False, "1.0.0"),
    )
    monkeypatch.setattr(
        installer,
        "install_tool",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    install_tools(["adb"], cfg, version="2.0.0")
    assert len(calls) == 1


def test_install_tools_force_bypasses_satisfied_check(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    calls = []

    def should_not_run(*_args):
        raise AssertionError("force install should not check existing state")

    monkeypatch.setattr(installer, "installation_satisfied", should_not_run)
    monkeypatch.setattr(
        installer,
        "install_tool",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    install_tools(["adb"], cfg, force=True)
    assert len(calls) == 1
