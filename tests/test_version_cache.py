"""Tests for fast version lookup helpers."""

from unittest.mock import MagicMock, patch

from droidreaver.installer import get_latest_version
from droidreaver.registry import get_tool
from droidreaver.utils import (
    clear_version_caches,
    fetch_pypi_latest_version,
    load_pip_package_versions,
    normalize_pkg_name,
    run_cmd,
)


def test_normalize_pkg_name():
    assert normalize_pkg_name("Frida-Tools") == "frida-tools"
    assert normalize_pkg_name("some_pkg") == "some-pkg"


def test_run_cmd_timeout_returns_nonzero():
    with patch("droidreaver.utils.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("cmd", 1)):
        result = run_cmd("sleep 999", timeout=1)
    assert result.returncode == 124


def test_load_pip_package_versions_parses_json():
    clear_version_caches()
    fake = MagicMock(returncode=0, stdout='[{"name": "frida", "version": "17.0.0"}]', stderr="")
    with patch("droidreaver.utils.run_cmd", return_value=fake):
        versions = load_pip_package_versions(use_cache=False)
    assert versions["frida"] == "17.0.0"


def test_fetch_pypi_latest_version_uses_cache(monkeypatch):
    clear_version_caches()
    calls: list[str] = []

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "info": {"version": "9.9.9"},
                "releases": {"17.12.0": [{"url": "x"}], "9.9.9": []},
            }

    def fake_get(url, timeout=10):
        calls.append(url)
        return FakeResp()

    monkeypatch.setattr("droidreaver.utils.requests.get", fake_get)
    monkeypatch.setattr("droidreaver.utils._read_cache", lambda _path: None)

    with patch("droidreaver.utils._write_cache"):
        first = fetch_pypi_latest_version("frida")
        second = fetch_pypi_latest_version("frida")
    assert first == "17.12.0"
    assert second == "17.12.0"
    assert len(calls) == 1


def test_fetch_pypi_latest_version_rejects_invalid_disk_cache(monkeypatch):
    clear_version_caches()
    import time

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "info": {"version": "17.14.1"},
                "releases": {"17.14.1": [{"url": "x"}], "17.12.0": [{"url": "y"}]},
            }

    monkeypatch.setattr("droidreaver.utils.requests.get", lambda url, timeout=10: FakeResp())
    monkeypatch.setattr(
        "droidreaver.utils._read_cache",
        lambda _path: {"version": "9.9.9", "_cached_at": time.time()},
    )

    with patch("droidreaver.utils._write_cache") as write:
        ver = fetch_pypi_latest_version("frida")
    assert ver == "17.14.1"
    write.assert_called_once()


def test_get_latest_version_pip_uses_pypi_not_pip_index():
    clear_version_caches()
    tool = get_tool("frida")
    with patch("droidreaver.installer.fetch_pypi_latest_version", return_value="17.11.0") as mock_pypi:
        with patch("droidreaver.installer.run_cmd") as mock_run:
            assert get_latest_version(tool) == "17.11.0"
    mock_pypi.assert_called_once_with("frida")
    mock_run.assert_not_called()
