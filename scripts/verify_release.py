"""Validate that a release tag matches project metadata."""

from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ROOT = Path(__file__).resolve().parents[1]


def _project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as f:
        return str(tomllib.load(f)["project"]["version"])


def _package_version() -> str:
    text = (ROOT / "droidreaver" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, flags=re.MULTILINE)
    if not match:
        raise SystemExit("Could not find droidreaver.__version__")
    return match.group(1)


def verify(tag: str) -> None:
    if not tag.startswith("v"):
        raise SystemExit(f"Release tag must start with 'v': {tag}")
    version = tag[1:]
    project_version = _project_version()
    package_version = _package_version()
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    errors: list[str] = []
    if project_version != version:
        errors.append(f"pyproject.toml version is {project_version}, expected {version}")
    if package_version != version:
        errors.append(f"droidreaver.__version__ is {package_version}, expected {version}")
    if f"## [{version}]" not in changelog:
        errors.append(f"CHANGELOG.md has no section for [{version}]")

    if errors:
        raise SystemExit("\n".join(errors))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_release.py vX.Y.Z", file=sys.stderr)
        return 2
    verify(argv[1])
    print(f"Release metadata OK for {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
