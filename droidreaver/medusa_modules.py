"""Load Frida JavaScript from Medusa .med module files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from droidreaver.config import install_dir

MEDUSA_ROOT_MODULE = "modules/root_detection/anti_root.med"
MEDUSA_ROOT_SPEC = f"medusa:{MEDUSA_ROOT_MODULE}"


def medusa_install_dir(config: dict) -> Path | None:
    path = install_dir(config) / "medusa"
    return path if path.is_dir() else None


def parse_med_module(med_path: Path) -> str:
    """Return the Code block from a Medusa .med JSON file."""
    raw = med_path.read_text(encoding="utf-8")
    data = json.loads(raw, strict=False)
    code = data.get("Code")
    if not code or not str(code).strip():
        raise ValueError(f"No Code in Medusa module: {med_path}")
    return str(code).strip()


def _cache_path(key: str) -> Path:
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    cache = Path.home() / ".droidreaver" / "cache" / "medusa-js"
    cache.mkdir(parents=True, exist_ok=True)
    return cache / f"{digest}.js"


def materialize_medusa_module(config: dict, relative_path: str) -> Path:
    """Extract a .med module to a cached .js file for Frida -l."""
    medusa = medusa_install_dir(config)
    if not medusa:
        raise FileNotFoundError("Medusa is not installed")
    med_path = medusa / relative_path
    if not med_path.is_file():
        raise FileNotFoundError(f"Medusa module missing: {relative_path}")

    cache_file = _cache_path(relative_path)
    if cache_file.is_file() and cache_file.stat().st_mtime >= med_path.stat().st_mtime:
        return cache_file

    code = parse_med_module(med_path)
    header = (
        f"// Medusa module: {relative_path}\n"
        "// https://github.com/Ch0pin/medusa\n\n"
    )
    cache_file.write_text(header + code + "\n", encoding="utf-8")
    return cache_file


def resolve_bypass_script(config: dict, spec: str, scripts_dir: Path) -> Path:
    """Resolve a script spec to a filesystem path.

    Spec formats:
      - plain.js           → bundled under droidreaver/scripts/
      - medusa:modules/…  → live Medusa install (cached), else bundled fallback
    """
    if spec.startswith("medusa:"):
        relative = spec.split(":", 1)[1]
        try:
            return materialize_medusa_module(config, relative)
        except FileNotFoundError:
            fallback_name = {
                MEDUSA_ROOT_MODULE: "medusa_universal_root.js",
            }.get(relative)
            if fallback_name:
                bundled = scripts_dir / fallback_name
                if bundled.is_file():
                    return bundled
            raise
    path = scripts_dir / spec
    if not path.is_file():
        raise FileNotFoundError(f"Missing bundled script: {path}")
    return path
