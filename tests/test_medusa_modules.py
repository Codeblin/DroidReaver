"""Tests for Medusa module extraction."""

import json
from pathlib import Path
from unittest.mock import patch

from droidreaver.medusa_modules import (
    MEDUSA_ROOT_MODULE,
    parse_med_module,
    resolve_bypass_script,
)


def test_parse_med_module_extracts_code(tmp_path: Path):
    med = tmp_path / "test.med"
    med.write_text(
        json.dumps(
            {
                "Name": "root_detection/universal_root_detection_bypass",
                "Code": "console.log('medusa-root');",
            }
        ),
        encoding="utf-8",
    )
    assert parse_med_module(med) == "console.log('medusa-root');"


def test_resolve_bypass_script_uses_bundled_fallback(tmp_path: Path, monkeypatch):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    bundled = scripts / "medusa_universal_root.js"
    bundled.write_text("// bundled fallback\n", encoding="utf-8")

    spec = f"medusa:{MEDUSA_ROOT_MODULE}"
    with patch("droidreaver.medusa_modules.medusa_install_dir", return_value=None):
        path = resolve_bypass_script({}, spec, scripts)
    assert path == bundled
