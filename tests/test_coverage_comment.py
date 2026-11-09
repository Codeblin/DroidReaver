import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "coverage_comment.py"
_spec = importlib.util.spec_from_file_location("coverage_comment", _SCRIPT)
assert _spec and _spec.loader
coverage_comment = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(coverage_comment)


def test_format_coverage_markdown(tmp_path):
    xml = tmp_path / "coverage.xml"
    xml.write_text(
        """<?xml version="1.0" ?>
<coverage line-rate="0.8" branch-rate="0.5" lines-covered="8" lines-valid="10">
  <packages>
    <package>
      <classes>
        <class filename="droidreaver/cli.py" line-rate="0.4"/>
        <class filename="droidreaver/utils.py" line-rate="0.95"/>
      </classes>
    </package>
  </packages>
</coverage>
""",
        encoding="utf-8",
    )
    md = coverage_comment.format_coverage_markdown(xml)
    assert coverage_comment.MARKER in md
    assert "80.0%" in md
    assert "droidreaver/cli.py" in md
    assert "40.0%" in md
