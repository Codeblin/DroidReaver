"""Build a markdown coverage summary from coverage.py Cobertura XML."""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

MARKER = "<!-- droidreaver-coverage -->"


def _pct(rate: str | None) -> float:
    try:
        return float(rate or 0.0) * 100.0
    except ValueError:
        return 0.0


def format_coverage_markdown(xml_path: Path) -> str:
    root = ET.parse(xml_path).getroot()
    line_pct = _pct(root.get("line-rate"))
    branch_pct = _pct(root.get("branch-rate"))
    covered = root.get("lines-covered", "?")
    valid = root.get("lines-valid", "?")

    files: list[tuple[float, str]] = []
    for cls in root.iter("class"):
        name = cls.get("filename") or cls.get("name") or "?"
        files.append((_pct(cls.get("line-rate")), name.replace("\\", "/")))
    files.sort(key=lambda item: (item[0], item[1]))

    lines = [
        MARKER,
        "## Test coverage",
        "",
        f"| Metric | Value |",
        f"| --- | --- |",
        f"| Lines | **{line_pct:.1f}%** ({covered}/{valid}) |",
        f"| Branches | **{branch_pct:.1f}%** |",
        "",
    ]
    weak = [row for row in files if row[0] < 80][:15]
    if weak:
        lines.extend(
            [
                "Lowest-coverage files:",
                "",
                "| File | Lines |",
                "| --- | ---: |",
            ]
        )
        for pct, name in weak:
            lines.append(f"| `{name}` | {pct:.1f}% |")
        lines.append("")
    lines.append(
        "_From `coverage.xml` on ubuntu-latest. HTML report is attached to the "
        "**coverage-ubuntu** workflow artifact._"
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", type=Path, default=Path("coverage.xml"), nargs="?")
    parser.add_argument("-o", "--output", type=Path, default=Path("coverage-comment.md"))
    args = parser.parse_args()
    if not args.xml.is_file():
        raise SystemExit(f"coverage XML not found: {args.xml}")
    text = format_coverage_markdown(args.xml)
    args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
