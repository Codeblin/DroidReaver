"""Build a markdown coverage summary from coverage.py Cobertura XML."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

MARKER = "<!-- droidreaver-coverage -->"
API_VERSION = "2022-11-28"


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
        "_From `coverage.xml` on ubuntu-latest. Full table is also in the "
        "Actions job summary. (Marketplace upload-artifact is blocked by org policy.)_"
    )
    return "\n".join(lines) + "\n"


def _github_json(
    token: str,
    method: str,
    url: str,
    payload: dict | None = None,
) -> object:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8")
        raise SystemExit(f"GitHub API {method} {url} failed ({exc.code}): {err}") from exc
    return json.loads(body) if body else None


def upsert_pr_comment(token: str, repo: str, pr_number: str, body: str) -> None:
    """Create or update the sticky coverage comment on a pull request."""
    page = 1
    existing_id = None
    while True:
        comments = _github_json(
            token,
            "GET",
            f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}",
        )
        if not isinstance(comments, list) or not comments:
            break
        for comment in comments:
            if MARKER in str(comment.get("body") or ""):
                existing_id = comment.get("id")
                break
        if existing_id or len(comments) < 100:
            break
        page += 1
    if existing_id:
        _github_json(
            token,
            "PATCH",
            f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}",
            {"body": body},
        )
        print(f"Updated coverage comment {existing_id}")
        return
    _github_json(
        token,
        "POST",
        f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
        {"body": body},
    )
    print("Created coverage comment")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", type=Path, default=Path("coverage.xml"), nargs="?")
    parser.add_argument("-o", "--output", type=Path, default=Path("coverage-comment.md"))
    parser.add_argument(
        "--post-pr",
        action="store_true",
        help="Upsert a sticky PR comment (needs GH_TOKEN, GITHUB_REPOSITORY, PR_NUMBER)",
    )
    args = parser.parse_args()
    if not args.xml.is_file():
        raise SystemExit(f"coverage XML not found: {args.xml}")
    text = format_coverage_markdown(args.xml)
    args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    if args.post_pr:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        repo = os.environ.get("GITHUB_REPOSITORY")
        pr_number = os.environ.get("PR_NUMBER")
        if not token or not repo or not pr_number:
            raise SystemExit("GH_TOKEN, GITHUB_REPOSITORY, and PR_NUMBER are required for --post-pr")
        upsert_pr_comment(token, repo, pr_number, text)


if __name__ == "__main__":
    main()
