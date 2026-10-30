"""Tests for progress indicators."""

from droidreaver.progress import work_progress, work_spinner


def test_work_spinner_runs():
    with work_spinner("Testing…") as update:
        update("Still testing…")


def test_work_progress_runs():
    with work_progress("Working…", total=3) as (update, advance):
        for i in range(3):
            update(f"Step {i + 1}")
            advance()
