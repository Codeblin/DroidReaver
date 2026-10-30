"""Tests for fix planner."""

from droidreaver.doctor import CheckResult
from droidreaver.fix import RISK_LEVELS, FixAction, build_fix_plan, format_impact_cell


def test_fix_plan_frida_mismatch():
    config = {"pins": {}, "settings": {}, "ignored": {"tools": []}}
    checks = [
        CheckResult(
            "Frida pin group",
            "fail",
            "Pinned frida 16.1.4 but runtime installed is 17.11.0",
            fix="droidreaver use 16.1.4",
        ),
    ]
    plan = build_fix_plan(config, checks)
    assert any(a.id == "sync-frida-group" for a in plan)


def test_fix_plan_adb_missing():
    config = {"pins": {}, "settings": {}, "ignored": {"tools": []}}
    checks = [
        CheckResult("ADB", "fail", "Not found in PATH", fix="droidreaver install adb"),
    ]
    plan = build_fix_plan(config, checks)
    assert any(a.id == "install-adb" for a in plan)


def test_fix_plan_manual_java():
    config = {"pins": {}, "settings": {}, "ignored": {"tools": []}}
    checks = [
        CheckResult(
            "Java",
            "warn",
            "Not found",
            fix="Install JDK",
            automated=False,
        ),
    ]
    plan = build_fix_plan(config, checks)
    assert len(plan) == 1
    assert plan[0].automated is False


def test_fix_plan_only_filter():
    config = {"pins": {}, "settings": {}, "ignored": {"tools": []}}
    checks = [
        CheckResult("ADB", "fail", "Not found", fix="install adb"),
        CheckResult(
            "Frida pin group",
            "fail",
            "Version mismatch: frida=1, objection=2",
            fix="update",
        ),
    ]
    plan = build_fix_plan(config, checks, only={"adb"})
    assert all(a.category == "adb" for a in plan)
    assert len(plan) == 1


def test_fix_plan_dry_run_empty_when_healthy():
    config = {"pins": {}, "settings": {}, "ignored": {"tools": []}}
    checks = [CheckResult("Python", "ok", "3.12.0")]
    plan = build_fix_plan(config, checks)
    assert plan == []


def test_risk_levels_defined():
    assert "low" in RISK_LEVELS
    assert "detail" in RISK_LEVELS["medium"]
    assert "examples" in RISK_LEVELS["high"]


def test_format_impact_cell_uses_risk_detail():
    action = FixAction(
        id="test",
        category="frida",
        title="Test",
        description="desc",
        risk="medium",
        automated=True,
        source_check="test",
        risk_detail="Custom impact note",
    )
    cell = format_impact_cell(action)
    assert "Custom impact note" in cell
    assert "Medium impact" in cell
