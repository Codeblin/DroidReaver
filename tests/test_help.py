"""Tests for categorized help output."""

from click.testing import CliRunner

from droidreaver.cli import main
from droidreaver.help_fmt import DroidReaverGroup


def test_main_uses_categorized_group():
    assert isinstance(main, DroidReaverGroup)


def test_help_has_sections():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Environment" in result.output
    assert "Presets" in result.output
    assert "hook" in result.output
    assert "Arsenal — Dynamic Analysis" in result.output
    assert "Arsenal — Static Analysis" in result.output
    assert "status" in result.output
    assert "frida" in result.output


def test_run_passes_flags_to_tool():
    """Flags after the tool name must reach the underlying CLI (not Click)."""
    runner = CliRunner()
    # Before fix, Click rejected unknown options like --version on `run`.
    with runner.isolated_filesystem():
        from unittest.mock import patch

        with patch("droidreaver.cli.ensure_config"), patch(
            "droidreaver.cli.load_config", return_value={}
        ), patch("droidreaver.cli.run_invocation", return_value=0) as run:
            result = runner.invoke(main, ["run", "frida", "--version"])

    assert result.exit_code == 0
    run.assert_called_once_with("frida", ["--version"], {})
