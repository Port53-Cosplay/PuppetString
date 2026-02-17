"""Tests for the PuppetString CLI.

HOW PYTEST WORKS (quick version):
    - Any file named test_*.py gets picked up automatically
    - Any function named test_* inside it is a test
    - Tests use `assert` to check things: assert 1 + 1 == 2
    - Run all tests with: pytest
    - Run just this file with: pytest tests/test_cli.py

WHAT IS CliRunner?
    Typer (our CLI framework) provides a test helper called CliRunner.
    It simulates running the CLI command without actually opening a terminal.
    So instead of manually typing `puppetstring --version` in a shell,
    we can call it from code and check the output programmatically.
"""

from typer.testing import CliRunner

from puppetstring import __version__
from puppetstring.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    """Running `puppetstring --version` should print the version."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_shows_all_commands() -> None:
    """Running `puppetstring --help` should list all themed commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    # Check that all six puppet-themed commands appear
    assert "pull" in result.output
    assert "tangle" in result.output
    assert "cut" in result.output
    assert "dance" in result.output
    assert "unravel" in result.output
    assert "stage" in result.output


def test_responsible_use_flag() -> None:
    """Running `puppetstring --responsible-use` should show the policy."""
    result = runner.invoke(app, ["--responsible-use"])
    assert result.exit_code == 0
    assert "Responsible Use" in result.output
    assert "authorization" in result.output.lower()


def test_pull_requires_target() -> None:
    """Running `puppetstring pull` without --target should fail."""
    result = runner.invoke(app, ["pull"])
    assert result.exit_code != 0


def test_pull_with_target() -> None:
    """Running `puppetstring pull -t <target>` should work (placeholder)."""
    result = runner.invoke(app, ["pull", "-t", "mcp://localhost:3000"])
    assert result.exit_code == 0
    assert "mcp://localhost:3000" in result.output


def test_tangle_requires_target() -> None:
    """Running `puppetstring tangle` without --target should fail."""
    result = runner.invoke(app, ["tangle"])
    assert result.exit_code != 0


def test_stage_with_action() -> None:
    """Running `puppetstring stage up` should work (placeholder)."""
    result = runner.invoke(app, ["stage", "up"])
    assert result.exit_code == 0
    assert "up" in result.output
