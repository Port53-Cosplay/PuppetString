"""Tests for the stage command — test target process management.

Covers:
    - Model construction and serialization
    - StageManager initialization, up/down/status with mocked subprocess
    - Helper functions (_is_port_in_use, _detach_kwargs, _find_examples_dir)
    - CLI validation and command dispatch
    - Terminal rendering of status tables
"""

from __future__ import annotations

import os
import platform
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from puppetstring.staging.models import (
    ProcessState,
    StageState,
    TargetDefinition,
    TargetName,
    TargetStatus,
)

# ── TestModels ───────────────────────────────────────────────────


class TestModels:
    """Test staging data models."""

    def test_target_name_values(self) -> None:
        assert TargetName.MCP == "mcp"
        assert TargetName.AGENT == "agent"
        assert TargetName.SWARM == "swarm"
        assert len(TargetName) == 3

    def test_target_name_from_string(self) -> None:
        assert TargetName("mcp") is TargetName.MCP
        assert TargetName("agent") is TargetName.AGENT
        assert TargetName("swarm") is TargetName.SWARM

    def test_target_definition_construction(self) -> None:
        defn = TargetDefinition(
            name=TargetName.MCP,
            display_name="Test MCP",
            description="A test target",
            script_path="vulnerable_mcp_server/server.py",
            port=3000,
        )
        assert defn.name == TargetName.MCP
        assert defn.port == 3000
        assert defn.host == "127.0.0.1"
        assert str(defn.script_posix) == "vulnerable_mcp_server/server.py"

    def test_process_state_serialization(self) -> None:
        ps = ProcessState(
            target_name=TargetName.AGENT,
            pid=12345,
            port=8000,
            log_file="test.log",  # noqa: S108
        )
        data = ps.model_dump()
        assert data["target_name"] == "agent"
        assert data["pid"] == 12345
        assert data["port"] == 8000
        assert "started_at" in data

    def test_stage_state_round_trip(self) -> None:
        ps = ProcessState(
            target_name=TargetName.MCP,
            pid=99,
            port=3000,
        )
        state = StageState(processes=[ps])
        json_str = state.model_dump_json()
        restored = StageState.model_validate_json(json_str)
        assert len(restored.processes) == 1
        assert restored.processes[0].pid == 99
        assert restored.processes[0].target_name == TargetName.MCP

    def test_target_status_defaults(self) -> None:
        status = TargetStatus(
            name=TargetName.SWARM,
            display_name="Swarm",
            description="Test",
            port=8001,
        )
        assert status.pid is None
        assert status.running is False
        assert status.healthy is False
        assert status.started_at is None

    def test_target_status_running(self) -> None:
        now = datetime.now()
        status = TargetStatus(
            name=TargetName.AGENT,
            display_name="Agent",
            description="Test",
            port=8000,
            pid=555,
            running=True,
            healthy=True,
            started_at=now,
        )
        assert status.pid == 555
        assert status.running is True
        assert status.healthy is True


# ── TestHelpers ──────────────────────────────────────────────────


class TestHelpers:
    """Test module-level helper functions."""

    def test_find_examples_dir(self) -> None:
        from puppetstring.staging.manager import _find_examples_dir

        examples = _find_examples_dir()
        assert examples.is_dir()
        assert (examples / "vulnerable_agent").is_dir()
        assert (examples / "vulnerable_mcp_server").is_dir()
        assert (examples / "multi_agent_demo").is_dir()

    def test_state_file_path_is_in_temp(self) -> None:
        import tempfile

        from puppetstring.staging.manager import _state_file_path

        path = _state_file_path()
        assert str(path).startswith(tempfile.gettempdir())
        assert "puppetstring_stage_" in path.name

    def test_state_file_path_is_deterministic(self) -> None:
        from puppetstring.staging.manager import _state_file_path

        assert _state_file_path() == _state_file_path()

    def test_is_port_in_use_unused_port(self) -> None:
        from puppetstring.staging.manager import _is_port_in_use

        # Port 0 is never "in use" for connect — OS assigns a random one
        assert _is_port_in_use("127.0.0.1", 39999) is False

    def test_detach_kwargs_has_expected_keys(self) -> None:
        from puppetstring.staging.manager import _detach_kwargs

        kwargs = _detach_kwargs()
        if platform.system() == "Windows":
            assert "creationflags" in kwargs
        else:
            assert kwargs.get("start_new_session") is True

    def test_is_pid_alive_current_process(self) -> None:
        import os

        from puppetstring.staging.manager import _is_pid_alive

        assert _is_pid_alive(os.getpid()) is True

    def test_is_pid_alive_bogus_pid(self) -> None:
        from puppetstring.staging.manager import _is_pid_alive

        # PID 2^30 almost certainly doesn't exist
        assert _is_pid_alive(2**30) is False

    def test_is_safe_log_path_valid(self) -> None:
        import tempfile

        from puppetstring.staging.manager import _is_safe_log_path

        valid = os.path.join(tempfile.gettempdir(), "puppetstring_mcp.log")
        assert _is_safe_log_path(valid) is True

    def test_is_safe_log_path_rejects_traversal(self) -> None:
        from puppetstring.staging.manager import _is_safe_log_path

        assert _is_safe_log_path("/etc/passwd") is False
        assert _is_safe_log_path("C:\\Users\\victim\\important.docx") is False

    def test_is_safe_log_path_rejects_wrong_name(self) -> None:
        import tempfile

        from puppetstring.staging.manager import _is_safe_log_path

        wrong_name = os.path.join(tempfile.gettempdir(), "evil.log")
        assert _is_safe_log_path(wrong_name) is False

    def test_is_safe_log_path_rejects_wrong_extension(self) -> None:
        import tempfile

        from puppetstring.staging.manager import _is_safe_log_path

        wrong_ext = os.path.join(tempfile.gettempdir(), "puppetstring_mcp.exe")
        assert _is_safe_log_path(wrong_ext) is False

    def test_is_puppetstring_process_rejects_bogus_pid(self) -> None:
        from puppetstring.staging.manager import _is_puppetstring_process

        assert _is_puppetstring_process(2**30) is False


# ── TestStageManager ─────────────────────────────────────────────


class TestStageManager:
    """Test StageManager with mocked subprocess and filesystem."""

    def test_init_finds_examples(self) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        assert mgr.examples_dir.is_dir()

    def test_init_fails_without_examples(self) -> None:
        from puppetstring.staging.manager import StageManager

        with patch(
            "puppetstring.staging.manager._find_examples_dir",
            side_effect=FileNotFoundError("no examples"),
        ):
            with pytest.raises(FileNotFoundError, match="no examples"):
                StageManager()

    def test_status_returns_all_targets(self) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        statuses = mgr.status()
        assert len(statuses) == 3
        names = {s.name for s in statuses}
        assert names == {TargetName.MCP, TargetName.AGENT, TargetName.SWARM}

    def test_status_all_stopped_initially(self) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        # Use a temp state file so we don't pollute real state
        mgr._state_path = Path(__file__).parent / "_test_state_nonexistent.json"
        statuses = mgr.status()
        assert all(not s.running for s in statuses)

    @patch("puppetstring.staging.manager._is_port_in_use", return_value=True)
    def test_up_port_already_in_use(self, mock_port: MagicMock) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        # Ensure no existing process state so it hits the "port in use" branch
        mgr._state_path = Path(__file__).parent / "_test_state_nonexistent.json"
        statuses = mgr.up([TargetName.AGENT])
        assert len(statuses) == 1
        assert statuses[0].running is False
        assert statuses[0].healthy is False

    def test_down_when_nothing_running(self) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        mgr._state_path = Path(__file__).parent / "_test_state_nonexistent.json"
        statuses = mgr.down([TargetName.MCP])
        assert len(statuses) == 1
        assert statuses[0].running is False

    def test_down_kills_tracked_process(self, tmp_path: Path) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        state_file = tmp_path / "state.json"
        mgr._state_path = state_file

        # Write a fake state with a bogus PID
        state = StageState(
            processes=[ProcessState(target_name=TargetName.AGENT, pid=2**30, port=8000)]
        )
        state_file.write_text(state.model_dump_json(), encoding="utf-8")

        with patch("puppetstring.staging.manager._is_pid_alive", return_value=False):
            statuses = mgr.down([TargetName.AGENT])

        assert len(statuses) == 1
        assert statuses[0].running is False
        # State file should have the process removed
        restored = StageState.model_validate_json(state_file.read_text(encoding="utf-8"))
        assert len(restored.processes) == 0

    def test_load_state_corrupt_file(self, tmp_path: Path) -> None:
        from puppetstring.staging.manager import StageManager

        mgr = StageManager()
        state_file = tmp_path / "corrupt.json"
        state_file.write_text("not valid json{{{", encoding="utf-8")
        mgr._state_path = state_file

        statuses = mgr.status()
        assert len(statuses) == 3  # Returns all targets as stopped

    @patch("puppetstring.staging.manager.subprocess.Popen")
    @patch("puppetstring.staging.manager._is_port_in_use")
    @patch("puppetstring.staging.manager._is_pid_alive", return_value=True)
    def test_up_starts_process(
        self,
        mock_alive: MagicMock,
        mock_port: MagicMock,
        mock_popen: MagicMock,
        tmp_path: Path,
    ) -> None:
        from puppetstring.staging.manager import StageManager

        # Port check: first call False (not in use), then True (healthy)
        mock_port.side_effect = [False, True]
        mock_proc = MagicMock()
        mock_proc.pid = 42
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        mgr = StageManager()
        mgr._state_path = tmp_path / "state.json"

        statuses = mgr.up([TargetName.AGENT])
        assert len(statuses) == 1
        assert statuses[0].pid == 42
        assert statuses[0].healthy is True
        mock_popen.assert_called_once()


# ── TestStageCLI ─────────────────────────────────────────────────


class TestStageCLI:
    """Test CLI argument validation and command dispatch."""

    def test_invalid_action(self) -> None:
        from typer.testing import CliRunner

        from puppetstring.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["stage", "invalid"])
        assert result.exit_code == 1
        assert "Unknown action" in result.output

    def test_invalid_target(self) -> None:
        from typer.testing import CliRunner

        from puppetstring.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["stage", "status", "-t", "bogus"])
        assert result.exit_code == 1
        assert "Unknown target" in result.output

    @patch("puppetstring.staging.manager.StageManager.status")
    def test_status_command(self, mock_status: MagicMock) -> None:
        from typer.testing import CliRunner

        from puppetstring.cli import app

        mock_status.return_value = [
            TargetStatus(
                name=TargetName.MCP,
                display_name="Vulnerable MCP Server",
                description="Test",
                port=3000,
                running=False,
                healthy=False,
            ),
        ]
        runner = CliRunner()
        result = runner.invoke(app, ["stage", "status", "-t", "mcp"])
        assert result.exit_code == 0
        assert "STOPPED" in result.output

    @patch("puppetstring.staging.manager.StageManager.down")
    def test_down_command(self, mock_down: MagicMock) -> None:
        from typer.testing import CliRunner

        from puppetstring.cli import app

        mock_down.return_value = [
            TargetStatus(
                name=TargetName.AGENT,
                display_name="Vulnerable AI Agent",
                description="Test",
                port=8000,
                running=False,
                healthy=False,
            ),
        ]
        runner = CliRunner()
        result = runner.invoke(app, ["stage", "down", "-t", "agent"])
        assert result.exit_code == 0

    @patch("puppetstring.staging.manager.StageManager.up")
    def test_up_unhealthy_exits_1(self, mock_up: MagicMock) -> None:
        from typer.testing import CliRunner

        from puppetstring.cli import app

        mock_up.return_value = [
            TargetStatus(
                name=TargetName.MCP,
                display_name="Vulnerable MCP Server",
                description="Test",
                port=3000,
                running=False,
                healthy=False,
            ),
        ]
        runner = CliRunner()
        result = runner.invoke(app, ["stage", "up", "-t", "mcp"])
        assert result.exit_code == 1


# ── TestStageRendering ───────────────────────────────────────────


class TestStageRendering:
    """Test terminal rendering of stage status."""

    def test_render_running_targets(self, capsys: pytest.CaptureFixture[str]) -> None:
        from puppetstring.reporting.terminal import render_stage_status

        statuses = [
            TargetStatus(
                name=TargetName.MCP,
                display_name="Vulnerable MCP Server",
                description="FastMCP server",
                port=3000,
                pid=100,
                running=True,
                healthy=True,
            ),
        ]
        render_stage_status(statuses, "up")
        # Rich output goes through its own console, so we just check no exception

    def test_render_stopped_targets(self, capsys: pytest.CaptureFixture[str]) -> None:
        from puppetstring.reporting.terminal import render_stage_status

        statuses = [
            TargetStatus(
                name=TargetName.AGENT,
                display_name="Vulnerable AI Agent",
                description="HTTP agent",
                port=8000,
                running=False,
                healthy=False,
            ),
        ]
        render_stage_status(statuses, "status")

    def test_render_empty_list(self) -> None:
        from puppetstring.reporting.terminal import render_stage_status

        render_stage_status([], "status")

    def test_render_mixed_status(self) -> None:
        from puppetstring.reporting.terminal import render_stage_status

        statuses = [
            TargetStatus(
                name=TargetName.MCP,
                display_name="MCP",
                description="MCP server",
                port=3000,
                pid=100,
                running=True,
                healthy=True,
            ),
            TargetStatus(
                name=TargetName.AGENT,
                display_name="Agent",
                description="HTTP agent",
                port=8000,
                running=False,
                healthy=False,
            ),
            TargetStatus(
                name=TargetName.SWARM,
                display_name="Swarm",
                description="Multi-agent",
                port=8001,
                pid=200,
                running=True,
                healthy=False,
            ),
        ]
        render_stage_status(statuses, "up")

    def test_render_down_action(self) -> None:
        from puppetstring.reporting.terminal import render_stage_status

        statuses = [
            TargetStatus(
                name=TargetName.MCP,
                display_name="MCP",
                description="Test",
                port=3000,
                running=False,
                healthy=False,
            ),
        ]
        render_stage_status(statuses, "down")
