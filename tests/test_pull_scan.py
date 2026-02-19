"""Tests for the MCP scanner (Phase 1).

Uses a MockMCPAdapter so tests run fast without a real server.
Tests cover:
    - Data models (ToolInfo, Finding, ScanResult)
    - Each check function (enumeration, auth, permissions, input validation, config)
    - Scanner orchestrator
    - CLI integration via CliRunner
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from puppetstring.cli import app
from puppetstring.core.models import (
    Finding,
    PermissionLevel,
    ScanResult,
    Severity,
    ToolInfo,
)
from puppetstring.modules.mcp_scanner.checks import (
    check_auth,
    check_config,
    check_input_validation,
    check_permissions,
    check_tool_enumeration,
)

runner = CliRunner()


# ── Fixtures ─────────────────────────────────────────────────────

MOCK_TOOLS = [
    ToolInfo(
        name="read_file",
        description="Read any file from the filesystem. No restrictions.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
    ToolInfo(
        name="run_command",
        description="Execute a shell command and return its output.",
        input_schema={
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    ),
    ToolInfo(
        name="query_db",
        description="Run a SQL query against the database.",
        input_schema={
            "type": "object",
            "properties": {"sql": {"type": "string"}},
            "required": ["sql"],
        },
    ),
    ToolInfo(
        name="list_directory",
        description="List files in any directory.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    ),
    ToolInfo(
        name="send_request",
        description="Send an HTTP request to any URL and return the response.",
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    ),
    ToolInfo(
        name="get_env",
        description="Get the value of any environment variable.",
        input_schema={
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    ),
    ToolInfo(
        name="write_file",
        description="Write content to any file path.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    ),
    ToolInfo(
        name="mystery_tool",
        description=None,
        input_schema={
            "type": "object",
            "properties": {"data": {"type": "string"}},
            "required": ["data"],
        },
    ),
]


class MockMCPAdapter:
    """Fake adapter that returns canned data for testing."""

    def __init__(self, target: str = "mcp://localhost:3000") -> None:
        self.target = target
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_tools(self) -> list[ToolInfo]:
        return list(MOCK_TOOLS)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        # Simulate a server that accepts everything (no validation)
        return {"is_error": False, "content": f"OK: {name}({arguments})"}

    async def get_server_info(self) -> dict[str, Any]:
        return {
            "server_name": "VulnerableMCPServer",
            "protocol_version": "2024-11-05",
            "capabilities": {},  # No logging capability
        }

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def __aenter__(self) -> MockMCPAdapter:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()


@pytest.fixture
def mock_adapter() -> MockMCPAdapter:
    return MockMCPAdapter()


@pytest.fixture
def empty_result() -> ScanResult:
    return ScanResult(target="mcp://localhost:3000", scan_type="scan")


# ── Model tests ──────────────────────────────────────────────────


class TestModels:
    def test_tool_info_defaults(self) -> None:
        tool = ToolInfo(name="test")
        assert not tool.is_dangerous
        assert tool.danger_reasons == []
        assert tool.permission_level == PermissionLevel.UNKNOWN

    def test_finding_sort_key(self) -> None:
        critical = Finding(title="A", severity=Severity.CRITICAL)
        low = Finding(title="B", severity=Severity.LOW)
        assert critical.sort_key < low.sort_key

    def test_scan_result_summary(self) -> None:
        result = ScanResult(
            target="test",
            scan_type="scan",
            findings=[
                Finding(title="A", severity=Severity.CRITICAL),
                Finding(title="B", severity=Severity.HIGH),
                Finding(title="C", severity=Severity.HIGH),
                Finding(title="D", severity=Severity.MEDIUM),
            ],
        )
        assert result.summary == {
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 0,
            "info": 0,
        }

    def test_scan_result_duration(self) -> None:
        now = datetime.now()
        result = ScanResult(
            target="test",
            scan_type="scan",
            started_at=now,
            finished_at=now + timedelta(seconds=5),
        )
        assert result.duration_seconds == pytest.approx(5.0, abs=0.1)

    def test_scan_result_sorted_findings(self) -> None:
        result = ScanResult(
            target="test",
            scan_type="scan",
            findings=[
                Finding(title="low", severity=Severity.LOW),
                Finding(title="crit", severity=Severity.CRITICAL),
                Finding(title="med", severity=Severity.MEDIUM),
            ],
        )
        sorted_f = result.sorted_findings
        assert sorted_f[0].title == "crit"
        assert sorted_f[1].title == "med"
        assert sorted_f[2].title == "low"


# ── Check function tests ─────────────────────────────────────────


class TestCheckToolEnumeration:
    async def test_flags_dangerous_tools(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_tool_enumeration(mock_adapter, empty_result)
        assert len(empty_result.tools) == 8
        dangerous_names = {t.name for t in empty_result.tools if t.is_dangerous}
        assert "run_command" in dangerous_names
        assert "read_file" in dangerous_names
        assert "query_db" in dangerous_names
        assert "write_file" in dangerous_names
        assert "send_request" in dangerous_names

    async def test_flags_missing_description(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_tool_enumeration(mock_adapter, empty_result)
        mystery = next(t for t in empty_result.tools if t.name == "mystery_tool")
        assert mystery.is_dangerous
        assert any("No description" in r for r in mystery.danger_reasons)

    async def test_produces_findings(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_tool_enumeration(mock_adapter, empty_result)
        # Should have findings for each dangerous tool + the no-description tool
        assert len(empty_result.findings) >= 5

    async def test_empty_tools(self, empty_result: ScanResult) -> None:
        adapter = MockMCPAdapter()
        adapter.list_tools = AsyncMock(return_value=[])  # type: ignore[method-assign]
        await check_tool_enumeration(adapter, empty_result)
        assert any("No tools" in f.title for f in empty_result.findings)


class TestCheckAuth:
    async def test_flags_no_auth(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_auth(mock_adapter, empty_result)
        assert len(empty_result.findings) == 1
        assert empty_result.findings[0].severity == Severity.CRITICAL
        assert "A8" in empty_result.findings[0].owasp_ids


class TestCheckPermissions:
    async def test_classifies_tools(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_permissions(mock_adapter, empty_result)
        run_cmd = next(t for t in empty_result.tools if t.name == "run_command")
        assert run_cmd.permission_level == PermissionLevel.CODE_EXECUTION

        read_f = next(t for t in empty_result.tools if t.name == "read_file")
        assert read_f.permission_level == PermissionLevel.READ_ONLY

        write_f = next(t for t in empty_result.tools if t.name == "write_file")
        assert write_f.permission_level in (
            PermissionLevel.READ_WRITE,
            PermissionLevel.DESTRUCTIVE,
        )

    async def test_produces_permission_findings(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_permissions(mock_adapter, empty_result)
        # Should have findings for code execution + destructive/read-write
        severity_titles = [f.title for f in empty_result.findings]
        assert any("Code execution" in t for t in severity_titles)


class TestCheckInputValidation:
    async def test_detects_path_traversal(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        empty_result.tools = list(MOCK_TOOLS)
        await check_input_validation(mock_adapter, empty_result)
        path_findings = [f for f in empty_result.findings if "Path traversal" in f.title]
        assert len(path_findings) >= 1

    async def test_detects_sql_injection(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        empty_result.tools = list(MOCK_TOOLS)
        await check_input_validation(mock_adapter, empty_result)
        sql_findings = [f for f in empty_result.findings if "SQL injection" in f.title]
        assert len(sql_findings) >= 1

    async def test_detects_oversized_input(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        empty_result.tools = list(MOCK_TOOLS)
        await check_input_validation(mock_adapter, empty_result)
        oversized = [f for f in empty_result.findings if "Oversized" in f.title]
        assert len(oversized) >= 1


class TestCheckConfig:
    async def test_flags_unencrypted_transport(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_config(mock_adapter, empty_result)
        tls_findings = [f for f in empty_result.findings if "Unencrypted" in f.title]
        assert len(tls_findings) == 1

    async def test_flags_missing_logging(
        self, mock_adapter: MockMCPAdapter, empty_result: ScanResult
    ) -> None:
        await check_config(mock_adapter, empty_result)
        log_findings = [f for f in empty_result.findings if "logging" in f.title.lower()]
        assert len(log_findings) == 1

    async def test_https_no_tls_finding(self, empty_result: ScanResult) -> None:
        adapter = MockMCPAdapter(target="https://localhost:3000")
        await check_config(adapter, empty_result)
        tls_findings = [f for f in empty_result.findings if "Unencrypted" in f.title]
        assert len(tls_findings) == 0


# ── Scanner orchestrator test ─────────────────────────────────────


class TestMCPScanner:
    async def test_full_scan_with_mock(self) -> None:
        with patch(
            "puppetstring.modules.mcp_scanner.scanner.MCPAdapter",
            return_value=MockMCPAdapter(),
        ):
            from puppetstring.modules.mcp_scanner.scanner import MCPScanner

            scanner = MCPScanner(target="mcp://localhost:3000")
            result = await scanner.run(scan_type="scan")

            assert result.target == "mcp://localhost:3000"
            assert result.scan_type == "scan"
            assert len(result.tools) == 8
            assert len(result.findings) >= 10  # Many checks produce multiple findings
            assert result.finished_at is not None
            assert result.error is None

    async def test_tools_only_scan(self) -> None:
        with patch(
            "puppetstring.modules.mcp_scanner.scanner.MCPAdapter",
            return_value=MockMCPAdapter(),
        ):
            from puppetstring.modules.mcp_scanner.scanner import MCPScanner

            scanner = MCPScanner(target="mcp://localhost:3000")
            result = await scanner.run(scan_type="tools")

            assert len(result.tools) == 8
            # Should NOT have auth findings (auth check not run)
            auth_findings = [f for f in result.findings if "authentication" in f.title.lower()]
            assert len(auth_findings) == 0

    async def test_auth_only_scan(self) -> None:
        with patch(
            "puppetstring.modules.mcp_scanner.scanner.MCPAdapter",
            return_value=MockMCPAdapter(),
        ):
            from puppetstring.modules.mcp_scanner.scanner import MCPScanner

            scanner = MCPScanner(target="mcp://localhost:3000")
            result = await scanner.run(scan_type="auth")

            # Should have auth finding but no tool enumeration
            assert len(result.tools) == 0
            auth_findings = [f for f in result.findings if "authentication" in f.title.lower()]
            assert len(auth_findings) == 1


# ── CLI integration tests ─────────────────────────────────────────


class TestCLIPull:
    def test_pull_scan_type_recognized(self) -> None:
        """The pull command recognizes MCP scan types without crashing."""
        with patch(
            "puppetstring.cli.asyncio.run",
            return_value=ScanResult(
                target="mcp://localhost:3000",
                scan_type="scan",
                finished_at=datetime.now(),
            ),
        ):
            result = runner.invoke(app, ["pull", "-t", "mcp://localhost:3000", "--type", "scan"])
            assert result.exit_code == 0

    def test_pull_fuzz_type_connection_failure(self) -> None:
        """Fuzz types exit with error when agent is unreachable."""
        result = runner.invoke(
            app,
            ["pull", "-t", "http://localhost:8000", "--type", "tool-abuse"],
        )
        # Exits 1 because the target agent isn't running
        assert result.exit_code == 1
        assert "connection failed" in result.output.lower()

    def test_pull_with_error_exits_nonzero(self) -> None:
        """If the scan has an error, exit code should be 1."""
        with patch(
            "puppetstring.cli.asyncio.run",
            return_value=ScanResult(
                target="mcp://localhost:9999",
                scan_type="scan",
                error="Connection refused",
                finished_at=datetime.now(),
            ),
        ):
            result = runner.invoke(app, ["pull", "-t", "mcp://localhost:9999", "--type", "scan"])
            assert result.exit_code == 1


# ── Reporter test ─────────────────────────────────────────────────


class TestTerminalReporter:
    def test_render_does_not_crash(self) -> None:
        """Rendering a populated ScanResult should not raise."""
        from puppetstring.reporting.terminal import render_scan_result

        result = ScanResult(
            target="mcp://localhost:3000",
            scan_type="scan",
            tools=list(MOCK_TOOLS),
            findings=[
                Finding(
                    title="Test critical",
                    severity=Severity.CRITICAL,
                    owasp_ids=["A1"],
                ),
                Finding(
                    title="Test low",
                    severity=Severity.LOW,
                    owasp_ids=["A9"],
                ),
            ],
            finished_at=datetime.now(),
        )
        # Should not raise
        render_scan_result(result)

    def test_render_with_error(self) -> None:
        """Rendering a result with an error should show the error."""
        from io import StringIO

        from rich.console import Console

        from puppetstring.reporting import terminal

        buf = StringIO()
        terminal.console = Console(file=buf, force_terminal=True)

        result = ScanResult(
            target="mcp://localhost:9999",
            scan_type="scan",
            error="Connection refused",
            finished_at=datetime.now(),
        )
        terminal.render_scan_result(result)
        output = buf.getvalue()
        assert "Connection refused" in output
