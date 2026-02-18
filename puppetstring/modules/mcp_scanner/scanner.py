"""MCP Scanner orchestrator — coordinates adapter + checks.

Usage:
    scanner = MCPScanner(target="mcp://localhost:3000", config=config)
    result = await scanner.run(scan_type="scan")
"""

from __future__ import annotations

from datetime import datetime

from puppetstring.adapters.mcp_adapter import MCPAdapter
from puppetstring.config import ScanConfig
from puppetstring.core.models import ScanResult
from puppetstring.modules.mcp_scanner.checks import (
    check_auth,
    check_config,
    check_input_validation,
    check_permissions,
    check_tool_enumeration,
)
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)

# Maps --type values to the checks they run
_SCAN_TYPE_MAP: dict[str, list[str]] = {
    "scan": ["tools", "auth", "permissions", "inputs", "config"],
    "all": ["tools", "auth", "permissions", "inputs", "config"],
    "tools": ["tools"],
    "auth": ["auth"],
    "permissions": ["tools", "permissions"],
    "inputs": ["tools", "inputs"],
    "config": ["config"],
}

MCP_SCAN_TYPES = set(_SCAN_TYPE_MAP.keys())


class MCPScanner:
    """Orchestrates an MCP server security scan."""

    def __init__(
        self,
        target: str,
        scan_config: ScanConfig | None = None,
    ) -> None:
        self.target = target
        self.config = scan_config or ScanConfig()

    async def run(self, scan_type: str = "scan") -> ScanResult:
        """Run the scan and return a ScanResult."""
        result = ScanResult(target=self.target, scan_type=scan_type)
        checks_to_run = _SCAN_TYPE_MAP.get(scan_type, _SCAN_TYPE_MAP["scan"])

        logger.info(
            "Starting MCP scan: target=%s type=%s checks=%s",
            self.target,
            scan_type,
            checks_to_run,
        )

        adapter = MCPAdapter(target=self.target, timeout=self.config.timeout)

        try:
            async with adapter:
                if "tools" in checks_to_run:
                    await check_tool_enumeration(adapter, result)

                if "auth" in checks_to_run:
                    await check_auth(adapter, result)

                if "permissions" in checks_to_run:
                    await check_permissions(adapter, result)

                if "inputs" in checks_to_run and self.config.check_inputs:
                    await check_input_validation(adapter, result)

                if "config" in checks_to_run:
                    await check_config(adapter, result)

        except Exception as e:  # noqa: BLE001
            logger.error("Scan failed: %s", e)
            result.error = str(e)

        result.finished_at = datetime.now()

        logger.info(
            "Scan complete: %d tools, %d findings in %.1fs",
            len(result.tools),
            len(result.findings),
            result.duration_seconds,
        )

        return result
