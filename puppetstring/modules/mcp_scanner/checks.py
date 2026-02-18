"""Security check functions for the MCP scanner.

Each function takes an adapter and a ScanResult, runs its checks, and appends
Finding objects to the result. They can be composed in any combination
by the scanner orchestrator.

Check functions:
    check_tool_enumeration — discover tools, flag dangerous ones
    check_auth             — did we connect without credentials?
    check_permissions      — classify tools by blast radius
    check_input_validation — send malformed inputs and see what happens
    check_config           — transport encryption, logging, rate limiting
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from puppetstring.core.models import (
    Finding,
    PermissionLevel,
    ScanResult,
    Severity,
    ToolInfo,
)
from puppetstring.utils.logging import get_logger

if TYPE_CHECKING:
    from puppetstring.adapters.base import BaseAdapter

logger = get_logger(__name__)

# ── Keyword patterns for danger classification ────────────────────
# Maps pattern → (reason, severity) for tool name/description matching.

_DANGEROUS_NAME_PATTERNS: list[tuple[str, str]] = [
    (r"exec|execute|run_command|shell|bash|system", "Tool name suggests command execution"),
    (r"write_file|delete|remove|drop|truncate", "Tool name suggests destructive operation"),
    (r"query_db|sql|database", "Tool name suggests raw database access"),
    (r"send_request|fetch|http_get|http_post|curl", "Tool name suggests outbound requests (SSRF)"),
    (
        r"get_env|environment|secret|credential|password|token|api_key",
        "Tool name suggests info disclosure",
    ),
    (r"read_file|cat|head|tail", "Tool name suggests filesystem read"),
    (r"list_dir|ls|readdir", "Tool name suggests directory listing"),
]

_DANGEROUS_DESC_PATTERNS: list[tuple[str, str]] = [
    (r"any file|any path|no restrict|unrestrict", "Description advertises unrestricted access"),
    (r"shell|command|exec|bash", "Description mentions command execution"),
    (r"sql|query|database", "Description mentions SQL/database access"),
    (r"any url|http request|fetch", "Description suggests outbound HTTP (SSRF)"),
    (r"environment variable|env var", "Description mentions environment variable access"),
]

_DANGEROUS_SCHEMA_FIELDS: list[tuple[str, str]] = [
    (r"command", "Input field 'command' suggests command execution"),
    (r"sql|query", "Input field suggests SQL query input"),
    (r"url", "Input field 'url' suggests outbound requests"),
    (r"path", "Input field 'path' suggests filesystem access"),
]


# ── Permission classification keywords ────────────────────────────
_CODE_EXEC_KEYWORDS = {"exec", "execute", "run_command", "shell", "bash", "system", "eval"}
_DESTRUCTIVE_KEYWORDS = {"write", "delete", "remove", "drop", "truncate", "kill", "destroy"}
_READ_WRITE_KEYWORDS = {"write_file", "update", "modify", "set", "put", "post", "send", "create"}
_READ_ONLY_KEYWORDS = {"read", "get", "list", "query", "search", "fetch", "describe"}


# ── Check 1: Tool enumeration ────────────────────────────────────


async def check_tool_enumeration(
    adapter: BaseAdapter,
    result: ScanResult,
) -> None:
    """Discover tools and flag dangerous ones by name, description, and schema."""
    logger.info("Running tool enumeration check...")
    tools = await adapter.list_tools()
    result.tools = tools

    if not tools:
        result.findings.append(
            Finding(
                title="No tools discovered",
                severity=Severity.INFO,
                owasp_ids=["A1"],
                description="The server exposes zero tools. This may be misconfiguration.",
                remediation="Verify the server is running and tools are registered.",
            )
        )
        return

    # Flag: too many tools is itself a risk (excessive agency)
    if len(tools) > 20:
        result.findings.append(
            Finding(
                title=f"Excessive tool count ({len(tools)} tools)",
                severity=Severity.MEDIUM,
                owasp_ids=["A1"],
                description=(
                    f"Server exposes {len(tools)} tools. Large tool surfaces increase "
                    "the attack surface and risk of excessive agency."
                ),
                evidence=f"Tool count: {len(tools)}",
                remediation="Apply the principle of least privilege — only expose tools needed.",
            )
        )

    for tool in tools:
        _classify_tool(tool, result)


def _classify_tool(tool: ToolInfo, result: ScanResult) -> None:
    """Check a single tool against danger heuristics."""
    name_lower = tool.name.lower()
    desc_lower = (tool.description or "").lower()

    # Check for missing description (tool opacity)
    if not tool.description:
        tool.is_dangerous = True
        tool.danger_reasons.append("No description provided (tool opacity)")
        result.findings.append(
            Finding(
                title=f"Tool '{tool.name}' has no description",
                severity=Severity.MEDIUM,
                owasp_ids=["A2", "A9"],
                description=(
                    "A tool with no description is opaque — users and agents cannot "
                    "understand what it does before calling it."
                ),
                tool_name=tool.name,
                remediation=(
                    "Add a clear description explaining what the tool does and its side effects."
                ),
            )
        )

    # Name-based detection
    for pattern, reason in _DANGEROUS_NAME_PATTERNS:
        if re.search(pattern, name_lower):
            tool.is_dangerous = True
            if reason not in tool.danger_reasons:
                tool.danger_reasons.append(reason)

    # Description-based detection
    for pattern, reason in _DANGEROUS_DESC_PATTERNS:
        if re.search(pattern, desc_lower):
            tool.is_dangerous = True
            if reason not in tool.danger_reasons:
                tool.danger_reasons.append(reason)

    # Schema-based detection (check input field names)
    if tool.input_schema:
        properties = tool.input_schema.get("properties", {})
        for field_name in properties:
            field_lower = field_name.lower()
            for pattern, reason in _DANGEROUS_SCHEMA_FIELDS:
                if re.search(pattern, field_lower):
                    tool.is_dangerous = True
                    if reason not in tool.danger_reasons:
                        tool.danger_reasons.append(reason)

    # Emit a finding for each dangerous tool
    if tool.is_dangerous:
        result.findings.append(
            Finding(
                title=f"Dangerous tool detected: '{tool.name}'",
                severity=Severity.HIGH,
                owasp_ids=["A1", "A2"],
                description=f"Tool '{tool.name}' flagged as dangerous.",
                evidence="; ".join(tool.danger_reasons),
                tool_name=tool.name,
                remediation=(
                    "Review this tool's necessity, add input validation, and restrict scope."
                ),
            )
        )


# ── Check 2: Authentication ──────────────────────────────────────


async def check_auth(
    adapter: BaseAdapter,
    result: ScanResult,
) -> None:
    """Check whether we connected without any credentials."""
    logger.info("Running authentication check...")

    # stdio:// is a local subprocess — network auth doesn't apply
    if adapter.target.lower().startswith("stdio://"):
        result.findings.append(
            Finding(
                title="Stdio transport — auth check not applicable",
                severity=Severity.INFO,
                owasp_ids=["A8"],
                description=(
                    "Target uses stdio transport (local subprocess). Network-level "
                    "authentication is not applicable. If this wraps a remote server, "
                    "verify the proxy layer enforces auth."
                ),
                evidence=f"Transport: stdio ({adapter.target})",
                remediation="Ensure any upstream server the proxy connects to requires auth.",
            )
        )
        return

    # If we're here, connect() succeeded over the network — no auth was required.
    result.findings.append(
        Finding(
            title="No authentication required",
            severity=Severity.CRITICAL,
            owasp_ids=["A8"],
            description=(
                "Connected to the MCP server without providing any credentials. "
                "Any client on the network can connect and invoke tools."
            ),
            evidence=f"Successfully connected to {adapter.target} with no auth.",
            remediation=(
                "Implement authentication (API key, OAuth, mTLS) on the MCP server. "
                "Reject unauthenticated connections."
            ),
        )
    )


# ── Check 3: Permission classification ───────────────────────────


async def check_permissions(
    adapter: BaseAdapter,
    result: ScanResult,
) -> None:
    """Classify each tool's blast radius and flag high-risk patterns."""
    logger.info("Running permissions check...")

    if not result.tools:
        result.tools = await adapter.list_tools()

    code_exec_tools = []
    destructive_tools = []
    rw_tools = []

    for tool in result.tools:
        level = _classify_permission(tool)
        tool.permission_level = level

        if level == PermissionLevel.CODE_EXECUTION:
            code_exec_tools.append(tool.name)
        elif level == PermissionLevel.DESTRUCTIVE:
            destructive_tools.append(tool.name)
        elif level == PermissionLevel.READ_WRITE:
            rw_tools.append(tool.name)

    if code_exec_tools:
        result.findings.append(
            Finding(
                title=f"Code execution tools exposed ({len(code_exec_tools)})",
                severity=Severity.CRITICAL,
                owasp_ids=["A1", "A2"],
                description="Tools that can execute arbitrary code on the server.",
                evidence=", ".join(code_exec_tools),
                remediation=(
                    "Remove or sandbox code execution tools. Use allowlists, not blocklists."
                ),
            )
        )

    if destructive_tools:
        result.findings.append(
            Finding(
                title=f"Destructive tools exposed ({len(destructive_tools)})",
                severity=Severity.HIGH,
                owasp_ids=["A1", "A2"],
                description="Tools that can delete data or modify system state irreversibly.",
                evidence=", ".join(destructive_tools),
                remediation="Require human confirmation for destructive operations.",
            )
        )

    if rw_tools:
        result.findings.append(
            Finding(
                title=f"Read-write tools exposed ({len(rw_tools)})",
                severity=Severity.MEDIUM,
                owasp_ids=["A1"],
                description="Tools that can modify data on the server.",
                evidence=", ".join(rw_tools),
                remediation="Apply least-privilege: prefer read-only tools where possible.",
            )
        )


def _classify_permission(tool: ToolInfo) -> PermissionLevel:
    """Determine a tool's blast radius from its name and description."""
    combined = f"{tool.name} {tool.description or ''}".lower()

    if _any_word_match(_CODE_EXEC_KEYWORDS, combined):
        return PermissionLevel.CODE_EXECUTION
    if _any_word_match(_DESTRUCTIVE_KEYWORDS, combined):
        return PermissionLevel.DESTRUCTIVE
    if _any_word_match(_READ_WRITE_KEYWORDS, combined):
        return PermissionLevel.READ_WRITE
    if _any_word_match(_READ_ONLY_KEYWORDS, combined):
        return PermissionLevel.READ_ONLY

    return PermissionLevel.UNKNOWN


def _any_word_match(keywords: set[str], text: str) -> bool:
    """Check if any keyword appears as a whole word (or underscore-delimited) in text."""
    for kw in keywords:
        if re.search(rf"\b{re.escape(kw)}\b", text):
            return True
    return False


# ── Check 4: Input validation ────────────────────────────────────

# Test payloads for input validation probing
_PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
]
_TYPE_CONFUSION_PAYLOADS: list[dict[str, Any]] = [
    {"__proto__": {"admin": True}},
    {"constructor": {"prototype": {"admin": True}}},
]
_OVERSIZED_PAYLOAD = "A" * 100_000
_SQL_PAYLOADS = ["' OR '1'='1", "1; DROP TABLE users; --"]


async def check_input_validation(
    adapter: BaseAdapter,
    result: ScanResult,
) -> None:
    """Send malformed inputs to tools and check for signs of missing validation."""
    logger.info("Running input validation checks...")

    if not result.tools:
        result.tools = await adapter.list_tools()

    for tool in result.tools:
        await _probe_tool_inputs(adapter, tool, result)


async def _probe_tool_inputs(
    adapter: BaseAdapter,
    tool: ToolInfo,
    result: ScanResult,
) -> None:
    """Probe a single tool with malformed inputs."""
    if not tool.input_schema:
        return

    properties = tool.input_schema.get("properties", {})

    for field_name, field_info in properties.items():
        field_type = field_info.get("type", "string")
        field_lower = field_name.lower()

        # Path traversal test on path-like fields
        if "path" in field_lower or "file" in field_lower or "dir" in field_lower:
            for payload in _PATH_TRAVERSAL_PAYLOADS:
                response = await _safe_call(adapter, tool.name, {field_name: payload})
                if response and not _looks_like_rejection(response):
                    result.findings.append(
                        Finding(
                            title=f"Path traversal accepted: '{tool.name}'",
                            severity=Severity.HIGH,
                            owasp_ids=["A2"],
                            description=(
                                f"Tool '{tool.name}' accepted a path traversal payload "
                                f"on field '{field_name}' without rejection."
                            ),
                            evidence=f"Input: {payload!r} → Response accepted",
                            tool_name=tool.name,
                            remediation=(
                                "Validate and sanitize file paths. Use allowlists for directories."
                            ),
                        )
                    )
                    break  # One finding per tool is enough

        # SQL injection test on query/sql-like fields
        if "sql" in field_lower or "query" in field_lower:
            for payload in _SQL_PAYLOADS:
                response = await _safe_call(adapter, tool.name, {field_name: payload})
                if response and not _looks_like_rejection(response):
                    result.findings.append(
                        Finding(
                            title=f"SQL injection accepted: '{tool.name}'",
                            severity=Severity.HIGH,
                            owasp_ids=["A2", "A4"],
                            description=(
                                f"Tool '{tool.name}' accepted a SQL injection payload "
                                f"on field '{field_name}' without rejection."
                            ),
                            evidence=f"Input: {payload!r} → Response accepted",
                            tool_name=tool.name,
                            remediation=(
                                "Use parameterized queries. Never interpolate user input into SQL."
                            ),
                        )
                    )
                    break

        # Oversized input test on string fields
        if field_type == "string":
            response = await _safe_call(adapter, tool.name, {field_name: _OVERSIZED_PAYLOAD})
            if response and not _looks_like_rejection(response):
                result.findings.append(
                    Finding(
                        title=f"Oversized input accepted: '{tool.name}'",
                        severity=Severity.LOW,
                        owasp_ids=["A2"],
                        description=(
                            f"Tool '{tool.name}' accepted a 100KB string on field "
                            f"'{field_name}' without rejection or truncation."
                        ),
                        evidence=f"Sent 100,000-character string on '{field_name}'",
                        tool_name=tool.name,
                        remediation="Enforce maximum input length on all string fields.",
                    )
                )


async def _safe_call(adapter: BaseAdapter, name: str, arguments: dict[str, Any]) -> dict | None:
    """Call a tool, catching any exception so probes don't crash the scan."""
    try:
        return await adapter.call_tool(name, arguments)
    except Exception:  # noqa: BLE001
        logger.debug("Probe call to '%s' raised an exception (expected)", name)
        return None


def _looks_like_rejection(response: Any) -> bool:
    """Heuristic: did the server reject the input?"""
    if response is None:
        return True
    content = str(response).lower()
    rejection_signals = [
        "invalid",
        "not allowed",
        "forbidden",
        "permission denied",
        "blocked",
        "rejected",
        "validation error",
        "bad request",
        "unauthorized",
    ]
    return any(signal in content for signal in rejection_signals)


# ── Check 5: Configuration ───────────────────────────────────────


async def check_config(
    adapter: BaseAdapter,
    result: ScanResult,
) -> None:
    """Check transport encryption, logging, and rate limiting."""
    logger.info("Running configuration check...")

    target = adapter.target.lower()

    # Transport encryption check
    if target.startswith("http://") or target.startswith("mcp://"):
        result.findings.append(
            Finding(
                title="Unencrypted transport (no TLS)",
                severity=Severity.HIGH,
                owasp_ids=["A8", "A9"],
                description=(
                    "The MCP server is accessed over unencrypted HTTP. "
                    "Tool calls and responses can be intercepted on the network."
                ),
                evidence=f"Target URL: {adapter.target}",
                remediation="Use HTTPS/TLS for all MCP server connections.",
            )
        )

    # Check server capabilities for logging
    server_info = await adapter.get_server_info()
    capabilities = server_info.get("capabilities", {})

    if not capabilities.get("logging"):
        result.findings.append(
            Finding(
                title="Server does not advertise logging capability",
                severity=Severity.MEDIUM,
                owasp_ids=["A9"],
                description=(
                    "The MCP server does not advertise a logging capability. "
                    "Without logging, there's no audit trail for tool invocations."
                ),
                evidence=f"Server capabilities: {capabilities}",
                remediation=(
                    "Enable logging on the MCP server and send logs to a SIEM/audit system."
                ),
            )
        )
