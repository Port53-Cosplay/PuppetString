"""Intentionally vulnerable MCP server for PuppetString testing.

WARNING: This server is DELIBERATELY INSECURE. It exists as a practice
target for the PuppetString scanner. DO NOT run this in production or
on a network-accessible interface.

Vulnerabilities by design:
    - No authentication required
    - No input validation or path restrictions
    - Raw shell command execution
    - Raw SQL query execution (simulated)
    - SSRF via unrestricted URL fetching
    - Environment variable disclosure
    - Unrestricted file write
    - A tool with no description (opacity)
    - No logging of tool invocations
    - Unencrypted transport (plain HTTP)
"""

from __future__ import annotations

import os
import subprocess  # noqa: S404
from pathlib import Path

from mcp.server.fastmcp import FastMCP

server = FastMCP(
    name="VulnerableMCPServer",
    instructions="A deliberately insecure MCP server for security testing.",
    host="127.0.0.1",
    port=3000,
)


# ── Tool 1: Path traversal ───────────────────────────────────────
@server.tool(description="Read any file from the filesystem. No restrictions.")
def read_file(path: str) -> str:
    """Read a file — no path validation whatsoever."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return f"Error reading file: {e}"


# ── Tool 2: Command injection ────────────────────────────────────
@server.tool(description="Execute a shell command and return its output.")
def run_command(command: str) -> str:
    """Execute arbitrary shell commands — maximum blast radius."""
    try:
        result = subprocess.run(  # noqa: S603, S602
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout + result.stderr
    except Exception as e:  # noqa: BLE001
        return f"Error executing command: {e}"


# ── Tool 3: SQL injection ────────────────────────────────────────
@server.tool(description="Run a SQL query against the database.")
def query_db(sql: str) -> str:
    """Accepts raw SQL — no parameterization or sanitization."""
    # Simulated — we don't actually have a database, but the tool's
    # interface is what the scanner analyzes.
    return f"[simulated] Executed SQL: {sql}"


# ── Tool 4: Directory listing (no restrictions) ──────────────────
@server.tool(description="List files in any directory.")
def list_directory(path: str) -> str:
    """List directory contents — no path restrictions."""
    try:
        entries = sorted(Path(path).iterdir())
        return "\n".join(str(e) for e in entries)
    except Exception as e:  # noqa: BLE001
        return f"Error listing directory: {e}"


# ── Tool 5: SSRF ─────────────────────────────────────────────────
@server.tool(description="Send an HTTP request to any URL and return the response.")
def send_request(url: str) -> str:
    """Fetch any URL — classic SSRF vector."""
    import httpx  # noqa: PLC0415

    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True)
        return f"Status: {resp.status_code}\n{resp.text[:2000]}"
    except Exception as e:  # noqa: BLE001
        return f"Error fetching URL: {e}"


# ── Tool 6: Info disclosure ──────────────────────────────────────
@server.tool(description="Get the value of any environment variable.")
def get_env(name: str) -> str:
    """Expose environment variables — credentials, secrets, paths."""
    value = os.environ.get(name)
    if value is None:
        return f"Environment variable '{name}' is not set."
    return value


# ── Tool 7: Unrestricted write ───────────────────────────────────
@server.tool(description="Write content to any file path.")
def write_file(path: str, content: str) -> str:
    """Write to any file — no restrictions, no confirmation."""
    try:
        Path(path).write_text(content, encoding="utf-8")
        return f"Successfully wrote {len(content)} bytes to {path}"
    except Exception as e:  # noqa: BLE001
        return f"Error writing file: {e}"


# ── Tool 8: Mystery tool (no description) ────────────────────────
@server.tool()
def mystery_tool(data: str) -> str:
    """This tool has NO description — a red flag for tool opacity."""
    return f"Processed: {data}"


if __name__ == "__main__":
    server.run(transport="sse")
