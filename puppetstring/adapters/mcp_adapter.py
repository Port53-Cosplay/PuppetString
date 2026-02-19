"""MCP adapter — connects to MCP servers via SSE or stdio transport.

Auto-detects which transport to use based on the target URL:
    mcp://host:port  → SSE (rewritten to http://host:port/sse)
    http://...       → SSE (used as-is, /sse appended if missing)
    stdio://command  → stdio (spawns the command as a subprocess)
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse, urlunparse

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import Implementation

from puppetstring.adapters.base import BaseAdapter
from puppetstring.core.models import ToolInfo
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


class MCPAdapter(BaseAdapter):
    """Adapter for MCP servers using the official MCP Python SDK.

    Manages the transport + session lifecycle via AsyncExitStack so that
    connect() and disconnect() can be called separately (not just via
    async-with nesting).
    """

    def __init__(self, target: str, timeout: int = 30) -> None:
        super().__init__(target)
        self.timeout = timeout
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None
        self._server_info: dict[str, Any] = {}

    async def connect(self) -> None:
        """Open transport, create session, run MCP initialize handshake."""
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()

        parsed = urlparse(self.target)
        scheme = parsed.scheme.lower()

        if scheme in ("mcp", "http", "https"):
            read_stream, write_stream = await self._connect_sse(parsed)
        elif scheme == "stdio":
            read_stream, write_stream = await self._connect_stdio(parsed)
        else:
            msg = f"Unsupported scheme '{scheme}' in target URL: {self.target}"
            raise ValueError(msg)

        self._session = await self._stack.enter_async_context(
            ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=self.timeout),
                client_info=Implementation(name="PuppetString", version="0.1.0"),
            )
        )

        init_result = await self._session.initialize()
        self._server_info = {
            "server_name": getattr(init_result, "serverInfo", {})
            if not hasattr(init_result, "serverInfo")
            else (init_result.serverInfo.name if init_result.serverInfo else "unknown"),
            "protocol_version": getattr(init_result, "protocolVersion", "unknown"),
            "capabilities": _caps_to_dict(getattr(init_result, "capabilities", None)),
        }
        self._connected = True
        logger.info("Connected to MCP server: %s", _sanitize_url(self.target))

    async def _connect_sse(self, parsed: Any) -> tuple:
        """Set up SSE transport and return (read_stream, write_stream)."""
        if parsed.scheme == "mcp":
            host = parsed.hostname or "localhost"
            port = parsed.port or 3000
            url = f"http://{host}:{port}/sse"
        else:
            url = self.target
            if not url.rstrip("/").endswith("/sse"):
                url = url.rstrip("/") + "/sse"

        logger.debug("SSE transport → %s", url)
        return await self._stack.enter_async_context(  # type: ignore[union-attr]
            sse_client(url=url, timeout=self.timeout)
        )

    async def _connect_stdio(self, parsed: Any) -> tuple:
        """Set up stdio transport and return (read_stream, write_stream)."""
        # stdio://python -m my_server  →  command="python", args=["-m", "my_server"]
        import shlex  # noqa: PLC0415

        raw = self.target.removeprefix("stdio://")
        parts = shlex.split(raw)
        if not parts:
            msg = f"Empty command in stdio target: {self.target}"
            raise ValueError(msg)
        command = parts[0]
        args = parts[1:]

        logger.debug("Stdio transport → %s %s", command, args)
        return await self._stack.enter_async_context(  # type: ignore[union-attr]
            stdio_client(StdioServerParameters(command=command, args=args))
        )

    async def disconnect(self) -> None:
        """Tear down session and transport."""
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
        self._session = None
        self._connected = False
        logger.info("Disconnected from MCP server: %s", _sanitize_url(self.target))

    async def list_tools(self) -> list[ToolInfo]:
        """Enumerate all tools exposed by the server (handles pagination)."""
        if self._session is None:
            msg = "Not connected — call connect() first"
            raise RuntimeError(msg)

        all_tools: list[ToolInfo] = []
        cursor: str | None = None

        while True:
            result = await self._session.list_tools(cursor=cursor)
            for t in result.tools:
                all_tools.append(
                    ToolInfo(
                        name=t.name,
                        description=t.description,
                        input_schema=t.inputSchema if t.inputSchema else None,
                        output_schema=getattr(t, "outputSchema", None),
                        annotations=_annotations_to_dict(getattr(t, "annotations", None)),
                    )
                )
            cursor = getattr(result, "nextCursor", None)
            if not cursor:
                break

        logger.info("Discovered %d tools", len(all_tools))
        return all_tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call a tool and return its result content."""
        if self._session is None:
            msg = "Not connected — call connect() first"
            raise RuntimeError(msg)

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments),
                timeout=self.timeout,
            )
        except TimeoutError:
            logger.warning("Tool call '%s' timed out after %ds", name, self.timeout)
            return {"error": "timeout", "tool": name}

        # Extract text content from the result
        texts = []
        for block in result.content:
            if hasattr(block, "text"):
                texts.append(block.text)
        return {
            "is_error": result.isError,
            "content": "\n".join(texts) if texts else str(result.content),
        }

    async def get_server_info(self) -> dict[str, Any]:
        """Return metadata captured during the initialize handshake."""
        return self._server_info


def _sanitize_url(url: str) -> str:
    """Strip credentials from a URL for safe logging."""
    try:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            port_suffix = f":{parsed.port}" if parsed.port else ""
            safe = parsed._replace(netloc=f"***@{parsed.hostname}{port_suffix}")
            return urlunparse(safe)
    except Exception:  # noqa: BLE001
        logger.debug("Failed to sanitize URL, returning as-is")
    return url


def _caps_to_dict(caps: Any) -> dict[str, bool]:
    """Convert ServerCapabilities to a simple dict of capability → True."""
    if caps is None:
        return {}
    result = {}
    for field in ("tools", "resources", "prompts", "logging"):
        if getattr(caps, field, None) is not None:
            result[field] = True
    return result


def _annotations_to_dict(annotations: Any) -> dict | None:
    """Convert ToolAnnotations to a plain dict, or None."""
    if annotations is None:
        return None
    try:
        return annotations.model_dump(exclude_none=True)
    except AttributeError:
        return None
