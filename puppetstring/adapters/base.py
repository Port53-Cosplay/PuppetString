"""Abstract base adapter that all target adapters must implement.

Every target type PuppetString can connect to (MCP server, HTTP agent, etc.)
gets an adapter class that follows this blueprint. The scanner and fuzzer
work with the abstract interface so they don't care what's behind it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from puppetstring.core.models import ToolInfo


class BaseAdapter(ABC):
    """Blueprint for all target adapters.

    Usage:
        async with SomeAdapter(target_url) as adapter:
            tools = await adapter.list_tools()
            result = await adapter.call_tool("read_file", {"path": "/etc/passwd"})
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self._connected = False

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the target."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Cleanly close the connection."""

    @abstractmethod
    async def list_tools(self) -> list[ToolInfo]:
        """Discover all tools exposed by the target."""

    @abstractmethod
    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Invoke a tool and return its result."""

    @abstractmethod
    async def get_server_info(self) -> dict[str, Any]:
        """Return metadata about the server (name, version, capabilities)."""

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def __aenter__(self) -> BaseAdapter:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()
