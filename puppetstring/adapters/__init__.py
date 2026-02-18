"""Target adapters for MCP servers, HTTP agents, etc."""

from puppetstring.adapters.base import BaseAdapter
from puppetstring.adapters.mcp_adapter import MCPAdapter

__all__ = ["BaseAdapter", "MCPAdapter"]
