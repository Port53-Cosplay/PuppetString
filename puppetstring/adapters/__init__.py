"""Target adapters for MCP servers, HTTP agents, multi-agent swarms, etc.

Three families of adapters:

    BaseAdapter    — For tool servers (MCP). You call tools directly.
    AgentAdapter   — For AI agents. You send messages, they call tools.
    SwarmAdapter   — For multi-agent systems. You interact at the swarm level.

LangChainAdapter is lazy-imported to avoid pulling in langchain unless needed.
"""

from puppetstring.adapters.agent_adapter import AgentAdapter
from puppetstring.adapters.base import BaseAdapter
from puppetstring.adapters.http_adapter import HTTPAgentAdapter
from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter
from puppetstring.adapters.mcp_adapter import MCPAdapter
from puppetstring.adapters.swarm_adapter import SwarmAdapter

__all__ = [
    "AgentAdapter",
    "BaseAdapter",
    "HTTPAgentAdapter",
    "HTTPSwarmAdapter",
    "LangChainAdapter",
    "MCPAdapter",
    "SwarmAdapter",
]


def __getattr__(name: str):  # noqa: ANN204
    """Lazy import for LangChainAdapter to avoid loading langchain eagerly."""
    if name == "LangChainAdapter":
        from puppetstring.adapters.langchain_adapter import LangChainAdapter

        return LangChainAdapter
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
