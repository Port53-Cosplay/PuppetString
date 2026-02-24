"""HTTP adapter for multi-agent swarm systems that expose a REST API.

Same relationship as HTTPAgentAdapter → AgentAdapter, but for swarms:
HTTPSwarmAdapter → SwarmAdapter. It maps each SwarmAdapter method to an
HTTP endpoint call.

Target API shape (matches examples/multi_agent_demo/server.py):

    GET  /health                → server info
    GET  /agents                → list agents
    GET  /agents/{id}           → single agent
    POST /agents/{id}/message   → send message as another agent
    GET  /memory                → all shared memory
    GET  /memory/{namespace}    → one namespace
    POST /memory                → write to shared memory
    GET  /delegation            → delegation history
    POST /delegation            → delegate task
    POST /agents/inject         → inject new agent
    DELETE /agents/{id}         → remove agent
    POST /reset                 → reset swarm

Usage:

    async with HTTPSwarmAdapter("http://localhost:8001") as swarm:
        agents = await swarm.list_agents()
        obs = await swarm.send_message_as("researcher", "executor", "run ls")
        print(obs.tool_calls)
"""

from __future__ import annotations

from typing import Any

import httpx

from puppetstring.adapters.swarm_adapter import SwarmAdapter
from puppetstring.core.models import ToolCall
from puppetstring.modules.agent_swarm.models import AgentInfo, SwarmObservation
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


class HTTPSwarmAdapter(SwarmAdapter):
    """Adapter for multi-agent swarms accessible via HTTP REST APIs."""

    def __init__(
        self,
        target: str,
        *,
        timeout: int = 60,
        **kwargs: Any,
    ) -> None:
        super().__init__(target, **kwargs)
        self._base_url = target.rstrip("/")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # ── Connection lifecycle ──────────────────────────────────────

    async def connect(self) -> None:
        """Create HTTP client and verify the swarm is reachable."""
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(self._timeout),
        )

        try:
            resp = await self._client.get("/health")
            resp.raise_for_status()
            data = resp.json()
            logger.info(
                "Connected to swarm at %s (%d agents)",
                self._base_url,
                data.get("agent_count", 0),
            )
        except httpx.ConnectError as exc:
            await self._client.aclose()
            self._client = None
            msg = f"Cannot connect to swarm at {self._base_url}: {exc}"
            raise ConnectionError(msg) from exc

        self._connected = True

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._connected = False
        logger.info("Disconnected from swarm at %s", self._base_url)

    def _ensure_client(self) -> httpx.AsyncClient:
        """Return the client or raise if not connected."""
        if self._client is None:
            msg = "Not connected — call connect() first"
            raise RuntimeError(msg)
        return self._client

    # ── Agent discovery ───────────────────────────────────────────

    async def list_agents(self) -> list[AgentInfo]:
        """GET /agents → list of AgentInfo."""
        client = self._ensure_client()
        resp = await client.get("/agents")
        resp.raise_for_status()
        data = resp.json()
        return [AgentInfo(**agent) for agent in data]

    async def get_agent_info(self, agent_id: str) -> AgentInfo:
        """GET /agents/{id} → AgentInfo."""
        client = self._ensure_client()
        resp = await client.get(f"/agents/{agent_id}")
        resp.raise_for_status()
        return AgentInfo(**resp.json())

    # ── Cross-agent messaging ─────────────────────────────────────

    async def send_message_as(
        self,
        sender_id: str,
        recipient_id: str,
        message: str,
    ) -> SwarmObservation:
        """POST /agents/{recipient}/message → SwarmObservation."""
        client = self._ensure_client()
        resp = await client.post(
            f"/agents/{recipient_id}/message",
            json={"sender_id": sender_id, "message": message},
        )
        resp.raise_for_status()
        data = resp.json()
        return self._parse_observation(data.get("observation", data))

    # ── Shared memory ─────────────────────────────────────────────

    async def read_shared_memory(
        self,
        namespace: str = "default",
    ) -> dict[str, Any]:
        """GET /memory/{namespace} → dict."""
        client = self._ensure_client()
        resp = await client.get(f"/memory/{namespace}")
        resp.raise_for_status()
        return resp.json()

    async def write_shared_memory(
        self,
        key: str,
        value: str,
        namespace: str = "default",
    ) -> bool:
        """POST /memory → bool."""
        client = self._ensure_client()
        resp = await client.post(
            "/memory",
            json={"key": key, "value": value, "namespace": namespace},
        )
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("written", False))

    # ── Delegation ────────────────────────────────────────────────

    async def get_delegation_chain(
        self,
        task_id: str = "",
    ) -> list[dict[str, Any]]:
        """GET /delegation → list of delegation records."""
        client = self._ensure_client()
        resp = await client.get("/delegation")
        resp.raise_for_status()
        return resp.json()

    async def delegate_task(
        self,
        from_agent: str,
        to_agent: str,
        task: str,
    ) -> SwarmObservation:
        """POST /delegation → SwarmObservation."""
        client = self._ensure_client()
        resp = await client.post(
            "/delegation",
            json={
                "from_agent": from_agent,
                "to_agent": to_agent,
                "task": task,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return self._parse_observation(data.get("observation", data))

    # ── Rogue agent injection ─────────────────────────────────────

    async def inject_agent(self, agent_config: dict[str, Any]) -> str:
        """POST /agents/inject → agent_id."""
        client = self._ensure_client()
        resp = await client.post("/agents/inject", json=agent_config)
        resp.raise_for_status()
        data = resp.json()
        return data.get("agent_id", "")

    async def remove_agent(self, agent_id: str) -> bool:
        """DELETE /agents/{id} → bool."""
        client = self._ensure_client()
        resp = await client.delete(f"/agents/{agent_id}")
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("removed", False))

    # ── Swarm reset ───────────────────────────────────────────────

    async def reset_swarm(self) -> None:
        """POST /reset → reset to initial state."""
        client = self._ensure_client()
        resp = await client.post("/reset")
        resp.raise_for_status()
        logger.info("Swarm reset to initial state")

    # ── Health check ──────────────────────────────────────────────

    async def health_check(self) -> bool:
        """GET /health → bool."""
        try:
            client = self._ensure_client()
            resp = await client.get("/health")
            resp.raise_for_status()
            data = resp.json()
            return data.get("status") == "ok"
        except Exception:  # noqa: BLE001
            return False

    # ── Observation parsing ───────────────────────────────────────

    @staticmethod
    def _parse_observation(data: dict[str, Any]) -> SwarmObservation:
        """Convert a JSON dict into a SwarmObservation with ToolCall parsing."""
        raw_tool_calls = data.get("tool_calls", [])
        tool_calls = [
            ToolCall(
                name=tc.get("name", "unknown"),
                arguments=tc.get("arguments"),
                result=tc.get("result"),
            )
            for tc in raw_tool_calls
            if isinstance(tc, dict)
        ]

        return SwarmObservation(
            affected_agent=data.get("affected_agent", ""),
            action_taken=data.get("action_taken", ""),
            tool_calls=tool_calls,
            shared_memory_changes=data.get("shared_memory_changes", {}),
            delegation_path=data.get("delegation_path", []),
            raw=data.get("raw"),
            error=data.get("error"),
        )
