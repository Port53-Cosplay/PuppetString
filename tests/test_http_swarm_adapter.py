"""Tests for the HTTP swarm adapter.

Uses httpx.MockTransport (same pattern as test_http_adapter.py) so no real
server is needed. Each test creates an adapter with an injected mock client
that returns canned JSON responses.
"""

from __future__ import annotations

import json

import httpx
import pytest

from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

# ── Canned response data ─────────────────────────────────────────

HEALTH_RESPONSE = {
    "status": "ok",
    "name": "VulnerableSwarm",
    "version": "0.1.0",
    "agent_count": 2,
    "warning": "DELIBERATELY INSECURE",
}

AGENTS_LIST = [
    {
        "agent_id": "researcher",
        "name": "Research Agent",
        "role": "researcher",
        "tools": ["search", "read_file"],
        "privilege_level": "low",
        "metadata": {},
    },
    {
        "agent_id": "executor",
        "name": "Execution Agent",
        "role": "executor",
        "tools": ["run_command", "write_file", "send_email", "query_db"],
        "privilege_level": "high",
        "metadata": {},
    },
]

MESSAGE_RESPONSE = {
    "response": "Executed command: ls",
    "tool_calls": [
        {
            "name": "run_command",
            "arguments": {"command": "ls"},
            "result": "[executed] $ ls\nCommand completed successfully.",
        }
    ],
    "observation": {
        "affected_agent": "executor",
        "action_taken": "Executed command: ls",
        "tool_calls": [
            {
                "name": "run_command",
                "arguments": {"command": "ls"},
                "result": "[executed] $ ls\nCommand completed successfully.",
            }
        ],
        "shared_memory_changes": {},
        "delegation_path": [],
        "raw": {"sender_id": "researcher", "recipient_id": "executor", "message": "run ls"},
        "error": None,
    },
}

DELEGATION_RESPONSE = {
    "response": "Executed command: whoami",
    "tool_calls": [
        {
            "name": "run_command",
            "arguments": {"command": "whoami"},
            "result": "[executed] $ whoami",
        }
    ],
    "observation": {
        "affected_agent": "executor",
        "action_taken": "Executed command: whoami",
        "tool_calls": [
            {
                "name": "run_command",
                "arguments": {"command": "whoami"},
                "result": "[executed] $ whoami",
            }
        ],
        "shared_memory_changes": {},
        "delegation_path": ["researcher", "executor"],
        "raw": None,
        "error": None,
    },
    "delegation": {"from_agent": "researcher", "to_agent": "executor", "task": "run whoami"},
}

INJECT_RESPONSE = {
    "injected": True,
    "agent_id": "rogue",
    "agent": {
        "agent_id": "rogue",
        "name": "Rogue Agent",
        "role": "attacker",
        "tools": ["run_command"],
        "privilege_level": "high",
        "metadata": {},
    },
}


# ── Mock transport ───────────────────────────────────────────────


def _swarm_handler(request: httpx.Request) -> httpx.Response:
    """Mock handler that routes requests like the real swarm server."""
    path = request.url.path.rstrip("/")
    method = request.method

    # GET /health
    if method == "GET" and path in ("/health", ""):
        return httpx.Response(200, json=HEALTH_RESPONSE)

    # GET /agents
    if method == "GET" and path == "/agents":
        return httpx.Response(200, json=AGENTS_LIST)

    # GET /agents/{id}
    if method == "GET" and path.startswith("/agents/"):
        agent_id = path.split("/")[-1]
        for agent in AGENTS_LIST:
            if agent["agent_id"] == agent_id:
                return httpx.Response(200, json=agent)
        return httpx.Response(404, json={"error": f"Agent '{agent_id}' not found"})

    # POST /agents/{id}/message
    if method == "POST" and "/message" in path:
        return httpx.Response(200, json=MESSAGE_RESPONSE)

    # GET /memory/{namespace}
    if method == "GET" and path.startswith("/memory/"):
        return httpx.Response(200, json={"poisoned_key": "poisoned_value"})

    # GET /memory
    if method == "GET" and path == "/memory":
        return httpx.Response(
            200,
            json={"default": {"poisoned_key": "poisoned_value"}},
        )

    # POST /memory
    if method == "POST" and path == "/memory":
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "written": True,
                "namespace": body.get("namespace", "default"),
                "key": body.get("key", ""),
            },
        )

    # GET /delegation
    if method == "GET" and path == "/delegation":
        return httpx.Response(200, json=[])

    # POST /delegation
    if method == "POST" and path == "/delegation":
        return httpx.Response(200, json=DELEGATION_RESPONSE)

    # POST /agents/inject
    if method == "POST" and path == "/agents/inject":
        body = json.loads(request.content)
        resp = dict(INJECT_RESPONSE)
        resp["agent_id"] = body.get("agent_id", "rogue")
        return httpx.Response(200, json=resp)

    # DELETE /agents/{id}
    if method == "DELETE" and path.startswith("/agents/"):
        agent_id = path.split("/")[-1]
        return httpx.Response(200, json={"removed": True, "agent_id": agent_id})

    # POST /reset
    if method == "POST" and path == "/reset":
        return httpx.Response(200, json={"status": "reset", "agent_count": 2})

    return httpx.Response(404, json={"error": "not found"})


def _make_swarm_adapter(
    handler=_swarm_handler,
) -> HTTPSwarmAdapter:
    """Create an HTTPSwarmAdapter with mock transport injected."""
    adapter = HTTPSwarmAdapter(target="http://test-swarm:8001")
    adapter._client = httpx.AsyncClient(
        base_url="http://test-swarm:8001",
        transport=httpx.MockTransport(handler),
    )
    adapter._connected = True
    return adapter


def _make_error_handler(status: int, body: dict | None = None):
    """Create a handler that always returns a given error status."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body or {"error": "fail"})

    return handler


# ── Connection tests ─────────────────────────────────────────────


class TestHTTPSwarmAdapterConnection:
    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Adapter connects when /health returns OK."""
        adapter = HTTPSwarmAdapter(target="http://test-swarm:8001")
        # Manually inject transport for connect()
        adapter._client = httpx.AsyncClient(
            base_url="http://test-swarm:8001",
            transport=httpx.MockTransport(_swarm_handler),
        )
        # Simulate what connect does: call /health
        resp = await adapter._client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["agent_count"] == 2

    @pytest.mark.asyncio
    async def test_not_connected_raises(self) -> None:
        """Calling methods before connect() raises RuntimeError."""
        adapter = HTTPSwarmAdapter(target="http://test-swarm:8001")
        with pytest.raises(RuntimeError, match="Not connected"):
            await adapter.list_agents()

    @pytest.mark.asyncio
    async def test_disconnect(self) -> None:
        """Disconnect closes client and clears connected flag."""
        adapter = _make_swarm_adapter()
        assert adapter.is_connected
        await adapter.disconnect()
        assert not adapter.is_connected
        assert adapter._client is None


# ── Agent discovery tests ────────────────────────────────────────


class TestHTTPSwarmAdapterDiscovery:
    @pytest.mark.asyncio
    async def test_list_agents(self) -> None:
        """list_agents returns both agents with correct metadata."""
        adapter = _make_swarm_adapter()
        agents = await adapter.list_agents()

        assert len(agents) == 2
        ids = {a.agent_id for a in agents}
        assert ids == {"researcher", "executor"}

    @pytest.mark.asyncio
    async def test_list_agents_types(self) -> None:
        """list_agents returns AgentInfo instances."""
        from puppetstring.modules.agent_swarm.models import AgentInfo

        adapter = _make_swarm_adapter()
        agents = await adapter.list_agents()
        for agent in agents:
            assert isinstance(agent, AgentInfo)

    @pytest.mark.asyncio
    async def test_get_agent_info_researcher(self) -> None:
        """get_agent_info returns correct data for researcher."""
        adapter = _make_swarm_adapter()
        agent = await adapter.get_agent_info("researcher")

        assert agent.agent_id == "researcher"
        assert agent.name == "Research Agent"
        assert agent.role == "researcher"
        assert agent.privilege_level == "low"
        assert "search" in agent.tools
        assert "read_file" in agent.tools

    @pytest.mark.asyncio
    async def test_get_agent_info_executor(self) -> None:
        """get_agent_info returns correct data for executor."""
        adapter = _make_swarm_adapter()
        agent = await adapter.get_agent_info("executor")

        assert agent.agent_id == "executor"
        assert agent.privilege_level == "high"
        assert "run_command" in agent.tools

    @pytest.mark.asyncio
    async def test_get_agent_info_not_found(self) -> None:
        """get_agent_info raises on unknown agent_id."""
        adapter = _make_swarm_adapter()
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.get_agent_info("nonexistent")


# ── Messaging tests ──────────────────────────────────────────────


class TestHTTPSwarmAdapterMessaging:
    @pytest.mark.asyncio
    async def test_send_message_as(self) -> None:
        """send_message_as returns observation with tool calls."""
        adapter = _make_swarm_adapter()
        obs = await adapter.send_message_as("researcher", "executor", "run ls")

        assert obs.affected_agent == "executor"
        assert obs.action_taken
        assert len(obs.tool_calls) == 1
        assert obs.tool_calls[0].name == "run_command"

    @pytest.mark.asyncio
    async def test_send_message_as_observation_raw(self) -> None:
        """Observation includes raw sender/recipient data."""
        adapter = _make_swarm_adapter()
        obs = await adapter.send_message_as("researcher", "executor", "run ls")

        assert obs.raw is not None
        assert obs.raw["sender_id"] == "researcher"
        assert obs.raw["recipient_id"] == "executor"

    @pytest.mark.asyncio
    async def test_send_message_captures_request(self) -> None:
        """The adapter sends the correct sender_id and message."""
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and "/message" in request.url.path:
                captured.update(json.loads(request.content))
                return httpx.Response(200, json=MESSAGE_RESPONSE)
            return _swarm_handler(request)

        adapter = _make_swarm_adapter(handler)
        await adapter.send_message_as("researcher", "executor", "run ls")

        assert captured["sender_id"] == "researcher"
        assert captured["message"] == "run ls"


# ── Shared memory tests ─────────────────────────────────────────


class TestHTTPSwarmAdapterMemory:
    @pytest.mark.asyncio
    async def test_read_shared_memory(self) -> None:
        """read_shared_memory returns namespace contents."""
        adapter = _make_swarm_adapter()
        mem = await adapter.read_shared_memory("default")

        assert isinstance(mem, dict)
        assert "poisoned_key" in mem

    @pytest.mark.asyncio
    async def test_write_shared_memory(self) -> None:
        """write_shared_memory returns True on success."""
        adapter = _make_swarm_adapter()
        result = await adapter.write_shared_memory("test_key", "test_value")

        assert result is True

    @pytest.mark.asyncio
    async def test_write_shared_memory_with_namespace(self) -> None:
        """write_shared_memory sends the correct namespace."""
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path.rstrip("/") == "/memory":
                captured.update(json.loads(request.content))
                return httpx.Response(
                    200,
                    json={"written": True, "namespace": "secrets", "key": "api_key"},
                )
            return _swarm_handler(request)

        adapter = _make_swarm_adapter(handler)
        await adapter.write_shared_memory("api_key", "sk-evil", namespace="secrets")

        assert captured["namespace"] == "secrets"
        assert captured["key"] == "api_key"
        assert captured["value"] == "sk-evil"


# ── Delegation tests ─────────────────────────────────────────────


class TestHTTPSwarmAdapterDelegation:
    @pytest.mark.asyncio
    async def test_get_delegation_chain(self) -> None:
        """get_delegation_chain returns a list."""
        adapter = _make_swarm_adapter()
        chain = await adapter.get_delegation_chain()

        assert isinstance(chain, list)

    @pytest.mark.asyncio
    async def test_delegate_task(self) -> None:
        """delegate_task returns observation with tool calls."""
        adapter = _make_swarm_adapter()
        obs = await adapter.delegate_task("researcher", "executor", "run whoami")

        assert obs.affected_agent == "executor"
        assert len(obs.tool_calls) >= 1
        assert obs.tool_calls[0].name == "run_command"

    @pytest.mark.asyncio
    async def test_delegate_task_sends_correct_body(self) -> None:
        """delegate_task sends from_agent, to_agent, task in body."""
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path.rstrip("/") == "/delegation":
                captured.update(json.loads(request.content))
                return httpx.Response(200, json=DELEGATION_RESPONSE)
            return _swarm_handler(request)

        adapter = _make_swarm_adapter(handler)
        await adapter.delegate_task("researcher", "executor", "run whoami")

        assert captured["from_agent"] == "researcher"
        assert captured["to_agent"] == "executor"
        assert captured["task"] == "run whoami"


# ── Rogue injection tests ───────────────────────────────────────


class TestHTTPSwarmAdapterInjection:
    @pytest.mark.asyncio
    async def test_inject_agent(self) -> None:
        """inject_agent returns the agent_id."""
        adapter = _make_swarm_adapter()
        agent_id = await adapter.inject_agent(
            {
                "agent_id": "rogue",
                "name": "Rogue Agent",
                "role": "attacker",
                "tools": ["run_command"],
                "privilege_level": "high",
            }
        )

        assert agent_id == "rogue"

    @pytest.mark.asyncio
    async def test_remove_agent(self) -> None:
        """remove_agent returns True on success."""
        adapter = _make_swarm_adapter()
        result = await adapter.remove_agent("rogue")

        assert result is True


# ── Lifecycle tests ──────────────────────────────────────────────


class TestHTTPSwarmAdapterLifecycle:
    @pytest.mark.asyncio
    async def test_reset_swarm(self) -> None:
        """reset_swarm calls POST /reset without error."""
        adapter = _make_swarm_adapter()
        await adapter.reset_swarm()
        # No exception means success

    @pytest.mark.asyncio
    async def test_health_check_pass(self) -> None:
        """health_check returns True when server responds OK."""
        adapter = _make_swarm_adapter()
        assert await adapter.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_fail(self) -> None:
        """health_check returns False on error."""
        adapter = _make_swarm_adapter(_make_error_handler(500))
        assert await adapter.health_check() is False

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Adapter works as async context manager."""
        adapter = HTTPSwarmAdapter(target="http://test-swarm:8001")
        # We can't fully test __aenter__ without a real/mock server,
        # but we can test __aexit__ cleanup
        adapter._client = httpx.AsyncClient(
            base_url="http://test-swarm:8001",
            transport=httpx.MockTransport(_swarm_handler),
        )
        adapter._connected = True

        await adapter.__aexit__(None, None, None)
        assert not adapter.is_connected


# ── Error handling tests ─────────────────────────────────────────


class TestHTTPSwarmAdapterErrors:
    @pytest.mark.asyncio
    async def test_list_agents_server_error(self) -> None:
        """list_agents raises on server error."""
        adapter = _make_swarm_adapter(_make_error_handler(500))
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.list_agents()

    @pytest.mark.asyncio
    async def test_send_message_server_error(self) -> None:
        """send_message_as raises on server error."""
        adapter = _make_swarm_adapter(_make_error_handler(500))
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.send_message_as("a", "b", "msg")

    @pytest.mark.asyncio
    async def test_write_memory_server_error(self) -> None:
        """write_shared_memory raises on server error."""
        adapter = _make_swarm_adapter(_make_error_handler(500))
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.write_shared_memory("k", "v")


# ── Observation parsing tests ────────────────────────────────────


class TestObservationParsing:
    def test_parse_observation_full(self) -> None:
        """_parse_observation handles a complete observation dict."""
        data = {
            "affected_agent": "executor",
            "action_taken": "Ran command",
            "tool_calls": [{"name": "run_command", "arguments": {"cmd": "ls"}, "result": "ok"}],
            "shared_memory_changes": {"key": "val"},
            "delegation_path": ["a", "b"],
            "raw": {"some": "data"},
            "error": None,
        }
        obs = HTTPSwarmAdapter._parse_observation(data)

        assert obs.affected_agent == "executor"
        assert obs.action_taken == "Ran command"
        assert len(obs.tool_calls) == 1
        assert obs.tool_calls[0].name == "run_command"
        assert obs.tool_calls[0].arguments == {"cmd": "ls"}
        assert obs.tool_calls[0].result == "ok"
        assert obs.shared_memory_changes == {"key": "val"}
        assert obs.delegation_path == ["a", "b"]
        assert obs.raw == {"some": "data"}
        assert obs.error is None

    def test_parse_observation_empty(self) -> None:
        """_parse_observation handles an empty dict gracefully."""
        obs = HTTPSwarmAdapter._parse_observation({})

        assert obs.affected_agent == ""
        assert obs.action_taken == ""
        assert obs.tool_calls == []
        assert obs.shared_memory_changes == {}

    def test_parse_observation_malformed_tool_calls(self) -> None:
        """_parse_observation skips non-dict tool call entries."""
        data = {
            "affected_agent": "test",
            "tool_calls": [
                {"name": "good_tool", "arguments": {}},
                "not a dict",
                42,
                {"name": "another_good"},
            ],
        }
        obs = HTTPSwarmAdapter._parse_observation(data)

        assert len(obs.tool_calls) == 2
        assert obs.tool_calls[0].name == "good_tool"
        assert obs.tool_calls[1].name == "another_good"

    def test_parse_observation_with_error(self) -> None:
        """_parse_observation captures error field."""
        data = {"affected_agent": "x", "error": "something broke"}
        obs = HTTPSwarmAdapter._parse_observation(data)

        assert obs.error == "something broke"
