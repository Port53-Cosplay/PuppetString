"""Smoke tests for the multi-agent demo server.

These tests start a real HTTP server in a background daemon thread on
port 18001 (not 8001, to avoid conflicts with a manually-running instance)
and make real HTTP requests against it.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Generator
from http.client import HTTPConnection

import pytest

from examples.multi_agent_demo.server import create_server, reset_swarm

TEST_HOST = "127.0.0.1"
TEST_PORT = 18001


@pytest.fixture(scope="module")
def server() -> Generator[None, None, None]:
    """Start the swarm server in a background daemon thread."""
    srv = create_server(TEST_HOST, TEST_PORT)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    # Give the server a moment to bind
    time.sleep(0.3)
    yield
    srv.shutdown()


@pytest.fixture(autouse=True)
def _reset_between_tests() -> Generator[None, None, None]:
    """Reset swarm state between every test."""
    reset_swarm()
    yield


def _get(path: str) -> tuple[int, dict]:
    """Helper: GET request, returns (status, json_body)."""
    conn = HTTPConnection(TEST_HOST, TEST_PORT, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = json.loads(resp.read())
    status = resp.status
    conn.close()
    return status, body


def _post(path: str, data: dict) -> tuple[int, dict]:
    """Helper: POST request with JSON body, returns (status, json_body)."""
    conn = HTTPConnection(TEST_HOST, TEST_PORT, timeout=5)
    payload = json.dumps(data).encode("utf-8")
    conn.request(
        "POST",
        path,
        body=payload,
        headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
    )
    resp = conn.getresponse()
    body = json.loads(resp.read())
    status = resp.status
    conn.close()
    return status, body


def _delete(path: str) -> tuple[int, dict]:
    """Helper: DELETE request, returns (status, json_body)."""
    conn = HTTPConnection(TEST_HOST, TEST_PORT, timeout=5)
    conn.request("DELETE", path)
    resp = conn.getresponse()
    body = json.loads(resp.read())
    status = resp.status
    conn.close()
    return status, body


class TestMultiAgentServer:
    def test_health(self, server: None) -> None:
        """GET /health returns server info with agent count."""
        status, data = _get("/health")

        assert status == 200
        assert data["status"] == "ok"
        assert data["agent_count"] == 2
        assert "VulnerableSwarm" in data["name"]

    def test_list_agents(self, server: None) -> None:
        """GET /agents returns both default agents."""
        status, data = _get("/agents")

        assert status == 200
        assert isinstance(data, list)
        assert len(data) == 2
        ids = {a["agent_id"] for a in data}
        assert ids == {"researcher", "executor"}

    def test_send_message(self, server: None) -> None:
        """POST /agents/{id}/message returns an observation."""
        status, data = _post(
            "/agents/executor/message",
            {"sender_id": "researcher", "message": "search for security vulnerabilities"},
        )

        assert status == 200
        assert "observation" in data
        assert data["observation"]["affected_agent"] == "executor"

    def test_memory_round_trip(self, server: None) -> None:
        """Write to shared memory, then read it back."""
        # Write
        w_status, w_data = _post(
            "/memory",
            {"key": "test_key", "value": "test_value", "namespace": "default"},
        )
        assert w_status == 200
        assert w_data["written"] is True

        # Read
        r_status, r_data = _get("/memory/default")
        assert r_status == 200
        assert r_data.get("test_key") == "test_value"

    def test_reset(self, server: None) -> None:
        """POST /reset restores initial state."""
        # Inject an agent first
        _post(
            "/agents/inject",
            {"agent_id": "intruder", "name": "Intruder", "role": "attacker"},
        )
        # Verify it exists
        status, data = _get("/agents")
        assert len(data) == 3

        # Reset
        r_status, r_data = _post("/reset", {})
        assert r_status == 200
        assert r_data["agent_count"] == 2

        # Verify intruder is gone
        status, data = _get("/agents")
        assert len(data) == 2

    def test_inject_and_remove_agent(self, server: None) -> None:
        """Inject a rogue agent, verify it exists, then remove it."""
        # Inject
        status, data = _post(
            "/agents/inject",
            {
                "agent_id": "rogue",
                "name": "Rogue",
                "role": "attacker",
                "tools": ["run_command"],
                "privilege_level": "high",
            },
        )
        assert status == 200
        assert data["injected"] is True

        # Verify
        status, data = _get("/agents/rogue")
        assert status == 200
        assert data["agent_id"] == "rogue"

        # Remove
        status, data = _delete("/agents/rogue")
        assert status == 200
        assert data["removed"] is True

        # Verify gone
        status, data = _get("/agents/rogue")
        assert status == 404

    def test_delegation(self, server: None) -> None:
        """POST /delegation delegates a task and returns an observation."""
        status, data = _post(
            "/delegation",
            {
                "from_agent": "researcher",
                "to_agent": "executor",
                "task": "search for internal documents",
            },
        )

        assert status == 200
        assert "observation" in data
        assert "delegation" in data
        assert data["delegation"]["from_agent"] == "researcher"
        assert data["delegation"]["to_agent"] == "executor"
