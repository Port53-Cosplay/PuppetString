"""Stage manager — subprocess-based process management for test targets.

Starts, stops, and monitors the vulnerable test targets that ship with
PuppetString. Uses subprocess.Popen with platform-specific detach flags
so targets survive the parent terminal closing.

State is persisted to a JSON file in the system temp directory so that
`stage status` and `stage down` work across terminal sessions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from puppetstring.staging.models import (
    ProcessState,
    StageState,
    TargetDefinition,
    TargetName,
    TargetStatus,
)

logger = logging.getLogger("puppetstring.staging")

# ── Target registry ──────────────────────────────────────────────

TARGET_REGISTRY: dict[TargetName, TargetDefinition] = {
    TargetName.MCP: TargetDefinition(
        name=TargetName.MCP,
        display_name="Vulnerable MCP Server",
        description="FastMCP server with 8 insecure tools (file read, shell exec, SQL, etc.)",
        script_path="vulnerable_mcp_server/server.py",
        port=3000,
    ),
    TargetName.AGENT: TargetDefinition(
        name=TargetName.AGENT,
        display_name="Vulnerable AI Agent",
        description="Pattern-matching HTTP agent with simulated tool use (port 8000)",
        script_path="vulnerable_agent/agent.py",
        port=8000,
    ),
    TargetName.SWARM: TargetDefinition(
        name=TargetName.SWARM,
        display_name="Multi-Agent Swarm",
        description="Two-agent system with privilege escalation surface (port 8001)",
        script_path="multi_agent_demo/server.py",
        port=8001,
    ),
}

# ── Helper functions (module-level, testable) ────────────────────

HEALTH_CHECK_TIMEOUT = 10  # seconds to wait for a target to become healthy
HEALTH_CHECK_INTERVAL = 0.3  # seconds between health check polls


def _find_examples_dir() -> Path:
    """Locate the examples/ directory relative to the package source."""
    # Walk up from this file: staging/ -> puppetstring/ -> project root
    pkg_dir = Path(__file__).resolve().parent.parent
    project_root = pkg_dir.parent

    examples = project_root / "examples"
    if examples.is_dir():
        return examples

    msg = (
        f"Cannot find examples/ directory (looked in {project_root}). "
        "This typically means PuppetString was installed from PyPI without "
        "the examples. Clone the repo or use an editable install."
    )
    raise FileNotFoundError(msg)


def _project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).resolve().parent.parent.parent


def _state_file_path() -> Path:
    """Return the path to the state file in the system temp directory.

    The filename includes a hash of the project root so multiple checkouts
    don't collide.
    """
    root_hash = hashlib.sha256(str(_project_root()).encode()).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / f"puppetstring_stage_{root_hash}.json"


def _is_port_in_use(host: str, port: int) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running (cross-platform)."""
    if platform.system() == "Windows":
        try:
            result = subprocess.run(  # noqa: S603
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return str(pid) in result.stdout
        except (subprocess.SubprocessError, OSError):
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Process exists but we can't signal it
            return True


def _kill_process(pid: int) -> bool:
    """Kill a process by PID (cross-platform). Returns True if killed."""
    if platform.system() == "Windows":
        try:
            subprocess.run(  # noqa: S603
                ["taskkill", "/F", "/PID", str(pid)],  # noqa: S607
                capture_output=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return True
        except (subprocess.SubprocessError, OSError):
            return False
    else:
        import signal

        try:
            os.kill(pid, signal.SIGTERM)
            return True
        except (ProcessLookupError, PermissionError):
            return False


def _is_puppetstring_process(pid: int) -> bool:
    """Verify a PID belongs to a Python process started by PuppetString.

    Defence-in-depth: before killing a PID read from the state file, confirm
    its command line contains ``sys.executable`` (or ``python``) and one of the
    known example script names. This prevents state-file tampering from
    targeting unrelated processes.
    """
    known_scripts = {"server.py", "agent.py"}

    if platform.system() == "Windows":
        try:
            result = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "wmic",
                    "process",
                    "where",
                    f"ProcessId={pid}",
                    "get",
                    "CommandLine",
                    "/FORMAT:LIST",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            cmdline = result.stdout.lower()
        except (subprocess.SubprocessError, OSError):
            return False
    else:
        try:
            proc_path = Path(f"/proc/{pid}/cmdline")
            cmdline = proc_path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            return False

    if "python" not in cmdline:
        return False
    return any(script in cmdline for script in known_scripts)


def _is_safe_log_path(log_file: str) -> bool:
    """Validate that a log file path is inside the temp directory.

    Defence-in-depth: before deleting a path read from the state file,
    confirm it resolves to within the system temp directory and matches the
    expected ``puppetstring_*.log`` naming pattern.
    """
    try:
        resolved = Path(log_file).resolve()
        temp_dir = Path(tempfile.gettempdir()).resolve()
        if not str(resolved).startswith(str(temp_dir)):
            return False
        if not resolved.name.startswith("puppetstring_") or not resolved.name.endswith(".log"):
            return False
    except (OSError, ValueError):
        return False
    return True


def _detach_kwargs() -> dict:
    """Return platform-specific kwargs for subprocess.Popen to detach the child."""
    if platform.system() == "Windows":
        create_new_process_group = 0x00000200
        detached_process = 0x00000008
        return {"creationflags": create_new_process_group | detached_process}
    else:
        return {"start_new_session": True}


# ── StageManager ─────────────────────────────────────────────────


class StageManager:
    """Manages the lifecycle of vulnerable test target processes."""

    def __init__(self) -> None:
        self._examples_dir = _find_examples_dir()
        self._state_path = _state_file_path()

    @property
    def examples_dir(self) -> Path:
        return self._examples_dir

    def _load_state(self) -> StageState:
        """Load the state file, returning empty state if missing or corrupt."""
        if not self._state_path.exists():
            return StageState()
        try:
            data = self._state_path.read_text(encoding="utf-8")
            return StageState.model_validate_json(data)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Corrupt state file, starting fresh: %s", self._state_path)
            return StageState()

    def _save_state(self, state: StageState) -> None:
        """Persist state to the JSON file."""
        state.updated_at = __import__("datetime").datetime.now()
        self._state_path.write_text(state.model_dump_json(indent=2), encoding="utf-8")

    def _resolve_targets(self, target_names: list[TargetName]) -> list[TargetDefinition]:
        """Resolve target names to definitions."""
        return [TARGET_REGISTRY[name] for name in target_names]

    def up(self, target_names: list[TargetName]) -> list[TargetStatus]:
        """Start the specified targets. Returns status for each."""
        state = self._load_state()
        results: list[TargetStatus] = []

        for defn in self._resolve_targets(target_names):
            # Check if already running
            existing = next((p for p in state.processes if p.target_name == defn.name), None)
            if existing and _is_pid_alive(existing.pid) and _is_port_in_use(defn.host, defn.port):
                logger.info("%s already running (PID %d)", defn.display_name, existing.pid)
                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        pid=existing.pid,
                        running=True,
                        healthy=True,
                        started_at=existing.started_at,
                    )
                )
                continue

            # Clean stale entry if present
            if existing:
                state.processes = [p for p in state.processes if p.target_name != defn.name]

            # Check port not in use by something else
            if _is_port_in_use(defn.host, defn.port):
                logger.error("Port %d already in use by another process", defn.port)
                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        running=False,
                        healthy=False,
                    )
                )
                continue

            # Start the process
            script = self._examples_dir / defn.script_path
            if not script.exists():
                logger.error("Script not found: %s", script)
                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        running=False,
                        healthy=False,
                    )
                )
                continue

            log_file = Path(tempfile.gettempdir()) / f"puppetstring_{defn.name}.log"
            log_handle = log_file.open("w", encoding="utf-8")

            try:
                proc = subprocess.Popen(  # noqa: S603
                    [sys.executable, str(script)],
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    **_detach_kwargs(),
                )
            except OSError as exc:
                logger.error("Failed to start %s: %s", defn.display_name, exc)
                log_handle.close()
                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        running=False,
                        healthy=False,
                    )
                )
                continue

            # Health check: poll port
            healthy = False
            deadline = time.monotonic() + HEALTH_CHECK_TIMEOUT
            while time.monotonic() < deadline:
                if _is_port_in_use(defn.host, defn.port):
                    healthy = True
                    break
                # Check process hasn't crashed
                if proc.poll() is not None:
                    break
                time.sleep(HEALTH_CHECK_INTERVAL)

            ps = ProcessState(
                target_name=defn.name,
                pid=proc.pid,
                port=defn.port,
                log_file=str(log_file),
            )
            state.processes.append(ps)

            results.append(
                TargetStatus(
                    name=defn.name,
                    display_name=defn.display_name,
                    description=defn.description,
                    port=defn.port,
                    pid=proc.pid,
                    running=_is_pid_alive(proc.pid),
                    healthy=healthy,
                    started_at=ps.started_at,
                )
            )

        self._save_state(state)
        return results

    def down(self, target_names: list[TargetName]) -> list[TargetStatus]:
        """Stop the specified targets. Returns status for each."""
        state = self._load_state()
        results: list[TargetStatus] = []

        for defn in self._resolve_targets(target_names):
            existing = next((p for p in state.processes if p.target_name == defn.name), None)

            if existing:
                killed = False
                if _is_pid_alive(existing.pid):
                    if _is_puppetstring_process(existing.pid):
                        killed = _kill_process(existing.pid)
                    else:
                        logger.warning(
                            "PID %d is alive but not a PuppetString process — skipping kill",
                            existing.pid,
                        )

                # Clean up log file (validate path is in temp dir first)
                if existing.log_file and _is_safe_log_path(existing.log_file):
                    try:
                        Path(existing.log_file).unlink(missing_ok=True)
                    except OSError:
                        pass

                state.processes = [p for p in state.processes if p.target_name != defn.name]

                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        pid=existing.pid if not killed else None,
                        running=False,
                        healthy=False,
                    )
                )
            else:
                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        running=False,
                        healthy=False,
                    )
                )

        self._save_state(state)
        return results

    def status(self) -> list[TargetStatus]:
        """Check the live status of all targets."""
        state = self._load_state()
        results: list[TargetStatus] = []
        cleaned = False

        for defn in TARGET_REGISTRY.values():
            existing = next((p for p in state.processes if p.target_name == defn.name), None)

            if existing:
                alive = _is_pid_alive(existing.pid)
                port_ok = _is_port_in_use(defn.host, defn.port)

                if not alive:
                    # Stale entry — process died
                    state.processes = [p for p in state.processes if p.target_name != defn.name]
                    cleaned = True
                    results.append(
                        TargetStatus(
                            name=defn.name,
                            display_name=defn.display_name,
                            description=defn.description,
                            port=defn.port,
                            running=False,
                            healthy=False,
                        )
                    )
                else:
                    results.append(
                        TargetStatus(
                            name=defn.name,
                            display_name=defn.display_name,
                            description=defn.description,
                            port=defn.port,
                            pid=existing.pid,
                            running=True,
                            healthy=port_ok,
                            started_at=existing.started_at,
                        )
                    )
            else:
                results.append(
                    TargetStatus(
                        name=defn.name,
                        display_name=defn.display_name,
                        description=defn.description,
                        port=defn.port,
                        running=False,
                        healthy=False,
                    )
                )

        if cleaned:
            self._save_state(state)

        return results
