"""Data models for the stage command — test target process management.

Models:
    TargetName: Enum of available test targets (mcp, agent, swarm)
    TargetDefinition: Static registry entry for a target (script path, port, etc.)
    ProcessState: Runtime state for one managed process (PID, port, log file)
    StageState: Container for the state file (list of ProcessState + timestamp)
    TargetStatus: Display model merging definition + live health check
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import BaseModel, Field


class TargetName(StrEnum):
    """Available test targets."""

    MCP = "mcp"
    AGENT = "agent"
    SWARM = "swarm"


class TargetDefinition(BaseModel):
    """Static registry entry for a test target."""

    name: TargetName
    display_name: str
    description: str
    script_path: str  # Relative to examples/ dir (forward slashes)
    port: int
    host: str = "127.0.0.1"

    @property
    def script_posix(self) -> PurePosixPath:
        """Script path as a PurePosixPath for cross-platform joining."""
        return PurePosixPath(self.script_path)


class ProcessState(BaseModel):
    """Runtime state for one managed process (persisted to state file)."""

    target_name: TargetName
    pid: int
    port: int
    started_at: datetime = Field(default_factory=datetime.now)
    log_file: str = ""


class StageState(BaseModel):
    """State file container — list of active processes."""

    processes: list[ProcessState] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=datetime.now)


class TargetStatus(BaseModel):
    """Display model merging a target definition with live health status."""

    name: TargetName
    display_name: str
    description: str
    port: int
    pid: int | None = None
    running: bool = False
    healthy: bool = False
    started_at: datetime | None = None
