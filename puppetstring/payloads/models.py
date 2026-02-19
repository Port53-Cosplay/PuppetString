"""Payload data models.

A "payload" is one attack message that the fuzzer sends to an agent.
Each payload has:
  - A name (short identifier, like "unauthorized_file_read")
  - A category (which type of attack: tool-abuse, memory-poison, etc.)
  - The actual text to send to the agent
  - The intent (what this attack is trying to accomplish, in plain English)
  - OWASP IDs this attack maps to
  - Optional multi-turn follow-ups (for attacks that span multiple messages)

Payloads live in YAML files organized by category. The loader reads them
into these models so the fuzzer has structured, validated data to work with.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Payload(BaseModel):
    """One attack payload to send to an agent."""

    name: str
    category: str  # "tool-abuse", "memory-poison", "boundary", "chain"
    text: str  # the actual message to send
    intent: str  # what this attack is trying to achieve
    owasp_ids: list[str] = Field(default_factory=list)
    follow_ups: list[str] = Field(default_factory=list)  # multi-turn attacks
    tags: list[str] = Field(default_factory=list)  # for filtering


class PayloadSet(BaseModel):
    """A collection of payloads loaded from one or more YAML files."""

    category: str
    description: str = ""
    payloads: list[Payload] = Field(default_factory=list)
