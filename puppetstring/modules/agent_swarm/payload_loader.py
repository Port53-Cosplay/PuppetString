"""Payload loader for agent-to-agent attack payloads.

Same pattern as ``puppetstring/modules/prompt_injection/payload_loader.py``
but for swarm-specific payloads. Loads YAML files into SwarmPayload models.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from puppetstring.modules.agent_swarm.models import (
    AgentInfo,
    SwarmAttackType,
    SwarmPayload,
)
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)

# Built-in payloads directory (right next to this file)
_BUILTIN_DIR = Path(__file__).resolve().parent / "payloads"

# Maps category names to YAML filenames
_CATEGORY_FILES: dict[str, str] = {
    "trust": "trust_exploitation.yaml",
    "memory": "shared_memory.yaml",
    "delegation": "delegation_abuse.yaml",
    "rogue": "rogue_agent.yaml",
}

# Privilege level ranking for placeholder resolution
_PRIVILEGE_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "admin": 3,
}


def load_swarm_payload_file(path: Path) -> list[SwarmPayload]:
    """Load swarm payloads from a single YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        List of validated SwarmPayload objects.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the YAML structure is invalid.
    """
    resolved = path.resolve()
    if not resolved.is_file():
        msg = f"Payload file not found: {resolved}"
        raise FileNotFoundError(msg)

    logger.debug("Loading swarm payloads from %s", resolved)

    with open(resolved, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        msg = f"Payload file must be a YAML mapping, got {type(raw).__name__}: {resolved}"
        raise ValueError(msg)

    category = raw.get("category", "unknown")
    raw_payloads = raw.get("payloads", [])

    if not isinstance(raw_payloads, list):
        msg = f"'payloads' must be a list in {resolved}"
        raise ValueError(msg)

    payloads: list[SwarmPayload] = []
    for entry in raw_payloads:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-dict payload entry in %s", resolved)
            continue

        entry.setdefault("category", category)

        # Parse attack_type string to enum if present
        if "attack_type" in entry and isinstance(entry["attack_type"], str):
            try:
                entry["attack_type"] = SwarmAttackType(entry["attack_type"])
            except ValueError:
                logger.warning("Unknown attack_type '%s' in %s", entry["attack_type"], resolved)
                continue

        payloads.append(SwarmPayload.model_validate(entry))

    logger.info(
        "Loaded %d swarm payloads from %s (category: %s)",
        len(payloads),
        resolved.name,
        category,
    )
    return payloads


def load_builtin_swarm_payloads(
    categories: list[str] | None = None,
) -> list[SwarmPayload]:
    """Load built-in swarm attack payloads.

    Args:
        categories: Which categories to load. None = all.
                    Valid: "trust", "memory", "delegation", "rogue"

    Returns:
        Flat list of SwarmPayload objects.
    """
    if categories is None:
        categories = list(_CATEGORY_FILES.keys())

    all_payloads: list[SwarmPayload] = []

    for cat in categories:
        filename = _CATEGORY_FILES.get(cat)
        if filename is None:
            logger.warning("Unknown swarm payload category '%s', skipping", cat)
            continue

        path = _BUILTIN_DIR / filename
        if not path.is_file():
            logger.warning("Built-in swarm payload file missing: %s", path)
            continue

        payloads = load_swarm_payload_file(path)
        all_payloads.extend(payloads)

    logger.info(
        "Loaded %d total swarm payloads across %d categories",
        len(all_payloads),
        len(categories),
    )
    return all_payloads


def resolve_agent_placeholders(
    payloads: list[SwarmPayload],
    agents: list[AgentInfo],
) -> list[SwarmPayload]:
    """Replace ``{low_priv}`` and ``{high_priv}`` with actual agent IDs.

    Finds the lowest-privilege and highest-privilege agents from the
    discovered agent list and substitutes placeholders in payload fields.

    Args:
        payloads: Payloads with placeholder agent IDs.
        agents: Discovered agents with privilege_level set.

    Returns:
        New list of payloads with placeholders resolved.
    """
    if not agents:
        return payloads

    # Sort agents by privilege level
    sorted_agents = sorted(
        agents,
        key=lambda a: _PRIVILEGE_RANK.get(a.privilege_level.lower(), 0),
    )
    low_priv_id = sorted_agents[0].agent_id
    high_priv_id = sorted_agents[-1].agent_id

    logger.debug(
        "Resolving placeholders: {low_priv}=%s, {high_priv}=%s",
        low_priv_id,
        high_priv_id,
    )

    resolved: list[SwarmPayload] = []
    for payload in payloads:
        data = payload.model_dump()

        # Replace placeholders in string fields
        for field_name in ("sender_agent", "target_agent"):
            value = data.get(field_name, "")
            if isinstance(value, str):
                value = value.replace("{low_priv}", low_priv_id)
                value = value.replace("{high_priv}", high_priv_id)
                data[field_name] = value

        resolved.append(SwarmPayload.model_validate(data))

    return resolved
