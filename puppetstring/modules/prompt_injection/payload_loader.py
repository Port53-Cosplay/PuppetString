"""Payload loader for indirect prompt injection payloads.

Same pattern as puppetstring/payloads/loader.py but for injection-specific
payloads. Loads YAML files into InjectionPayload models.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from puppetstring.modules.prompt_injection.models import (
    EncodingTechnique,
    InjectionPayload,
    ParsedGoal,
)
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)

# Built-in payloads directory (right next to this file)
_BUILTIN_DIR = Path(__file__).resolve().parent / "payloads"

# Maps category names to YAML filenames
_CATEGORY_FILES: dict[str, str] = {
    "document": "document_injection.yaml",
    "tool-output": "tool_output_injection.yaml",
    "encoding": "encoding_bypasses.yaml",
}


def load_injection_payload_file(path: Path) -> list[InjectionPayload]:
    """Load injection payloads from a single YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        List of validated InjectionPayload objects.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the YAML structure is invalid.
    """
    resolved = path.resolve()
    if not resolved.is_file():
        msg = f"Payload file not found: {resolved}"
        raise FileNotFoundError(msg)

    logger.debug("Loading injection payloads from %s", resolved)

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

    payloads: list[InjectionPayload] = []
    for entry in raw_payloads:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-dict payload entry in %s", resolved)
            continue

        entry.setdefault("category", category)

        # Map "text" field to "hidden_text" (YAML uses "text" for readability)
        if "text" in entry and "hidden_text" not in entry:
            entry["hidden_text"] = entry.pop("text")

        # Set default goal from intent if not specified
        if "goal" not in entry:
            entry["goal"] = entry.get("intent", "")

        # Parse technique string to enum if present
        if "technique" in entry and isinstance(entry["technique"], str):
            try:
                entry["technique"] = EncodingTechnique(entry["technique"])
            except ValueError:
                logger.warning("Unknown technique '%s' in %s", entry["technique"], resolved)
                entry.pop("technique", None)

        payloads.append(InjectionPayload.model_validate(entry))

    logger.info(
        "Loaded %d injection payloads from %s (category: %s)",
        len(payloads),
        resolved.name,
        category,
    )
    return payloads


def load_builtin_injection_payloads(
    categories: list[str] | None = None,
    goal_filter: str | None = None,
) -> list[InjectionPayload]:
    """Load built-in injection payloads.

    Args:
        categories: Which categories to load. None = all.
                    Valid: "document", "tool-output", "encoding"
        goal_filter: Optional filter string. If set, only return payloads
                     whose goal contains this string (case-insensitive).

    Returns:
        Flat list of InjectionPayload objects.
    """
    if categories is None:
        categories = list(_CATEGORY_FILES.keys())

    all_payloads: list[InjectionPayload] = []

    for cat in categories:
        filename = _CATEGORY_FILES.get(cat)
        if filename is None:
            logger.warning("Unknown injection payload category '%s', skipping", cat)
            continue

        path = _BUILTIN_DIR / filename
        if not path.is_file():
            logger.warning("Built-in injection payload file missing: %s", path)
            continue

        payloads = load_injection_payload_file(path)
        all_payloads.extend(payloads)

    if goal_filter:
        all_payloads = _filter_by_goal(all_payloads, goal_filter)

    logger.info(
        "Loaded %d total injection payloads across %d categories",
        len(all_payloads),
        len(categories),
    )
    return all_payloads


def _filter_by_goal(payloads: list[InjectionPayload], goal_filter: str) -> list[InjectionPayload]:
    """Smart goal-based payload filtering.

    Uses ParsedGoal to classify the goal and match against payload tags.
    Falls back to substring matching for unrecognized goals.
    """
    parsed = ParsedGoal(goal_filter)

    if parsed.matching_tags:
        # Tag-based matching: return payloads that share any tag with the goal
        tag_set = set(parsed.matching_tags)
        matched = [p for p in payloads if tag_set & set(p.tags)]
        if matched:
            logger.debug(
                "Smart goal filter matched %d payloads via tags %s",
                len(matched),
                parsed.matching_tags,
            )
            return matched
        # If tag matching found nothing, fall through to substring

    # Substring fallback (existing behavior)
    goal_lower = goal_filter.lower()
    return [p for p in payloads if goal_lower in p.goal.lower()]
