"""Shared constants used across PuppetString.

These are values that never change and are referenced from multiple places.
Keeping them here avoids magic strings scattered throughout the codebase.
"""

# ── OWASP Top 10 for Agentic AI Applications (2026) ───────────────
# This is our coverage framework — every finding PuppetString produces
# maps back to one or more of these categories.
#
# WHAT IS OWASP?
#   OWASP (Open Worldwide Application Security Project) is a nonprofit that
#   publishes free security guidance. Their "Top 10" lists are industry-standard
#   references for the most critical security risks in a given domain.
#   The "Top 10 for Agentic AI" (2026) is specifically about risks in AI
#   systems that can take actions (agents), not just generate text.

OWASP_AGENTIC_TOP_10 = {
    "A1": {
        "id": "A1",
        "name": "Excessive Agency",
        "description": (
            "Agent has more permissions or tools than needed for its task. "
            "Like giving an intern the CEO's master key."
        ),
    },
    "A2": {
        "id": "A2",
        "name": "Uncontrolled Tool Execution",
        "description": (
            "Agent executes tools without proper validation or confirmation. "
            "It just does whatever it's asked without checking if it should."
        ),
    },
    "A3": {
        "id": "A3",
        "name": "Prompt Injection via Tools",
        "description": (
            "Adversarial content hidden in tool outputs (search results, documents, "
            "API responses) tricks the agent into doing something unintended."
        ),
    },
    "A4": {
        "id": "A4",
        "name": "Insecure Output Handling",
        "description": (
            "Agent outputs are fed to downstream systems without sanitization. "
            "The agent's response might contain code, SQL, or commands that "
            "get executed by the next system in the chain."
        ),
    },
    "A5": {
        "id": "A5",
        "name": "Memory & Context Manipulation",
        "description": (
            "Poisoning the agent's memory or context window to influence its "
            "future behavior. Like whispering bad advice that it remembers forever."
        ),
    },
    "A6": {
        "id": "A6",
        "name": "Overreliance on Agent Outputs",
        "description": (
            "Systems or humans blindly trust agent decisions without verification. "
            "Organizational/process issue — out of scope for automated testing."
        ),
    },
    "A7": {
        "id": "A7",
        "name": "Multi-Agent Trust Exploitation",
        "description": (
            "Agents blindly trust other agents in multi-agent systems. A compromised "
            "agent can manipulate its peers through shared context or delegated tasks."
        ),
    },
    "A8": {
        "id": "A8",
        "name": "Identity & Access Mismanagement",
        "description": (
            "Agents inherit overprivileged identities or there's no proper auth "
            "between the agent and the tools/services it accesses."
        ),
    },
    "A9": {
        "id": "A9",
        "name": "Inadequate Logging & Monitoring",
        "description": (
            "Agent actions aren't properly logged or monitored. If something goes "
            "wrong, there's no audit trail to figure out what happened."
        ),
    },
    "A10": {
        "id": "A10",
        "name": "Supply Chain Vulnerabilities in Agent Components",
        "description": (
            "Compromised tools, plugins, or MCP servers in the agent's supply chain. "
            "The agent trusts a tool that has been tampered with."
        ),
    },
}

# ── Severity levels ────────────────────────────────────────────────
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}
