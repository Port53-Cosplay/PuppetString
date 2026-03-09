"""Remediation generator — produces fix suggestions for findings.

Uses LiteLLM to generate context-aware remediation advice when an API key
is available. Falls back to pre-written templates keyed by OWASP category
when the LLM is unavailable.
"""

from __future__ import annotations

from puppetstring.modules.owasp_audit.models import UnifiedFinding
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)

# ── Template remediation text per OWASP category ─────────────────
# These are the fallback when no LLM API key is configured.

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "A1": (
        "Excessive Agency: Apply the principle of least privilege. Remove tools the agent "
        "does not need for its primary task. Implement approval workflows for destructive "
        "operations. Define explicit tool allowlists per agent role."
    ),
    "A2": (
        "Uncontrolled Tool Execution: Add input validation on all tool parameters. "
        "Implement human-in-the-loop confirmation for sensitive operations (file writes, "
        "API calls, shell commands). Rate-limit tool invocations."
    ),
    "A3": (
        "Prompt Injection via Tools: Sanitize all external data before including it in "
        "agent context. Use data/instruction separation (e.g., XML tags, special tokens). "
        "Implement canary-based detection for instruction-following in tool outputs."
    ),
    "A4": (
        "Insecure Output Handling: Never pass agent outputs directly to interpreters "
        "(SQL engines, shell, eval). Sanitize and validate agent outputs before downstream "
        "consumption. Use parameterized queries and structured output formats."
    ),
    "A5": (
        "Memory & Context Manipulation: Validate memory contents before retrieval. "
        "Implement memory integrity checks (checksums, signatures). Limit the window "
        "of influence for injected context. Use separate memory stores per trust level."
    ),
    "A6": (
        "Overreliance on Agent Outputs: Implement human review for high-stakes decisions. "
        "Add confidence scores to agent outputs. Establish clear escalation paths for "
        "uncertain or high-impact actions. This is primarily an organizational control."
    ),
    "A7": (
        "Multi-Agent Trust Exploitation: Authenticate inter-agent communications. "
        "Implement per-agent permission boundaries. Don't let low-privilege agents "
        "delegate tasks to high-privilege agents without approval. Validate the source "
        "of delegated instructions."
    ),
    "A8": (
        "Identity & Access Mismanagement: Use scoped credentials per agent (not shared "
        "service accounts). Implement proper authentication between agents and their tools. "
        "Rotate credentials regularly. Audit access patterns."
    ),
    "A9": (
        "Inadequate Logging & Monitoring: Log all tool invocations with full parameters "
        "and results. Implement alerting for anomalous tool usage patterns. Maintain "
        "an audit trail of agent decisions and actions. Monitor for prompt injection attempts."
    ),
    "A10": (
        "Supply Chain Vulnerabilities: Vet all MCP servers, plugins, and tool providers. "
        "Pin tool/server versions. Verify tool integrity (checksums, signatures). "
        "Monitor for supply chain compromise indicators. Use allowlists for approved tools."
    ),
}

_LLM_SYSTEM_PROMPT = (
    "You are a security remediation advisor for AI agent systems. "
    "Given a security finding from a red team assessment, provide a concise, "
    "actionable remediation recommendation. Focus on specific technical fixes, "
    "not generic advice. Keep your response under 200 words."
)

_LLM_USER_TEMPLATE = """Security Finding:
Title: {title}
Severity: {severity}
OWASP Categories: {owasp_ids}
Source Module: {source_module}
Description: {description}
Evidence: {evidence}

Provide a specific remediation recommendation for this finding."""


class RemediationGenerator:
    """Generates remediation advice for unified findings."""

    def __init__(self, model: str = "claude-haiku-4-5-20251001") -> None:
        self._model = model

    async def generate(self, finding: UnifiedFinding) -> str:
        """Generate remediation text for a finding.

        Tries LLM first, falls back to template on failure.
        """
        if finding.remediation:
            return finding.remediation

        try:
            return await self._generate_llm(finding)
        except Exception as exc:  # noqa: BLE001
            logger.debug("LLM remediation failed, using template: %s", exc)
            return self._generate_template(finding)

    def generate_sync(self, finding: UnifiedFinding) -> str:
        """Synchronous template-only remediation (no LLM call)."""
        if finding.remediation:
            return finding.remediation
        return self._generate_template(finding)

    async def _generate_llm(self, finding: UnifiedFinding) -> str:
        """Call LLM for context-aware remediation."""
        import litellm  # noqa: PLC0415

        user_prompt = _LLM_USER_TEMPLATE.format(
            title=finding.title,
            severity=finding.severity.value,
            owasp_ids=", ".join(finding.owasp_ids),
            source_module=finding.source_module,
            description=finding.description,
            evidence=finding.evidence[:500],
        )

        response = await litellm.acompletion(
            model=self._model,
            messages=[
                {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=400,
        )

        return response.choices[0].message.content or self._generate_template(finding)

    @staticmethod
    def _generate_template(finding: UnifiedFinding) -> str:
        """Generate remediation from pre-written templates."""
        parts: list[str] = []
        for oid in finding.owasp_ids:
            if oid in _REMEDIATION_TEMPLATES:
                parts.append(_REMEDIATION_TEMPLATES[oid])

        if parts:
            return " ".join(parts)

        # Generic fallback if no OWASP IDs matched
        return (
            "Review the finding details and implement appropriate security controls. "
            "Consult the OWASP Top 10 for Agentic AI for category-specific guidance."
        )
