"""Tests for the remediation generator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from puppetstring.core.models import Severity
from puppetstring.modules.owasp_audit.models import UnifiedFinding
from puppetstring.reporting.remediation import (
    _REMEDIATION_TEMPLATES,
    RemediationGenerator,
)


class TestRemediationTemplates:
    """Tests for template-based remediation (no LLM)."""

    @pytest.mark.parametrize(
        "owasp_id",
        ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10"],
    )
    def test_all_owasp_categories_have_templates(self, owasp_id: str) -> None:
        assert owasp_id in _REMEDIATION_TEMPLATES
        assert len(_REMEDIATION_TEMPLATES[owasp_id]) > 20

    def test_template_fallback_per_owasp_id(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.HIGH,
            owasp_ids=["A3"],
            source_module="tangle",
        )
        result = gen.generate_sync(finding)
        assert "Prompt Injection" in result

    def test_template_fallback_multi_owasp(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.HIGH,
            owasp_ids=["A1", "A3"],
        )
        result = gen.generate_sync(finding)
        assert "Excessive Agency" in result
        assert "Prompt Injection" in result

    def test_generic_fallback_for_unknown_owasp(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.MEDIUM,
            owasp_ids=["A99"],
        )
        result = gen.generate_sync(finding)
        assert "OWASP" in result

    def test_existing_remediation_returned_as_is(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.LOW,
            owasp_ids=["A1"],
            remediation="Already has remediation text",
        )
        result = gen.generate_sync(finding)
        assert result == "Already has remediation text"


class TestRemediationLLM:
    """Tests for LLM-based remediation."""

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_template(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.HIGH,
            owasp_ids=["A3"],
            source_module="tangle",
        )

        with patch.dict("sys.modules", {"litellm": MagicMock()}) as _:
            import litellm  # noqa: PLC0415

            litellm.acompletion = AsyncMock(side_effect=Exception("No API key"))
            result = await gen.generate(finding)

        # Should fall back to template
        assert "Prompt Injection" in result

    @pytest.mark.asyncio
    async def test_llm_success_returns_llm_text(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.HIGH,
            owasp_ids=["A3"],
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "LLM generated fix"

        with patch.dict("sys.modules", {"litellm": MagicMock()}) as _:
            import litellm  # noqa: PLC0415

            litellm.acompletion = AsyncMock(return_value=mock_response)
            result = await gen.generate(finding)

        assert result == "LLM generated fix"

    @pytest.mark.asyncio
    async def test_existing_remediation_skips_llm(self) -> None:
        gen = RemediationGenerator()
        finding = UnifiedFinding(
            title="Test",
            severity=Severity.HIGH,
            owasp_ids=["A3"],
            remediation="Pre-existing fix",
        )
        result = await gen.generate(finding)
        assert result == "Pre-existing fix"
