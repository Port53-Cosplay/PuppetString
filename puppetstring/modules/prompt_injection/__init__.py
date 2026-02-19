"""Indirect prompt injection testing module (`puppetstring tangle`).

Provides document generation (poisoned SVG/HTML/PDF/Markdown/Image) and
live agent testing (tool output interception + injection classification).
"""

from puppetstring.modules.prompt_injection.document_generator import DocumentGenerator
from puppetstring.modules.prompt_injection.encoding import UnicodeEncoder
from puppetstring.modules.prompt_injection.engine import TangleEngine
from puppetstring.modules.prompt_injection.judge import InjectionJudge
from puppetstring.modules.prompt_injection.models import (
    DocumentFormat,
    EncodingTechnique,
    GoalType,
    InjectionClassification,
    InjectionPayload,
    InjectionResult,
    InjectionVector,
    ParsedGoal,
    TangleRunResult,
)
from puppetstring.modules.prompt_injection.payload_generator import PayloadGenerator

__all__ = [
    "DocumentFormat",
    "DocumentGenerator",
    "EncodingTechnique",
    "GoalType",
    "InjectionClassification",
    "InjectionJudge",
    "InjectionPayload",
    "InjectionResult",
    "InjectionVector",
    "ParsedGoal",
    "PayloadGenerator",
    "TangleEngine",
    "TangleRunResult",
    "UnicodeEncoder",
]
