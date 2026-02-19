"""Data models for indirect prompt injection testing (Phase 3: `puppetstring tangle`).

These Pydantic models define the shape of all data flowing through the tangle
module. Two modes:

    1. DOCUMENT MODE — Generate poisoned documents (SVG, HTML, PDF, Markdown)
       that contain hidden instructions. Upload them to any AI system to test
       whether the agent follows the hidden instructions.

    2. LIVE MODE — Test a running agent by intercepting tool outputs and
       injecting adversarial content mid-flight. The agent calls a tool,
       we poison the result, and see if the agent follows the hidden instructions.

Model hierarchy:
    InjectionPayload     — one adversarial payload (text + metadata)
    GeneratedDocument    — one poisoned file produced by document mode
    InjectionResult      — one test result (payload + agent response + judgment)
    TangleRunResult      — complete output of a tangle session
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from puppetstring.core.models import AgentResponse, Severity
from puppetstring.utils.constants import SEVERITY_ORDER

# ── Enums ─────────────────────────────────────────────────────────


class InjectionVector(StrEnum):
    """How the adversarial content reaches the agent."""

    DOCUMENT = "document"  # Hidden in a file the agent reads
    TOOL_OUTPUT = "tool-output"  # Injected into a tool's return value
    ALL = "all"  # Run all vectors


class DocumentFormat(StrEnum):
    """File formats that can carry hidden instructions."""

    SVG = "svg"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"
    IMAGE = "image"
    PLAINTEXT = "plaintext"


class EncodingTechnique(StrEnum):
    """Steganographic / encoding techniques for hiding instructions."""

    # SVG-specific
    SVG_DESC = "svg-desc"  # <desc> element
    SVG_TITLE = "svg-title"  # <title> element
    SVG_METADATA = "svg-metadata"  # <metadata> with Dublin Core
    SVG_INVISIBLE_TEXT = "svg-invisible-text"  # font-size:0 or white text
    SVG_HIDDEN_RECT = "svg-hidden-rect"  # text behind opaque rect
    SVG_COMMENT = "svg-comment"  # XML comments
    SVG_DATA_ATTR = "svg-data-attr"  # custom data-* attributes

    # HTML-specific
    HTML_WHITE_TEXT = "html-white-text"  # color:white; font-size:0.1px
    HTML_DISPLAY_NONE = "html-display-none"  # display:none div
    HTML_COMMENT = "html-comment"  # HTML comments
    HTML_ARIA_HIDDEN = "html-aria-hidden"  # aria-hidden off-screen span
    HTML_DATA_ATTR = "html-data-attr"  # data-* attributes

    # Markdown-specific
    MD_COMMENT = "md-comment"  # HTML comments in markdown
    MD_LINK_TITLE = "md-link-title"  # [text](url "hidden")
    MD_ALT_TEXT = "md-alt-text"  # image alt text

    # PDF-specific
    PDF_WHITE_TEXT = "pdf-white-text"  # white text on white background
    PDF_METADATA = "pdf-metadata"  # Author/Subject/Keywords fields
    PDF_TINY_TEXT = "pdf-tiny-text"  # near-zero font at margins

    # Image-specific (PNG)
    IMAGE_EXIF = "image-exif"  # EXIF ImageDescription, Artist, Copyright
    IMAGE_XMP = "image-xmp"  # XMP XML metadata packet
    IMAGE_OVERLAY = "image-overlay"  # near-invisible text drawn on image
    IMAGE_IPTC = "image-iptc"  # PNG text chunks (Description, Comment)

    # Unicode (works in any text format)
    UNICODE_ZERO_WIDTH = "unicode-zero-width"  # ZWJ/ZWNJ/ZWSP
    UNICODE_TAGS = "unicode-tags"  # Tag characters U+E0001-E007F
    UNICODE_HOMOGLYPHS = "unicode-homoglyphs"  # Cyrillic/Greek lookalikes
    UNICODE_SEPARATORS = "unicode-separators"  # invisible separators


class GoalType(StrEnum):
    """Categories of injection goals for smart payload filtering."""

    CANARY = "canary"  # Inject a specific word/phrase into output
    EXFIL_SYSTEM_PROMPT = "exfil:system-prompt"  # Extract system instructions
    EXFIL_API_KEYS = "exfil:api-keys"  # Extract API keys / credentials
    TOOL_ABUSE_FILE_READ = "tool-abuse:file-read"  # Trick into reading files
    TOOL_ABUSE_COMMAND = "tool-abuse:command"  # Trick into running commands
    TOOL_ABUSE_EMAIL = "tool-abuse:email"  # Trick into sending emails
    OVERRIDE_IDENTITY = "override:identity"  # Override persona / behavior
    OVERRIDE_SAFETY = "override:safety"  # Bypass safety guidelines
    DOS = "dos"  # Cause denial of service / refusal
    SOCIAL_ENGINEERING = "social-engineering"  # Trick user via agent


class ParsedGoal:
    """Parsed injection goal with type classification for smart filtering.

    Parses goal strings like:
        "canary:BANANA"          → GoalType.CANARY, detail="BANANA"
        "exfil:system-prompt"    → GoalType.EXFIL_SYSTEM_PROMPT
        "tool-abuse:file-read"   → GoalType.TOOL_ABUSE_FILE_READ
        "override:identity"      → GoalType.OVERRIDE_IDENTITY
        "make it say hello"      → inferred via keyword heuristic

    The `matching_tags` property returns YAML payload tags that correspond
    to this goal type, enabling smart filtering without substring matching.
    """

    __slots__ = ("raw", "goal_type", "detail")

    # Map structured goal prefixes to GoalType values
    _PREFIX_MAP: dict[str, GoalType] = {
        "canary": GoalType.CANARY,
        "exfil:system-prompt": GoalType.EXFIL_SYSTEM_PROMPT,
        "exfil:api-keys": GoalType.EXFIL_API_KEYS,
        "tool-abuse:file-read": GoalType.TOOL_ABUSE_FILE_READ,
        "tool-abuse:command": GoalType.TOOL_ABUSE_COMMAND,
        "tool-abuse:email": GoalType.TOOL_ABUSE_EMAIL,
        "override:identity": GoalType.OVERRIDE_IDENTITY,
        "override:safety": GoalType.OVERRIDE_SAFETY,
        "dos": GoalType.DOS,
        "social-engineering": GoalType.SOCIAL_ENGINEERING,
    }

    # Map GoalType to payload tags for filtering
    _TAG_MAP: dict[GoalType, list[str]] = {
        GoalType.CANARY: ["canary"],
        GoalType.EXFIL_SYSTEM_PROMPT: ["exfiltration"],
        GoalType.EXFIL_API_KEYS: ["exfiltration"],
        GoalType.TOOL_ABUSE_FILE_READ: ["tool-abuse", "tool-chain", "file"],
        GoalType.TOOL_ABUSE_COMMAND: ["tool-abuse", "command"],
        GoalType.TOOL_ABUSE_EMAIL: ["action", "email"],
        GoalType.OVERRIDE_IDENTITY: ["override", "identity", "jailbreak"],
        GoalType.OVERRIDE_SAFETY: ["jailbreak", "bypass"],
        GoalType.DOS: ["dos"],
        GoalType.SOCIAL_ENGINEERING: ["social-engineering"],
    }

    # Keyword heuristic for freeform goal strings
    _KEYWORD_MAP: dict[str, GoalType] = {
        "canary": GoalType.CANARY,
        "banana": GoalType.CANARY,
        "pineapple": GoalType.CANARY,
        "mango": GoalType.CANARY,
        "system prompt": GoalType.EXFIL_SYSTEM_PROMPT,
        "exfiltrate": GoalType.EXFIL_SYSTEM_PROMPT,
        "exfil": GoalType.EXFIL_SYSTEM_PROMPT,
        "api key": GoalType.EXFIL_API_KEYS,
        "credential": GoalType.EXFIL_API_KEYS,
        "read file": GoalType.TOOL_ABUSE_FILE_READ,
        "read_file": GoalType.TOOL_ABUSE_FILE_READ,
        "/etc/passwd": GoalType.TOOL_ABUSE_FILE_READ,
        "run command": GoalType.TOOL_ABUSE_COMMAND,
        "run_command": GoalType.TOOL_ABUSE_COMMAND,
        "execute": GoalType.TOOL_ABUSE_COMMAND,
        "send email": GoalType.TOOL_ABUSE_EMAIL,
        "send_email": GoalType.TOOL_ABUSE_EMAIL,
        "override": GoalType.OVERRIDE_IDENTITY,
        "persona": GoalType.OVERRIDE_IDENTITY,
        "identity": GoalType.OVERRIDE_IDENTITY,
        "jailbreak": GoalType.OVERRIDE_SAFETY,
        "ignore safety": GoalType.OVERRIDE_SAFETY,
        "deny": GoalType.DOS,
        "refuse": GoalType.DOS,
        "phishing": GoalType.SOCIAL_ENGINEERING,
        "social engineer": GoalType.SOCIAL_ENGINEERING,
    }

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.goal_type: GoalType | None = None
        self.detail: str = ""
        self._parse()

    def _parse(self) -> None:
        """Parse the raw goal string into a typed goal."""
        goal_lower = self.raw.lower().strip()

        # Try structured prefix matching (longest match first)
        for prefix, gtype in sorted(
            self._PREFIX_MAP.items(), key=lambda x: len(x[0]), reverse=True
        ):
            if goal_lower.startswith(prefix):
                self.goal_type = gtype
                # Extract detail after the prefix (e.g., "canary:BANANA" → "BANANA")
                remainder = self.raw[len(prefix) :].lstrip(":").strip()
                self.detail = remainder
                return

        # Fall back to keyword heuristic
        for keyword, gtype in self._KEYWORD_MAP.items():
            if keyword in goal_lower:
                self.goal_type = gtype
                self.detail = self.raw
                return

        # Unknown goal — no type classification
        self.detail = self.raw

    @property
    def matching_tags(self) -> list[str]:
        """Return payload tags that match this goal type."""
        if self.goal_type is None:
            return []
        return self._TAG_MAP.get(self.goal_type, [])

    @property
    def is_structured(self) -> bool:
        """Whether the goal was parsed from a structured prefix (e.g., 'canary:BANANA')."""
        return self.goal_type is not None


class InjectionClassification(StrEnum):
    """How the judge grades an indirect injection attempt.

    EXPLOITED — The agent followed the hidden instructions.
    PARTIAL   — The agent showed influence but didn't fully comply.
    BLOCKED   — The agent ignored the hidden instructions entirely.
    ERROR     — Something went wrong (timeout, crash, etc.).
    """

    EXPLOITED = "exploited"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    ERROR = "error"


# ── Payload models ────────────────────────────────────────────────


class InjectionPayload(BaseModel):
    """One adversarial payload for indirect prompt injection.

    Unlike fuzzer payloads (which are sent directly as user messages),
    injection payloads are HIDDEN in data the agent consumes. The agent
    shouldn't see them as user instructions — that's the whole point.
    """

    name: str
    category: str  # "document", "tool-output", "encoding"
    hidden_text: str  # the adversarial instruction to hide
    goal: str  # what success looks like ("agent says BANANA")
    technique: EncodingTechnique | None = None
    target_format: DocumentFormat | None = None
    trigger_query: str = ""  # benign query that triggers the agent to read the data
    owasp_ids: list[str] = Field(default_factory=lambda: ["A3"])
    tags: list[str] = Field(default_factory=list)

    # For tool-output injection: which tool to poison and how
    tool_name: str | None = None  # e.g. "search", "read_file"
    result_prefix: str = ""  # prepend to real tool result
    result_replace: str = ""  # replace tool result entirely


# ── Output models ─────────────────────────────────────────────────


class GeneratedDocument(BaseModel):
    """One poisoned document produced by document generation mode."""

    format: DocumentFormat
    technique: EncodingTechnique
    filename: str
    file_path: Path | None = None
    hidden_text: str  # what was hidden
    visible_content: str = ""  # summary of what the document looks like
    raw_content: str = ""  # the actual file content (for non-binary formats)
    size_bytes: int = 0

    model_config = {"arbitrary_types_allowed": True}


class InjectionResult(BaseModel):
    """One complete injection test: what we hid, what happened, how it was judged."""

    payload_name: str
    payload_category: str
    hidden_text: str
    goal: str
    technique: EncodingTechnique | None = None
    trigger_query: str = ""
    response: AgentResponse | None = None  # None for document-only mode
    classification: InjectionClassification = InjectionClassification.ERROR
    severity: Severity = Severity.INFO
    explanation: str = ""
    owasp_ids: list[str] = Field(default_factory=lambda: ["A3"])

    @property
    def sort_key(self) -> int:
        """Numeric sort key (lower = more severe)."""
        return SEVERITY_ORDER.get(self.severity.value, 99)


class TangleRunResult(BaseModel):
    """Complete output of a tangle session — documents + test results + metadata."""

    target: str  # "document-generation" or the target URL
    vector: str  # "document", "tool-output", "all"
    goal: str = ""
    documents: list[GeneratedDocument] = Field(default_factory=list)
    results: list[InjectionResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def summary(self) -> dict[str, int]:
        """Count results by classification."""
        counts: dict[str, int] = {c.value: 0 for c in InjectionClassification}
        for r in self.results:
            counts[r.classification.value] += 1
        return counts

    @property
    def exploited_count(self) -> int:
        return sum(1 for r in self.results if r.classification == InjectionClassification.EXPLOITED)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.classification == InjectionClassification.PARTIAL)

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.results if r.classification == InjectionClassification.BLOCKED)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.classification == InjectionClassification.ERROR)

    @property
    def sorted_results(self) -> list[InjectionResult]:
        """Results sorted by severity (critical first)."""
        return sorted(self.results, key=lambda r: r.sort_key)
