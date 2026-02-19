"""Configuration management for PuppetString.

HOW THIS WORKS (plain English):
    PuppetString needs to know things like "which LLM provider should I use?"
    and "how long should I wait before timing out?" These settings can come
    from three places, in order of priority (highest wins):

    1. CLI flags        (e.g., --output json)       — highest priority
    2. Config file      (.puppetstring.toml)         — project-level defaults
    3. Built-in defaults (defined below)             — fallback if nothing else

    This module handles loading the config file and providing those defaults.
    CLI flags override config file values, which override built-in defaults.

WHAT IS TOML?
    TOML is a config file format (like JSON or YAML, but designed to be easy
    for humans to read and write). Python 3.11+ can read it natively with the
    built-in `tomllib` module — no extra library needed.

    Example .puppetstring.toml:
        [general]
        llm_provider = "anthropic"
        verbose = false

        [scan]
        timeout = 30

WHAT IS PYDANTIC?
    Pydantic is a data validation library. You define a class with typed fields,
    and Pydantic ensures the data matches those types. If someone puts
    timeout = "banana" in their config file, Pydantic catches it immediately
    with a clear error instead of letting it blow up later in confusing ways.
"""

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

# ── Default config file name ──────────────────────────────────────
CONFIG_FILENAME = ".puppetstring.toml"


# ── Config models ─────────────────────────────────────────────────
# Each section of the TOML file maps to one of these classes.
# The Field() calls define default values and descriptions.


class GeneralConfig(BaseModel):
    """Top-level general settings."""

    llm_provider: str = Field(
        default="anthropic",
        description="LLM provider: anthropic, openai, or ollama",
    )
    llm_model: str = Field(
        default="claude-haiku-4-5-20251001",
        description="Model name for LLM judge and dynamic payload generation",
    )
    llm_api_key_env: str = Field(
        default="ANTHROPIC_API_KEY",
        description="Name of the environment variable holding the API key",
    )
    output_format: str = Field(
        default="terminal",
        description="Default output format: terminal, html, json, markdown",
    )
    output_dir: str = Field(
        default="./puppetstring_results",
        description="Directory for storing results",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )


class ScanConfig(BaseModel):
    """Settings for the `pull --type scan` command (MCP scanning)."""

    timeout: int = Field(
        default=30,
        description="Seconds to wait per tool test before timing out",
    )
    max_tools: int = Field(
        default=100,
        description="Maximum number of tools to enumerate from an MCP server",
    )
    check_auth: bool = Field(default=True, description="Check authentication mechanisms")
    check_permissions: bool = Field(default=True, description="Map tool permissions")
    check_inputs: bool = Field(default=True, description="Test input validation")
    check_config: bool = Field(default=True, description="Review server configuration")


class FuzzConfig(BaseModel):
    """Settings for the `pull --type [fuzz]` command (workflow fuzzing)."""

    timeout: int = Field(
        default=300,
        description=(
            "Seconds to wait per request. Local LLMs with tool-calling loops "
            "can take 2-3 min per message — increase this for multi-turn payloads."
        ),
    )
    payloads_dir: str = Field(
        default="default",
        description="'default' uses built-in payloads, or specify a path",
    )
    max_payloads: int = Field(
        default=50,
        description="Maximum payloads to send per category",
    )
    delay_between_payloads: float = Field(
        default=1.0,
        description="Seconds to wait between sending payloads (be nice to targets)",
    )
    conversation_reset: bool = Field(
        default=True,
        description="Reset the conversation between each payload",
    )
    judge_model: str = Field(
        default="claude-haiku-4-5-20251001",
        description="LLM model used to judge whether attacks succeeded",
    )


class InjectConfig(BaseModel):
    """Settings for the `tangle` command (indirect prompt injection)."""

    encoding_variants: bool = Field(
        default=True,
        description="Test Unicode/homoglyph encoding bypasses",
    )
    generate_dynamic_payloads: bool = Field(
        default=True,
        description="Use an LLM to generate novel payloads on the fly",
    )
    default_goal: str = Field(
        default="Include the word BANANA in every sentence",
        description="Default adversarial goal for document generation",
    )
    default_formats: list[str] = Field(
        default=["svg", "html", "markdown"],
        description="Default document formats to generate (svg, html, markdown, pdf)",
    )
    output_dir: str = Field(
        default="./puppetstring_results/tangle_documents",
        description="Directory for generated poisoned documents",
    )
    judge_model: str = Field(
        default="claude-haiku-4-5-20251001",
        description="LLM model used to judge injection results",
    )
    delay_between_injections: float = Field(
        default=1.0,
        description="Seconds to wait between injection attempts",
    )
    max_injections: int = Field(
        default=50,
        description="Maximum injection payloads to test per run",
    )


class ReportConfig(BaseModel):
    """Settings for the `unravel` command (report generation)."""

    include_full_transcripts: bool = Field(
        default=True,
        description="Include complete conversation logs in reports",
    )
    include_remediation: bool = Field(
        default=True,
        description="Include remediation suggestions per finding",
    )
    company_name: str = Field(
        default="",
        description="Company name for branded reports (leave empty for generic)",
    )


class PuppetStringConfig(BaseModel):
    """Root configuration model — contains all sections."""

    general: GeneralConfig = Field(default_factory=GeneralConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    fuzz: FuzzConfig = Field(default_factory=FuzzConfig)
    inject: InjectConfig = Field(default_factory=InjectConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)


# ── Config loading ────────────────────────────────────────────────


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """Search for .puppetstring.toml starting from start_dir, walking up to root.

    This mimics how tools like .gitignore work — it looks in the current
    directory first, then the parent, then the grandparent, etc., until it
    either finds the file or reaches the filesystem root.
    """
    search_dir = (start_dir or Path.cwd()).resolve()

    while True:
        candidate = search_dir / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        parent = search_dir.parent
        if parent == search_dir:
            # Reached filesystem root without finding the file
            return None
        search_dir = parent


def load_config(config_path: Path | None = None) -> PuppetStringConfig:
    """Load configuration from a TOML file, falling back to defaults.

    Args:
        config_path: Explicit path to a config file. If None, searches
                     for .puppetstring.toml in the current directory and parents.

    Returns:
        A fully validated PuppetStringConfig with all defaults filled in.
    """
    if config_path is None:
        config_path = find_config_file()

    if config_path is not None and config_path.is_file():
        with open(config_path, "rb") as f:
            raw = tomllib.load(f)
        return PuppetStringConfig.model_validate(raw)

    # No config file found — use all defaults
    return PuppetStringConfig()
