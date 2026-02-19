"""Smoke tests — verify the install is sane and all modules import.

These tests exist to catch wiring issues early. If the editable install
breaks (e.g., pointing to a deleted directory, wrong Python, missing
dependency), these tests will fail LOUDLY before anything else confuses you.

Run with: python -m pytest tests/test_smoke.py -v
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

# ── Every module that should be importable after `pip install -e .` ──

EXPECTED_MODULES = [
    "puppetstring",
    "puppetstring.cli",
    "puppetstring.config",
    "puppetstring.core.models",
    "puppetstring.adapters.agent_adapter",
    "puppetstring.adapters.http_adapter",
    "puppetstring.adapters.mcp_adapter",
    "puppetstring.modules.mcp_scanner",
    "puppetstring.modules.workflow_fuzzer",
    "puppetstring.modules.prompt_injection",
    "puppetstring.modules.prompt_injection.encoding",
    "puppetstring.modules.prompt_injection.document_generator",
    "puppetstring.modules.prompt_injection.engine",
    "puppetstring.modules.prompt_injection.judge",
    "puppetstring.modules.prompt_injection.models",
    "puppetstring.modules.prompt_injection.payload_loader",
    "puppetstring.modules.prompt_injection.payload_generator",
    "puppetstring.payloads.loader",
    "puppetstring.reporting.terminal",
    "puppetstring.utils.logging",
    "puppetstring.utils.constants",
]


class TestEnvironmentSanity:
    """Verify the development environment is correctly set up."""

    def test_running_in_venv(self) -> None:
        """Python should be running inside a virtual environment."""
        assert sys.prefix != sys.base_prefix, (
            f"Not running in a venv! sys.prefix={sys.prefix}, "
            f"sys.base_prefix={sys.base_prefix}. "
            "Activate the venv before running tests."
        )

    def test_package_is_importable(self) -> None:
        """The puppetstring package must be importable."""
        import puppetstring

        assert puppetstring.__file__ is not None

    def test_package_has_version(self) -> None:
        """The package must expose a __version__."""
        from puppetstring import __version__

        assert __version__, "Package __version__ is empty or not set"

    def test_package_source_directory_exists(self) -> None:
        """The resolved package directory must exist on disk."""
        import puppetstring

        pkg_dir = Path(puppetstring.__file__).resolve().parent
        assert pkg_dir.exists(), f"Package directory does not exist: {pkg_dir}"
        assert (pkg_dir / "cli.py").exists(), f"cli.py missing from {pkg_dir}"

    def test_cli_entry_point(self) -> None:
        """The Typer app must be importable and not None."""
        from puppetstring.cli import app

        assert app is not None


class TestModuleImports:
    """Every core module must be importable without errors.

    If any of these fail, the editable install is broken or a dependency
    is missing. Fix the install before doing anything else.
    """

    def _import(self, module_name: str) -> None:
        """Try to import a module; raise AssertionError with details on failure."""
        try:
            importlib.import_module(module_name)
        except ImportError as exc:
            raise AssertionError(  # noqa: B904
                f"Cannot import {module_name}: {exc}. "
                "Is the editable install pointing to the right directory? "
                "Try: pip install -e ."
            )

    def test_import_puppetstring(self) -> None:
        self._import("puppetstring")

    def test_import_cli(self) -> None:
        self._import("puppetstring.cli")

    def test_import_config(self) -> None:
        self._import("puppetstring.config")

    def test_import_core_models(self) -> None:
        self._import("puppetstring.core.models")

    def test_import_agent_adapter(self) -> None:
        self._import("puppetstring.adapters.agent_adapter")

    def test_import_http_adapter(self) -> None:
        self._import("puppetstring.adapters.http_adapter")

    def test_import_mcp_adapter(self) -> None:
        self._import("puppetstring.adapters.mcp_adapter")

    def test_import_mcp_scanner(self) -> None:
        self._import("puppetstring.modules.mcp_scanner")

    def test_import_workflow_fuzzer(self) -> None:
        self._import("puppetstring.modules.workflow_fuzzer")

    def test_import_prompt_injection(self) -> None:
        self._import("puppetstring.modules.prompt_injection")

    def test_import_encoding(self) -> None:
        self._import("puppetstring.modules.prompt_injection.encoding")

    def test_import_document_generator(self) -> None:
        self._import("puppetstring.modules.prompt_injection.document_generator")

    def test_import_injection_engine(self) -> None:
        self._import("puppetstring.modules.prompt_injection.engine")

    def test_import_injection_judge(self) -> None:
        self._import("puppetstring.modules.prompt_injection.judge")

    def test_import_injection_models(self) -> None:
        self._import("puppetstring.modules.prompt_injection.models")

    def test_import_payload_loader(self) -> None:
        self._import("puppetstring.modules.prompt_injection.payload_loader")

    def test_import_payload_generator(self) -> None:
        self._import("puppetstring.modules.prompt_injection.payload_generator")

    def test_import_payloads_loader(self) -> None:
        self._import("puppetstring.payloads.loader")

    def test_import_terminal_reporter(self) -> None:
        self._import("puppetstring.reporting.terminal")

    def test_import_utils_logging(self) -> None:
        self._import("puppetstring.utils.logging")

    def test_import_utils_constants(self) -> None:
        self._import("puppetstring.utils.constants")
