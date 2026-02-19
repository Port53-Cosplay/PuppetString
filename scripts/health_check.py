#!/usr/bin/env python3
"""PuppetString Environment Health Check.

Verifies that the development environment is correctly wired:
  1. Running inside a virtual environment (not system Python)
  2. The editable install points to the expected source directory
  3. All core modules can be imported
  4. The CLI entry point resolves correctly

Run this after:
  - Migrating the project to a new directory
  - Re-creating the virtual environment
  - Running pip install -e .
  - Any session where something "just stopped working"

Usage:
    python scripts/health_check.py
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────

# Every subpackage that should be importable after `pip install -e .`
CORE_IMPORTS = [
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
    "puppetstring.payloads.loader",
    "puppetstring.reporting.terminal",
    "puppetstring.utils.logging",
    "puppetstring.utils.constants",
]

# ── Checks ──────────────────────────────────────────────────────────

_pass = 0
_fail = 0


def _check(label: str, passed: bool, detail: str = "") -> None:
    global _pass, _fail  # noqa: PLW0603
    if passed:
        _pass += 1
        print(f"  PASS  {label}")
    else:
        _fail += 1
        msg = f"  FAIL  {label}"
        if detail:
            msg += f"  --  {detail}"
        print(msg)


def check_venv() -> None:
    """Verify we're running inside a virtual environment."""
    in_venv = sys.prefix != sys.base_prefix
    _check(
        "Running inside a virtual environment",
        in_venv,
        f"sys.prefix={sys.prefix}" if not in_venv else "",
    )


def check_editable_install() -> None:
    """Verify the editable install points to a real, accessible directory."""
    try:
        import puppetstring

        pkg_path = Path(puppetstring.__file__).resolve().parent
        _check(
            f"puppetstring package resolves to: {pkg_path}",
            pkg_path.exists(),
        )

        # Check that the resolved path contains expected files
        cli_path = pkg_path / "cli.py"
        _check(
            "cli.py exists in package directory",
            cli_path.exists(),
            f"Expected {cli_path}" if not cli_path.exists() else "",
        )

        # Check that the package is an editable install (has a .pth or direct link)
        # by verifying the source is not inside site-packages
        site_packages = Path(sys.prefix) / "Lib" / "site-packages"
        is_editable = not str(pkg_path).startswith(str(site_packages))
        _check(
            "Package is an editable install (not in site-packages)",
            is_editable,
            f"Found in site-packages at {pkg_path}" if not is_editable else "",
        )

    except ImportError as exc:
        _check("puppetstring package importable", False, str(exc))


def check_imports() -> None:
    """Verify all core modules can be imported."""
    for module_name in CORE_IMPORTS:
        try:
            importlib.import_module(module_name)
            _check(f"import {module_name}", True)
        except ImportError as exc:
            _check(f"import {module_name}", False, str(exc))
        except Exception as exc:  # noqa: BLE001
            _check(f"import {module_name}", False, f"Unexpected error: {exc}")


def check_cli_entry_point() -> None:
    """Verify the CLI entry point resolves."""
    try:
        from puppetstring.cli import app

        _check(
            "CLI entry point (puppetstring.cli:app) resolves",
            app is not None,
        )
    except ImportError as exc:
        _check("CLI entry point resolves", False, str(exc))


def check_version() -> None:
    """Verify __version__ is set."""
    try:
        from puppetstring import __version__

        _check(
            f"Package version: {__version__}",
            bool(__version__),
        )
    except ImportError as exc:
        _check("Package version accessible", False, str(exc))


# ── Main ────────────────────────────────────────────────────────────


def run_health_check() -> bool:
    """Run all health checks. Returns True if all passed."""
    print("=" * 60)
    print("  PuppetString Environment Health Check")
    print("=" * 60)
    print()

    print(f"Python:  {sys.executable}")
    print(f"Version: {sys.version}")
    print(f"Prefix:  {sys.prefix}")
    print()

    print("-- Virtual Environment --")
    check_venv()
    print()

    print("-- Editable Install --")
    check_editable_install()
    print()

    print("-- Module Imports --")
    check_imports()
    print()

    print("-- CLI & Version --")
    check_cli_entry_point()
    check_version()
    print()

    print("=" * 60)
    total = _pass + _fail
    if _fail == 0:
        print(f"  ALL {total} CHECKS PASSED")
    else:
        print(f"  {_fail} FAILED out of {total} checks")
    print("=" * 60)

    return _fail == 0


if __name__ == "__main__":
    success = run_health_check()
    sys.exit(0 if success else 1)
