"""Shared test fixtures for PuppetString.

WHAT ARE FIXTURES?
    In pytest, a "fixture" is a reusable piece of setup code. Instead of
    repeating the same setup in every test, you define it once as a fixture
    and pytest automatically provides it to any test that asks for it.

    Example — if 10 tests all need a default config object, instead of
    creating it 10 times, you write one fixture and each test just says
    "give me the default_config fixture."

WHAT IS conftest.py?
    conftest.py is a special pytest file. Any fixtures defined here are
    automatically available to ALL test files in this directory (and
    subdirectories) without needing to import them. It's like a shared
    toolkit for your tests.
"""

import pytest

from puppetstring.config import PuppetStringConfig
from puppetstring.core.models import ScanResult


@pytest.fixture
def default_config() -> PuppetStringConfig:
    """Provide a default PuppetString configuration for tests."""
    return PuppetStringConfig()


@pytest.fixture
def scan_result() -> ScanResult:
    """Provide an empty ScanResult for tests."""
    return ScanResult(target="mcp://localhost:3000", scan_type="scan")
