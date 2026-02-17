"""Tests for configuration loading."""

from puppetstring.config import PuppetStringConfig, load_config


def test_default_config_loads() -> None:
    """Loading config with no file should return valid defaults."""
    config = load_config()
    assert config.general.llm_provider == "anthropic"
    assert config.scan.timeout == 30
    assert config.fuzz.delay_between_payloads == 1.0


def test_config_has_all_sections(default_config: PuppetStringConfig) -> None:
    """Default config should have all expected sections."""
    assert default_config.general is not None
    assert default_config.scan is not None
    assert default_config.fuzz is not None
    assert default_config.inject is not None
    assert default_config.report is not None
