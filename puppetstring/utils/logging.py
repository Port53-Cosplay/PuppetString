"""Structured logging for PuppetString using Rich.

HOW THIS WORKS (plain English):
    Instead of using print() everywhere (which gives you ugly, unstructured
    output), PuppetString uses Python's built-in `logging` module with Rich
    as the display layer. This gives us:

    - Colored output (errors in red, warnings in yellow, etc.)
    - Timestamps on every message
    - Log levels (DEBUG, INFO, WARNING, ERROR) so you can control verbosity
    - The ability to log to a file later without changing any code

    Throughout the codebase, instead of:
        print("Scanning target...")

    We do:
        logger = get_logger(__name__)
        logger.info("Scanning target...")

    The __name__ part automatically tags each log message with which module
    it came from, so you can tell if a message came from the scanner vs.
    the fuzzer vs. the CLI.

WHAT IS Rich?
    Rich is a Python library that makes terminal output beautiful. It adds
    colors, tables, progress bars, and formatted panels. We use it for both
    logging (this file) and for displaying scan results (later phases).
"""

import logging

from rich.console import Console
from rich.logging import RichHandler

# ── Shared console instance ───────────────────────────────────────
# A single Console object used across the whole app. This ensures
# consistent output formatting and avoids creating multiple consoles.
console = Console(stderr=True)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the entire application.

    Args:
        verbose: If True, show DEBUG-level messages (very detailed).
                 If False, show INFO and above (normal usage).
    """
    level = logging.DEBUG if verbose else logging.INFO

    # RichHandler makes log messages pretty in the terminal
    handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,  # Don't show file paths in output — too noisy
        markup=True,  # Allow Rich markup like [bold] in log messages
    )

    logging.basicConfig(
        level=level,
        format="%(message)s",  # Rich handles the formatting, so keep this simple
        handlers=[handler],
        force=True,  # Override any existing logging config
    )

    # Quiet down noisy third-party libraries
    # These libraries log a LOT at DEBUG level and it drowns out our messages
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger for a module.

    Usage:
        from puppetstring.utils.logging import get_logger
        logger = get_logger(__name__)
        logger.info("Starting scan...")
        logger.warning("No authentication found!")
        logger.error("Connection failed: %s", error_message)
    """
    return logging.getLogger(name)
