"""Payload library — attack messages for fuzzing AI agents."""

from puppetstring.payloads.loader import (
    load_builtin_payloads,
    load_custom_payloads,
    load_payload_file,
)
from puppetstring.payloads.models import Payload, PayloadSet

__all__ = [
    "Payload",
    "PayloadSet",
    "load_builtin_payloads",
    "load_custom_payloads",
    "load_payload_file",
]
