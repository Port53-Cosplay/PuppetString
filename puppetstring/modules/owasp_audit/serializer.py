"""Result serializer — saves and loads DanceRunResult to/from disk.

Results are stored as individual JSON files in a results directory with
a manifest.json tracking what's present. This lets `unravel` work
independently of `dance` — results can be generated in one session and
reported on in another.
"""

from __future__ import annotations

import json
from pathlib import Path

from puppetstring.core.models import FuzzRunResult, ScanResult
from puppetstring.modules.agent_swarm.models import SwarmRunResult
from puppetstring.modules.owasp_audit.models import (
    DanceRunResult,
    OWASPCoverage,
    ResultManifest,
    UnifiedFinding,
)
from puppetstring.modules.prompt_injection.models import TangleRunResult
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)

_MANIFEST_FILE = "manifest.json"
_SCAN_FILE = "scan_result.json"
_FUZZ_FILE = "fuzz_result.json"
_TANGLE_FILE = "tangle_result.json"
_SWARM_FILE = "swarm_result.json"
_COVERAGE_FILE = "coverage.json"
_FINDINGS_FILE = "findings.json"


class ResultSerializer:
    """Saves and loads audit results to/from a directory of JSON files."""

    @staticmethod
    def save(results_dir: str | Path, result: DanceRunResult) -> Path:
        """Save a DanceRunResult to disk as individual JSON files.

        Args:
            results_dir: Directory to write files into (created if needed).
            result: The full audit result to save.

        Returns:
            Path to the results directory.
        """
        base = Path(results_dir).resolve()
        base.mkdir(parents=True, exist_ok=True)

        manifest = ResultManifest(
            target=result.target,
            created_at=result.started_at,
        )

        if result.scan_result is not None:
            _write_json(base / _SCAN_FILE, result.scan_result.model_dump_json(indent=2))
            manifest.has_scan = True

        if result.fuzz_result is not None:
            _write_json(base / _FUZZ_FILE, result.fuzz_result.model_dump_json(indent=2))
            manifest.has_fuzz = True

        if result.tangle_result is not None:
            _write_json(base / _TANGLE_FILE, result.tangle_result.model_dump_json(indent=2))
            manifest.has_tangle = True

        if result.swarm_result is not None:
            _write_json(base / _SWARM_FILE, result.swarm_result.model_dump_json(indent=2))
            manifest.has_swarm = True

        if result.coverage.categories:
            _write_json(base / _COVERAGE_FILE, result.coverage.model_dump_json(indent=2))
            manifest.has_coverage = True

        if result.all_findings:
            findings_data = [f.model_dump() for f in result.all_findings]
            _write_json(base / _FINDINGS_FILE, json.dumps(findings_data, indent=2, default=str))

        _write_json(base / _MANIFEST_FILE, manifest.model_dump_json(indent=2))

        logger.info("Results saved to %s", base)
        return base

    @staticmethod
    def load(results_dir: str | Path) -> DanceRunResult:
        """Load a DanceRunResult from a results directory.

        Handles missing files gracefully — if a sub-result file doesn't
        exist, that field is left as None.

        Args:
            results_dir: Directory containing the result JSON files.

        Returns:
            A DanceRunResult reconstructed from the files on disk.

        Raises:
            FileNotFoundError: If the results directory doesn't exist.
        """
        base = Path(results_dir).resolve()
        if not base.is_dir():
            msg = f"Results directory not found: {base}"
            raise FileNotFoundError(msg)

        # Load manifest if available
        manifest = _load_model(base / _MANIFEST_FILE, ResultManifest)
        target = manifest.target if manifest else ""

        result = DanceRunResult(target=target, passive_only=True)

        # Load each sub-result
        result.scan_result = _load_model(base / _SCAN_FILE, ScanResult)
        result.fuzz_result = _load_model(base / _FUZZ_FILE, FuzzRunResult)
        result.tangle_result = _load_model(base / _TANGLE_FILE, TangleRunResult)
        result.swarm_result = _load_model(base / _SWARM_FILE, SwarmRunResult)
        result.coverage = _load_model(base / _COVERAGE_FILE, OWASPCoverage) or OWASPCoverage()

        # Load findings
        findings_path = base / _FINDINGS_FILE
        if findings_path.is_file():
            try:
                raw = json.loads(findings_path.read_text(encoding="utf-8"))
                result.all_findings = [UnifiedFinding.model_validate(f) for f in raw]
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning("Failed to load findings: %s", exc)

        if manifest:
            result.started_at = manifest.created_at

        return result


def _write_json(path: Path, content: str) -> None:
    """Write a JSON string to a file safely."""
    # Validate path doesn't escape the parent directory
    resolved = path.resolve()
    parent = path.parent.resolve()
    if not str(resolved).startswith(str(parent)):
        msg = f"Path traversal detected: {path}"
        raise ValueError(msg)
    resolved.write_text(content, encoding="utf-8")


def _load_model(path: Path, model_cls: type) -> object | None:
    """Load a Pydantic model from a JSON file, returning None on failure."""
    if not path.is_file():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return model_cls.model_validate(data)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to load %s: %s", path.name, exc)
        return None
