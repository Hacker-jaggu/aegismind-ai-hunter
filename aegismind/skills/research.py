"""Metadata-only public research notes; this module does not scrape or execute sources."""
from datetime import date
from pathlib import Path
import json
from typing import Any
from .evidence import redact_sensitive


def save_research_note(path: str | Path, *, title: str, source_url: str,
                       accessed_on: str, source_type: str, license_note: str,
                       lessons: list[str], validation: list[str],
                       false_positive_indicators: list[str],
                       confidence: str, safe_use_constraints: list[str]) -> Path:
    """Persist concise original notes and source metadata, not copied report text."""
    if not source_url.startswith("https://"):
        raise ValueError("research source must use HTTPS")
    date.fromisoformat(accessed_on)
    if not license_note.strip():
        raise ValueError("record source license/terms or state 'unknown; do not reproduce'")
    if confidence not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("confidence must be LOW, MEDIUM, or HIGH")
    record: dict[str, Any] = {
        "title": title, "source_url": source_url, "accessed_on": accessed_on,
        "source_type": source_type, "license_note": license_note,
        "lessons": lessons, "validation_methods": validation,
        "false_positive_indicators": false_positive_indicators,
        "confidence": confidence, "safe_use_constraints": safe_use_constraints,
        "copied_source_text": False,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(redact_sensitive(record), indent=2, ensure_ascii=False), encoding="utf-8")
    return target
