"""Secret-aware evidence persistence for local reports."""
import json
import re
from pathlib import Path
from typing import Any

_SENSITIVE_KEYS = re.compile(r"(authorization|cookie|set-cookie|api.?key|token|password|secret|session)", re.I)
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+")
_KEY_VALUE = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*[:=]\s*[^\s,;]+")


def redact_sensitive(value: Any, *, key: str = "") -> Any:
    if _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_sensitive(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return _KEY_VALUE.sub(lambda m: m.group(1) + "=[REDACTED]", _BEARER.sub(r"\1 [REDACTED]", value))
    return value


def write_evidence(path: str | Path, evidence: dict[str, Any]) -> Path:
    """Write only redacted JSON evidence; caller chooses a local output directory."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    safe = redact_sensitive(evidence)
    target.write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
    return target
