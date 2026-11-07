"""Secret-aware evidence persistence for local reports."""
import json
import re
from pathlib import Path
from typing import Any

_SENSITIVE_KEYS = re.compile(
    r"(authorization|proxy.?authorization|cookie|set-cookie|api.?key|token|password|secret|session|email|phone|reset.?url)",
    re.I,
)
_HEADER_SECRET = re.compile(
    r"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*)[^\r\n]*"
)
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+")
_KEY_VALUE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|password|secret|session[_-]?id|reset[_-]?token)\s*[:=]\s*[^\s,;&]+"
)
_QUERY_SECRET = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|id_token|token|api[_-]?key|key|code|reset_token|session|sessionid)=)[^&#\s]+"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def _redact_string(value: str) -> str:
    value = _HEADER_SECRET.sub(r"\1[REDACTED]", value)
    value = _BEARER.sub(r"\1 [REDACTED]", value)
    value = _QUERY_SECRET.sub(r"\1[REDACTED]", value)
    value = _KEY_VALUE.sub(lambda match: match.group(1) + "=[REDACTED]", value)
    return _JWT.sub("[REDACTED_JWT]", value)


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
        return _redact_string(value)
    return value


def write_evidence(path: str | Path, evidence: dict[str, Any]) -> Path:
    """Write redacted JSON evidence; callers must still review it before sharing."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    safe = redact_sensitive(evidence)
    target.write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
    return target
