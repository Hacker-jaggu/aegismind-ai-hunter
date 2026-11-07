"""Exact-host authorization grants for bounded, authorized assessments."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


def normalize_hostname(host: str) -> str:
    """Normalize one exact hostname; wildcards and malformed names are rejected."""
    if not isinstance(host, str):
        raise TypeError("hostname must be a string")
    value = host.strip().rstrip(".").lower()
    if not value or "*" in value or "/" in value or "@" in value:
        raise ValueError("an exact hostname is required; wildcards are not allowed")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("invalid internationalized hostname") from exc
        if len(value) > 253:
            raise ValueError("hostname is too long")
        labels = value.split(".")
        label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        if any(not label_re.fullmatch(label) for label in labels):
            raise ValueError("invalid hostname label")
        return value


def normalize_host_list(hosts) -> tuple[str, ...]:
    values = {normalize_hostname(host) for host in hosts}
    if not values:
        raise ValueError("at least one exact authorized hostname is required")
    return tuple(sorted(values))


@dataclass(frozen=True)
class AuthorizationGrant:
    """Operator-supplied authorization record; it does not independently prove permission."""

    reference: str
    allowed_hosts: tuple[str, ...]
    expires_at: datetime
    max_requests: int = 200
    allowed_methods: tuple[str, ...] = ("GET", "OPTIONS")

    def __post_init__(self):
        reference = self.reference.strip() if isinstance(self.reference, str) else ""
        if not reference or len(reference) > 256:
            raise ValueError("a short authorization reference is required")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("expires_at must be timezone-aware")
        if type(self.max_requests) is not int or not 1 <= self.max_requests <= 5000:
            raise ValueError("max_requests must be an integer between 1 and 5000")
        methods = tuple(sorted({str(method).upper() for method in self.allowed_methods}))
        if not methods or not set(methods).issubset({"GET", "OPTIONS"}):
            raise ValueError("only GET and OPTIONS are supported by this passive grant")
        object.__setattr__(self, "reference", reference)
        object.__setattr__(self, "allowed_hosts", normalize_host_list(self.allowed_hosts))
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(timezone.utc))
        object.__setattr__(self, "allowed_methods", methods)

    def validate(self, hosts, *, methods=("GET", "OPTIONS"), request_count=0, now=None) -> None:
        """Raise PermissionError unless time, exact hosts, methods and request budget all pass."""
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("validation time must be timezone-aware")
        current = current.astimezone(timezone.utc)
        if current >= self.expires_at:
            raise PermissionError("authorization grant has expired")
        requested_hosts = normalize_host_list(hosts)
        if not set(requested_hosts).issubset(self.allowed_hosts):
            raise PermissionError("requested hostname is outside the exact authorization scope")
        requested_methods = {str(method).upper() for method in methods}
        if not requested_methods.issubset(self.allowed_methods):
            raise PermissionError("HTTP method is not authorized by this grant")
        if type(request_count) is not int or request_count < 0 or request_count > self.max_requests:
            raise PermissionError("request budget exceeds the authorization grant")

    def allows_url(self, url: str, *, now=None) -> bool:
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return False
            if parsed.username is not None or parsed.password is not None:
                return False
            self.validate((parsed.hostname,), now=now)
            return True
        except (TypeError, ValueError, PermissionError):
            return False
