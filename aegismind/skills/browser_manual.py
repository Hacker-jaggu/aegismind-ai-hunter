"""Browser adapter contract. No live browser automation is bundled by default."""
from dataclasses import dataclass
from typing import Any, Protocol

from ..scope import in_scope
from .evidence import redact_sensitive


@dataclass
class BrowserVerification:
    performed: bool
    status: str
    evidence: dict[str, Any]
    limitation: str


class BrowserDriver(Protocol):
    """A real adapter must abort cross-host redirects before issuing their requests."""

    def open(self, url: str, *, allowed_hosts: frozenset[str]) -> Any: ...
    def capture_observation(self) -> dict[str, Any]: ...


def manual_verify(
    url: str,
    *,
    authorized: bool,
    allowed_hosts: set[str] | tuple[str, ...] = (),
    driver: BrowserDriver | None = None,
) -> BrowserVerification:
    """Require explicit authorization and exact-host scope before browser navigation."""
    if not authorized:
        return BrowserVerification(False, "BLOCKED_UNAUTHORIZED", {},
                                   "Explicit authorization for this exact target was not supplied.")

    normalized_hosts = frozenset(h.lower().rstrip(".") for h in allowed_hosts)
    if not in_scope(url, normalized_hosts):
        return BrowserVerification(False, "BLOCKED_OUT_OF_SCOPE", {},
                                   "The URL does not match an explicitly allowed exact hostname.")

    if driver is None:
        return BrowserVerification(False, "MANUAL_VERIFICATION_NOT_PERFORMED", {},
                                   "No supported real browser driver is configured; no browser test was simulated.")

    # The adapter must enforce this allowlist during navigation and redirects, not only after capture.
    driver.open(url, allowed_hosts=normalized_hosts)
    raw_evidence = driver.capture_observation()
    if not isinstance(raw_evidence, dict):
        return BrowserVerification(False, "INVALID_BROWSER_EVIDENCE", {},
                                   "The browser adapter did not return a structured evidence object.")

    evidence = redact_sensitive(raw_evidence)
    final_url = evidence.get("final_url")
    if final_url and not in_scope(str(final_url), normalized_hosts):
        return BrowserVerification(False, "BLOCKED_OUT_OF_SCOPE", {},
                                   "The adapter reported an out-of-scope final URL; review redirect enforcement.")

    return BrowserVerification(True, "OBSERVATION_CAPTURED", evidence,
                               "Observation only; a human must review baseline, impact, and repeatability.")
