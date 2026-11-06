"""Browser adapter contract. No live browser automation is bundled by default."""
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class BrowserVerification:
    performed: bool
    status: str
    evidence: dict[str, Any]
    limitation: str


class BrowserDriver(Protocol):
    def open(self, url: str) -> Any: ...
    def capture_observation(self) -> dict[str, Any]: ...


def manual_verify(url: str, *, authorized: bool, driver: BrowserDriver | None = None) -> BrowserVerification:
    """Require explicit scope authorization and a real injected browser driver."""
    if not authorized:
        return BrowserVerification(False, "BLOCKED_UNAUTHORIZED", {},
                                   "Explicit authorization for this exact target was not supplied.")
    if driver is None:
        return BrowserVerification(False, "MANUAL_VERIFICATION_NOT_PERFORMED", {},
                                   "No supported real browser driver is configured; no browser test was simulated.")
    driver.open(url)
    evidence = driver.capture_observation()
    return BrowserVerification(True, "OBSERVATION_CAPTURED", evidence,
                               "Observation only; a human must review baseline, impact, and repeatability.")
