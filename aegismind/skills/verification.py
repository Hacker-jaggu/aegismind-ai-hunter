"""Evidence-gated classification; scanner output alone can never confirm a bug."""
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Mapping


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    confidence: str
    gates: dict[str, bool]
    rationale: str

    def to_dict(self):
        result = asdict(self)
        result["status"] = self.status.value
        return result


REQUIRED_GATES = (
    "scope_authorized", "reproduced", "baseline_compared",
    "impact_evidenced", "alternatives_reviewed", "repeatable", "claim_contradicted",
)


def verify_candidate(gates: Mapping[str, bool], *, scanner_only: bool = False) -> VerificationResult:
    """Classify only supplied evidence gates; this function does not perform network tests."""
    normalized = {name: bool(gates.get(name, False)) for name in REQUIRED_GATES}
    if scanner_only:
        return VerificationResult(VerificationStatus.INCONCLUSIVE, "LOW", normalized,
                                 "Scanner output alone is not manual verification.")
    if not normalized["scope_authorized"]:
        return VerificationResult(VerificationStatus.INCONCLUSIVE, "LOW", normalized,
                                 "Authorization and exact scope have not been established.")
    if normalized["claim_contradicted"] and normalized["baseline_compared"] and normalized["alternatives_reviewed"]:
        return VerificationResult(VerificationStatus.FALSE_POSITIVE, "HIGH", normalized,
                                 "Controlled evidence contradicts the stated vulnerability claim.")
    if normalized["reproduced"] and normalized["baseline_compared"] and normalized["impact_evidenced"] and normalized["alternatives_reviewed"] and normalized["repeatable"]:
        return VerificationResult(VerificationStatus.CONFIRMED, "HIGH", normalized,
                                 "All independent verification gates have supporting evidence.")
    if normalized["reproduced"] and normalized["baseline_compared"] and normalized["alternatives_reviewed"]:
        return VerificationResult(VerificationStatus.LIKELY, "MEDIUM", normalized,
                                 "Reproduced and compared, but impact or repeatability evidence is incomplete.")
    return VerificationResult(VerificationStatus.INCONCLUSIVE, "LOW", normalized,
                             "Insufficient independent evidence to confirm or reject the candidate.")
