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
    evidence_refs: dict[str, str]
    rationale: str

    def to_dict(self):
        result = asdict(self)
        result["status"] = self.status.value
        return result


REQUIRED_GATES = (
    "scope_authorized", "reproduced", "baseline_compared",
    "impact_evidenced", "alternatives_reviewed", "repeatable", "claim_contradicted",
)


def _has_evidence(evidence_refs: Mapping[str, str], required: tuple[str, ...]) -> bool:
    return all(isinstance(evidence_refs.get(name), str) and evidence_refs[name].strip()
               for name in required)


def verify_candidate(
    gates: Mapping[str, bool],
    *,
    scanner_only: bool = False,
    evidence_refs: Mapping[str, str] | None = None,
) -> VerificationResult:
    """Classify supplied evidence gates; this helper does not perform network tests."""
    if not isinstance(gates, Mapping):
        raise TypeError("gates must be a mapping of gate names to booleans")

    normalized: dict[str, bool] = {}
    for name in REQUIRED_GATES:
        value = gates.get(name, False)
        if type(value) is not bool:
            raise TypeError(f"verification gate {name!r} must be a boolean")
        normalized[name] = value

    refs = {} if evidence_refs is None else dict(evidence_refs)
    unknown_refs = set(refs) - set(REQUIRED_GATES)
    if unknown_refs:
        raise ValueError(f"unknown evidence gate references: {sorted(unknown_refs)}")
    if any(not isinstance(value, str) or not value.strip() for value in refs.values()):
        raise TypeError("each evidence reference must be a non-empty string")

    def result(status: VerificationStatus, confidence: str, rationale: str) -> VerificationResult:
        return VerificationResult(status, confidence, normalized, refs, rationale)

    if scanner_only:
        return result(VerificationStatus.INCONCLUSIVE, "LOW",
                      "Scanner output alone is not manual verification.")
    if not normalized["scope_authorized"]:
        return result(VerificationStatus.INCONCLUSIVE, "LOW",
                      "Authorization and exact scope have not been established.")

    false_positive_gates = ("baseline_compared", "alternatives_reviewed", "claim_contradicted")
    if (normalized["claim_contradicted"] and normalized["baseline_compared"]
            and normalized["alternatives_reviewed"]):
        if _has_evidence(refs, false_positive_gates):
            return result(VerificationStatus.FALSE_POSITIVE, "HIGH",
                          "Controlled evidence references contradict the stated vulnerability claim.")
        return result(VerificationStatus.INCONCLUSIVE, "LOW",
                      "Contradictory gates were supplied without evidence references.")

    confirmed_gates = (
        "scope_authorized", "reproduced", "baseline_compared",
        "impact_evidenced", "alternatives_reviewed", "repeatable",
    )
    if all(normalized[name] for name in confirmed_gates):
        if _has_evidence(refs, confirmed_gates):
            return result(VerificationStatus.CONFIRMED, "HIGH",
                          "All independent verification gates have supporting evidence references.")
        return result(VerificationStatus.INCONCLUSIVE, "LOW",
                      "All gates were marked true, but one or more evidence references are missing.")

    likely_gates = ("scope_authorized", "reproduced", "baseline_compared", "alternatives_reviewed")
    if all(normalized[name] for name in likely_gates) and _has_evidence(refs, likely_gates):
        return result(VerificationStatus.LIKELY, "MEDIUM",
                      "Reproduced and compared with evidence references, but impact or repeatability is incomplete.")

    return result(VerificationStatus.INCONCLUSIVE, "LOW",
                  "Insufficient independent evidence to confirm or reject the candidate.")
