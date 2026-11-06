from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str
    status: str
    confidence: str
    url: str
    evidence: dict[str, Any]
    verification_layers: list[str]
    why_it_matters: str
    impact_limitations: str
    remediation: str
    references: list[str]

    def to_dict(self):
        return asdict(self)
