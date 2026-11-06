"""AegisMind opt-in skill framework. Skills never execute automatically."""
from .registry import Skill, SkillRegistry
from .verification import VerificationResult, VerificationStatus, verify_candidate
from .evidence import redact_sensitive, write_evidence

__all__ = ["Skill", "SkillRegistry", "VerificationResult", "VerificationStatus",
           "verify_candidate", "redact_sensitive", "write_evidence"]
