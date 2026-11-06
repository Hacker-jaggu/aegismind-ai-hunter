"""AegisMind opt-in skill framework. Skills never execute automatically."""
from .registry import Skill, SkillRegistry
from .verification import VerificationResult, VerificationStatus, verify_candidate
from .evidence import redact_sensitive, write_evidence
from .reverse_engineering import identify_file
from .browser_manual import BrowserVerification, manual_verify
from .research import save_research_note

__all__ = [
    "Skill", "SkillRegistry", "VerificationResult", "VerificationStatus",
    "verify_candidate", "redact_sensitive", "write_evidence", "identify_file",
    "BrowserVerification", "manual_verify", "save_research_note",
]
