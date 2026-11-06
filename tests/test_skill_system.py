import json
import pytest

from aegismind.skills.registry import Skill, SkillRegistry
from aegismind.skills.verification import VerificationStatus, verify_candidate
from aegismind.skills.evidence import redact_sensitive, write_evidence
from aegismind.skills.reverse_engineering import identify_file


def test_registry_requires_explicit_approval_and_no_fake_runner():
    registry = SkillRegistry()
    registry.register(Skill("sample-inspector", "0.1.0", "Test-only skill"))
    with pytest.raises(PermissionError):
        registry.run("sample-inspector")
    with pytest.raises(RuntimeError):
        registry.run("sample-inspector", approved=True)


def test_registry_rejects_duplicate_ids():
    registry = SkillRegistry()
    skill = Skill("sample", "1.0.0", "sample")
    registry.register(skill)
    with pytest.raises(ValueError):
        registry.register(skill)


def test_scanner_only_cannot_confirm():
    result = verify_candidate({}, scanner_only=True)
    assert result.status is VerificationStatus.INCONCLUSIVE


def test_verification_requires_all_gates_for_confirmed():
    gates = {name: True for name in (
        "scope_authorized", "reproduced", "baseline_compared", "impact_evidenced",
        "alternatives_reviewed", "repeatable")}
    assert verify_candidate(gates).status is VerificationStatus.CONFIRMED
    gates["repeatable"] = False
    assert verify_candidate(gates).status is VerificationStatus.LIKELY



def test_false_positive_requires_explicit_contradictory_evidence():
    gates = {
        "scope_authorized": True, "reproduced": True, "baseline_compared": True,
        "impact_evidenced": False, "alternatives_reviewed": True, "repeatable": False,
        "claim_contradicted": True,
    }
    assert verify_candidate(gates).status is VerificationStatus.FALSE_POSITIVE

def test_unscoped_candidate_is_not_confirmed():
    gates = {name: True for name in (
        "scope_authorized", "reproduced", "baseline_compared", "impact_evidenced",
        "alternatives_reviewed", "repeatable")}
    gates["scope_authorized"] = False
    assert verify_candidate(gates).status is VerificationStatus.INCONCLUSIVE


def test_redaction_nested_and_strings(tmp_path):
    sample = {"Cookie": "sid=secret", "headers": {"Authorization": "Bearer abc"},
              "note": "api_key=xyz"}
    safe = redact_sensitive(sample)
    assert safe["Cookie"] == "[REDACTED]"
    assert safe["headers"]["Authorization"] == "[REDACTED]"
    assert "xyz" not in safe["note"]
    path = write_evidence(tmp_path / "evidence.json", sample)
    saved = json.loads(path.read_text())
    assert "abc" not in path.read_text()


def test_identify_elf_and_hash(tmp_path):
    sample = tmp_path / "tiny.elf"
    sample.write_bytes(b"\x7fELF" + b"\x00" * 14 + b"\x03\x00" + b"hello-string")
    result = identify_file(sample)
    assert result["format"] == "ELF"
    assert result["architecture"] == "x86"
    assert len(result["sha256"]) == 64
    assert result["executed"] is False


def test_identify_rejects_oversized_file(tmp_path):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"x" * 20)
    with pytest.raises(ValueError):
        identify_file(sample, max_bytes=10)
