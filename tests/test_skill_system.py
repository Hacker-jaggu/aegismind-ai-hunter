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


def test_verification_requires_all_gates_and_evidence_for_confirmed():
    gates = {name: True for name in (
        "scope_authorized", "reproduced", "baseline_compared", "impact_evidenced",
        "alternatives_reviewed", "repeatable")}
    refs = {name: f"evidence://{name}" for name, value in gates.items() if value}
    assert verify_candidate(gates, evidence_refs=refs).status is VerificationStatus.CONFIRMED
    gates["repeatable"] = False
    refs = {name: f"evidence://{name}" for name, value in gates.items() if value}
    assert verify_candidate(gates, evidence_refs=refs).status is VerificationStatus.LIKELY


def test_missing_evidence_refs_prevent_confirmation():
    gates = {name: True for name in (
        "scope_authorized", "reproduced", "baseline_compared", "impact_evidenced",
        "alternatives_reviewed", "repeatable")}
    assert verify_candidate(gates).status is VerificationStatus.INCONCLUSIVE


def test_truthy_strings_are_not_accepted_as_verification_gates():
    with pytest.raises(TypeError):
        verify_candidate({"scope_authorized": "false"})


def test_false_positive_requires_contradiction_and_evidence():
    gates = {
        "scope_authorized": True, "reproduced": True, "baseline_compared": True,
        "impact_evidenced": False, "alternatives_reviewed": True, "repeatable": False,
        "claim_contradicted": True,
    }
    refs = {name: f"evidence://{name}" for name, value in gates.items() if value}
    assert verify_candidate(gates, evidence_refs=refs).status is VerificationStatus.FALSE_POSITIVE


def test_unscoped_candidate_is_not_confirmed():
    gates = {name: True for name in (
        "scope_authorized", "reproduced", "baseline_compared", "impact_evidenced",
        "alternatives_reviewed", "repeatable")}
    gates["scope_authorized"] = False
    refs = {name: f"evidence://{name}" for name, value in gates.items() if value}
    assert verify_candidate(gates, evidence_refs=refs).status is VerificationStatus.INCONCLUSIVE


def test_redaction_nested_headers_urls_and_jwt(tmp_path):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue123456"
    sample = {
        "Cookie": "sid=secret",
        "headers": {"Authorization": "Bearer abc"},
        "note": "Cookie: sid=secret\nAuthorization: Bearer abc\nhttps://example.test/reset?token=reset-secret",
        "jwt": jwt,
        "api_note": "api_key=xyz",
    }
    safe = redact_sensitive(sample)
    assert safe["Cookie"] == "[REDACTED]"
    assert safe["headers"]["Authorization"] == "[REDACTED]"
    assert "secret" not in str(safe)
    assert "abc" not in str(safe)
    assert "reset-secret" not in str(safe)
    assert "xyz" not in str(safe)
    assert jwt not in str(safe)
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
