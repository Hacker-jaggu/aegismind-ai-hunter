import json
import pytest
from aegismind.skills.browser_manual import manual_verify
from aegismind.skills.research import save_research_note


class FakeBrowser:
    def __init__(self, evidence):
        self.evidence = evidence
        self.opened = None

    def open(self, url, *, allowed_hosts):
        self.opened = (url, allowed_hosts)

    def capture_observation(self):
        return self.evidence


def test_browser_unavailable_is_not_claimed_as_performed():
    result = manual_verify("https://example.test", authorized=True,
                           allowed_hosts={"example.test"})
    assert result.performed is False
    assert result.status == "MANUAL_VERIFICATION_NOT_PERFORMED"


def test_browser_requires_authorization():
    result = manual_verify("https://example.test", authorized=False)
    assert result.status == "BLOCKED_UNAUTHORIZED"


def test_browser_blocks_out_of_scope_before_opening():
    driver = FakeBrowser({})
    result = manual_verify("https://evil.test", authorized=True,
                           allowed_hosts={"example.test"}, driver=driver)
    assert result.status == "BLOCKED_OUT_OF_SCOPE"
    assert driver.opened is None


def test_browser_capture_is_redacted_and_allowlist_is_passed():
    driver = FakeBrowser({
        "final_url": "https://example.test/profile",
        "headers": {"Cookie": "sid=secret", "Authorization": "Bearer abc"},
        "event": "https://analytics.example/reset?token=reset-secret",
    })
    result = manual_verify("https://example.test", authorized=True,
                           allowed_hosts={"example.test"}, driver=driver)
    assert result.performed is True
    assert driver.opened[1] == frozenset({"example.test"})
    assert result.evidence["headers"]["Cookie"] == "[REDACTED]"
    assert "secret" not in str(result.evidence)
    assert "abc" not in str(result.evidence)
    assert "reset-secret" not in str(result.evidence)


def test_public_research_note_records_sources_and_no_copied_text(tmp_path):
    path = save_research_note(
        tmp_path / "note.json", title="Example lesson",
        source_url="https://example.org/advisory", accessed_on="2026-11-06",
        source_type="vendor advisory", license_note="Terms reviewed; paraphrase only",
        lessons=["Validate server-side authorization on each object."],
        validation=["Use two owned test accounts and compare access decisions."],
        false_positive_indicators=["Public object intended for anonymous access."],
        confidence="MEDIUM", safe_use_constraints=["Authorized targets only"])
    data = json.loads(path.read_text())
    assert data["copied_source_text"] is False
    assert data["source_url"].startswith("https://")


def test_research_requires_https_and_license_note(tmp_path):
    with pytest.raises(ValueError):
        save_research_note(
            tmp_path / "bad.json", title="x", source_url="http://example.org",
            accessed_on="2026-11-06", source_type="writeup", license_note="ok",
            lessons=[], validation=[], false_positive_indicators=[],
            confidence="LOW", safe_use_constraints=[])
