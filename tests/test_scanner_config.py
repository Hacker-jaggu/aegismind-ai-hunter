import pytest

from aegismind.scanner import Scanner


def test_timeout_and_delay_are_clamped_to_safe_upper_bounds(monkeypatch):
    monkeypatch.setenv("REQUEST_TIMEOUT", "120")
    monkeypatch.setenv("REQUEST_DELAY", "25")
    scanner = Scanner({"example.test"})
    assert scanner.timeout == 30.0
    assert scanner.delay == 10.0


def test_invalid_non_finite_timeout_is_rejected(monkeypatch):
    monkeypatch.setenv("REQUEST_TIMEOUT", "nan")
    with pytest.raises(ValueError):
        Scanner({"example.test"})


def test_negative_delay_is_rejected(monkeypatch):
    monkeypatch.setenv("REQUEST_DELAY", "-1")
    with pytest.raises(ValueError):
        Scanner({"example.test"})


def test_scanner_rejects_methods_outside_passive_allowlist():
    scanner = Scanner({"example.test"})
    with pytest.raises(ValueError):
        scanner.request("HEAD", "https://example.test/")
    with pytest.raises(ValueError):
        scanner.request("DELETE", "https://example.test/")
