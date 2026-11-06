from aegismind.scope import in_scope, safe_join

def test_exact_host_allowlist():
    assert in_scope("https://example.com/a", {"example.com"})
    assert not in_scope("https://evil-example.com", {"example.com"})
    assert not in_scope("https://sub.example.com", {"example.com"})

def test_redirect_scope():
    assert safe_join("https://example.com/a", "/b", {"example.com"}) == "https://example.com/b"
    assert safe_join("https://example.com", "https://evil.test", {"example.com"}) is None
