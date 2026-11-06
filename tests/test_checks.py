from aegismind.checks import inspect_response

class FakeResponse:
    status_code = 200
    headers = {"Content-Security-Policy":"default-src *; script-src 'unsafe-inline';","Set-Cookie":"sessionid=secret; Path=/"}
    raw = None

def test_cookie_values_not_saved_and_csp_reviewed():
    findings = inspect_response("https://example.com/",FakeResponse())
    cookie = next(f for f in findings if f.id.startswith("COOKIE-"))
    assert cookie.evidence["cookie_value_saved"] is False
    assert "secret" not in str(cookie.evidence)
    assert any(f.id == "CSP-WEAK-DIRECTIVES" for f in findings)
