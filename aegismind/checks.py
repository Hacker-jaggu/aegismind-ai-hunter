from .models import Finding

SECURITY_HEADERS = {
    "content-security-policy": ("CSP missing", "A05:2021 Security Misconfiguration", "Define a restrictive Content-Security-Policy appropriate to the application."),
    "x-content-type-options": ("X-Content-Type-Options missing", "A05:2021 Security Misconfiguration", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Referrer-Policy missing", "A05:2021 Security Misconfiguration", "Set a privacy-preserving Referrer-Policy."),
    "permissions-policy": ("Permissions-Policy missing", "A05:2021 Security Misconfiguration", "Define a Permissions-Policy for unneeded browser features.")
}

def inspect_response(url, response):
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    layers = ["L1: response header observed", "L2: deterministic header-presence check"]
    for name, (title, category, fix) in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append(Finding(
                id=f"HEADER-{name.upper().replace('-', '')}", title=title, category=category,
                severity="LOW", status="CONFIRMED", confidence="HIGH", url=url,
                evidence={"missing_header": name, "http_status": response.status_code},
                verification_layers=layers.copy(),
                why_it_matters=f"The response did not include {name}; a browser-side defense or policy is absent.",
                impact_limitations="Header absence alone does not prove an exploitable vulnerability or sensitive-data exposure.",
                remediation=fix, references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
            ))
    if url.lower().startswith("https://") and "strict-transport-security" not in headers:
        findings.append(Finding(
            id="HEADER-HSTS", title="HSTS header missing", category="A02:2021 Cryptographic Failures",
            severity="LOW", status="CONFIRMED", confidence="HIGH", url=url,
            evidence={"missing_header":"strict-transport-security"},
            verification_layers=["L1: HTTPS response observed", "L2: HSTS header absent"],
            why_it_matters="The HTTPS response did not advertise HTTP Strict Transport Security.",
            impact_limitations="This does not prove downgrade is possible; deployment and preload status matter.",
            remediation="After confirming HTTPS support across relevant hosts, deploy an appropriate HSTS policy.",
            references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"]
        ))
    set_cookie = response.headers.get("Set-Cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        missing = [x for x in ("secure", "httponly", "samesite") if x not in low]
        if missing:
            findings.append(Finding(
                id="COOKIE-ATTRIBUTES", title="Cookie security attributes may be incomplete",
                category="A07:2021 Identification and Authentication Failures", severity="LOW",
                status="NEEDS_REVIEW", confidence="MEDIUM", url=url,
                evidence={"set_cookie_attribute_gaps": missing, "cookie_value_saved": False},
                verification_layers=["L1: Set-Cookie metadata observed", "L2: attribute token check"],
                why_it_matters="One or more cookie security attributes were not observed.",
                impact_limitations="Multiple cookies may have different purposes; this MVP does not parse each cookie independently.",
                remediation="Review each cookie and set Secure, HttpOnly where appropriate, and a suitable SameSite policy.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"]
            ))
    acao = headers.get("access-control-allow-origin", "")
    acc = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acc == "true":
        findings.append(Finding(
            id="CORS-WILDCARD-CREDENTIALS", title="CORS wildcard origin combined with credentials header",
            category="A05:2021 Security Misconfiguration", severity="INFO", status="NEEDS_REVIEW",
            confidence="MEDIUM", url=url,
            evidence={"access_control_allow_origin": acao, "access_control_allow_credentials": acc},
            verification_layers=["L1: CORS response headers observed", "L2: wildcard/credentials combination detected"],
            why_it_matters="The response advertises wildcard origin with credentials, an inconsistent configuration.",
            impact_limitations="Browsers reject credentialed CORS access when ACAO is '*'; this is not proof of data theft.",
            remediation="Use an explicit allowlist of trusted origins and validate Origin server-side.",
            references=["https://developer.mozilla.org/docs/Web/HTTP/CORS"]
        ))
    return findings

def inspect_options(url, response):
    methods = response.headers.get("Allow", "")
    review = [m.strip().upper() for m in methods.split(",") if m.strip().upper() in {"TRACE", "PUT", "DELETE", "CONNECT"}]
    if not review:
        return []
    return [Finding(
        id="HTTP-METHODS", title="Potentially sensitive HTTP methods advertised",
        category="A05:2021 Security Misconfiguration", severity="INFO", status="NEEDS_REVIEW",
        confidence="LOW", url=url, evidence={"advertised_methods": methods, "review_methods": review},
        verification_layers=["L1: OPTIONS response observed", "L2: method names compared with review list"],
        why_it_matters="The server advertises methods that should be reviewed against application requirements.",
        impact_limitations="An advertised method does not prove it is enabled or exploitable.",
        remediation="Disable unneeded methods and enforce authorization for every route and method.",
        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
    )]
