# AegisMind AI Hunter
**SR-JAGGU Security Labs** — bounded, evidence-first web security assessment.

AegisMind is a lightweight Python CLI for authorized, unauthenticated web assessments. It combines exact-host scope enforcement, bounded same-host HTML link collection, conservative HTTP observations, deterministic verification notes, optional AI-assisted explanation (Groq/OpenAI-compatible APIs), and JSON/Markdown/SARIF reports.

> Honest coverage statement: v0.2.0 is a passive HTTP misconfiguration assessor, not a complete OWASP Top 10 scanner and not an exploit validator. CONFIRMED means the stated configuration condition was observed, not that it is exploitable or bounty-eligible.

## Safety model
- Use only on systems you own or have explicit written authorization to assess.
- Exact hostname allowlisting is mandatory; subdomains are not implicitly included.
- Only GET and OPTIONS requests are used. Redirects are recorded but never followed automatically.
- HTML link discovery is bounded; JavaScript is not executed, forms are not submitted, and query-string/action-like URLs are excluded.
- Page count is capped at 100, HTML reads at 1 MB per page, request timeout at 1–30 seconds, and request delay at 0.5–10 seconds.
- TLS certificate verification remains enabled.
- No brute force, credential attacks, destructive payloads, exploit chains, or data exfiltration.
- Sensitive response bodies and cookie values are not written to reports.

## Install
Python 3.10+ required.
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

## Run
python -m aegismind --url https://example.com --allow-host example.com --max-pages 20 --delay 1.0 --out reports
Repeat --allow-host for each explicitly authorized exact hostname. Do not use wildcards.

## Optional AI review
AI_API_KEY="your-key" AI_BASE_URL="https://api.groq.com/openai/v1" AI_MODEL="llama-3.3-70b-versatile" python -m aegismind --url https://example.com --allow-host example.com

Use a model currently available to your provider account. The scanner works without an API key. AI output is advisory only and cannot change deterministic finding status or severity. Review provider privacy/retention terms before sending assessment data.

## Resource controls
- --max-pages: maximum pages visited, capped at 100.
- --delay: request delay clamped to 0.5–10 seconds.
- --max-body-bytes: HTML read cap per page, clamped to 16 KB–1 MB.
- REQUEST_TIMEOUT: request timeout clamped to 1–30 seconds.
- .env options: REQUEST_TIMEOUT, REQUEST_DELAY, MAX_URLS, MAX_BODY_BYTES, AI_API_KEY, AI_BASE_URL, AI_MODEL.

## Checks
- Missing CSP, HSTS (HTTPS only), X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- Conservative CSP directive heuristics (broad sources, unsafe-inline/unsafe-eval, missing object-src/base-uri).
- Per-cookie Secure/HttpOnly/SameSite observations; cookie values are not retained.
- CORS wildcard plus credentials-header inconsistency (not treated as proof of data theft).
- OPTIONS-advertised sensitive methods (not proof a method is enabled).
- Exact-host link collection, redirect observation, bounded response reads.

## Status labels
- CONFIRMED: the stated configuration condition is directly observed; not exploitability.
- NEEDS_REVIEW: heuristic/context-dependent lead requiring manual validation.
- HIGH_CONFIDENCE: multiple independent signals support a lead.
- INFORMATIONAL: observation without demonstrated vulnerability.
- FALSE_POSITIVE: evidence contradicts a lead (manual reviewer decision).

## Output
Each run creates JSON, Markdown, and SARIF 2.1.0 reports. Reports include evidence, verification layers, limitations, and remediation guidance.

## OWASP coverage (partial)
Limited observations relevant to A02 Cryptographic Failures, A05 Security Misconfiguration, and A07 Identification and Authentication Failures (cookie attributes). It does not test A01 Broken Access Control, A03 Injection, A04 Insecure Design, A06 Vulnerable and Outdated Components, A08 Software and Data Integrity Failures, A09 Security Logging and Monitoring, or A10 SSRF. Do not advertise complete OWASP coverage.

## Development
python -m compileall -q aegismind
python -m pytest -q
See ROADMAP.md and docs-MONETIZATION.md for future development and ethical revenue paths.

## License
No license has been selected. All rights reserved by default. A public GitHub repository is not automatically open-source licensed. Choose a license only after confirming ownership and dependency terms.
