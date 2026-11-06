# AegisMind AI Hunter roadmap

## v0.2.0 — bounded passive assessment
- Exact-host allowlist remains mandatory.
- Bounded same-host HTML link collection; no JavaScript execution or form submission.
- Excludes query-string URLs and action-like paths from crawling.
- Per-page HTML read cap, page cap, and minimum request delay.
- Individual cookie attribute review without storing cookie values.
- Conservative CSP directive heuristics with explicit false-positive caveats.
- JSON, Markdown, and SARIF 2.1.0 reporting.

## Next milestones
1. Add integration tests using a local mock HTTP server for redirect, timeout, response-size, and scope behavior.
2. Add report redaction controls and optional PDF export.
3. Add a plugin interface for passive checks and a transparent OWASP coverage matrix.
4. Add optional authenticated testing only with explicit user-supplied test roles and per-program authorization.
5. Add reproducible packaging, release signing, dependency audit, and SBOM.
6. Build a small dashboard only after CLI reliability and privacy controls are tested.

## Non-goals
- No stealth, evasion, brute force, denial of service, credential theft, data exfiltration, or automatic exploitation.
- No claim of complete OWASP Top 10 coverage from passive checks.
- No AI-generated finding may override deterministic validation status.
