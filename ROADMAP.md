# AegisMind AI Hunter roadmap

## v0.2.0 — bounded passive assessment
- Exact-host allowlist remains mandatory.
- Bounded same-host HTML link collection; no JavaScript execution or form submission.
- Excludes query-string URLs and action-like paths from crawling.
- Per-page HTML read cap, page cap, timeout, and request delay.
- Individual cookie attribute review without storing cookie values.
- Conservative CSP heuristics with explicit false-positive caveats.
- JSON, Markdown, and SARIF 2.1.0 reporting.

## Next-version branch — implemented foundation (not yet released)
- Deterministic capability planner with explainable skill selection and resource budgets.
- Exact-host authorization grants with expiry, GET/OPTIONS allowlist, and request limits.
- Existing passive HTTP scanner registered and executed through the planner.
- Offline --plan-only CLI mode.
- Opt-in in-memory scheduled-job API with minimum daily interval, finite run count, cancellation, expiry, and per-run authorization revalidation.
- Evidence-gated verification, redaction, bounded file triage, and explicit browser adapter contract.

## Remaining milestones
1. Add integration tests using a local mock HTTP server for redirect, timeout, response-size, and scope behavior.
2. Add independent evidence artifact storage/resolution, provenance hashes, and per-finding report schema.
3. Add optional external-tool adapters for Ghidra/radare2/JADX only after explicit dependency approval and fixture-backed tests.
4. Implement real browser automation only with redirect interception and tested exact-host enforcement.
5. Add persistent scheduled jobs and a visible user-controlled scheduler only after secure storage, authorization refresh, cancellation semantics, and process supervision are designed.
6. Add reproducible packaging, dependency audit, SBOM, and release signing.
7. Consider a dashboard only after CLI reliability and privacy controls are tested.

## Non-goals
- No stealth, evasion, brute force, denial of service, credential theft, data exfiltration, or automatic exploitation.
- No claim of complete OWASP Top 10 coverage or XBOW parity.
- No AI-generated finding or model-proposed action may override deterministic policy, scope, approval, or resource limits.
