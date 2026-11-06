# Contributing

- Never add secrets, live target data, cookies, or private assessment reports.
- Add tests for new checks, scope handling, parsing, and report serialization.
- Keep network behavior bounded and non-destructive; no state-changing HTTP methods.
- Findings must explain evidence, verification layers, impact limitations, and remediation.
- AI output must remain advisory and must never promote a finding to confirmed.
- Do not claim full OWASP Top 10 coverage unless every category has a documented, tested capability.

Run python -m compileall -q aegismind and python -m pytest -q before submitting changes.
