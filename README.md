# AegisMind AI Hunter

**SR-JAGGU Security Labs** — evidence-first, scope-bound web security assessment CLI.

## Safety first
Only test systems you own or have explicit written authorization to assess. Exact hostname allowlisting is mandatory. The MVP uses conservative GET and OPTIONS requests, verifies TLS certificates, does not follow out-of-scope redirects, and avoids brute force, destructive payloads, credential attacks, or state-changing requests.

## Status
Version 0.1.0 is an early MVP, not a complete OWASP Top 10 scanner or a substitute for manual penetration testing. Current checks cover selected HTTP security headers, HTTPS/HSTS presence, cookie attribute observations, a limited CORS header consistency check, and advertised HTTP methods. Access-control flaws, injection, SSRF, business logic, authenticated workflows, and vulnerable components are not comprehensively tested.

## Install
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run
```bash
python -m aegismind --url https://example.com --allow-host example.com --out reports
```
Only replace the example host with an explicitly authorized target.

## Optional AI review (Groq / OpenAI-compatible)
Set environment variables; never commit API keys:
```bash
export AI_API_KEY="your-key"
export AI_BASE_URL="https://api.groq.com/openai/v1"
export AI_MODEL="llama-3.3-70b-versatile"
```
Model availability can change. AI output is advisory and cannot promote a finding to confirmed.

## Verification labels
- CONFIRMED: deterministic configuration observation, not necessarily proof of exploitability.
- HIGH_CONFIDENCE: multiple independent signals support a lead.
- NEEDS_REVIEW: manual validation required.
- INFORMATIONAL: observation without demonstrated vulnerability.
- FALSE_POSITIVE: evidence contradicts a lead.

Reports include evidence, verification layers, limitations, remediation, and AI caveats. Response bodies and cookie values are not saved.

## Development
```bash
pip install -e . pytest
python -m compileall -q aegismind
pytest -q
```

## License
No software license is selected yet. All rights reserved by default until the owner chooses and adds a license after reviewing ownership and third-party dependencies.
