# Security Policy

## Supported versions
Only the latest repository version is currently supported. This early-stage project has not undergone an independent security audit.

## Reporting a vulnerability
Do not publish exploit details, API keys, target credentials, private reports, or personal data in a public issue. Contact the repository owner privately through GitHub's security reporting channel if enabled. Include the affected version, minimal reproduction, impact, and a safe proof that does not access other users' data.

## Safe use
Use only systems you own or have explicit authorization to assess. The exact-host allowlist and authorization grant are operator assertions; AegisMind cannot independently verify program permission. Check the current program scope and rules before every assessment and before each scheduled execution.

The built-in scanner uses bounded GET/OPTIONS observations only, does not follow redirects, and enforces exact-host checks. Active/destructive skills are not executable through the safe registry. Skill callbacks are trusted in-process code, not an OS sandbox.

The scheduled-job API is opt-in, in-memory, visible and cancellable. It has a minimum one-day interval, finite run count, grant expiry, and a required external authorization revalidation callback before each run. It creates no daemon or hidden background process. Only registered network_passive skills can be scheduled. The registry checks the declared request estimate against the grant before execution, but the trusted skill runner must enforce its actual per-request budget; arbitrary callback code is not sandboxed.

Do not use this project for denial of service, credential attacks, stealth, unauthorized exploitation, malware deployment, persistence, or data exfiltration.
