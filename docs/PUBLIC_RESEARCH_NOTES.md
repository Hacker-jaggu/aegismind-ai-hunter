# Public Research Notes for AegisMind Next-Version Skills

Research snapshot: 2026-11-06  
Status: curated, paraphrased notes; not an automated ingestion pipeline.  
Scope: public material only. No private reports, private program data, target credentials, cookies, tokens, or copied report text are stored here.

## 1. Public HackerOne disclosures reviewed

### Report #4035023 — improper access control / sender identity binding

Source: https://hackerone.com/reports/4035023  
Public summary: an ordinary account was reported as able to cause authenticated mail to originate from an attacker-selected address in the service's own domain. The public search summary identifies the weakness as generic improper access control and shows a High severity classification.

Review limitation: the report page is JavaScript-rendered and its full reproduction thread was not available in the text review. These notes rely only on the public title/summary, not on unobserved request details. Confidence: MEDIUM for the general pattern; LOW for any inferred implementation detail.

Reusable pattern:
- Check whether server-side identity fields (sender, owner, tenant, role) are bound to the authenticated principal rather than trusted from client-controlled fields.
- Compare a baseline action using the account's own verified identity with a minimal test using a second identity/alias that is also controlled by the tester.
- Keep all messages inside controlled test mailboxes; do not send to real users or impersonate unrelated people.
- Capture the application decision and sanitized message metadata, not live message contents or authentication tokens.

False-positive indicators:
- The address is a documented, verified alias owned by the same test account.
- The product explicitly permits delegated sender identities and the test account has that permission.
- The visible sender label differs from the actual authenticated envelope/header identity.

General remediation direction:
- Derive sender identity from server-side verified account state.
- Enforce authorization for every sender/alias selection on the server.
- Audit identity changes and reject unverified or cross-tenant values.

### Report #4000185 — sensitive reset-token data in analytics events

Source: https://hackerone.com/reports/4000185  
Public summary: the disclosed report title describes password-reset tokens being sent to a third-party analytics destination in automatic page events.

Review limitation: the full report thread is JavaScript-rendered and was not available to the text review. The summary is sufficient to identify a telemetry exposure pattern, but not to assert the exact event schema or remediation deployed. Confidence: MEDIUM for the pattern; LOW for unobserved implementation specifics.

Reusable pattern:
- In an owned test account, inspect browser network activity during a password-reset flow and identify third-party analytics/telemetry requests.
- Check whether URLs, event properties, DOM-derived fields, referrers, or automatic page events contain reset tokens or other bearer secrets.
- Use a disposable test account and a synthetic reset flow; never redeem a token as a proof of account access.
- Redact token values before screenshots, HAR export, issue text, or local report persistence. Prefer recording the field name, destination, and a redacted value marker.

False-positive indicators:
- The value is a synthetic placeholder rather than a live bearer token.
- The observed value is already irreversibly redacted or expired and cannot authorize an action.
- The destination is a first-party endpoint or an explicitly documented secure processing component rather than an external analytics recipient.
- The captured request is a local test fixture, not an actual browser-generated event.

General remediation direction:
- Exclude credentials, reset tokens, session identifiers, and other bearer secrets from analytics payloads, URLs, referrers, and automatic event capture.
- Apply server-side allowlisting of telemetry fields and client-side data minimization.
- Rotate/revoke exposed live tokens through normal account-security procedures; do not test by using another person's token.

### Disclosure and privacy rule

HackerOne's disclosure guidance explains that public disclosure depends on program settings and formal approval; private reports must not be scraped or copied into a learning corpus. Limited disclosure and redaction exist specifically to reduce the exposure of sensitive details.

Source: https://docs.hackerone.com/en/articles/8475358-requesting-disclosure  
Related source: https://docs.hackerone.com/en/articles/8520035-limiting-disclosed-information

Pipeline rule: accept only publicly accessible, formally disclosed material; store source links and original paraphrased lessons, not report bodies, attachments, comments, tokens, credentials, personal data, or private findings. Record terms/license status and default to “unknown; do not reproduce” when unclear.

## 2. Primary testing guidance cross-check

### Broken object-level authorization / IDOR

Primary source: OWASP Web Security Testing Guide, WSTG-ATHZ-04  
https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References

Cross-checked lesson:
- Map object references and the user-controlled inputs that select them.
- Use at least two tester-owned accounts with distinct, tester-owned objects and known permissions.
- Establish a positive baseline as the object owner, then compare the same object request as the second controlled account.
- Verify object ownership and expected access policy before interpreting a response. A 200 status alone is not proof of unauthorized access.
- Never use identifiers belonging to real users. Never enumerate production objects. Stop if the test would expose another person's data.

False-positive indicators include public-by-design objects, shared organization/tenant access, delegated roles, stale sessions, cached responses, and test accounts that unintentionally share ownership or privileges.

### Evidence and disclosure handling

HackerOne's redaction and limited-disclosure guidance reinforces that reports may contain information unsuitable for public sharing. AegisMind should therefore redact secrets before local persistence and exports, and should never publish or submit a report automatically.

Sources:
- https://docs.hackerone.com/en/articles/8520035-limiting-disclosed-information
- https://www.hackerone.com/terms/disclosure-guidelines

## 3. Reverse-engineering tool capability notes

These are candidate adapters, not bundled dependencies or guarantees of universal support.

| Area | Candidate source/tool | Verified capability boundary |
|---|---|---|
| File identification | libmagic / `file` — https://manpages.debian.org/testing/libmagic1/magic.5.en.html | Magic-pattern identification is useful for type hints; it does not prove a file is safe or fully parseable. |
| ELF/PE/binary metadata | radare2 book — https://book.rada.re/analysis/intro.html and https://book.rada.re/refcard/intro.html | Documentation describes headers, imports, exports, symbols, libraries, strings, sections, analysis, references and graph views. Availability depends on the installed version/plugins and file support. |
| PE metadata | pefile — https://github.com/erocarrera/pefile | Can inspect PE headers, sections and import-related structures; malformed files still require bounded parsing and error handling. |
| Multi-format disassembly/decompilation | NSA Ghidra — https://github.com/NationalSecurityAgency/ghidra | Provides disassembly, decompilation, graphing and scripting across many formats/processor languages. Exact support depends on an installed language module and tool version; do not claim every architecture works. |
| Android APK/DEX | JADX — https://github.com/skylot/jadx | Decompiles DEX and supported Android package formats and decodes manifest/resources, but its own documentation warns that decompilation may be incomplete or fail. |
| APK signing metadata | Android `apksigner` — https://developer.android.com/tools/apksigner | `apksigner verify` checks signature verification for declared platform compatibility; it does not establish that the signer is the expected publisher unless compared with a trusted certificate baseline. |
| Malware dynamic triage | CAPE Sandbox — https://capev2.readthedocs.io/en/latest/introduction/what.html | Uses fresh isolated VMs and can collect behavioral/network artifacts. This is a separate sandbox infrastructure project, not a safe feature to run samples on the analyst's host. |

Architecture/format policy:
- Record the exact tool version, parser/plugin, detected format, architecture, and any unsupported or ambiguous fields.
- Start with x86/x86_64 and ARM/AArch64 only where the installed parser reports explicit support; add other architectures only after fixture-backed tests.
- Treat big-endian ELF, uncommon machine IDs, packed/obfuscated binaries, malformed containers, encrypted firmware, proprietary formats, and unsupported processor languages as UNKNOWN/UNSUPPORTED rather than guessing.
- Do not execute samples during static triage. Dynamic analysis belongs in a separately provisioned disposable VM/sandbox with host isolation, snapshots, resource limits, and networking disabled by default.
- Do not attempt DRM, license, or anti-cheat circumvention.

## 4. Browser-assisted manual verification workflow

No live target or real browser session was available during this research run. Manual verification was **not performed**. The current branch's browser module is an adapter contract only; it is not a browser automation implementation.

Proposed workflow for a future real browser adapter:

1. **Authorization gate:** record the exact in-scope host/application, written permission, program constraints, allowed test accounts, rate limits, and permitted test actions. Reject unknown or out-of-scope destinations before navigation.
2. **Controlled identities:** use only tester-owned accounts and synthetic objects. For access-control tests, document each account's role and which object it owns.
3. **Baseline capture:** use a real browser session to capture the baseline request/response, status, selected headers, cookie attribute names (never values), DOM state, and safe application behavior.
4. **Minimal test:** repeat one controlled request with one authorized test variable changed. Do not submit destructive forms, change passwords, send external messages, redeem tokens, or access real-user records.
5. **Control comparison:** compare owner-positive, second-account control, and test cases. Compare semantic response content and ownership markers, not status code alone.
6. **Independent verification:** require scope, reproduction, baseline comparison, impact evidence using synthetic data, alternate-explanation review, and repeatability. A scanner observation alone remains INCONCLUSIVE.
7. **Classification:** CONFIRMED, LIKELY, INCONCLUSIVE, or FALSE_POSITIVE with explicit per-gate evidence and confidence. Missing browser/session access must return MANUAL_VERIFICATION_NOT_PERFORMED.
8. **Evidence minimization:** retain only sanitized request/response fragments or hashes needed to explain the issue. Redact Authorization, Cookie, Set-Cookie, bearer tokens, API keys, reset links, personal data, and private target data before writing files.
9. **Report:** include affected asset, scope confirmation, prerequisites, exact reproduction steps, baseline/control results, sanitized evidence, impact, severity rationale, limitations, false-positive analysis, confidence, and remediation.
10. **Human approval:** do not submit HackerOne/Bugcrowd reports, contact the target, publish findings, or modify a remote repository automatically.

## 5. Skill-learning record schema

Every accepted lesson should become a small versioned local record with:
- `skill_id`, semantic version, title, and changelog;
- source URL, source type, access date, and license/terms note;
- paraphrased lesson, prerequisites, supported inputs, and validation method;
- false-positive indicators and remediation guidance;
- confidence and the reason for that confidence;
- safe-use constraints, authorization prerequisites, and prohibited actions;
- synthetic test fixtures and expected outputs;
- reviewer/approval state.

The research pipeline must be read-only by default. It may collect public metadata and create draft notes, but it must not execute newly learned techniques, install tools, activate skills, contact targets, or submit findings without explicit user approval.

## 6. Current implementation gap

The feature branch currently contains a minimal skill registry, a boolean evidence-gate classifier, basic sensitive-key/string redaction, a bounded static file identifier, a browser-driver Protocol, and metadata-only research-note persistence. These are foundations only.

Before calling the requested capabilities implemented, the project still needs:
- a typed skill interface with validated input, explicit dependencies, capability declarations, bounded execution context, and structured results;
- strict evidence objects per verification gate (not just caller-supplied booleans), plus tests rejecting non-boolean/truthy strings;
- broader redaction tests for cookie header text, JWT-like values, reset URLs, private data, and nested request/response structures;
- real browser adapter with exact-host enforcement, read-only defaults, sanitized network capture, DOM observations, and baseline/test comparison;
- optional, version-checked Ghidra/radare2/JADX/pefile/apksigner adapters with fixture-backed support matrices;
- bounded parsers for ELF/PE/Mach-O/APK/firmware/protocol formats and explicit unsupported-format results;
- isolated dynamic-debugging and malware-sandbox orchestration; never run unknown samples on the host;
- per-finding report generation and local evidence storage with safe permissions;
- public-source review workflow, human approval, source cross-checks, and changelog/tests for each learned skill.

Do not merge or release this foundation as a complete reverse-engineering or browser-verification product. Keep the PR draft until these limits are addressed or the release claims remain strictly limited to the implemented foundation.
