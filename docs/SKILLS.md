# AegisMind Skills and Decision Engine

This branch adds a deterministic skill planner, exact-host authorization grants, and an opt-in scheduled-job interface to the earlier skill foundation. This remains an early framework, not a complete autonomous pentesting product.

## Implemented in this branch

- **Skill registry and contracts:** explicit local registration; declared capabilities, action class, network requirement, input types, safety constraints, and estimated request/runtime/memory costs. No downloaded code is imported. Registry callbacks are trusted in-process code, not an OS sandbox.
- **Decision engine:** deterministic greedy capability matching with stable tie-breaking and explainable selection/skip reasons. Only installed passive local/network skills are eligible. Active and destructive action classes are blocked. Request, runtime, memory, and step budgets are checked before a plan is marked ready.
- **CLI integration:** the existing passive HTTP scanner is registered as a real skill and invoked through the planner. --plan-only prints the plan without network requests.
- **Authorization grants:** exact host normalization, wildcard rejection, timezone-aware expiry, method allowlist (GET/OPTIONS), and per-run request budget. A reference is an operator-supplied label; it is not independent proof of permission. The user must verify program authorization and scope.
- **Scheduled jobs:** opt-in, visible, cancellable, minimum one-day cadence, maximum 30 runs, finite expiry, exact-host scope, bounded request budget, and external authorization revalidation before every execution. No background thread or daemon is created.
- **Verification classifier:** strict boolean scope, reproduction, baseline, impact, alternate-explanation, and repeatability gates. CONFIRMED and FALSE_POSITIVE also require caller-supplied evidence references. References are not independently resolved or validated yet. Scanner-only leads remain INCONCLUSIVE.
- **Evidence handling:** redact sensitive-key fields, common authorization/cookie header lines, bearer/API-key/token/password values, secret query parameters, and JWT-like strings before local JSON persistence. Redaction is defense-in-depth, not a guarantee; review before sharing.
- **Static file triage:** size-limited file identification, SHA-256, bounded printable strings, basic ELF architecture identification, and ZIP/APK candidate inventory. Samples are never executed.
- **Browser contract:** blocks an initial URL that does not match an explicit exact-host allowlist and passes that allowlist to an injected driver. No real browser driver is bundled, and redirect enforcement depends on a future adapter honoring the contract.

## Scheduled-job limitations

The current scheduler is an in-memory library interface. The embedding application must call run_due() and supply a live authorization revalidation callback. Jobs do not survive process restart; no persistent scheduler, cron integration, background service, desktop UI, or notification channel is included. The scheduler passes a request budget to a trusted callback, but cannot sandbox arbitrary callback code or forcibly stop a callback that ignores its budget. Use only callbacks that enforce their own network, time, and resource limits.

## Not yet implemented

- Real browser session automation, request/response interception, DOM inspection, redirect enforcement, or live manual reproduction.
- Full per-finding report generation and durable evidence-reference resolution.
- Ghidra/radare2/JADX/pefile/apksigner adapters, decompilation, disassembly, symbol/call graph exploration, imports/exports, dependency and signature inspection.
- Complete PE, Mach-O, DEX, Android binary XML, APK signature, firmware, file-format, and protocol parsers.
- Network protocol/PCAP dissection, controlled dynamic debugging, and isolated malware sandbox orchestration.
- Automated HackerOne research ingestion, multi-source verification, and skill authoring/activation.
- Persistent scheduled-job storage, background scheduling service, and desktop job controls.
- Desktop-specific saving integration. Evidence can be written to a caller-selected local directory.

## Safety and limitations

Use only software, devices, files, and targets you own or are explicitly authorized to analyze. The authorization grant records an operator assertion and does not verify an external program's rules. The file triage API is static and bounded; it does not establish whether a file is benign. Never execute unknown samples on the host. Do not use this foundation for credential theft, unauthorized access, DRM/license/anti-cheat circumvention, stealth, persistence, or malware deployment. Tool support and architecture coverage are explicit and partial.

A skill is not considered complete until its implementation, supported-input matrix, safety constraints, tests, and documentation are present. Installing dependencies, activating external tools, and running new skills require explicit user approval.
