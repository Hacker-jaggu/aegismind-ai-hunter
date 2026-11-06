# AegisMind Skills (early foundation)

This branch provides an explicit in-memory registry, approval-flag-gated skill invocation, evidence-reference-gated finding classification, expanded starter redaction, bounded static file identification, and an exact-host-checked browser-driver contract. It does **not** provide universal reverse engineering, a live browser automation client, a decompiler, a firmware extractor, a protocol dissector, or a malware sandbox.

## Available now

- **Skill registry:** local explicit registration; no downloaded code imports; skill invocation requires an approval flag and a real runner. This is not an OS sandbox.
- **Verification classifier:** strict boolean scope, reproduction, baseline, impact, alternate-explanation, and repeatability gates. CONFIRMED and FALSE_POSITIVE also require caller-supplied evidence references. References are not independently resolved or validated yet. Scanner-only leads remain INCONCLUSIVE.
- **Evidence handling:** redact sensitive-key fields, common authorization/cookie header lines, bearer/API-key/token/password values, secret query parameters, and JWT-like strings before local JSON persistence. Redaction is defense-in-depth, not a guarantee; review before sharing.
- **Static file triage:** size-limited file identification, SHA-256, bounded printable strings, basic ELF architecture identification, and ZIP/APK candidate inventory. Samples are never executed.
- **Browser contract:** blocks an initial URL that does not match an explicit exact-host allowlist and passes that allowlist to an injected driver. No real browser driver is bundled, and redirect enforcement depends on a future adapter honoring the contract.

## Not yet implemented

- Real browser session automation, request/response interception, DOM inspection, redirect enforcement, or live manual reproduction.
- Full per-finding report generation and durable evidence-reference resolution.
- Ghidra/radare2/JADX/pefile/apksigner adapters, decompilation, disassembly, symbol/call graph exploration, imports/exports, dependency and signature inspection.
- Complete PE, Mach-O, DEX, Android binary XML, APK signature, firmware, file-format, and protocol parsers.
- Network protocol/PCAP dissection, controlled dynamic debugging, and isolated malware sandbox orchestration.
- Automated HackerOne research ingestion, multi-source verification, and skill authoring/activation.
- Desktop-specific saving integration. Evidence can be written to a caller-selected local directory.

## Safety and limitations

Use only software, devices, files, and targets you own or are explicitly authorized to analyze. The file triage API is static and bounded; it does not establish whether a file is benign. The skill registry runs trusted callbacks in-process and is not a security boundary. Never execute unknown samples on the host. Do not use this foundation for credential theft, unauthorized access, DRM/license/anti-cheat circumvention, stealth, persistence, or malware deployment. Tool support and architecture coverage are explicit and partial.

A skill is not considered complete until its implementation, supported-input matrix, safety constraints, tests, and documentation are present. Installing dependencies, activating external tools, and running new skills require explicit user approval.
