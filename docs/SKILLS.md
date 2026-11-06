# AegisMind Skills (early foundation)

This release of the skill foundation provides an explicit in-memory registry, approval-gated skill invocation, evidence redaction, evidence-gated finding classification, and bounded static file identification. It does **not** provide universal reverse engineering, a browser automation client, a decompiler, a firmware extractor, a protocol dissector, or a malware sandbox.

## Available now

- **Skill registry:** local explicit registration; no downloaded code imports; skill invocation requires an approval flag and a real runner.
- **Verification classifier:** scope, reproducibility, baseline, impact, alternate explanations, and repeatability gates. Scanner-only leads remain INCONCLUSIVE.
- **Evidence handling:** redact sensitive-key fields and common bearer/API-key/token/password strings before local JSON persistence.
- **Static file triage:** size-limited file identification, SHA-256, bounded printable strings, basic ELF architecture identification, and ZIP/APK candidate inventory. Samples are never executed.

## Not yet implemented

- Browser session automation and live request/response capture.
- Actual HTTP/manual reproduction workflow and application DOM inspection.
- Ghidra/radare2/JADX adapters, decompilation, disassembly, symbol/call graph exploration.
- Complete PE, Mach-O, DEX, Android binary XML, APK signature, and firmware parsers.
- Network protocol/PCAP dissection and dynamic debugging.
- Malware sandbox orchestration.
- Public HackerOne research ingestion, source cross-checking, and skill authoring pipeline.
- Desktop-specific saving integration. Reports can be written to a caller-selected local directory.

## Safety and limitations

Use only software, devices, files, and targets you own or are explicitly authorized to analyze. The file triage API is static and bounded; it does not establish whether a file is benign. Do not use this foundation for credential theft, unauthorized access, DRM/license/anti-cheat circumvention, stealth, persistence, or malware deployment. Never execute unknown samples on the host. Tool support and architecture coverage are explicit and partial.

A skill is not considered complete until its implementation, supported-input matrix, safety constraints, tests, and documentation are present. Installing dependencies, activating external tools, and running new skills require explicit user approval.
