# AegisMind Next-Version Skills Implementation Plan

Status: proposed; not implemented by this document.
Target: next development version (do not modify the immutable v0.2.0 tag/release).

This plan defines a modular skill system for authorized security analysis. A skill is not considered implemented until its code, tests, documentation, supported-format limits, and safe-use controls are present and verified.

## 1. Skill contract

Each skill should expose:
- a stable skill id and semantic version;
- a human-readable name and purpose;
- supported input types and explicit unsupported formats;
- required tools and optional dependencies;
- authorization/safety prerequisites;
- deterministic `validate_input`, `run`, and `render_evidence` interfaces;
- structured results with evidence references, limitations, and confidence;
- unit and integration tests using synthetic fixtures only.

The registry must load only installed, locally trusted skills. No downloaded skill is executed automatically. Skill installation, dependency installation, and execution require explicit user approval. Skills run with bounded time, memory, file size, and subprocess limits.

## 2. Proposed skill families

### Browser-assisted manual verification
- Real browser session integration only when a supported browser and automation backend are available.
- Capture request/response metadata, headers, cookie attributes (never cookie values), DOM observations, navigation, and application behavior.
- Compare a baseline with a minimal test case using owned test accounts.
- If browser access or a target session is unavailable, return MANUAL_VERIFICATION_NOT_PERFORMED.
- No destructive tests, real-user data access, account takeover, persistence, or out-of-scope testing.

### Multi-layer finding verification
Every candidate passes independent gates:
1. scope and authorization;
2. reproducibility;
3. baseline/control comparison;
4. impact evidence;
5. alternate-explanation analysis;
6. repeatability.

Allowed statuses: CONFIRMED, LIKELY, INCONCLUSIVE, FALSE_POSITIVE. Scanner output alone must never produce CONFIRMED. Store a rationale and evidence for every gate.

### Reverse engineering
- File identification: magic bytes, metadata, hashes, MIME, size limits.
- Static inspection: strings, imports/exports, dependencies, symbols, signatures, section and header metadata.
- APK: manifest, permissions, components, signing metadata, DEX/resource inventory.
- ELF/PE/Mach-O: architecture, sections, symbols, imports/exports, dependency metadata.
- Firmware: container identification, partition/filesystem inventory, hashes, and extraction only in bounded isolated workspaces.
- File formats and protocols: metadata, structural parsing, schema/field inventory, and controlled sample comparison.
- Decompilation/disassembly adapters: Ghidra, radare2/rizin, JADX, and platform-native inspection tools when installed.
- Symbol and call-graph exploration where symbols and tool support exist.
- Dynamic debugging only in an isolated, user-controlled environment with explicit authorization.
- Malware triage only in a disposable sandbox with networking disabled by default; no execution on the host.
- Document supported architectures and tool/version dependencies. Never claim universal format or architecture support.

Prohibited capabilities: credential theft, unauthorized access, DRM/license/anti-cheat circumvention, stealth, persistence, exploit deployment, malware deployment, and evasion.

### Evidence-backed reporting
Each finding report should include affected asset, scope confirmation, reproduction steps, sanitized request/response evidence, impact, severity rationale, verification layers, confidence, limitations, and remediation. Redact authorization headers, cookies, API keys, personal data, and private target data before persistence or export.

### Public research and skill learning
- Use publicly available disclosed reports, vendor advisories, standards, and primary documentation.
- Respect licenses, terms, rate limits, and privacy; do not scrape private/restricted reports or reproduce report text.
- Extract reusable patterns, prerequisites, validation methods, false-positive indicators, and remediation.
- Cross-check important claims against primary documentation and multiple sources where practical.
- Store sanitized notes with source URL, date accessed, confidence, safe-use constraints, tests, and changelog.
- Human approval required before installing tools, activating a skill, or executing newly learned techniques.

## 3. Proposed package layout

```text
aegismind/
  skills/
    api.py
    registry.py
    browser_manual/
    verification/
    reverse_engineering/
      file_identification/
      apk/
      elf_pe/
      firmware/
      file_formats/
      protocols/
      decompilation/
      dynamic_debugging/
      malware_triage/
    reporting/
    public_research/
  evidence/
    models.py
    redaction.py
    storage.py
  tests/
    fixtures/
    unit/
    integration/
docs/
  SKILLS.md
  SUPPORTED_FORMATS.md
  SAFE_ANALYSIS.md
```

The final layout must be reconciled with the actual package architecture before implementation; this proposed tree is not a claim that these modules currently exist.

## 4. Release gates

Do not publish a next-version release until:
- every advertised skill has working code and tests;
- unsupported formats and missing optional tools are handled clearly;
- browser workflow reports unavailable access honestly;
- evidence redaction tests cover cookies, authorization headers, tokens, and personal data;
- scope and authorization gates are tested;
- synthetic fixtures and local mock services cover integration behavior;
- CI passes on the release commit;
- docs, CLI help, supported-format matrix, and changelog match actual behavior;
- secret scanning and dependency review are complete.

Do not change the v0.2.0 tag/release, repository visibility, or add a license as part of this work.
