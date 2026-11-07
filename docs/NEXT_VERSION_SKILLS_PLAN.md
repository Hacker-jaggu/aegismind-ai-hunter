# AegisMind Next-Version Skills Implementation Plan

Status: proposed; not implemented as a complete product by this document.  
Target: next development version. The published v0.2.0 tag/release must remain unchanged.

This plan defines a modular skill system for authorized software analysis and browser-assisted verification. A skill is not considered implemented until its code, tests, documentation, supported-format limits, safety controls, and evidence output are present and verified.

## 1. Proposed modular skill interface

The current \`Skill\` dataclass and registry are only an early in-memory foundation. The target interface should separate skill metadata, execution context, and evidence results.

\`\`\`python
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

@dataclass(frozen=True)
class ResourceBudget:
    max_input_bytes: int
    max_runtime_seconds: int
    max_output_bytes: int
    max_subprocesses: int

@dataclass(frozen=True)
class SkillSpec:
    skill_id: str
    version: str
    description: str
    supported_inputs: tuple[str, ...]
    required_tools: tuple[str, ...]
    supported_architectures: tuple[str, ...]
    network_access: bool
    safety_constraints: tuple[str, ...]

@dataclass(frozen=True)
class SkillContext:
    input_path: Path | None
    target_url: str | None
    allowed_hosts: frozenset[str]
    authorization_reference: str | None
    budget: ResourceBudget
    evidence_directory: Path
    offline_by_default: bool = True

@dataclass
class SkillResult:
    status: str  # OK, UNSUPPORTED, BLOCKED, INCONCLUSIVE, ERROR
    summary: str
    evidence_refs: list[str]
    tool_versions: dict[str, str]
    confidence: str
    limitations: list[str]

class Skill(Protocol):
    spec: SkillSpec
    def validate_input(self, context: SkillContext) -> None: ...
    def run(self, context: SkillContext) -> SkillResult: ...
    def render_evidence(self, result: SkillResult) -> dict[str, Any]: ...
\`\`\`

Design requirements:
- Each skill has a stable ID and semantic version; dependencies and supported formats are declared, not inferred.
- The registry loads only installed, locally trusted implementations. It never imports downloaded code automatically.
- Installation, dependency installation, activation, and execution require explicit user approval.
- Pure parsers may run in-process only when inputs and memory use are bounded. External tools run as argument arrays (never shell-concatenated strings) in a restricted worker with timeout, output cap, file-size cap, and process limits.
- Network access is denied by default. A browser skill may access only exact allowlisted hosts and must block cross-host redirects before issuing the redirected request.
- No secrets or raw session cookies are placed in \`SkillContext\` or persisted in evidence. Browser authentication should use a user-controlled real browser session.
- Unsupported formats, missing tools, and unsupported architectures return explicit \`UNSUPPORTED\` results with tool/version details; they must never be guessed.
- Evidence references point to sanitized local artifacts with a content hash, creation time, source/tool version, and redaction status.

## 2. Proposed skill families

### Browser-assisted manual verification

A future adapter may use a real browser session and supported automation backend when installed. It must:
- verify explicit authorization and the exact host allowlist before navigation;
- enforce the allowlist across redirects and subresources;
- capture request/response metadata, selected headers, cookie attribute names only, DOM snapshots, and relevant application behavior;
- avoid storing cookie values, bearer tokens, API keys, reset tokens, personal data, or private target data;
- compare a baseline with a minimal test case using tester-owned accounts and synthetic objects;
- return \`MANUAL_VERIFICATION_NOT_PERFORMED\` when browser access, a target session, or a supported driver is unavailable.

No destructive tests, real-user data access, account takeover, persistence, external messages, token redemption, or out-of-scope testing.

### Multi-layer finding verification

Every candidate passes independent gates:
1. exact scope and authorization;
2. reproducibility;
3. baseline/control comparison;
4. impact evidence using tester-owned data;
5. alternate-explanation analysis;
6. repeatability.

Allowed statuses: \`CONFIRMED\`, \`LIKELY\`, \`INCONCLUSIVE\`, \`FALSE_POSITIVE\`. Scanner output alone must never produce \`CONFIRMED\`. Every positive gate must reference a sanitized evidence artifact; a caller-supplied boolean without an evidence reference is insufficient. The classifier must preserve rationale, evidence references, and confidence for each gate.

### Reverse engineering

Small independent skills should cover:
- **File identification:** magic bytes, MIME hints, metadata, hashes, file size, and safe format recognition.
- **Static inspection:** strings, headers, sections, imports/exports, symbols, dependencies, debug metadata, and signature metadata.
- **APK/DEX:** manifest, permissions, components, resources, DEX inventory, signing certificate metadata, and signature verification using supported Android SDK tools.
- **ELF/PE/Mach-O:** architecture, endianness, sections, symbols, imports/exports, dependencies, and signature data where the format/tool supports it.
- **Firmware:** container identification, partition/filesystem inventory, hashes, and extraction only in a bounded isolated workspace.
- **File formats and protocols:** structural parsing, schema/field inventory, and controlled sample comparison; PCAP analysis only for explicitly authorized captures.
- **Decompilation/disassembly:** adapters for Ghidra, radare2/rizin, JADX, and platform-native tools when installed and version-checked.
- **Symbol and call-graph exploration:** only where the binary format, debug symbols, processor language, and tool version support it.
- **Controlled dynamic debugging:** GDB/LLDB or platform debuggers only in a user-controlled isolated environment, with explicit authorization and no arbitrary remote target access.
- **Malware triage:** optional disposable VM/sandbox orchestration (for example, CAPE) with snapshots, host isolation, resource limits, and networking disabled by default. Unknown samples must never run on the analyst's host.

Prohibited capabilities: credential theft, unauthorized access, DRM/license/anti-cheat circumvention, stealth, persistence, exploit deployment, malware deployment, and evasion.

### Supported-format and architecture policy

There is no universal reverse-engineering support. Initial support should be declared only after fixture-backed tests:
- ELF: begin with x86/x86_64 and ARM/AArch64 when the installed parser explicitly supports them.
- PE: begin with x86/x86_64 only after a PE parser and fixtures are added.
- Mach-O: defer until the parser correctly handles both 32/64-bit and endianness variants.
- APK/DEX: support only Android package/DEX versions accepted by the installed JADX/Android tools; decompilation can be incomplete.
- Firmware: support named container/filesystem types only; unknown or encrypted images remain unsupported.
- Protocols: support named dissectors/parsers and documented capture formats only; do not claim arbitrary protocol understanding.

Every report must record detected format, architecture, endianness where relevant, parser/tool version, and unsupported or ambiguous fields. Ghidra requires a matching processor-language module; JADX may not decompile all code; signature verification does not prove publisher identity unless compared with a trusted certificate baseline.

### Evidence-backed reporting

Each finding report should include affected asset, exact scope confirmation, authorization reference, tester-owned account/fixture prerequisites, reproduction steps, baseline/control results, sanitized request/response evidence, impact evidence, severity rationale, confidence, verification-layer results, alternate explanations, false-positive indicators, limitations, remediation, and source/tool versions.

Reports must redact Authorization, Cookie, Set-Cookie, bearer tokens, API keys, reset links, personal data, and private target data before persistence or export. Never submit HackerOne/Bugcrowd reports, contact targets, publish findings, or save to a remote service automatically.

### Public research and skill learning

- Use only publicly accessible, formally disclosed HackerOne reports/writeups, vendor advisories, standards, and primary documentation.
- Respect source licenses, site terms, rate limits, and privacy. Do not scrape private/restricted reports, copy report text, or ingest attachments/comments containing sensitive data.
- Extract reusable patterns, prerequisites, validation methods, false-positive indicators, and remediation guidance in original paraphrased notes.
- Cross-check important claims against primary documentation and multiple sources where practical.
- Store sanitized records with source URL, source type, date accessed, license/terms note, confidence, safe-use constraints, tests, and changelog.
- Human approval is required before installing tools, activating a skill, or executing newly learned techniques.
- Research is read-only by default; no automatic target contact, report submission, remote publication, or repository modification.

## 3. Proposed package layout

\`\`\`text
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
      macho/
      firmware/
      file_formats/
      protocols/
      decompilation/
      symbols_graphs/
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
  NEXT_VERSION_SKILLS_PLAN.md
  PUBLIC_RESEARCH_NOTES.md
  SUPPORTED_FORMATS.md
  SAFE_ANALYSIS.md
\`\`\`

The final layout must be reconciled with the current package architecture before implementation. This proposed tree is not a claim that these modules currently exist.

## 4. Recommended implementation phases

1. **Foundation hardening:** typed skill/context/result contracts, strict scope checks, evidence-reference resolution, robust redaction, and bounded subprocess runner.
2. **Static analysis first:** file identification, hashes, strings, ELF/PE metadata, APK inventory/signature checks, and explicit unsupported-format handling.
3. **Decompilation and graphing adapters:** add Ghidra/radare2/JADX only as optional external tools; test synthetic binaries and record version/architecture support.
4. **Browser verification:** real browser adapter, redirect enforcement, baseline/control capture, DOM/network evidence, and manual-not-performed behavior when unavailable.
5. **Reporting and research:** per-finding report schema, sanitized evidence store, source-note workflow, confidence/provenance, and changelog.
6. **Isolated dynamic analysis:** only after dedicated disposable VM/sandbox infrastructure is available; never make it a default feature on the analyst laptop.

## 5. Release gates

Do not publish a next-version release until every advertised skill has working code/tests; unsupported formats and missing tools are handled clearly; browser verification reports unavailable access honestly and blocks out-of-scope redirects; redaction and authorization gates are tested; synthetic fixtures and local mock services cover integration behavior; dynamic analysis runs only in an isolated sandbox with explicit approval; CI passes on the release commit; documentation matches behavior; and secret/dependency reviews are complete.

Do not change the v0.2.0 tag/release, repository visibility, or add a license as part of this work.
