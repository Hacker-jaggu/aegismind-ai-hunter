import json
from pathlib import Path
from datetime import datetime, timezone

def write_reports(report, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    jp, mp = out_dir/f"aegismind-{stamp}.json", out_dir/f"aegismind-{stamp}.md"
    jp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# AegisMind AI Hunter Report", "", f"- Generated: {report['generated_at']}",
             f"- Start URL: {report['scope']['start_url']}", f"- Allowed hosts: {', '.join(report['scope']['allowed_hosts'])}",
             f"- Findings: {len(report['findings'])}", "", "## Findings", ""]
    for f in report["findings"]:
        lines += [f"### {f['title']}", "", f"- ID: `{f['id']}`", f"- Category: {f['category']}",
                  f"- Severity: {f['severity']}", f"- Status: {f['status']}", f"- Confidence: {f['confidence']}",
                  f"- URL: `{f['url']}`", f"- Why it matters: {f['why_it_matters']}",
                  f"- Impact limitations: {f['impact_limitations']}", f"- Remediation: {f['remediation']}",
                  "- Verification layers:"]
        lines.extend([f"  - {x}" for x in f["verification_layers"]])
        lines += ["- Evidence:", "```json", json.dumps(f["evidence"], indent=2), "```", ""]
    lines += ["## AI review", "", "```", str(report["ai_review"]), "```", "", "## Limitations", ""]
    lines.extend([f"- {x}" for x in report["limitations"]])
    mp.write_text("\n".join(lines), encoding="utf-8")
    return jp, mp
