import json
from pathlib import Path
from datetime import datetime,timezone
def _sarif_level(f):
 return {"CRITICAL":"error","HIGH":"error","MEDIUM":"warning","LOW":"note"}.get(f.get("severity","INFO").upper(),"note")
def to_sarif(report):
 rules={}; results=[]
 for f in report.get("findings",[]):
  rid=f.get("id","AEGISMIND-OBSERVATION")
  rules.setdefault(rid,{"id":rid,"name":f.get("title",rid),"shortDescription":{"text":f.get("title",rid)},"fullDescription":{"text":f.get("why_it_matters","")},"help":{"text":f.get("remediation","Review manually.")},"properties":{"category":f.get("category","Uncategorized")}})
  results.append({"ruleId":rid,"level":_sarif_level(f),"message":{"text":f"{f.get('title',rid)} — {f.get('status','NEEDS_REVIEW')}. {f.get('impact_limitations','')}"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f.get("url",report.get("scope",{}).get("start_url",""))}}}],"properties":{"status":f.get("status"),"confidence":f.get("confidence"),"evidence":f.get("evidence",{}),"verificationLayers":f.get("verification_layers",[])}})
 return {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"AegisMind AI Hunter","version":report.get("version","0.2.0"),"informationUri":"https://github.com/Hacker-jaggu/aegismind-ai-hunter","rules":list(rules.values())}},"results":results}]}
def write_reports(report,out_dir):
 out_dir.mkdir(parents=True,exist_ok=True); stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
 jp,mp,sp=(out_dir/f"aegismind-{stamp}.{ext}" for ext in ("json","md","sarif"))
 jp.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding="utf-8")
 counts={}
 for f in report.get("findings",[]):
  key=f.get("status","UNKNOWN"); counts[key]=counts.get(key,0)+1
 lines=["# AegisMind AI Hunter Report","",f"- Generated: {report['generated_at']}",f"- Start URL: {report['scope']['start_url']}",f"- Allowed hosts: {', '.join(report['scope']['allowed_hosts'])}",f"- Pages visited: {report['scope'].get('visited_pages',1)}",f"- Findings: {len(report['findings'])}",f"- Status counts: {json.dumps(counts)}","","## Findings",""]
 for f in report["findings"]:
  lines += [f"### {f['title']}","",f"- ID: {f['id']}",f"- Category: {f['category']}",f"- Severity: {f['severity']}",f"- Status: {f['status']}",f"- Confidence: {f['confidence']}",f"- URL: {f['url']}",f"- Why it matters: {f['why_it_matters']}",f"- Impact limitations: {f['impact_limitations']}",f"- Remediation: {f['remediation']}","- Verification layers:"]
  lines += [f"  - {x}" for x in f["verification_layers"]]
  lines += ["- Evidence:",json.dumps(f["evidence"],indent=2),""]
 lines += ["## AI review","",str(report["ai_review"]),"","## Limitations",""]+[f"- {x}" for x in report["limitations"]]
 mp.write_text("\n".join(lines),encoding="utf-8"); sp.write_text(json.dumps(to_sarif(report),indent=2,ensure_ascii=False),encoding="utf-8")
 return jp,mp,sp
