import argparse
from pathlib import Path
from .scanner import Scanner
from .report import write_reports

def main():
    p = argparse.ArgumentParser(description="AegisMind AI Hunter - safe, scope-bound web checks")
    p.add_argument("--url", required=True)
    p.add_argument("--allow-host", action="append", required=True, help="Exact authorized hostname; repeat as needed")
    p.add_argument("--out", default="reports")
    args = p.parse_args()
    report = Scanner(allowed_hosts=set(args.allow_host)).run(args.url)
    json_path, md_path = write_reports(report, Path(args.out))
    print(f"Assessment finished. Findings: {len(report['findings'])}")
    print(f"JSON: {json_path}\nMarkdown: {md_path}")
    print("Review evidence and program rules before reporting.")

if __name__ == "__main__":
    main()
