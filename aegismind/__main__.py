import argparse
from pathlib import Path
from .scanner import Scanner
from .report import write_reports
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def main():
    p = argparse.ArgumentParser(description="AegisMind AI Hunter - bounded, scope-bound web assessment")
    p.add_argument("--url", required=True, help="Starting URL, e.g. https://example.com")
    p.add_argument("--allow-host", action="append", required=True, help="Exact authorized hostname; repeat as needed")
    p.add_argument("--out", default="reports", help="Report output directory")
    p.add_argument("--max-pages", type=int, default=None, help="Maximum same-host HTML pages (1-100)")
    p.add_argument("--delay", type=float, default=None, help="Minimum delay between requests in seconds (at least 0.5)")
    p.add_argument("--max-body-bytes", type=int, default=None, help="Maximum HTML bytes read per page (capped at 1 MB)")
    args = p.parse_args()
    scanner = Scanner(allowed_hosts=set(args.allow_host), max_urls=args.max_pages, delay=args.delay,
                      max_body_bytes=args.max_body_bytes)
    report = scanner.run(args.url)
    json_path, md_path, sarif_path = write_reports(report, Path(args.out))
    print(f"Assessment finished. Pages visited: {report['scope']['visited_pages']}; findings: {len(report['findings'])}")
    print(f"JSON: {json_path}\nMarkdown: {md_path}\nSARIF: {sarif_path}")
    print("Review scope, evidence and limitations before submitting any report.")

if __name__ == "__main__":
    main()
