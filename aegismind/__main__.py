import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .authorization import AuthorizationGrant
from .decision import PlanRequest, Planner, ResourceBudget, execute_plan
from .report import write_reports
from .scanner import Scanner
from .skills.registry import Skill, SkillRegistry

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def main():
    parser = argparse.ArgumentParser(
        description="AegisMind AI Hunter - bounded, scope-bound web assessment"
    )
    parser.add_argument("--url", required=True, help="Starting URL, e.g. https://example.com")
    parser.add_argument("--allow-host", action="append", required=True,
                        help="Exact authorized hostname; repeat as needed; no wildcards")
    parser.add_argument("--authorization-ref", default="CLI --allow-host operator assertion",
                        help="Your authorization/ticket reference (the tool cannot verify permission)")
    parser.add_argument("--out", default="reports", help="Report output directory")
    parser.add_argument("--max-pages", type=int, default=None,
                        help="Maximum same-host HTML pages (1-100)")
    parser.add_argument("--delay", type=float, default=None,
                        help="Minimum delay between requests in seconds (at least 0.5)")
    parser.add_argument("--max-body-bytes", type=int, default=None,
                        help="Maximum HTML bytes read per page (capped at 1 MB)")
    parser.add_argument("--plan-only", action="store_true",
                        help="Show the deterministic skill plan without making network requests")
    args = parser.parse_args()

    scanner = Scanner(
        allowed_hosts=set(args.allow_host), max_urls=args.max_pages,
        delay=args.delay, max_body_bytes=args.max_body_bytes,
    )
    now = datetime.now(timezone.utc)
    request_budget = scanner.max_urls * 2
    runtime_budget = max(1, int(scanner.max_urls * 2 * (scanner.timeout + scanner.delay)))
    grant = AuthorizationGrant(
        reference=args.authorization_ref,
        allowed_hosts=tuple(args.allow_host),
        expires_at=now + timedelta(hours=4),
        max_requests=request_budget,
        allowed_methods=("GET", "OPTIONS"),
    )

    registry = SkillRegistry()

    def run_passive_http(*, start_url):
        return scanner.run(start_url)

    registry.register(Skill(
        skill_id="passive-http-assessment",
        version="0.2.0",
        description="Bounded unauthenticated GET/OPTIONS HTTP security observations",
        supported_inputs=("http_url",),
        safety_constraints=(
            "exact-host authorization required",
            "GET and OPTIONS only",
            "redirects are not followed",
            "page, byte, timeout and delay limits apply",
        ),
        runner=run_passive_http,
        capabilities=(
            "http.headers", "http.cookies", "http.csp", "http.cors",
            "http.options", "http.same_host_links",
        ),
        action_class="network_passive",
        network_access=True,
        estimated_requests=request_budget,
        estimated_runtime_seconds=runtime_budget,
        estimated_memory_mb=128,
    ))

    required = (
        "http.headers", "http.cookies", "http.csp", "http.cors",
        "http.options", "http.same_host_links",
    )
    plan_request = PlanRequest(
        goal="Run a bounded passive HTTP security assessment",
        required_capabilities=required,
        budget=ResourceBudget(
            max_steps=4, max_requests=request_budget,
            max_runtime_seconds=runtime_budget, max_memory_mb=256,
        ),
        allowed_hosts=tuple(args.allow_host),
        authorization_grant=grant,
        required_methods=("GET", "OPTIONS"),
    )
    plan = Planner().create_plan(plan_request, registry, now=now)

    print("Decision plan:")
    for explanation in plan.explanations:
        print(f"- {explanation}")
    if not plan.ready:
        raise SystemExit("Plan blocked or incomplete; no network requests were made.")
    if args.plan_only:
        print("Plan-only mode: no network requests were made.")
        return

    results = execute_plan(
        plan, registry, user_approved=True, authorization_grant=grant,
        runner_kwargs={"passive-http-assessment": {"start_url": args.url}},
        now=now,
    )
    report = results[0]["result"]
    json_path, md_path, sarif_path = write_reports(report, Path(args.out))
    print(
        f"Assessment finished. Pages visited: {report['scope']['visited_pages']}; "
        f"findings: {len(report['findings'])}"
    )
    print(f"JSON: {json_path}\nMarkdown: {md_path}\nSARIF: {sarif_path}")
    print("Review scope, evidence and limitations before submitting any report.")


if __name__ == "__main__":
    main()
