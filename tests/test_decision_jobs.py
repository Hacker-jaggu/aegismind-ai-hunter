from datetime import datetime, timedelta, timezone

import pytest

from aegismind.authorization import AuthorizationGrant, normalize_hostname
from aegismind.decision import PlanRequest, Planner, ResourceBudget, execute_plan
from aegismind.jobs import JobScheduler, MIN_INTERVAL_SECONDS
from aegismind.skills.registry import Skill, SkillRegistry

NOW = datetime(2026, 11, 7, 9, 0, tzinfo=timezone.utc)


def make_grant(*, hosts=("example.test",), expires=None, max_requests=50):
    return AuthorizationGrant(
        reference="program-scope-123",
        allowed_hosts=hosts,
        expires_at=expires or NOW + timedelta(days=5),
        max_requests=max_requests,
    )


def make_network_registry(runner):
    registry = SkillRegistry()
    registry.register(Skill(
        "http-passive", "1.0.0", "Passive HTTP observations",
        runner=runner, capabilities=("http.headers",),
        action_class="network_passive", network_access=True,
        estimated_requests=5, estimated_runtime_seconds=20, estimated_memory_mb=64,
    ))
    return registry


def test_hostname_normalization_and_wildcard_rejection():
    assert normalize_hostname("Example.TEST.") == "example.test"
    assert normalize_hostname("bücher.example") == "xn--bcher-kva.example"
    with pytest.raises(ValueError):
        normalize_hostname("*.example.test")


def test_grant_enforces_expiry_exact_hosts_methods_and_request_budget():
    grant = make_grant(max_requests=10)
    grant.validate(("EXAMPLE.test",), request_count=10, now=NOW)
    with pytest.raises(PermissionError):
        grant.validate(("sub.example.test",), now=NOW)
    with pytest.raises(PermissionError):
        grant.validate(("example.test",), methods=("DELETE",), now=NOW)
    with pytest.raises(PermissionError):
        grant.validate(("example.test",), request_count=11, now=NOW)
    with pytest.raises(PermissionError):
        grant.validate(("example.test",), now=NOW + timedelta(days=6))


def test_plan_selects_real_runner_and_explains_capabilities():
    registry = SkillRegistry()
    registry.register(Skill(
        "http-passive", "1.0.0", "Passive HTTP observations",
        runner=lambda: "ran",
        capabilities=("http.headers", "http.cookies"),
        action_class="network_passive", network_access=True,
        estimated_requests=4, estimated_runtime_seconds=20, estimated_memory_mb=64,
    ))
    request = PlanRequest(
        "Review HTTP posture", ("http.headers", "http.cookies"),
        ResourceBudget(max_steps=2, max_requests=10, max_runtime_seconds=60, max_memory_mb=128),
        allowed_hosts=("example.test",), authorization_grant=make_grant(),
    )
    plan = Planner().create_plan(request, registry, now=NOW)
    assert plan.ready is True
    assert [step.skill_id for step in plan.steps] == ["http-passive"]
    assert "http.headers" in plan.steps[0].reason
    assert plan.authorization_reference == "program-scope-123"


def test_plan_blocks_network_skill_without_authorization():
    registry = SkillRegistry()
    registry.register(Skill(
        "http-passive", "1.0.0", "Passive HTTP observations",
        runner=lambda: "must not run", capabilities=("http.headers",),
        action_class="network_passive", network_access=True, estimated_requests=2,
    ))
    request = PlanRequest(
        "Review HTTP posture", ("http.headers",),
        ResourceBudget(max_requests=10), allowed_hosts=("example.test",),
    )
    plan = Planner().create_plan(request, registry, now=NOW)
    assert plan.ready is False
    assert plan.uncovered_capabilities == ("http.headers",)
    assert any("authorization grant is missing" in item for item in plan.explanations)


def test_planner_never_selects_active_or_destructive_skills():
    registry = SkillRegistry()
    registry.register(Skill(
        "active-check", "1.0.0", "Active test",
        runner=lambda: "should not run", capabilities=("active.test",),
        action_class="active", network_access=True, estimated_requests=1,
    ))
    request = PlanRequest(
        "Run active test", ("active.test",), ResourceBudget(),
        allowed_hosts=("example.test",), authorization_grant=make_grant(),
    )
    plan = Planner().create_plan(request, registry, now=NOW)
    assert plan.ready is False
    assert any("not auto-plannable" in item for item in plan.explanations)


def test_execute_plan_requires_approval_and_revalidates_grant():
    calls = []
    registry = SkillRegistry()
    registry.register(Skill(
        "http-passive", "1.0.0", "Passive HTTP observations",
        runner=lambda marker: calls.append(marker) or "done",
        capabilities=("http.headers",), action_class="network_passive",
        network_access=True, estimated_requests=2,
    ))
    grant = make_grant()
    request = PlanRequest(
        "Review headers", ("http.headers",),
        ResourceBudget(max_requests=5), allowed_hosts=("example.test",),
        authorization_grant=grant,
    )
    plan = Planner().create_plan(request, registry, now=NOW)
    with pytest.raises(PermissionError):
        execute_plan(plan, registry, authorization_grant=grant, now=NOW)
    with pytest.raises(PermissionError):
        execute_plan(
            plan, registry, user_approved=True, authorization_grant=grant,
            runner_kwargs={"http-passive": {"marker": "expired"}},
            now=NOW + timedelta(days=6),
        )
    assert calls == []
    result = execute_plan(
        plan, registry, user_approved=True, authorization_grant=grant,
        runner_kwargs={"http-passive": {"marker": "approved"}},
        now=NOW,
    )
    assert result[0]["result"] == "done"
    assert calls == ["approved"]


def test_registry_direct_network_run_requires_grant_and_budget():
    registry = make_network_registry(lambda: "ran")
    with pytest.raises(PermissionError):
        registry.run("http-passive", approved=True)
    with pytest.raises(PermissionError):
        registry.run(
            "http-passive", approved=True, authorization_grant=make_grant(),
            allowed_hosts=("example.test",), authorization_request_budget=2, now=NOW,
        )
    assert registry.run(
        "http-passive", approved=True, authorization_grant=make_grant(),
        allowed_hosts=("example.test",), now=NOW,
    ) == "ran"


def test_scheduler_requires_opt_in_and_bounded_daily_interval():
    registry = make_network_registry(lambda: "ok")
    scheduler = JobScheduler(registry)
    grant = make_grant()
    with pytest.raises(PermissionError):
        scheduler.schedule(
            name="daily check", skill_id="http-passive",
            authorization_grant=grant, allowed_hosts=("example.test",),
            interval_seconds=MIN_INTERVAL_SECONDS, max_runs=2,
            request_budget=10, opt_in=False, now=NOW,
        )
    with pytest.raises(ValueError):
        scheduler.schedule(
            name="fast check", skill_id="http-passive",
            authorization_grant=grant, allowed_hosts=("example.test",),
            interval_seconds=3600, max_runs=2, request_budget=10,
            opt_in=True, now=NOW,
        )


def test_scheduler_revalidates_before_each_run_and_stops_at_max_runs():
    calls = []
    registry = make_network_registry(lambda: calls.append("ran") or "ok")
    scheduler = JobScheduler(registry)
    grant = make_grant()
    job = scheduler.schedule(
        name="daily passive check", skill_id="http-passive",
        authorization_grant=grant, allowed_hosts=("example.test",),
        interval_seconds=MIN_INTERVAL_SECONDS, max_runs=2,
        request_budget=10, opt_in=True, now=NOW,
    )
    first = scheduler.run_due(revalidate=lambda auth: True, now=NOW + timedelta(days=1))
    assert first[0]["status"] == "RAN"
    assert job.runs_completed == 1
    second = scheduler.run_due(revalidate=lambda auth: True, now=NOW + timedelta(days=2))
    assert second[0]["status"] == "RAN"
    assert job.status == "COMPLETED"
    assert len(calls) == 2
    assert scheduler.run_due(revalidate=lambda auth: True, now=NOW + timedelta(days=3)) == []


def test_scheduler_blocks_without_current_external_revalidation():
    calls = []
    registry = make_network_registry(lambda: calls.append(True))
    scheduler = JobScheduler(registry)
    job = scheduler.schedule(
        name="daily passive check", skill_id="http-passive",
        authorization_grant=make_grant(), allowed_hosts=("example.test",),
        interval_seconds=MIN_INTERVAL_SECONDS, max_runs=2,
        request_budget=10, opt_in=True, now=NOW,
    )
    events = scheduler.run_due(revalidate=lambda auth: False, now=NOW + timedelta(days=1))
    assert events[0]["status"] == "BLOCKED"
    assert job.last_error == "AUTHORIZATION_REVALIDATION_FAILED"
    assert calls == []


def test_scheduler_is_visible_and_cancellable():
    registry = make_network_registry(lambda: None)
    scheduler = JobScheduler(registry)
    job = scheduler.schedule(
        name="daily passive check", skill_id="http-passive",
        authorization_grant=make_grant(), allowed_hosts=("example.test",),
        interval_seconds=MIN_INTERVAL_SECONDS, max_runs=2,
        request_budget=10, opt_in=True, now=NOW,
    )
    listed = scheduler.list_jobs()
    assert listed[0]["job_id"] == job.job_id
    assert listed[0]["allowed_hosts"] == ["example.test"]
    assert scheduler.cancel(job.job_id) is True
    assert scheduler.cancel(job.job_id) is False
    assert scheduler.list_jobs()[0]["status"] == "CANCELLED"


def test_scheduler_cannot_outlive_authorization_grant():
    registry = make_network_registry(lambda: None)
    scheduler = JobScheduler(registry)
    grant = make_grant(expires=NOW + timedelta(days=2))
    with pytest.raises(ValueError):
        scheduler.schedule(
            name="long-lived job", skill_id="http-passive",
            authorization_grant=grant, allowed_hosts=("example.test",),
            interval_seconds=MIN_INTERVAL_SECONDS, max_runs=5,
            request_budget=10, opt_in=True,
            expires_at=NOW + timedelta(days=3), now=NOW,
        )


def test_scheduler_rejects_active_skill():
    registry = SkillRegistry()
    registry.register(Skill(
        "active-check", "1.0.0", "Active test", runner=lambda: None,
        action_class="active", network_access=True, estimated_requests=1,
    ))
    scheduler = JobScheduler(registry)
    with pytest.raises(PermissionError):
        scheduler.schedule(
            name="unsafe", skill_id="active-check",
            authorization_grant=make_grant(), allowed_hosts=("example.test",),
            interval_seconds=MIN_INTERVAL_SECONDS, max_runs=1,
            request_budget=10, opt_in=True, now=NOW,
        )


def test_cli_plan_only_does_not_start_network_scan(monkeypatch, capsys):
    import sys
    from aegismind import __main__ as cli

    class FakeScanner:
        def __init__(self, **kwargs):
            self.max_urls = 2
            self.timeout = 2.0
            self.delay = 0.5

        def run(self, start_url):
            raise AssertionError("plan-only mode must not make network requests")

    monkeypatch.setattr(cli, "Scanner", FakeScanner)
    monkeypatch.setattr(
        sys, "argv",
        ["aegismind", "--url", "https://example.test/",
         "--allow-host", "example.test", "--plan-only"],
    )
    cli.main()
    output = capsys.readouterr().out
    assert "Decision plan:" in output
    assert "Plan-only mode: no network requests were made." in output
