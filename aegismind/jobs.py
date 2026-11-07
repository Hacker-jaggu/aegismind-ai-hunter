"""Opt-in, in-memory scheduled jobs for registered passive network skills."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from .authorization import AuthorizationGrant, normalize_host_list
from .skills.registry import SkillRegistry

MIN_INTERVAL_SECONDS = 24 * 60 * 60
MAX_INTERVAL_SECONDS = 365 * 24 * 60 * 60
MAX_JOB_RUNS = 30


@dataclass
class ScheduledJob:
    job_id: str
    name: str
    skill_id: str
    allowed_hosts: tuple[str, ...]
    authorization_reference: str
    interval_seconds: int
    max_runs: int
    request_budget: int
    next_run_at: datetime
    expires_at: datetime
    status: str = "SCHEDULED"
    runs_completed: int = 0
    last_run_at: datetime | None = None
    last_error: str | None = None
    _grant: AuthorizationGrant = field(repr=False, default=None)
    _runner_kwargs: dict[str, Any] = field(repr=False, default_factory=dict)


class JobScheduler:
    """Visible/cancellable jobs; execution occurs only when the host calls run_due()."""

    def __init__(self, registry: SkillRegistry):
        if not isinstance(registry, SkillRegistry):
            raise TypeError("JobScheduler requires a SkillRegistry")
        self._registry = registry
        self._jobs: dict[str, ScheduledJob] = {}

    def schedule(
        self, *, name: str, skill_id: str, authorization_grant: AuthorizationGrant,
        allowed_hosts, interval_seconds: int, max_runs: int, request_budget: int,
        opt_in: bool, runner_kwargs: dict[str, Any] | None = None,
        expires_at: datetime | None = None, now: datetime | None = None,
    ) -> ScheduledJob:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("schedule time must be timezone-aware")
        current = current.astimezone(timezone.utc)
        if opt_in is not True:
            raise PermissionError("explicit opt-in is required to schedule a job")
        if not isinstance(name, str) or not name.strip() or not isinstance(skill_id, str) or not skill_id.strip():
            raise ValueError("job name and skill_id are required")
        skill = self._registry.get(skill_id)
        if skill.runner is None:
            raise RuntimeError("scheduled skill has no installed runner")
        if skill.action_class != "network_passive" or not skill.network_access:
            raise PermissionError("only registered network_passive skills may be scheduled")
        if type(interval_seconds) is not int or not MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS:
            raise ValueError("interval must be between 1 day and 365 days")
        if type(max_runs) is not int or not 1 <= max_runs <= MAX_JOB_RUNS:
            raise ValueError(f"max_runs must be between 1 and {MAX_JOB_RUNS}")
        if type(request_budget) is not int or request_budget < skill.estimated_requests:
            raise ValueError("request_budget must cover the skill's declared request estimate")
        if runner_kwargs is not None and not isinstance(runner_kwargs, dict):
            raise TypeError("runner_kwargs must be a dictionary")
        if any(not isinstance(key, str) for key in (runner_kwargs or {})):
            raise TypeError("runner_kwargs keys must be strings")
        reserved = {"approved", "authorization_grant", "allowed_hosts", "authorization_methods",
                    "authorization_request_budget", "now"}
        if reserved.intersection(runner_kwargs or {}):
            raise ValueError("runner_kwargs contains reserved authorization controls")
        hosts = normalize_host_list(allowed_hosts)
        authorization_grant.validate(
            hosts, methods=("GET", "OPTIONS"), request_count=request_budget, now=current
        )
        end = expires_at or authorization_grant.expires_at
        if end.tzinfo is None or end.utcoffset() is None:
            raise ValueError("job expiry must be timezone-aware")
        end = end.astimezone(timezone.utc)
        if end > authorization_grant.expires_at or end <= current:
            raise ValueError("job expiry must be future and no later than authorization expiry")
        next_run = current + timedelta(seconds=interval_seconds)
        if next_run >= end:
            raise ValueError("job expiry leaves no scheduled execution window")
        job = ScheduledJob(
            job_id=uuid4().hex, name=name.strip(), skill_id=skill_id.strip(),
            allowed_hosts=hosts, authorization_reference=authorization_grant.reference,
            interval_seconds=interval_seconds, max_runs=max_runs, request_budget=request_budget,
            next_run_at=next_run, expires_at=end, _grant=authorization_grant,
            _runner_kwargs=dict(runner_kwargs or {}),
        )
        self._jobs[job.job_id] = job
        return job

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job.status not in {"SCHEDULED", "BLOCKED"}:
            return False
        job.status = "CANCELLED"
        return True

    def list_jobs(self) -> list[dict[str, Any]]:
        return [{
            "job_id": job.job_id, "name": job.name, "skill_id": job.skill_id,
            "allowed_hosts": list(job.allowed_hosts), "authorization_reference": job.authorization_reference,
            "interval_seconds": job.interval_seconds, "max_runs": job.max_runs,
            "runs_completed": job.runs_completed, "next_run_at": job.next_run_at.isoformat(),
            "expires_at": job.expires_at.isoformat(), "status": job.status,
            "last_error": job.last_error,
        } for job in sorted(self._jobs.values(), key=lambda item: item.job_id)]

    def run_due(self, *, revalidate: Callable[[AuthorizationGrant], bool], now: datetime | None = None):
        """Run each due job at most once after fresh grant and external authorization checks."""
        if not callable(revalidate):
            raise TypeError("an authorization revalidation callback is required")
        fixed_now = now
        if fixed_now is not None and (fixed_now.tzinfo is None or fixed_now.utcoffset() is None):
            raise ValueError("run time must be timezone-aware")
        events = []
        for job in sorted(self._jobs.values(), key=lambda item: (item.next_run_at, item.job_id)):
            current = (fixed_now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            if job.status != "SCHEDULED" or job.next_run_at > current:
                continue
            if current >= job.expires_at:
                job.status = "EXPIRED"
                events.append({"job_id": job.job_id, "status": job.status})
                continue
            try:
                job._grant.validate(
                    job.allowed_hosts, methods=("GET", "OPTIONS"),
                    request_count=job.request_budget, now=current,
                )
                if revalidate(job._grant) is not True:
                    job.status = "BLOCKED"
                    job.last_error = "AUTHORIZATION_REVALIDATION_FAILED"
                    events.append({"job_id": job.job_id, "status": job.status})
                    continue
            except Exception:
                job.status = "BLOCKED"
                job.last_error = "AUTHORIZATION_REVALIDATION_ERROR"
                events.append({"job_id": job.job_id, "status": job.status})
                continue
            try:
                execution_time = (fixed_now or datetime.now(timezone.utc)).astimezone(timezone.utc)
                result = self._registry.run(
                    job.skill_id, approved=True, authorization_grant=job._grant,
                    allowed_hosts=job.allowed_hosts, authorization_methods=("GET", "OPTIONS"),
                    authorization_request_budget=job.request_budget, now=execution_time,
                    **job._runner_kwargs,
                )
                job.runs_completed += 1
                job.last_run_at = execution_time
                job.last_error = None
                if job.runs_completed >= job.max_runs:
                    job.status = "COMPLETED"
                else:
                    next_run = execution_time + timedelta(seconds=job.interval_seconds)
                    if next_run >= job.expires_at:
                        job.status = "COMPLETED"
                    else:
                        job.next_run_at = next_run
                events.append({"job_id": job.job_id, "status": "RAN", "result": result})
            except PermissionError:
                job.status = "BLOCKED"
                job.last_error = "EXECUTION_AUTHORIZATION_REJECTED"
                events.append({"job_id": job.job_id, "status": job.status})
            except Exception as exc:
                job.status = "FAILED"
                job.last_error = type(exc).__name__
                events.append({"job_id": job.job_id, "status": "FAILED", "error": type(exc).__name__})
        return events
