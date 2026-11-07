"""Deterministic, explainable planning with hard scope and resource gates."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .authorization import AuthorizationGrant, normalize_host_list
from .skills.registry import SkillRegistry

SAFE_ACTION_CLASSES = {"local_passive", "network_passive"}


@dataclass(frozen=True)
class ResourceBudget:
    max_steps: int = 8
    max_requests: int = 200
    max_runtime_seconds: int = 3600
    max_memory_mb: int = 512

    def __post_init__(self):
        limits = {
            "max_steps": (1, 20),
            "max_requests": (0, 5000),
            "max_runtime_seconds": (1, 86400),
            "max_memory_mb": (16, 4096),
        }
        for name, (minimum, maximum) in limits.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")


@dataclass(frozen=True)
class PlanRequest:
    goal: str
    required_capabilities: tuple[str, ...]
    budget: ResourceBudget
    allowed_hosts: tuple[str, ...] = ()
    authorization_grant: AuthorizationGrant | None = None
    required_methods: tuple[str, ...] = ("GET", "OPTIONS")

    def __post_init__(self):
        if not isinstance(self.goal, str) or not self.goal.strip():
            raise ValueError("a concrete goal is required")
        capabilities = tuple(sorted({str(item).strip().lower() for item in self.required_capabilities if str(item).strip()}))
        if not capabilities:
            raise ValueError("at least one required capability is needed")
        object.__setattr__(self, "required_capabilities", capabilities)
        if self.allowed_hosts:
            object.__setattr__(self, "allowed_hosts", normalize_host_list(self.allowed_hosts))
        if isinstance(self.required_methods, (str, bytes)):
            raise TypeError("required_methods must be a collection of method names")
        methods = tuple(sorted({str(method).upper() for method in self.required_methods}))
        if not methods or not set(methods).issubset({"GET", "OPTIONS"}):
            raise ValueError("only GET and OPTIONS are supported by this passive planner")
        object.__setattr__(self, "required_methods", methods)


@dataclass(frozen=True)
class PlanStep:
    skill_id: str
    capabilities: tuple[str, ...]
    reason: str
    estimated_requests: int
    estimated_runtime_seconds: int
    estimated_memory_mb: int
    network_access: bool


@dataclass(frozen=True)
class DecisionPlan:
    goal: str
    steps: tuple[PlanStep, ...]
    uncovered_capabilities: tuple[str, ...]
    explanations: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    required_methods: tuple[str, ...]
    authorization_reference: str | None
    ready: bool


class Planner:
    """Greedy deterministic planner; model-generated proposals are never trusted here."""

    def create_plan(self, request: PlanRequest, registry: SkillRegistry, *, now=None) -> DecisionPlan:
        current = now or datetime.now(timezone.utc)
        remaining = set(request.required_capabilities)
        selected: list[PlanStep] = []
        explanations: list[str] = []
        used_requests = used_runtime = used_memory = 0
        candidates = registry.all_skills()

        while remaining and len(selected) < request.budget.max_steps:
            eligible = []
            for skill in candidates:
                if any(step.skill_id == skill.skill_id for step in selected):
                    continue
                coverage = remaining.intersection(skill.capabilities)
                if not coverage:
                    continue
                if skill.runner is None:
                    explanations.append(f"{skill.skill_id}: skipped; no installed runner")
                    continue
                if skill.action_class not in SAFE_ACTION_CLASSES:
                    explanations.append(f"{skill.skill_id}: blocked; action class {skill.action_class!r} is not auto-plannable")
                    continue
                if skill.network_access or skill.action_class == "network_passive":
                    if not request.allowed_hosts or request.authorization_grant is None:
                        explanations.append(f"{skill.skill_id}: blocked; exact-host authorization grant is missing")
                        continue
                    try:
                        request.authorization_grant.validate(
                            request.allowed_hosts, methods=request.required_methods,
                            request_count=skill.estimated_requests, now=current,
                        )
                    except (PermissionError, ValueError) as exc:
                        explanations.append(f"{skill.skill_id}: blocked by authorization policy ({exc})")
                        continue
                if used_requests + skill.estimated_requests > request.budget.max_requests:
                    explanations.append(f"{skill.skill_id}: skipped; request budget would be exceeded")
                    continue
                if used_runtime + skill.estimated_runtime_seconds > request.budget.max_runtime_seconds:
                    explanations.append(f"{skill.skill_id}: skipped; runtime budget would be exceeded")
                    continue
                if used_memory + skill.estimated_memory_mb > request.budget.max_memory_mb:
                    explanations.append(f"{skill.skill_id}: skipped; memory budget would be exceeded")
                    continue
                cost = max(1, skill.estimated_requests + skill.estimated_runtime_seconds // 30 + skill.estimated_memory_mb // 64)
                eligible.append((-len(coverage), cost, skill.skill_id, skill, tuple(sorted(coverage))))
            if not eligible:
                break
            eligible.sort(key=lambda item: (item[0], item[1], item[2]))
            _, _, _, chosen, coverage = eligible[0]
            reason = "Covers " + ", ".join(coverage) + "; deterministic policy selected the lowest-cost eligible skill."
            selected.append(PlanStep(
                skill_id=chosen.skill_id, capabilities=coverage, reason=reason,
                estimated_requests=chosen.estimated_requests,
                estimated_runtime_seconds=chosen.estimated_runtime_seconds,
                estimated_memory_mb=chosen.estimated_memory_mb,
                network_access=chosen.network_access or chosen.action_class == "network_passive",
            ))
            remaining.difference_update(coverage)
            used_requests += chosen.estimated_requests
            used_runtime += chosen.estimated_runtime_seconds
            used_memory += chosen.estimated_memory_mb
            explanations.append(f"{chosen.skill_id}: selected; {reason}")

        if remaining:
            explanations.append("Uncovered capabilities: " + ", ".join(sorted(remaining)))
        else:
            explanations.append("All requested capabilities are covered by eligible installed skills.")
        return DecisionPlan(
            goal=request.goal, steps=tuple(selected),
            uncovered_capabilities=tuple(sorted(remaining)),
            explanations=tuple(explanations), allowed_hosts=tuple(request.allowed_hosts),
            required_methods=tuple(request.required_methods),
            authorization_reference=request.authorization_grant.reference if request.authorization_grant else None,
            ready=bool(selected) and not remaining,
        )


def execute_plan(
    plan: DecisionPlan,
    registry: SkillRegistry,
    *,
    user_approved: bool = False,
    authorization_grant: AuthorizationGrant | None = None,
    runner_kwargs: dict[str, dict] | None = None,
    now=None,
):
    """Execute only a complete plan after explicit approval and fresh authorization checks."""
    if not user_approved:
        raise PermissionError("explicit user approval is required before plan execution")
    if not plan.ready or plan.uncovered_capabilities:
        raise RuntimeError("incomplete decision plan cannot be executed")
    fixed_now = now
    results = []
    kwargs_by_skill = runner_kwargs or {}
    for step in plan.steps:
        current = fixed_now or datetime.now(timezone.utc)
        if step.network_access:
            if authorization_grant is None or authorization_grant.reference != plan.authorization_reference:
                raise PermissionError("the original authorization grant is required")
            authorization_grant.validate(
                plan.allowed_hosts, methods=plan.required_methods,
                request_count=step.estimated_requests, now=current,
            )
        result = registry.run(
            step.skill_id, approved=True,
            authorization_grant=authorization_grant,
            allowed_hosts=plan.allowed_hosts,
            authorization_methods=plan.required_methods,
            authorization_request_budget=step.estimated_requests,
            now=current,
            **kwargs_by_skill.get(step.skill_id, {})
        )
        results.append({"skill_id": step.skill_id, "result": result})
    return results
