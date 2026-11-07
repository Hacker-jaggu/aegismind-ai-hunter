"""Small explicit registry for locally trusted skills."""
from dataclasses import dataclass, field
from typing import Any, Callable

SAFE_ACTION_CLASSES = {"local_passive", "network_passive"}


@dataclass(frozen=True)
class Skill:
    skill_id: str
    version: str
    description: str
    supported_inputs: tuple[str, ...] = ()
    safety_constraints: tuple[str, ...] = ()
    runner: Callable[..., Any] | None = field(default=None, compare=False, repr=False)
    capabilities: tuple[str, ...] = ()
    action_class: str = "local_passive"
    network_access: bool = False
    estimated_requests: int = 0
    estimated_runtime_seconds: int = 1
    estimated_memory_mb: int = 16

    def __post_init__(self):
        if not self.skill_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in self.skill_id):
            raise ValueError("skill_id must be lowercase and contain only letters, digits, '-' or '_'")
        if not self.version or not self.description:
            raise ValueError("skill version and description are required")
        if self.action_class not in {"local_passive", "network_passive", "active", "destructive"}:
            raise ValueError("unsupported skill action_class")
        if type(self.network_access) is not bool:
            raise TypeError("network_access must be boolean")
        if self.runner is not None and not callable(self.runner):
            raise TypeError("runner must be callable when provided")
        if isinstance(self.capabilities, (str, bytes)):
            raise TypeError("capabilities must be a collection of capability names")
        if self.action_class == "network_passive" and not self.network_access:
            raise ValueError("network_passive skills must declare network_access=True")
        if self.network_access and self.action_class == "local_passive":
            raise ValueError("local_passive skills cannot declare network access")
        if self.network_access and self.estimated_requests < 1:
            raise ValueError("network skills must declare a positive estimated_requests budget")
        for name in ("estimated_requests", "estimated_runtime_seconds", "estimated_memory_mb"):
            value = getattr(self, name)
            minimum = 0 if name == "estimated_requests" else 1
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        capabilities = tuple(sorted({str(item).strip().lower() for item in self.capabilities if str(item).strip()}))
        object.__setattr__(self, "capabilities", capabilities)


class SkillRegistry:
    """In-memory registry; registration is explicit and never imports downloaded code."""

    def __init__(self):
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        if skill.skill_id in self._skills:
            raise ValueError(f"skill already registered: {skill.skill_id}")
        self._skills[skill.skill_id] = skill

    def get(self, skill_id: str) -> Skill:
        return self._skills[skill_id]

    def all_skills(self) -> tuple[Skill, ...]:
        return tuple(sorted(self._skills.values(), key=lambda item: item.skill_id))

    def list_skills(self) -> list[dict[str, Any]]:
        return [
            {"skill_id": s.skill_id, "version": s.version,
             "description": s.description, "supported_inputs": list(s.supported_inputs),
             "safety_constraints": list(s.safety_constraints),
             "capabilities": list(s.capabilities), "action_class": s.action_class,
             "network_access": s.network_access,
             "estimated_requests": s.estimated_requests,
             "estimated_runtime_seconds": s.estimated_runtime_seconds,
             "estimated_memory_mb": s.estimated_memory_mb,
             "available": s.runner is not None}
            for s in self.all_skills()
        ]

    def run(
        self, skill_id: str, *, approved: bool = False,
        authorization_grant=None, allowed_hosts=(), authorization_methods=("GET", "OPTIONS"),
        now=None, **kwargs
    ):
        skill = self.get(skill_id)
        if not approved:
            raise PermissionError("explicit user approval is required before running a skill")
        if skill.runner is None:
            raise RuntimeError("skill has no installed runner; no simulation is provided")
        if skill.action_class not in SAFE_ACTION_CLASSES:
            raise PermissionError("active or destructive skills are not executable by this safe runner")
        if skill.network_access or skill.action_class == "network_passive":
            if authorization_grant is None:
                raise PermissionError("a current exact-host authorization grant is required")
            authorization_grant.validate(
                allowed_hosts, methods=authorization_methods,
                request_count=skill.estimated_requests, now=now,
            )
        return skill.runner(**kwargs)
