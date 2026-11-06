"""Small explicit registry for locally trusted skills."""
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class Skill:
    skill_id: str
    version: str
    description: str
    supported_inputs: tuple[str, ...] = ()
    safety_constraints: tuple[str, ...] = ()
    runner: Callable[..., Any] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self):
        if not self.skill_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in self.skill_id):
            raise ValueError("skill_id must be lowercase and contain only letters, digits, '-' or '_'")
        if not self.version or not self.description:
            raise ValueError("skill version and description are required")


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

    def list_skills(self) -> list[dict[str, Any]]:
        return [
            {"skill_id": s.skill_id, "version": s.version,
             "description": s.description, "supported_inputs": list(s.supported_inputs),
             "safety_constraints": list(s.safety_constraints),
             "available": s.runner is not None}
            for s in sorted(self._skills.values(), key=lambda item: item.skill_id)
        ]

    def run(self, skill_id: str, *, approved: bool = False, **kwargs):
        skill = self.get(skill_id)
        if not approved:
            raise PermissionError("explicit user approval is required before running a skill")
        if skill.runner is None:
            raise RuntimeError("skill has no installed runner; no simulation is provided")
        return skill.runner(**kwargs)
