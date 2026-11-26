"""Administrator-controlled Nuclei profiles and approved template binding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NucleiProfile:
    name: str
    description: str
    max_templates: int
    rate_limit: int
    timeout_seconds: int


NUCLEI_PROFILES: dict[str, NucleiProfile] = {
    "safe_web_checks": NucleiProfile(
        "safe_web_checks",
        "Run only administrator-approved, non-intrusive templates",
        max_templates=32,
        rate_limit=10,
        timeout_seconds=10,
    )
}


def validate_parameters(
    parameters: dict[str, Any], approved_templates: dict[str, str]
) -> dict[str, Any]:
    if set(parameters) - {"profile", "templates"}:
        raise ValueError("Nuclei parameters contain unsupported fields.")
    profile = parameters.get("profile")
    if profile not in NUCLEI_PROFILES:
        raise ValueError("Nuclei profile is not supported.")
    templates = parameters.get("templates", [])
    if not isinstance(templates, list) or not templates:
        raise ValueError("At least one approved Nuclei template is required.")
    if any(not isinstance(item, str) or item not in approved_templates for item in templates):
        raise ValueError("Nuclei template is not approved.")
    normalized = sorted(set(templates))
    if len(normalized) > NUCLEI_PROFILES[profile].max_templates:
        raise ValueError("Nuclei template limit exceeded.")
    return {"profile": profile, "templates": normalized}


def profile_listing() -> list[dict[str, Any]]:
    return [
        {
            "name": profile.name,
            "description": profile.description,
            "max_templates": profile.max_templates,
            "external_operations": True,
        }
        for profile in NUCLEI_PROFILES.values()
    ]
