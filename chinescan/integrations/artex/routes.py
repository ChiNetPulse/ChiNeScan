"""Compile-time route policy. Authenticated paths are recognized but unavailable in M1."""

from urllib.parse import urlsplit


class RouteDenied(ValueError):
    """The method, path, or query is outside the fixed ARTEX allowlist."""


ALLOWED_GET_PATHS = frozenset({"/api/health"})
MILESTONE_ONE_FEATURES = frozenset({"health"})
AUTHENTICATED_FUTURE_PATH_TEMPLATES = frozenset(
    {
        "/api/tasks",
        "/api/tasks/{id}",
        "/api/exploration/findings",
        "/api/exploration/findings/{id}",
        "/api/exploration/findings/export",
        "/api/report",
    }
)


def validate_outbound_route(method: str, target: str, feature: str = "health") -> str:
    """Validate before a URL/request object or network connection is constructed."""
    if method != "GET":
        raise RouteDenied("ARTEX integration permits GET only")
    if feature not in MILESTONE_ONE_FEATURES:
        raise RouteDenied("ARTEX feature is not available in Milestone 1")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path not in ALLOWED_GET_PATHS:
        raise RouteDenied("ARTEX route is not in the compile-time allowlist")
    if parsed.query:
        raise RouteDenied("ARTEX health route does not accept query parameters")
    return parsed.path
