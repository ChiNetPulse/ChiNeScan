"""Single-route HTTP client for ARTEX health. No credentials, redirects, or retries."""

import json
import ssl

from chinescan.core.config.settings import ArtexIntegrationSettings
from chinescan.integrations.artex.models import ArtexHealth
from chinescan.integrations.artex.network import (
    DestinationPolicyError,
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    resolve_destination,
)
from chinescan.integrations.artex.routes import validate_outbound_route


class ArtexIntegrationError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArtexHealthClient:
    def __init__(self, settings: ArtexIntegrationSettings) -> None:
        self.settings = settings

    def get_health(self, *, correlation_id: str | None = None) -> ArtexHealth:
        del correlation_id  # Correlation is local audit metadata; not forwarded upstream.
        if (
            not self.settings.enabled
            or not self.settings.health_enabled
            or self.settings.mode != "health_only"
        ):
            raise ArtexIntegrationError("integration_disabled")
        if not self.settings.base_url:
            raise ArtexIntegrationError("configuration_invalid")
        route = validate_outbound_route("GET", "/api/health", "health")
        timeout = self.settings.timeout_seconds
        connection: PinnedHTTPConnection | PinnedHTTPSConnection
        try:
            destination = resolve_destination(self.settings.base_url)
            if destination.scheme == "https":
                connection = PinnedHTTPSConnection(
                    destination, timeout=timeout, context=ssl.create_default_context()
                )
            else:
                connection = PinnedHTTPConnection(destination, timeout=timeout)
            connection.request("GET", route, headers={"Accept": "application/json"})
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise ArtexIntegrationError("upstream_redirect_rejected")
            if response.status != 200:
                raise ArtexIntegrationError("upstream_http_error")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != (
                "application/json"
            ):
                raise ArtexIntegrationError("invalid_content_type")
            body = response.read(self.settings.max_response_bytes + 1)
            if len(body) > self.settings.max_response_bytes:
                raise ArtexIntegrationError("response_too_large")
            try:
                data = json.loads(body)
                health = ArtexHealth.model_validate(data)
                if health.version != self.settings.release_id:
                    raise ArtexIntegrationError("release_mismatch")
                return health
            except (ValueError, TypeError):
                raise ArtexIntegrationError("invalid_response_schema") from None
        except ArtexIntegrationError:
            raise
        except DestinationPolicyError as exc:
            raise ArtexIntegrationError(exc.code) from None
        except (OSError, TimeoutError, ssl.SSLError):
            raise ArtexIntegrationError("upstream_unavailable") from None
        finally:
            if "connection" in locals():
                connection.close()
