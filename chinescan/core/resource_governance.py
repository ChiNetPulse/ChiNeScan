"""Centralized resource governance, validated limits, and structured capacity errors."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from chinescan.core.config.settings import Settings

WorkloadCategory = Literal[
    "domain",
    "repository",
    "log_evidence",
    "malware_evidence",
    "chain_address",
]

# Operator-defined hard ceilings that environment/config overrides cannot exceed.
CEILING_PER_ORG_ACTIVE_LIMIT = 16
CEILING_GLOBAL_ACTIVE_LIMIT = 64
CEILING_PER_ORG_QUEUED_LIMIT = 64
CEILING_GLOBAL_QUEUED_LIMIT = 256
CEILING_WORKLOAD_ACTIVE_LIMIT = 32
CEILING_JOB_DEADLINE_SECONDS = 3600.0
CEILING_QUEUE_WAIT_SECONDS = 86_400.0
CEILING_OPERATION_TIMEOUT_SECONDS = 600.0
CEILING_SHUTDOWN_GRACE_SECONDS = 120.0
CEILING_MAX_FILES = 200_000
CEILING_MAX_TOTAL_BYTES = 10_737_418_240
CEILING_MAX_FILE_BYTES = 134_217_728
CEILING_MAX_DEPTH = 64
CEILING_ARCHIVE_MAX_ENTRIES = 100_000
CEILING_ARCHIVE_MAX_NESTING = 16
CEILING_ARCHIVE_MAX_DECOMPRESSED_BYTES = 2_147_483_648
CEILING_PARSER_MAX_OUTPUT_BYTES = 33_554_432
CEILING_MAX_FINDINGS_PER_JOB = 50_000
CEILING_SUBPROCESS_TIMEOUT_SECONDS = 600.0
CEILING_SUBPROCESS_MAX_OUTPUT_BYTES = 33_554_432
CEILING_NETWORK_CONNECT_TIMEOUT_SECONDS = 30.0
CEILING_NETWORK_READ_TIMEOUT_SECONDS = 60.0
CEILING_NETWORK_MAX_RESPONSE_BYTES = 16_777_216
CEILING_SAFE_RETRY_MAX_ATTEMPTS = 5
CEILING_SAFE_RETRY_DELAY_SECONDS = 30.0


def default_workload_limits() -> dict[str, int]:
    """Return default per-workload active execution concurrency limits."""
    return {
        "domain": 4,
        "repository": 2,
        "log_evidence": 4,
        "malware_evidence": 2,
        "chain_address": 2,
    }


class ResourceLimitError(OverflowError):
    """Structured capacity or quota rejection with stable error code and HTTP status."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 429,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class ExecutionDeadlineExceeded(RuntimeError):
    """Raised when a governed job or operation exceeds its monotonic deadline."""

    def __init__(self, code: str = "EXECUTION_DEADLINE_EXCEEDED", message: str = "") -> None:
        super().__init__(message or "Execution exceeded its configured deadline.")
        self.code = code


class ResourceLimits(BaseModel):
    """Validated, centralized resource limits and hard ceilings for governed execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Concurrency and queue capacity limits (counts)
    per_org_active_limit: int = Field(default=2, ge=1, le=CEILING_PER_ORG_ACTIVE_LIMIT)
    global_active_limit: int = Field(default=8, ge=1, le=CEILING_GLOBAL_ACTIVE_LIMIT)
    per_org_queued_limit: int = Field(default=4, ge=1, le=CEILING_PER_ORG_QUEUED_LIMIT)
    global_queued_limit: int = Field(default=16, ge=1, le=CEILING_GLOBAL_QUEUED_LIMIT)
    workload_concurrency_limits: dict[str, int] = Field(
        default_factory=default_workload_limits
    )

    # Deadline and timeout bounds (seconds)
    default_job_deadline_seconds: float = Field(
        default=300.0, ge=1.0, le=CEILING_JOB_DEADLINE_SECONDS
    )
    max_queue_wait_seconds: float = Field(
        default=900.0, ge=1.0, le=CEILING_QUEUE_WAIT_SECONDS
    )
    default_operation_timeout_seconds: float = Field(
        default=60.0, ge=0.5, le=CEILING_OPERATION_TIMEOUT_SECONDS
    )
    shutdown_grace_seconds: float = Field(
        default=5.0, ge=0.1, le=CEILING_SHUTDOWN_GRACE_SECONDS
    )

    # Input, archive, parser, and result bounds
    max_files: int = Field(default=50_000, ge=1, le=CEILING_MAX_FILES)
    max_total_bytes: int = Field(default=1_073_741_824, ge=1024, le=CEILING_MAX_TOTAL_BYTES)
    max_file_bytes: int = Field(default=16_777_216, ge=1024, le=CEILING_MAX_FILE_BYTES)
    max_depth: int = Field(default=32, ge=1, le=CEILING_MAX_DEPTH)
    archive_max_entries: int = Field(
        default=10_000, ge=1, le=CEILING_ARCHIVE_MAX_ENTRIES
    )
    archive_max_nesting: int = Field(default=4, ge=1, le=CEILING_ARCHIVE_MAX_NESTING)
    archive_max_decompressed_bytes: int = Field(
        default=268_435_456, ge=1024, le=CEILING_ARCHIVE_MAX_DECOMPRESSED_BYTES
    )
    parser_max_output_bytes: int = Field(
        default=4_194_304, ge=1024, le=CEILING_PARSER_MAX_OUTPUT_BYTES
    )
    max_findings_per_job: int = Field(
        default=5_000, ge=1, le=CEILING_MAX_FINDINGS_PER_JOB
    )

    # Subprocess bounds
    subprocess_timeout_seconds: float = Field(
        default=60.0, ge=0.5, le=CEILING_SUBPROCESS_TIMEOUT_SECONDS
    )
    subprocess_max_output_bytes: int = Field(
        default=4_194_304, ge=1024, le=CEILING_SUBPROCESS_MAX_OUTPUT_BYTES
    )

    # Network and safe-retry bounds
    network_connect_timeout_seconds: float = Field(
        default=5.0, ge=0.1, le=CEILING_NETWORK_CONNECT_TIMEOUT_SECONDS
    )
    network_read_timeout_seconds: float = Field(
        default=10.0, ge=0.1, le=CEILING_NETWORK_READ_TIMEOUT_SECONDS
    )
    network_max_response_bytes: int = Field(
        default=1_048_576, ge=256, le=CEILING_NETWORK_MAX_RESPONSE_BYTES
    )
    safe_retry_max_attempts: int = Field(
        default=2, ge=0, le=CEILING_SAFE_RETRY_MAX_ATTEMPTS
    )
    safe_retry_delay_seconds: float = Field(
        default=0.5, ge=0.0, le=CEILING_SAFE_RETRY_DELAY_SECONDS
    )

    @model_validator(mode="after")
    def validate_relationships(self) -> ResourceLimits:
        if self.per_org_active_limit > self.global_active_limit:
            raise ValueError("per_org_active_limit cannot exceed global_active_limit.")
        if self.per_org_queued_limit > self.global_queued_limit:
            raise ValueError("per_org_queued_limit cannot exceed global_queued_limit.")
        if self.per_org_active_limit > self.per_org_queued_limit:
            raise ValueError("per_org_active_limit cannot exceed per_org_queued_limit.")
        if self.global_active_limit > self.global_queued_limit:
            raise ValueError("global_active_limit cannot exceed global_queued_limit.")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_bytes.")
        if self.default_operation_timeout_seconds > self.default_job_deadline_seconds:
            raise ValueError(
                "default_operation_timeout_seconds cannot exceed default_job_deadline_seconds."
            )
        merged = default_workload_limits()
        for category, limit in self.workload_concurrency_limits.items():
            if category not in merged:
                raise ValueError(f"Unsupported workload category: {category}")
            if not (1 <= int(limit) <= CEILING_WORKLOAD_ACTIVE_LIMIT):
                raise ValueError(
                    f"Workload limit for {category} must be between 1 and "
                    f"{CEILING_WORKLOAD_ACTIVE_LIMIT}."
                )
            merged[category] = int(limit)
        object.__setattr__(self, "workload_concurrency_limits", merged)
        return self

    def workload_limit(self, category: str) -> int:
        """Return the active concurrency limit for a workload category."""
        return min(
            self.global_active_limit,
            self.workload_concurrency_limits.get(category, self.global_active_limit),
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> ResourceLimits:
        """Construct and validate ResourceLimits from application Settings."""
        return cls(
            per_org_active_limit=settings.execution_per_org_active_limit,
            global_active_limit=settings.execution_global_active_limit,
            per_org_queued_limit=settings.execution_per_org_queued_limit,
            global_queued_limit=settings.execution_global_queued_limit,
            default_job_deadline_seconds=float(settings.job_deadline_seconds),
            max_queue_wait_seconds=float(settings.execution_max_queue_wait_seconds),
            default_operation_timeout_seconds=float(
                settings.execution_operation_timeout_seconds
            ),
            shutdown_grace_seconds=float(settings.execution_shutdown_grace_seconds),
            max_files=settings.max_files,
            max_total_bytes=settings.max_total_bytes,
            max_file_bytes=settings.max_file_bytes,
            max_depth=settings.max_depth,
            archive_max_entries=settings.archive_max_entries,
            archive_max_nesting=settings.archive_max_nesting,
            archive_max_decompressed_bytes=settings.archive_max_decompressed_bytes,
            parser_max_output_bytes=settings.parser_max_output_bytes,
            max_findings_per_job=settings.max_findings_per_job,
            subprocess_timeout_seconds=float(settings.subprocess_timeout_seconds),
            subprocess_max_output_bytes=settings.subprocess_max_output_bytes,
            network_connect_timeout_seconds=float(settings.network_connect_timeout_seconds),
            network_read_timeout_seconds=float(settings.network_read_timeout_seconds),
            network_max_response_bytes=settings.network_max_response_bytes,
            safe_retry_max_attempts=settings.safe_retry_max_attempts,
            safe_retry_delay_seconds=float(settings.safe_retry_delay_seconds),
        )
