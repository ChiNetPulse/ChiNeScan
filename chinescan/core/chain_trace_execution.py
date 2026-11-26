"""Governed chain-trace adapters for immutable imports and fixed EVM providers."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from chinescan.chain_trace.labels import load_labels
from chinescan.chain_trace.models import TraceParams
from chinescan.chain_trace.providers.base import ChainProvider, Page
from chinescan.chain_trace.providers.evm import EvmProvider, stdlib_http_get
from chinescan.chain_trace.providers.offline import OfflineProvider
from chinescan.chain_trace.registry import CHAINS, normalize_address
from chinescan.chain_trace.service import ChainTraceService
from chinescan.core.execution_adapters import (
    AdapterCapabilities,
    AdapterControl,
    AdapterFailure,
    AdapterResult,
    ExecutionContext,
)
from chinescan.core.log_evidence import LogEvidenceStore
from chinescan.core.storage.sqlite import SQLiteRepository
from chinescan.domain_assessment.probe import ExecutionCancelled

CHAIN_IMPORT_TECHNIQUE = "chain_trace_import"
CHAIN_PROVIDER_TECHNIQUE = "chain_provider_lookup"
CHAIN_TRACE_VERSION = "builtin-chain-trace-v1"


class _ControlledProvider:
    """Check cancellation at each address boundary before delegating."""

    def __init__(self, provider: ChainProvider, control: AdapterControl) -> None:
        self.provider = provider
        self.control = control
        self.processed_addresses = 0
        self.offline = bool(getattr(provider, "offline", False))
        self.gaps = list(getattr(provider, "gaps", []))

    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page:
        self.control.check_cancelled()
        self.processed_addresses += 1
        percent = min(90, 10 + self.processed_addresses * 5)
        self.control.report_progress(percent, "chain_trace_progress")
        return self.provider.transfers(address, limit=limit, cursor=cursor)


class GovernedChainImportAdapter:
    """Run local trace analysis from a verified, registered CSV/JSON evidence snapshot."""

    def __init__(
        self,
        repository: SQLiteRepository,
        evidence: LogEvidenceStore,
        label_paths: tuple[str, ...] = (),
    ) -> None:
        self.repository, self.evidence = repository, evidence
        self.label_paths = label_paths
        self._capabilities = AdapterCapabilities(
            adapter_id="builtin.governed-chain-import",
            techniques=(CHAIN_IMPORT_TECHNIQUE,),
            target_types=("log_evidence",),
            action_class="passive",
            enabled=True,
            performs_external_operations=False,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if set(parameters) != {"chain", "seed", "depth"}:
            raise ValueError("A chain import requires a chain, seed, and depth.")
        chain_name = parameters["chain"]
        if not isinstance(chain_name, str) or chain_name not in CHAINS:
            raise ValueError("Unsupported chain.")
        chain = CHAINS[chain_name]
        seed = normalize_address(chain, parameters["seed"])
        depth = parameters["depth"]
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 6:
            raise ValueError("Trace depth is outside supported bounds.")
        return {"chain": chain.name, "seed": seed, "depth": depth}

    def execute(
        self,
        context: ExecutionContext,
        parameters: dict[str, Any],
        control: AdapterControl,
    ) -> AdapterResult:
        if (
            context.asset_type != "log_evidence"
            or context.technique != CHAIN_IMPORT_TECHNIQUE
            or context.action_class != "passive"
            or context.adapter_id != self.capabilities.adapter_id
            or context.adapter_version != "1"
            or context.target != f"log:{context.asset_id}"
            or not context.log_evidence_snapshot_id
            or not context.log_evidence_sha256
        ):
            raise AdapterFailure("CHAIN_IMPORT_CONTEXT_INVALID")
        try:
            chain_parameters = self.validate_parameters(parameters)
        except (TypeError, ValueError) as exc:
            raise AdapterFailure("CHAIN_IMPORT_PARAMETERS_INVALID") from exc
        snapshot, root = self.evidence.verify(
            context.organization_id,
            context.engagement_id,
            context.asset_id,
            context.log_evidence_snapshot_id,
        )
        if (
            snapshot is None
            or root is None
            or snapshot["sha256"] != context.log_evidence_sha256
            or snapshot["manifest_version"] != context.log_evidence_manifest_version
            or snapshot["source_format"] not in {"csv", "json"}
            or len(snapshot["manifest"].get("entries", [])) != 1
        ):
            raise AdapterFailure("CHAIN_IMPORT_EVIDENCE_UNAVAILABLE")
        entry = snapshot["manifest"]["entries"][0]
        if not isinstance(entry.get("size_bytes"), int) or entry["size_bytes"] > 2_000_000:
            raise AdapterFailure("CHAIN_IMPORT_SIZE_LIMIT")
        source = root / str(entry["path"])
        try:
            if source.is_symlink() or not source.resolve(strict=True).is_relative_to(
                root.resolve(strict=True)
            ):
                raise AdapterFailure("CHAIN_IMPORT_EVIDENCE_INVALID")
            text = source.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError, RuntimeError) as exc:
            raise AdapterFailure("CHAIN_IMPORT_EVIDENCE_INVALID") from exc
        try:
            provider = OfflineProvider(
                text,
                chain_parameters["chain"],
                snapshot["source_format"],
                require_chain_field=True,
            )
        except (ValueError, TypeError) as exc:
            raise AdapterFailure("CHAIN_IMPORT_FORMAT_INVALID") from exc
        control.report_progress(10, "chain_import_verified")
        params = TraceParams(
            chain=chain_parameters["chain"],
            seed=chain_parameters["seed"],
            depth=chain_parameters["depth"],
            node_limit=500,
        )
        labels, label_gaps = load_labels([Path(value) for value in self.label_paths])
        scan, findings = ChainTraceService(
            _ControlledProvider(provider, control), labels, self.repository, label_gaps
        ).trace(
            params,
            authorization=True,
            operator=context.requester_user_id,
            authorization_method="engagement_policy",
            control=control,
            target_namespace=context.job_id,
        )
        control.check_cancelled()
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="partial" if scan.status == "partial" else "complete",
            result_id=scan.scan_id,
            summary={
                "chain": params.chain,
                "finding_count": len(findings),
                "evidence_sha256": context.log_evidence_sha256,
                "analysis_version": CHAIN_TRACE_VERSION,
                "source_kind": "registered_import",
            },
        )


class GovernedChainProviderAdapter:
    """Run a bounded Etherscan V2 lookup against the built-in provider only."""

    def __init__(
        self,
        repository: SQLiteRepository,
        *,
        api_key: str | None = None,
        http_get: Callable[..., Any] = stdlib_http_get,
        max_requests: int = 25,
        deadline_seconds: float = 60,
        label_paths: tuple[str, ...] = (),
    ) -> None:
        self.repository = repository
        self.api_key = api_key if api_key is not None else os.getenv("CHINESCAN_ETHERSCAN_KEY", "")
        self.http_get = http_get
        self.label_paths = label_paths
        self.max_requests = min(100, max(1, max_requests))
        self.deadline_seconds = min(120, max(1, deadline_seconds))
        self._capabilities = AdapterCapabilities(
            adapter_id="builtin.governed-chain-provider",
            techniques=(CHAIN_PROVIDER_TECHNIQUE,),
            target_types=("chain_address",),
            action_class="sensitive",
            enabled=True,
            performs_external_operations=True,
        )

    @property
    def capabilities(self) -> AdapterCapabilities:
        return self._capabilities

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if parameters:
            raise ValueError("Provider lookup does not accept caller parameters.")
        if not self.api_key:
            raise ValueError("The configured provider credential is unavailable.")
        return {}

    def execute(
        self,
        context: ExecutionContext,
        parameters: dict[str, Any],
        control: AdapterControl,
    ) -> AdapterResult:
        self.validate_parameters(parameters)
        parts = context.target.split(":")
        if (
            context.asset_type != "chain_address"
            or context.technique != CHAIN_PROVIDER_TECHNIQUE
            or context.action_class != "sensitive"
            or context.adapter_id != self.capabilities.adapter_id
            or context.adapter_version != "1"
            or len(parts) != 4
            or parts[0] != "chain"
            or parts[2] != "etherscan-v2"
            or context.chain_context
            != {"chain": parts[1], "address": parts[3], "provider": "etherscan-v2"}
        ):
            raise AdapterFailure("CHAIN_PROVIDER_CONTEXT_INVALID")
        chain = CHAINS.get(parts[1])
        if not chain or chain.family != "evm" or not chain.chain_id:
            raise AdapterFailure("CHAIN_PROVIDER_UNSUPPORTED")
        try:
            address = normalize_address(chain, parts[3])
        except ValueError as exc:
            raise AdapterFailure("CHAIN_PROVIDER_TARGET_INVALID") from exc
        if (
            not self.api_key
            or chain.explorer_api != "https://api.etherscan.io/v2/api"
            or chain.host_allowlist != ("api.etherscan.io",)
        ):
            raise AdapterFailure("CHAIN_PROVIDER_NOT_CONFIGURED")
        control.report_progress(5, "provider_lookup_authorization")
        provider = EvmProvider(
            chain.explorer_api,
            self.api_key,
            self.http_get,
            chain.name,
            allowed_hosts=chain.host_allowlist,
            allow_nonstandard_port=False,
            chain_id=chain.chain_id,
            deadline_seconds=self.deadline_seconds,
            max_requests=self.max_requests,
            retries=0,
            throttle_seconds=0.2,
            before_request=lambda: control.authorize_external_action(
                context.target, context.technique
            ),
        )
        labels, label_gaps = load_labels([Path(value) for value in self.label_paths])
        # The registered asset and approval authorize one root address only. Do
        # not follow transfer recipients as new external lookup targets.
        params = TraceParams(chain=chain.name, seed=address, depth=1, node_limit=100)
        try:
            scan, findings = ChainTraceService(
                _ControlledProvider(provider, control), labels, self.repository, label_gaps
            ).trace(
                params,
                authorization=True,
                operator=context.requester_user_id,
                authorization_method="engagement_policy_provider_approval",
                control=control,
                target_namespace=context.job_id,
            )
        except ExecutionCancelled:
            raise
        except Exception as exc:
            raise AdapterFailure("CHAIN_PROVIDER_LOOKUP_FAILED") from exc
        control.report_progress(95, "provider_result_persisted")
        return AdapterResult(
            adapter_id=self.capabilities.adapter_id,
            status="partial" if scan.status == "partial" else "complete",
            result_id=scan.scan_id,
            summary={
                "chain": chain.name,
                "provider": "etherscan-v2",
                "finding_count": len(findings),
                "analysis_version": CHAIN_TRACE_VERSION,
                "provider_reported": True,
            },
        )
