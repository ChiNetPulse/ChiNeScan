"""Bounded CSV and JSON explorer export importer."""

import csv
import json
import re
from decimal import Decimal, InvalidOperation
from io import StringIO

from chinescan.chain_trace.models import Transfer
from chinescan.chain_trace.providers.base import Page
from chinescan.chain_trace.registry import CHAINS, normalize_address

MAX_IMPORT_BYTES = 2_000_000
MAX_ROWS = 50_000


def _value(row: dict[str, object], *keys: str, default: object = "") -> object:
    return next((row[key] for key in keys if row.get(key) is not None), default)


class OfflineProvider:
    offline = True

    def __init__(
        self,
        text: str,
        chain: str,
        format: str = "csv",
        *,
        require_chain_field: bool = False,
    ) -> None:
        if len(text.encode()) > MAX_IMPORT_BYTES:
            raise ValueError("import exceeds 2 MB")
        self.gaps: list[str] = []
        try:
            rows = csv.DictReader(StringIO(text)) if format == "csv" else json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("import JSON is malformed or too deeply nested") from exc
        if format != "csv" and isinstance(rows, dict):
            rows = rows.get("transfers", rows.get("data", []))
        self.items: list[Transfer] = []
        for index, row in enumerate(rows):
            if index >= MAX_ROWS:
                self.gaps.append("import_row_cap")
                break
            if require_chain_field and (
                not isinstance(row, dict)
                or str(row.get("chain", "")).casefold() != chain.casefold()
            ):
                raise ValueError("import row chain does not match the selected network")
            normalized_receiver = (
                _value(row, "receiver", "to", "to_address") if isinstance(row, dict) else ""
            )
            normalized_sender = (
                (_value(row, "sender", "from", "from_address") or None)
                if isinstance(row, dict)
                else None
            )
            if require_chain_field:
                chain_config = CHAINS.get(chain)
                if chain_config is None or not isinstance(row, dict):
                    raise ValueError("import row chain is unsupported")
                tx_hash = str(_value(row, "tx_hash", "hash", "transactionHash"))
                if chain_config.family == "evm":
                    valid_hash = re.fullmatch(r"0x[a-fA-F0-9]{64}", tx_hash) is not None
                elif chain_config.family in {"utxo", "tron"}:
                    valid_hash = re.fullmatch(r"[a-fA-F0-9]{64}", tx_hash) is not None
                elif chain_config.family == "solana":
                    valid_hash = re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{64,88}", tx_hash) is not None
                else:
                    valid_hash = False
                receiver = normalized_receiver
                sender = normalized_sender
                try:
                    if not valid_hash or not isinstance(receiver, str):
                        raise ValueError("invalid chain transaction identifier")
                    normalized_receiver = normalize_address(chain_config, receiver)
                    if sender is not None:
                        if not isinstance(sender, str):
                            raise ValueError("invalid sender")
                        normalized_sender = normalize_address(chain_config, sender)
                except ValueError as exc:
                    raise ValueError("import row contains an invalid chain identifier") from exc
            try:
                amount = Decimal(str(_value(row, "amount", "value")))
                self.items.append(
                    Transfer(
                        chain=chain,
                        tx_hash=str(_value(row, "tx_hash", "hash", "transactionHash")),
                        block_time=int(
                            str(_value(row, "block_time", "timeStamp", "timestamp", default=0))
                        ),
                        sender=normalized_sender,
                        receiver=str(normalized_receiver),
                        asset=str(_value(row, "asset", "tokenSymbol", default="UNKNOWN")),
                        amount=amount,
                        kind=str(_value(row, "kind", default="transfer")).lower(),
                    )
                )
            except (ValueError, TypeError, InvalidOperation, KeyError):
                self.gaps.append("import_row_invalid")

    def transfers(self, address: str, *, limit: int, cursor: str | None = None) -> Page:
        offset = int(cursor or 0)
        selected = [
            item for item in self.items if item.sender == address or item.receiver == address
        ]
        page = selected[offset : offset + limit]
        return Page(
            tuple(page),
            offset + limit < len(selected),
            str(offset + limit) if offset + limit < len(selected) else None,
        )
