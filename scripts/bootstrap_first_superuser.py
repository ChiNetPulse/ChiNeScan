#!/usr/bin/env python3
"""Issue the one-time first ChineScan administrator setup token."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chinescan.core.first_superuser import (
    FIRST_SUPERUSER_EMAIL,
    FirstSuperuserBootstrapError,
    bootstrap_first_superuser,
)
from chinescan.core.storage.postgres import PostgresRepository


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        default=os.environ.get("CHINESCAN_DATABASE_URL"),
        help="Protected PostgreSQL URL; defaults to CHINESCAN_DATABASE_URL.",
    )
    parser.add_argument("--storage-root", type=Path, default=Path(".chinescan-data"))
    args = parser.parse_args()
    if not args.database_url:
        parser.error("CHINESCAN_DATABASE_URL is required")

    repository = None
    try:
        repository = PostgresRepository(args.database_url, storage_root=args.storage_root)
        result = bootstrap_first_superuser(repository.engine, email=FIRST_SUPERUSER_EMAIL)
    except FirstSuperuserBootstrapError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if repository is not None:
            repository.close()

    print(f"First administrator: {result.email}")
    print("Setup token (displayed once; deliver out-of-band):")
    print(result.setup_token)
    print(f"Expires at Unix time: {result.expires_at:.0f}")
    print("Complete setup through POST /api/auth/first-superuser/setup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
