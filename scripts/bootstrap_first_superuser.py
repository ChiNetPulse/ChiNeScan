#!/usr/bin/env python3
"""Issue the one-time first ChineScan administrator setup token.

If a previous bootstrap already created the superuser account but the token
expired before activation, this script automatically issues a fresh token for
the existing unactivated account without touching the user ID, organization,
or membership.
"""

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
    reissue_first_superuser_token,
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
        try:
            result = bootstrap_first_superuser(repository.engine, email=FIRST_SUPERUSER_EMAIL)
        except FirstSuperuserBootstrapError:
            # Fresh bootstrap failed — the account may already exist from a prior
            # run whose token expired unused.  Attempt a secure reissue; this
            # call will itself fail with a clear message if the account has
            # already been activated or is otherwise ineligible.
            result = reissue_first_superuser_token(repository.engine, email=FIRST_SUPERUSER_EMAIL)
            print(
                "(Existing unactivated account detected; "
                "a fresh token has been issued for the same user ID.)",
                file=sys.stderr,
            )
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
