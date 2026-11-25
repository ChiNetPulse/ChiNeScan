"""Cross-platform unit tests for storage security ACL parsing and validation helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from chinescan.core.storage import security


def test_parse_icacls_entries_and_is_reparse_or_link(tmp_path: Path) -> None:
    target = tmp_path / "managed-dir"
    assert security.is_reparse_or_link(target) is True
    target.mkdir()
    assert security.is_reparse_or_link(target) is False

    stdout = (
        f"{target} BUILTIN\\Administrators:(OI)(CI)(F)\n"
        f"          NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"
        f"          DOMAIN\\Operator:(OI)(CI)(F)\n"
        "Successfully processed 1 files; Failed processing 0 files\n"
    )
    entries = security.parse_icacls_entries(stdout, target)
    assert ("builtin\\administrators", "OI)(CI)(F") in entries
    assert ("nt authority\\system", "OI)(CI)(F") in entries
    assert ("domain\\operator", "OI)(CI)(F") in entries


def test_get_windows_operator_identity_and_verify_acl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    security.get_windows_operator_identity.cache_clear()
    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(
            returncode=0, stdout='"DOMAIN\\op","S-1-5-21-100"\n', stderr=""
        ),
    )
    assert security.get_windows_operator_identity() == ("DOMAIN\\op", "S-1-5-21-100")

    security.get_windows_operator_identity.cache_clear()
    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(returncode=1, stdout="", stderr="denied"),
    )
    with pytest.raises(security.StorageSecurityError, match="exit code 1"):
        security.get_windows_operator_identity()

    def raise_oserror(*_a: object, **_kw: object) -> object:
        raise OSError("missing")

    monkeypatch.setattr(security.subprocess, "run", raise_oserror)
    ok, reason = security.verify_windows_directory_acl(tmp_path, "DOMAIN\\op", "S-1-5-21-100")
    assert ok is False and reason is not None

    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(
            returncode=0,
            stdout=(
                f"{tmp_path} DOMAIN\\op:(OI)(CI)(F)\n"
                "          NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"
                "          BUILTIN\\Administrators:(OI)(CI)(F)\n"
            ),
            stderr="",
        ),
    )
    ok2, reason2 = security.verify_windows_directory_acl(tmp_path, "DOMAIN\\op", "S-1-5-21-100")
    assert ok2 is True and reason2 is None

    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(
            returncode=0,
            stdout=f"{tmp_path} DOMAIN\\op:(I)(OI)(CI)(F)\n",
            stderr="",
        ),
    )
    ok_inh, reason_inh = security.verify_windows_directory_acl(
        tmp_path, "DOMAIN\\op", "S-1-5-21-100"
    )
    assert ok_inh is False and reason_inh is not None and "Inherited" in reason_inh

    monkeypatch.setattr(
        security.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(
            returncode=0,
            stdout=f"{tmp_path} Everyone:(OI)(CI)(RX)\n",
            stderr="",
        ),
    )
    ok3, reason3 = security.verify_windows_directory_acl(tmp_path, "DOMAIN\\op", "S-1-5-21-100")
    assert ok3 is False and reason3 is not None
