from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chinescan.core.storage.security import (
    StorageSecurityError,
    is_reparse_or_link,
    parse_icacls_entries,
    secure_snapshot_directory,
    verify_snapshot_storage_security,
    verify_windows_directory_acl,
)


def test_is_reparse_or_link(tmp_path: Path) -> None:
    normal_dir = tmp_path / "normal"
    normal_dir.mkdir()
    assert not is_reparse_or_link(normal_dir)

    normal_file = normal_dir / "file.txt"
    normal_file.write_text("content", encoding="utf-8")
    assert not is_reparse_or_link(normal_file)

    try:
        link = tmp_path / "link"
        link.symlink_to(normal_dir, target_is_directory=True)
        assert is_reparse_or_link(link)
    except (OSError, NotImplementedError):
        # Symlink creation may require privilege on Windows developer mode
        pass


def test_validate_path_safety_rejects_root(tmp_path: Path) -> None:
    root = Path("C:\\") if os.name == "nt" else Path("/")
    with pytest.raises(StorageSecurityError, match="filesystem root"):
        secure_snapshot_directory(root)


def test_managed_snapshot_path_rejects_symlink_component(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable in this environment")

    with pytest.raises(StorageSecurityError, match="reparse point or symbolic link"):
        secure_snapshot_directory(linked_parent / "managed-snapshots")


def test_posix_security_enforcement(tmp_path: Path) -> None:
    target = tmp_path / "posix-snapshots"
    with patch("os.name", "posix"):
        with patch("os.chmod") as mock_chmod:
            with patch.object(Path, "stat") as mock_stat:
                mock_stat_res = MagicMock()
                mock_stat_res.st_mode = stat.S_IFDIR | 0o700
                mock_stat.return_value = mock_stat_res
                secured = secure_snapshot_directory(target)
                assert secured == target.resolve()
                mock_chmod.assert_called_once_with(target.resolve(), 0o700)


def test_posix_security_fails_on_permissive_mode(tmp_path: Path) -> None:
    target = tmp_path / "permissive-snapshots"
    target.mkdir()
    with patch("os.name", "posix"):
        with patch.object(Path, "stat") as mock_stat:
            mock_stat_res = MagicMock()
            mock_stat_res.st_mode = stat.S_IFDIR | 0o777
            mock_stat.return_value = mock_stat_res
            with pytest.raises(StorageSecurityError, match="too permissive"):
                verify_snapshot_storage_security(target)


def test_parse_icacls_entries(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    stdout = f"""{target} BUILTIN\\Administrators:(OI)(CI)(F)
                     NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                     DOMAIN\\Operator:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
"""
    entries = parse_icacls_entries(stdout, target)
    assert len(entries) == 3
    assert entries[0] == ("builtin\\administrators", "OI)(CI)(F")
    assert entries[1] == ("nt authority\\system", "OI)(CI)(F")
    assert entries[2] == ("domain\\operator", "OI)(CI)(F")


def test_verify_windows_directory_acl_detects_inherited_ace(tmp_path: Path) -> None:
    target = tmp_path / "inherited"
    stdout = f"""{target} BUILTIN\\Administrators:(I)(OI)(CI)(F)
                     NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)
                     DOMAIN\\Operator:(OI)(CI)(F)
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
        valid, reason = verify_windows_directory_acl(target, "DOMAIN\\Operator", "S-1-5-21-999")
        assert not valid
        assert reason is not None
        assert "Inherited ACE" in reason


def test_verify_windows_directory_acl_detects_unauthorized_principal(tmp_path: Path) -> None:
    target = tmp_path / "unauth"
    stdout = f"""{target} Everyone:(RX)
                     BUILTIN\\Administrators:(OI)(CI)(F)
                     NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
                     DOMAIN\\Operator:(OI)(CI)(F)
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
        valid, reason = verify_windows_directory_acl(target, "DOMAIN\\Operator", "S-1-5-21-999")
        assert not valid
        assert reason is not None
        assert "Unauthorized principal" in reason


def test_verify_windows_directory_acl_detects_missing_system(tmp_path: Path) -> None:
    target = tmp_path / "missing_system"
    stdout = f"""{target} BUILTIN\\Administrators:(OI)(CI)(F)
                     DOMAIN\\Operator:(OI)(CI)(F)
"""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=stdout, stderr="")
        valid, reason = verify_windows_directory_acl(target, "DOMAIN\\Operator", "S-1-5-21-999")
        assert not valid
        assert reason is not None
        assert "SYSTEM" in reason


@pytest.mark.skipif(os.name != "nt", reason="Windows live NTFS ACL test")
def test_windows_live_snapshot_securing(tmp_path: Path) -> None:
    target = tmp_path / "live-snapshots"
    secured = secure_snapshot_directory(target)
    assert secured.is_dir()

    # Effective ACLs must verify cleanly
    verified = verify_snapshot_storage_security(secured)
    assert verified == secured

    # Subdirectory and file must inherit protections
    sub = secured / "org-uuid"
    sub.mkdir()
    child_file = sub / "digest.txt"
    child_file.write_text("data", encoding="utf-8")
    assert child_file.is_file()

    # Re-securing already secure directory should succeed idempotently
    re_secured = secure_snapshot_directory(secured)
    assert re_secured == secured

    # Polluting ACL with Everyone must fail closed
    subprocess.run(["icacls.exe", str(secured), "/grant", "*S-1-1-0:(RX)"], check=True)
    with pytest.raises(StorageSecurityError, match="Unauthorized principal"):
        verify_snapshot_storage_security(secured)
