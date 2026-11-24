"""Storage security helper for managed repository snapshot storage.

Applies explicit restrictive NTFS ACLs on Windows and mode 0700 permissions
on POSIX systems. Ensures that only the authorized operator, SYSTEM, and
Administrators have access to managed snapshot directories.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


class StorageSecurityError(Exception):
    """Raised when managed storage security validation or provisioning fails."""


def is_reparse_or_link(path: Path) -> bool:
    """Check if a path is a symbolic link, directory junction, or reparse point."""
    try:
        info = path.lstat()
        return path.is_symlink() or bool(
            os.name == "nt"
            and getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
    except OSError:
        return True


def get_windows_operator_identity() -> tuple[str, str]:
    """Retrieve current Windows user name and SID via whoami.exe."""
    try:
        who = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise StorageSecurityError(f"Unable to execute whoami.exe: {exc}") from exc
    if who.returncode != 0:
        detail = (who.stderr or "").strip()
        raise StorageSecurityError(
            f"whoami.exe failed with exit code {who.returncode}: {detail}"
        )
    line = who.stdout.strip()
    if not line:
        raise StorageSecurityError("whoami.exe returned empty output.")
    parts = line.strip('"').split('","')
    if len(parts) < 2:
        raise StorageSecurityError("whoami.exe returned unexpected output format.")
    return parts[0].strip(), parts[1].strip()


def parse_icacls_entries(stdout: str, canonical_path: Path) -> list[tuple[str, str]]:
    """Parse icacls stdout into (principal, permissions) tuples."""
    entries: list[tuple[str, str]] = []
    canonical_str = str(canonical_path).casefold()
    name_str = canonical_path.name.casefold()

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or ":(" not in line:
            continue
        if line.startswith("Successfully") or line.startswith("Failed"):
            continue

        raw_trimmed = raw_line.lstrip()
        if raw_trimmed.casefold().startswith(canonical_str):
            raw_trimmed = raw_trimmed[len(canonical_str):].lstrip()
        elif name_str in raw_trimmed.casefold():
            parts = raw_trimmed.split(None, 1)
            if len(parts) > 1 and ":(" in parts[1]:
                raw_trimmed = parts[1]

        if ":(" not in raw_trimmed:
            continue
        principal, rights = raw_trimmed.split(":(", 1)
        entries.append((principal.strip().casefold(), rights.rstrip(")")))
    return entries


def verify_windows_directory_acl(
    directory: Path, operator_name: str, operator_sid: str
) -> tuple[bool, str | None]:
    """Verify that a directory has restrictive, non-inherited NTFS ACLs."""
    try:
        res = subprocess.run(
            ["icacls.exe", str(directory)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Failed to execute icacls.exe: {exc}"

    if res.returncode != 0:
        detail = (res.stderr or "").strip()
        return False, f"icacls.exe returned error code {res.returncode}: {detail}"

    entries = parse_icacls_entries(res.stdout, directory)
    if not entries:
        return False, "No access control entries returned by icacls.exe."

    operator_user = operator_name.split("\\")[-1].casefold()
    allowed_principals = {
        operator_name.casefold(),
        operator_user,
        operator_sid.casefold(),
        "nt authority\\system",
        "system",
        "s-1-5-18",
        "builtin\\administrators",
        "administrators",
        "s-1-5-32-544",
        "owner rights",
        "creator owner",
        "s-1-3-4",
        "s-1-3-0",
    }

    has_operator = False
    has_system = False
    has_admin = False

    for princ, rights in entries:
        # Check for inheritance flags
        if "(i)" in f"({rights})".casefold():
            return False, f"Inherited ACE detected for principal '{princ}'."

        matched = any(
            princ == ap or princ.endswith("\\" + ap) for ap in allowed_principals
        )
        if not matched:
            return False, f"Unauthorized principal in ACL: '{princ}'."

        if (
            princ in {operator_name.casefold(), operator_sid.casefold()}
            or princ.endswith("\\" + operator_user)
        ):
            has_operator = True
        if princ in {"nt authority\\system", "system", "s-1-5-18"}:
            has_system = True
        if (
            princ in {"builtin\\administrators", "administrators", "s-1-5-32-544"}
            or princ.endswith("\\administrators")
        ):
            has_admin = True

    if not has_operator:
        return False, "Current operator is not granted access in directory ACL."
    if not has_system:
        return False, "SYSTEM identity is missing from directory ACL."
    if not has_admin:
        return False, "Administrators group is missing from directory ACL."

    return True, None


def _validate_path_safety(canonical: Path) -> None:
    """Verify that path is safe and not an unintended or system root."""
    if len(canonical.parts) <= 1 or canonical.parent == canonical:
        raise StorageSecurityError("Managed snapshot directory cannot be a filesystem root.")

    for parent in reversed(canonical.parents):
        if parent.exists() and is_reparse_or_link(parent):
            raise StorageSecurityError(
                f"Parent directory {parent} contains an unsafe reparse point or link."
            )

    if os.name == "nt":
        disallowed = [
            os.environ.get("WINDIR", "C:\\Windows").casefold(),
            os.environ.get("ProgramFiles", "C:\\Program Files").casefold(),
            os.environ.get("USERPROFILE", "").casefold(),
        ]
        canon_lower = str(canonical).casefold()
        for root_dir in disallowed:
            if root_dir and canon_lower == root_dir:
                raise StorageSecurityError(
                    f"Managed snapshot directory cannot be a system directory: {canonical}"
                )


def _reject_linked_path_components(path: Path) -> None:
    """Reject links/reparse points in the caller-supplied path before resolution."""
    expanded = path.expanduser()
    if ".." in expanded.parts:
        raise StorageSecurityError("Managed snapshot path cannot contain parent traversal.")
    candidate = type(path)(os.path.abspath(os.fspath(expanded)))
    for current in (*reversed(candidate.parents), candidate):
        if (current.exists() or current.is_symlink()) and is_reparse_or_link(current):
            raise StorageSecurityError(
                "Managed snapshot path contains a reparse point or symbolic link."
            )


def verify_snapshot_storage_security(path: Path) -> Path:
    """Verify that managed snapshot storage directory exists and has safe permissions."""
    _reject_linked_path_components(path)
    canonical = path.expanduser().resolve(strict=False)
    _validate_path_safety(canonical)

    if not canonical.exists():
        raise StorageSecurityError(f"Snapshot directory does not exist: {canonical}")
    if not canonical.is_dir():
        raise StorageSecurityError(f"Snapshot path is not a directory: {canonical}")
    if is_reparse_or_link(canonical):
        raise StorageSecurityError(f"Snapshot directory is a reparse point or symlink: {canonical}")

    if os.name == "nt":
        operator_name, operator_sid = get_windows_operator_identity()
        valid, reason = verify_windows_directory_acl(canonical, operator_name, operator_sid)
        if not valid:
            raise StorageSecurityError(f"Windows ACL verification failed for {canonical}: {reason}")
    else:
        info = canonical.stat(follow_symlinks=False)
        if (info.st_mode & 0o077) != 0:
            raise StorageSecurityError(
                f"Directory permissions {oct(info.st_mode)} are too permissive; expected 0700."
            )
    return canonical


def secure_snapshot_directory(path: Path) -> Path:
    """Create or validate managed repository snapshot root with restrictive permissions.

    On Windows:
    - Verifies path safety and rejects reparse points/symlinks.
    - If needed, removes inheritance and explicitly grants Full Control with container
      and object inheritance to the current operator, SYSTEM, and Administrators.
    - Verifies effective ACLs fail-closed.

    On POSIX:
    - Enforces mode 0700 permissions restricted to the process owner.
    """
    _reject_linked_path_components(path)
    canonical = path.expanduser().resolve(strict=False)
    _validate_path_safety(canonical)

    if not canonical.exists():
        canonical.mkdir(parents=True, exist_ok=True)

    if not canonical.is_dir():
        raise StorageSecurityError(f"Configured path is not a directory: {canonical}")
    if is_reparse_or_link(canonical):
        raise StorageSecurityError(
            f"Configured snapshot path is an unsafe reparse point: {canonical}"
        )

    if os.name == "nt":
        operator_name, operator_sid = get_windows_operator_identity()
        valid, _ = verify_windows_directory_acl(canonical, operator_name, operator_sid)
        if not valid:
            # Apply restrictive permissions: disable inheritance, grant operator, SYSTEM, Admin
            cmd = [
                "icacls.exe",
                str(canonical),
                "/inheritance:r",
                "/grant:r",
                f"*{operator_sid}:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ]
            try:
                apply_res = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10, check=False
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise StorageSecurityError(
                    f"Failed to execute icacls to secure snapshot storage: {exc}"
                ) from exc
            if apply_res.returncode != 0:
                detail = (apply_res.stderr or apply_res.stdout or "").strip()
                raise StorageSecurityError(
                    f"icacls failed to apply permissions (code {apply_res.returncode}): {detail}"
                )

            # Fail closed: verify effective permissions
            verified, reason = verify_windows_directory_acl(
                canonical, operator_name, operator_sid
            )
            if not verified:
                raise StorageSecurityError(
                    f"Snapshot storage ACL verification failed after configuration: {reason}"
                )
    else:
        try:
            os.chmod(canonical, 0o700)
        except OSError as exc:
            raise StorageSecurityError(f"Failed to set directory mode 0700: {exc}") from exc
        info = canonical.stat(follow_symlinks=False)
        if (info.st_mode & 0o077) != 0:
            raise StorageSecurityError(
                f"Directory permissions {oct(info.st_mode)} are too permissive; expected 0700."
            )

    return canonical
