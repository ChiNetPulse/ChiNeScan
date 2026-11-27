"""Report locally observable Phase 6 deployment prerequisites.

This is a read-only preflight. It never changes namespaces, firewall rules,
ACLs, cgroups, or Windows security policy and therefore cannot replace a
deployment acceptance exercise.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import sys
from pathlib import Path


def main() -> int:
    for name, value in collect_preflight().items():
        print(f"{name}={value}")
    print("result=deployment_verification_required")
    return 0


def collect_preflight() -> dict[str, bool | str]:
    linux = sys.platform.startswith("linux")
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "process_tree_api": os.name in {"nt", "posix"},
        "linux_user_namespace_configured": _linux_value(
            "/proc/sys/kernel/unprivileged_userns_clone"
        )
        if linux
        else "not_applicable",
        "linux_cgroup_v2_mount": Path("/sys/fs/cgroup/cgroup.controllers").exists()
        if linux
        else "not_applicable",
        "linux_unshare_binary": shutil.which("unshare") is not None if linux else "not_applicable",
        "windows_job_object_api": callable(getattr(ctypes, "WinDLL", None))
        if os.name == "nt"
        else "not_applicable",
        "network_policy_verified": False,
        "hardened_execution_ready": False,
    }


def _linux_value(path: str) -> str:
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return "unavailable"


if __name__ == "__main__":
    raise SystemExit(main())
