"""Privileged setup boundary used immediately before a Linux worker exec."""

from __future__ import annotations

import os
import sys

from chinescan.core.linux_isolation import (
    LinuxIsolationUnavailable,
    apply_filesystem_boundary,
    apply_seccomp,
    drop_capabilities,
)


def main() -> int:
    marker = os.environ.get("CHINESCAN_CGROUP_PATH")
    try:
        if marker:
            with open(os.path.join(marker, "cgroup.procs"), "w", encoding="ascii") as stream:
                stream.write(str(os.getpid()))
        if os.environ.get("CHINESCAN_DROP_CAPABILITIES") == "1":
            drop_capabilities()
        if os.environ.get("CHINESCAN_SECCOMP") == "1":
            apply_seccomp()
        if os.environ.get("CHINESCAN_LANDLOCK") == "1":
            read_roots = tuple(
                filter(None, os.environ.get("CHINESCAN_FS_READ_ROOTS", "").split(os.pathsep))
            )
            write_roots = tuple(
                filter(None, os.environ.get("CHINESCAN_FS_WRITE_ROOTS", "").split(os.pathsep))
            )
            apply_filesystem_boundary(read_roots, write_roots)
    except (OSError, LinuxIsolationUnavailable) as exc:
        print(f"CHINESCAN_ISOLATION_FAILURE:{type(exc).__name__}", file=sys.stderr)
        return 125
    separator = sys.argv.index("--") if "--" in sys.argv else -1
    if separator < 0 or separator + 1 >= len(sys.argv):
        return 125
    os.execvpe(sys.argv[separator + 1], sys.argv[separator + 1 :], os.environ)
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
