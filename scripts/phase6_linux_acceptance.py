"""Probe the actual Linux subprocess launcher without changing host policy.

This is an acceptance probe, not an isolation provider. It records controls
visible inside a child launched by ``run_supervised_subprocess``. Namespace,
cgroup, seccomp, capability, filesystem, and network controls must be supplied
by the Linux deployment when the profile requires them.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from chinescan.core.execution_isolation import IsolationProfile, IsolationUnavailableError
from chinescan.core.subprocess_supervision import run_supervised_subprocess

_CHILD_PROBE = r"""
import json, os
from pathlib import Path

status = Path('/proc/self/status').read_text(encoding='ascii', errors='replace')
def value(name):
    prefix = name + ':'
    for line in status.splitlines():
        if line.startswith(prefix):
            return line.split(':', 1)[1].strip()
    return None

print(json.dumps({
    'status': {name: value(name) for name in (
        'NoNewPrivs', 'Seccomp', 'Seccomp_filters', 'CapInh', 'CapPrm',
        'CapEff', 'CapBnd', 'CapAmb', 'NSpid',
    )},
    'namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in (
        'user', 'mnt', 'pid', 'net',
    )},
    'cgroup': Path('/proc/self/cgroup').read_text(encoding='ascii').strip(),
}))
try:
    Path('/etc/chinescan-phase6-probe').write_text('probe', encoding='ascii')
except OSError as exc:
    print(json.dumps({'filesystem_write': type(exc).__name__}))
else:
    print(json.dumps({'filesystem_write': 'allowed'}))
"""


def _namespace_ids() -> dict[str, str]:
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in ("user", "mnt", "pid", "net")}


def main() -> int:
    if not sys.platform.startswith("linux"):
        print(json.dumps({"result": "blocked", "reason": "linux_host_required"}))
        return 2
    profile = IsolationProfile(network_isolation_required=False)
    report: dict[str, Any] = {
        "platform": sys.platform,
        "host_namespaces": _namespace_ids(),
        "requested_controls": ["posix_rlimits", "process_tree_cleanup"],
        "application_managed_controls": ["posix_rlimits", "process_tree_cleanup"],
        "deployment_managed_controls": [
            "user_namespace",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "cgroup_v2",
            "seccomp",
            "capability_reduction",
            "network_egress_policy",
        ],
    }
    try:
        result = run_supervised_subprocess(
            [sys.executable, "-c", _CHILD_PROBE],
            isolation_profile=profile,
            require_hardened_isolation=True,
            timeout_seconds=10,
        )
    except IsolationUnavailableError as exc:
        report.update({"result": "blocked", "error_code": exc.code, "reason": str(exc)})
        print(json.dumps(report, sort_keys=True))
        return 2
    report.update({"result": "executed", "child_output": result.stdout.decode("utf-8", "replace")})
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
