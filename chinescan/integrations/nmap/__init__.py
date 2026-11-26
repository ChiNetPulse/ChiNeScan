"""Governed Nmap integration primitives.

The package contains only typed profile/target validation, bounded XML parsing,
and a no-shell executor. Admission and authorization remain in the core
execution-governance service.
"""

from chinescan.integrations.nmap.executor import NmapExecutionError, NmapExecutor
from chinescan.integrations.nmap.models import NmapProfileName, NmapScanResult
from chinescan.integrations.nmap.parser import NmapParseError, parse_nmap_xml
from chinescan.integrations.nmap.profiles import NMAP_PROFILES, build_nmap_arguments
from chinescan.integrations.nmap.targets import NmapTargetError, validate_nmap_target

__all__ = [
    "NMAP_PROFILES",
    "NmapExecutor",
    "NmapExecutionError",
    "NmapParseError",
    "NmapProfileName",
    "NmapScanResult",
    "NmapTargetError",
    "build_nmap_arguments",
    "parse_nmap_xml",
    "validate_nmap_target",
]
