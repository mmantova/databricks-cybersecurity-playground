"""
Activities each source type can produce.

Coverage gaps treat a TTP as blind when it needs an activity outside this set.
The notebook assesses Zeek with source_type="netflow".
"""

from typing import Dict, Final, FrozenSet

from lumina_cortex.vocabulary.ocsf_to_activity import VOCABULARY


SOURCE_TYPES: Final[frozenset[str]] = frozenset({
    "sysmon",
    "netflow",
    "cloudtrail",
    "ocsf_jsonl",
    "zeek",
    "windows",
    "ssh",
})

# Sysmon EventID map (lumina-vocab-2): no EventID produces Network: Connection Close,
# File: Create, or Registry: Delete.
_SYSMON_ACTIVITIES: Final[FrozenSet[str]] = frozenset({
    "Authentication: Logoff",
    "Authentication: Logon",
    "Authentication: Logon Failure",
    "DNS: Query",
    "File: Access",
    "File: Delete",
    "File: Read",
    "File: Write",
    "Module: Load",
    "Network: Connection Open",
    "Process: Launch",
    "Process: Open",
    "Process: Terminate",
    "Registry: Create",
    "Registry: Modify",
})

SOURCE_CAPABILITIES: Final[Dict[str, FrozenSet[str]]] = {
    "sysmon": _SYSMON_ACTIVITIES,
    "netflow": frozenset({
        "Network: Connection Open",
        "Network: Connection Close",
        "DNS: Query",
        "DNS: Response",
    }),
    "cloudtrail": frozenset({
        "API: Call",
        "Cloud: Activity",
        "Authentication: Logon",
        "Authentication: Logon Failure",
    }),
    "ocsf_jsonl": VOCABULARY,
    "zeek": frozenset({
        "Network: Connection Open",
        "Network: Connection Close",
        "DNS: Query",
        "DNS: Response",
    }),
    "windows": frozenset({
        "Process: Launch",
        "Process: Terminate",
        "Process: Open",
        "Module: Load",
        "File: Access",
        "Network: Connection Open",
        "File: Read",
        "File: Write",
        "File: Delete",
        "Registry: Modify",
        "Registry: Create",
        "Registry: Delete",
        "Authentication: Logon",
        "Authentication: Logon Failure",
        "Authentication: Logoff",
    }),
    "ssh": frozenset({
        "Authentication: Logon",
        "Authentication: Logon Failure",
        "Authentication: Logoff",
    }),
}


def get_capabilities(source_type: str) -> FrozenSet[str]:
    """Activities this source type can produce."""
    if source_type not in SOURCE_CAPABILITIES:
        raise KeyError(f"Unknown source type: {source_type}")
    return SOURCE_CAPABILITIES[source_type]
