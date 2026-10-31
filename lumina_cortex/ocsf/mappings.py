"""
OCSF adapter mappings and source capabilities.

This module defines the mapping from source types to OCSF classes
and the capabilities of each source type.
"""

from typing import Dict, Final, FrozenSet

from lumina_cortex.config.thresholds import THESIS_THRESHOLDS_V1
from lumina_cortex.ocsf.adapters.sysmon import EVENT_ID_MAPPING as SYSMON_EVENT_ID_MAPPING
from lumina_cortex.ocsf.adapters.sysmon import EventKind
from lumina_cortex.ocsf.schema import ACTIVITY_IDS, CLASS_UIDS
from lumina_cortex.vocabulary.ocsf_to_activity import VOCABULARY, activity_for


# Source types supported by Lumina Cortex
SOURCE_TYPES: Final[frozenset[str]] = frozenset({
    "sysmon",
    "netflow",
    "cloudtrail",
    "ocsf_jsonl",
    "zeek",
    "windows",
    "ssh",
})

def _activities_of(mapping: Dict[int, EventKind]) -> FrozenSet[str]:
    """The canonical activities an adapter's EventID mapping produces."""
    return frozenset(
        activity_for({
            "class_uid": CLASS_UIDS[kind.ocsf_class],
            "activity_id": ACTIVITY_IDS[kind.ocsf_class][kind.activity],
        })
        for kind in mapping.values()
    )


# Activities that each source type can produce: what the coverage gaps read (a TTP needing
# an activity outside its source's set is blind) and the one table of them
# (``lumina_cortex.mitre.coverage`` imports it). A source type with an adapter mapping
# EventIDs takes its set from that mapping, so the two cannot diverge.
SOURCE_CAPABILITIES: Final[Dict[str, FrozenSet[str]]] = {
    # Sysmon and the Windows Security events it carries (lumina-vocab-2, ADR 0005): exactly
    # its EVENT_ID_MAPPING. No EventID maps to Network: Connection Close, File: Create or
    # Registry: Delete (Sysmon 12, create/delete key, is read as Registry: Create).
    "sysmon": _activities_of(SYSMON_EVENT_ID_MAPPING),
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
    # OCSF JSONL can contain any activity of the vocabulary
    "ocsf_jsonl": VOCABULARY,
    "zeek": frozenset({
        "Network: Connection Open",
        "Network: Connection Close",
        "DNS: Query",
        "DNS: Response",
    }),
    # Windows EVTX (no adapter yet): Auth, Process, Module, limited File/Registry,
    # Network (Security 5156)
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

# Adapter module paths for each source type
ADAPTERS: Final[Dict[str, str]] = {
    "sysmon": "lumina_cortex.ocsf.adapters.sysmon",
    "netflow": "lumina_cortex.ocsf.adapters.netflow",
    "cloudtrail": "lumina_cortex.ocsf.adapters.cloudtrail",
    "ocsf_jsonl": "lumina_cortex.ocsf.adapters.ocsf_jsonl",
    "zeek": "lumina_cortex.ocsf.adapters.zeek",
    "windows": "lumina_cortex.ocsf.adapters.windows",
    "ssh": "lumina_cortex.ocsf.adapters.ssh",
}


def get_adapter(source_type: str) -> str:
    """
    Get the adapter module path for a source type.

    Args:
        source_type: The source type identifier.

    Returns:
        The module path for the adapter.

    Raises:
        KeyError: If the source type is not supported.
    """
    if source_type not in ADAPTERS:
        raise KeyError(f"Unknown source type: {source_type}")
    return ADAPTERS[source_type]


def get_capabilities(source_type: str) -> FrozenSet[str]:
    """
    Get the activity capabilities for a source type.

    Args:
        source_type: The source type identifier.

    Returns:
        A frozenset of activity names the source can produce.

    Raises:
        KeyError: If the source type is not supported.
    """
    if source_type not in SOURCE_CAPABILITIES:
        raise KeyError(f"Unknown source type: {source_type}")
    return SOURCE_CAPABILITIES[source_type]
