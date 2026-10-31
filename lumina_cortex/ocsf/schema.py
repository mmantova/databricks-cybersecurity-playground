"""
OCSF schema constants and definitions.

This module defines the OCSF version and class/category constants used
throughout Lumina Cortex. Based on OCSF 1.3.0 schema.
"""

from typing import Final

# OCSF schema version used by Lumina Cortex
OCSF_VERSION: Final[str] = "1.3.0"

# OCSF Class UIDs (from OCSF 1.3.0 schema)
CLASS_UIDS: Final[dict[str, int]] = {
    "process_activity": 1001,
    "file_activity": 1002,
    "registry_activity": 1003,
    "module_activity": 1005,
    "authentication": 3002,
    "network_activity": 4001,
    "dns_activity": 4003,
    "api_activity": 5001,
    "cloud_activity": 5002,
}

# OCSF Category UIDs
CATEGORY_UIDS: Final[dict[str, int]] = {
    "system_activity": 1,
    "findings": 2,
    "iam": 3,
    "network_activity": 4,
    "discovery": 5,
    "application_activity": 6,
}

# Activity IDs per class
ACTIVITY_IDS: Final[dict[str, dict[str, int]]] = {
    "network_activity": {
        "open": 1,
        "close": 2,
    },
    "dns_activity": {
        "query": 1,
        "response": 2,
    },
    "process_activity": {
        "launch": 1,
        "terminate": 2,
        "open": 3,
    },
    "module_activity": {
        "load": 1,
    },
    "file_activity": {
        "read": 1,
        "write": 2,
        "delete": 3,
        "create": 4,
        "access": 5,
    },
    "registry_activity": {
        "modify": 1,
        "create": 2,
        "delete": 3,
    },
    "authentication": {
        "logon": 1,
        "logon_failure": 2,
        "logoff": 3,
    },
}

# Status IDs
STATUS_IDS: Final[dict[str, int]] = {
    "unknown": 0,
    "success": 1,
    "failure": 2,
    "error": 3,
}

# Required OCSF keys that adapters must emit
REQUIRED_OCSF_KEYS: Final[frozenset[str]] = frozenset({
    "class_uid",
    "category_uid",
    "activity_id",
    "time",
    "metadata",
})

# Optional but recommended OCSF keys
OPTIONAL_OCSF_KEYS: Final[frozenset[str]] = frozenset({
    "actor",
    "device",
    "dst_endpoint",
    "src_endpoint",
    "file",
    "process",
    "registry",
    "user",
    "cloud",
    "api",
})
