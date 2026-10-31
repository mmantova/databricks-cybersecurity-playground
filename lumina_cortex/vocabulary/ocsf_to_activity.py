"""
OCSF to PM4Py activity vocabulary.

This module defines the closed set of canonical activity names derived from
OCSF categories and classes. Each activity follows the space rule:
    ^[A-Z][A-Za-z]*: [A-Z][A-Za-z]*( [A-Z][A-Za-z]*)*$

That is: exactly one space after the colon, PascalCase words on both sides.

This vocabulary is FROZEN. Adding new activities requires a new vocabulary version.
"""

import re
from typing import Dict, FrozenSet, Optional

from lumina_cortex.errors import NonCanonicalLogError


# Version tag for the vocabulary
# lumina-vocab-2 adds Process: Open and Module: Load (ADR 0005)
VOCABULARY_VERSION: str = "lumina-vocab-2"

# Regex pattern for the space rule (one space after colon)
_SPACE_RULE_PATTERN = re.compile(
    r"^[A-Z][A-Za-z]*: [A-Z][A-Za-z]*( [A-Z][A-Za-z]*)*$"
)

# Canonical OCSF to PM4Py activity vocabulary (21 activities)
# Each follows the space rule: "Category: ActivityName"
# Derived from OCSF 1.3.0 classes/categories per spec §3.3
VOCABULARY: FrozenSet[str] = frozenset({
    # Network Activity
    "Network: Connection Open",
    "Network: Connection Close",
    # DNS Activity
    "DNS: Query",
    "DNS: Response",
    # Process Activity
    "Process: Launch",
    "Process: Terminate",
    "Process: Open",
    # Module Activity
    "Module: Load",
    # File Activity
    "File: Read",
    "File: Write",
    "File: Delete",
    "File: Create",
    "File: Access",
    # Registry Activity
    "Registry: Modify",
    "Registry: Create",
    "Registry: Delete",
    # Authentication Activity
    "Authentication: Logon",
    "Authentication: Logon Failure",
    "Authentication: Logoff",
    # Cloud/API Activity
    "API: Call",
    "Cloud: Activity",
})

# Mapping from OCSF (class_uid, activity_id) tuples to canonical activity names.
# Ids checked against the OCSF 1.3.0 schema API (https://schema.ocsf.io/api/1.3.0/classes/<name>).
# Before 0.5.0 this table used wrong class_uids (1001 as Process, 1002 as File,
# 1003 as Registry, 5001/5002 as API/Cloud) and treated (3002, 2) as a logon failure.
_OCSF_TO_ACTIVITY: Dict[tuple[int, int], str] = {
    # Network Activity (4001): 1 Open, 2 Close
    (4001, 1): "Network: Connection Open",
    (4001, 2): "Network: Connection Close",
    # DNS Activity (4003): 1 Query, 2 Response
    (4003, 1): "DNS: Query",
    (4003, 2): "DNS: Response",
    # Process Activity (1007): 1 Launch, 2 Terminate, 3 Open
    (1007, 1): "Process: Launch",
    (1007, 2): "Process: Terminate",
    (1007, 3): "Process: Open",
    # Module Activity (1005): 1 Load
    (1005, 1): "Module: Load",
    # File System Activity (1001): 1 Create, 2 Read, 3 Update, 4 Delete, 14 Open.
    # OCSF has no "Write"; Update is the write.
    (1001, 1): "File: Create",
    (1001, 2): "File: Read",
    (1001, 3): "File: Write",
    (1001, 4): "File: Delete",
    (1001, 14): "File: Access",
    # Registry Key Activity (201001, Windows extension): 1 Create, 3 Modify, 4 Delete
    (201001, 1): "Registry: Create",
    (201001, 3): "Registry: Modify",
    (201001, 4): "Registry: Delete",
    # Registry Value Activity (201002, Windows extension): 2 Set, 4 Delete
    (201002, 2): "Registry: Modify",
    (201002, 4): "Registry: Delete",
    # Authentication (3002): 1 Logon, 2 Logoff. A failed logon is (3002, 1) with
    # status_id 2 (Failure); see activity_for. Ticket activities (3, 4, 5, 6) are not mapped.
    (3002, 1): "Authentication: Logon",
    (3002, 2): "Authentication: Logoff",
    # API Activity (6003): 1 Create, 2 Read, 3 Update, 4 Delete
    (6003, 1): "API: Call",
    (6003, 2): "API: Call",
    (6003, 3): "API: Call",
    (6003, 4): "API: Call",
    # "Cloud: Activity" has no OCSF class; adapters emit it directly.
}

# OCSF status_id for a failed outcome.
_STATUS_FAILURE = 2


def activity_for(event: dict) -> Optional[str]:
    """
    Look up the canonical activity name for an OCSF event.

    Args:
        event: An OCSF event dict with class_uid and activity_id, and optionally
            status_id. A logon (3002, 1) with status_id 2 is a logon failure.

    Returns:
        The canonical activity name, or None if not found.
    """
    class_uid = event.get("class_uid")
    activity_id = event.get("activity_id")

    if class_uid is None or activity_id is None:
        return None

    if (class_uid, activity_id) == (3002, 1) and event.get("status_id") == _STATUS_FAILURE:
        return "Authentication: Logon Failure"

    return _OCSF_TO_ACTIVITY.get((class_uid, activity_id))


def is_canonical(name: str) -> bool:
    """
    Check if an activity name is in the canonical vocabulary.

    Args:
        name: The activity name to check.

    Returns:
        True if the name is in the vocabulary.
    """
    return name in VOCABULARY


def validate_activity(name: str) -> str:
    """
    Validate that an activity name is canonical.

    Args:
        name: The activity name to validate.

    Returns:
        The validated activity name.

    Raises:
        NonCanonicalLogError: If the name is not canonical.
    """
    if not is_canonical(name):
        raise NonCanonicalLogError(
            f"Non-canonical activity name: {name!r}",
            details={"name": name, "vocabulary_version": VOCABULARY_VERSION},
        )
    return name


def matches_space_rule(name: str) -> bool:
    """
    Check if an activity name matches the space rule pattern.

    The space rule requires exactly one space after the colon:
        "Process: Launch" (valid)
        "Process:Launch" (invalid - no space)
        "Process:  Launch" (invalid - two spaces)

    Args:
        name: The activity name to check.

    Returns:
        True if the name matches the space rule pattern.
    """
    return bool(_SPACE_RULE_PATTERN.match(name))
