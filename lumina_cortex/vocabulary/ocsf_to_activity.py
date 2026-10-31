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

# Mapping from OCSF (class_uid, activity_id) tuples to canonical activity names
# This is the canonical mapping used by ocsf_to_pm4py
_OCSF_TO_ACTIVITY: Dict[tuple[int, int], str] = {
    # Network Activity (class_uid=4001)
    (4001, 1): "Network: Connection Open",
    (4001, 2): "Network: Connection Close",
    # DNS Activity (class_uid=4003)
    (4003, 1): "DNS: Query",
    (4003, 2): "DNS: Response",
    # Process Activity (class_uid=1001)
    (1001, 1): "Process: Launch",
    (1001, 2): "Process: Terminate",
    (1001, 3): "Process: Open",
    # Module Activity (class_uid=1005)
    (1005, 1): "Module: Load",
    # File Activity (class_uid=1002)
    (1002, 1): "File: Read",
    (1002, 2): "File: Write",
    (1002, 3): "File: Delete",
    (1002, 4): "File: Create",
    (1002, 5): "File: Access",
    # Registry Activity (class_uid=1003)
    (1003, 1): "Registry: Modify",
    (1003, 2): "Registry: Create",
    (1003, 3): "Registry: Delete",
    # Authentication Activity (class_uid=3002)
    (3002, 1): "Authentication: Logon",
    (3002, 2): "Authentication: Logon Failure",
    (3002, 3): "Authentication: Logoff",
    # API/Cloud Activity (class_uid=5001, 5002)
    (5001, 1): "API: Call",
    (5002, 1): "Cloud: Activity",
}


def activity_for(event: dict) -> Optional[str]:
    """
    Look up the canonical activity name for an OCSF event.

    Args:
        event: An OCSF event dict with class_uid and activity_id.

    Returns:
        The canonical activity name, or None if not found.
    """
    class_uid = event.get("class_uid")
    activity_id = event.get("activity_id")

    if class_uid is None or activity_id is None:
        return None

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
