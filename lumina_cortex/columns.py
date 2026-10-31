"""
Column name constants for PM4Py DataFrames.

This module defines the canonical column names used throughout Lumina Cortex.
ACTIVITY is the ONLY place where the literal 'concept:name' appears.
"""

from typing import Final

# PM4Py standard column names
CASE: Final[str] = "case:concept:name"
ACTIVITY: Final[str] = "concept:name"  # The ONLY place this literal appears
TIMESTAMP: Final[str] = "time:timestamp"
RESOURCE: Final[str] = "org:resource"

# OCSF metadata columns preserved in the DataFrame
OCSF_COLUMNS: Final[tuple[str, ...]] = (
    "ocsf.class_uid",
    "ocsf.category_uid",
    "ocsf.category_name",
    "ocsf.activity_id",
    "ocsf.activity_name",
    "ocsf.time",
    "ocsf.metadata.version",
)

# Who and where of each event, as the adapters map them to OCSF (None when the source
# does not carry it). The engines ignore them; they let a reader name the host, user or
# endpoints behind a behaviour.
ENTITY_COLUMNS: Final[tuple[str, ...]] = (
    "ocsf.device.hostname",
    "ocsf.user.name",
    "ocsf.src_endpoint.ip",
    "ocsf.dst_endpoint.ip",
    "ocsf.dst_endpoint.port",
)
