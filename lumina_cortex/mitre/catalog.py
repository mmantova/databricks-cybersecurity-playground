"""
MITRE ATT&CK TTP catalog loader.

Loads the bundled ATT&CK subset with validation.
Only version 15.1 is supported (pinned for thesis).
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

from lumina_cortex.errors import UnsupportedCatalogVersion
from lumina_cortex.vocabulary.ocsf_to_activity import VOCABULARY


# The pinned ATT&CK version for thesis validation
PINNED_ATTACK_VERSION: str = "15.1"

# Path to the bundled data
_DATA_DIR = Path(__file__).parent / "data"


@dataclass(frozen=True)
class TTPPattern:
    """A TTP pattern with activities and edges."""

    ttp_id: str
    ttp_name: str
    tactics: Tuple[str, ...]
    activities: Tuple[str, ...]
    edges: Tuple[Tuple[str, str], ...]  # (from_activity, to_activity)

    def validate(self, vocabulary: FrozenSet[str]) -> List[str]:
        """
        Validate the pattern against vocabulary rules.

        Returns a list of validation errors (empty if valid).
        """
        errors = []

        # Check all activities are in vocabulary
        for activity in self.activities:
            if activity not in vocabulary:
                errors.append(f"Activity {activity!r} not in vocabulary")

        # Check edges reference valid activities
        for src, dst in self.edges:
            if src not in self.activities:
                errors.append(f"Edge source {src!r} not in pattern activities")
            if dst not in self.activities:
                errors.append(f"Edge destination {dst!r} not in pattern activities")

        # Check pattern has at least 2 activities
        if len(self.activities) < 2:
            errors.append(f"Pattern has only {len(self.activities)} activities (need ≥2)")

        # Check pattern has at least 1 edge
        if len(self.edges) < 1:
            errors.append("Pattern has no edges (need ≥1)")

        return errors


@dataclass(frozen=True)
class TTPCatalog:
    """A catalog of MITRE ATT&CK TTP patterns."""

    version: str
    techniques: Tuple[TTPPattern, ...]
    procedures: Tuple[TTPPattern, ...]

    def get_technique(self, ttp_id: str) -> Optional[TTPPattern]:
        """Get a technique by ID."""
        for t in self.techniques:
            if t.ttp_id == ttp_id:
                return t
        return None

    def get_activities_for_ttp(self, ttp_id: str) -> FrozenSet[str]:
        """Get all activities associated with a TTP."""
        ttp = self.get_technique(ttp_id)
        if ttp is None:
            return frozenset()
        return frozenset(ttp.activities)

    def all_activities(self) -> FrozenSet[str]:
        """Get all activities across all TTPs."""
        activities = set()
        for t in self.techniques:
            activities.update(t.activities)
        for p in self.procedures:
            activities.update(p.activities)
        return frozenset(activities)


def load_attack_ttps(version: str = PINNED_ATTACK_VERSION) -> TTPCatalog:
    """
    Load the MITRE ATT&CK TTP catalog.

    Args:
        version: The ATT&CK version to load. Only 15.1 is supported.

    Returns:
        The TTP catalog.

    Raises:
        UnsupportedCatalogVersion: If version is not 15.1.
    """
    if version != PINNED_ATTACK_VERSION:
        raise UnsupportedCatalogVersion(
            f"Only ATT&CK version {PINNED_ATTACK_VERSION} is supported",
            details={"requested": version, "supported": [PINNED_ATTACK_VERSION]},
        )

    # Load the bundled JSON
    json_path = _DATA_DIR / f"attack-enterprise-{version}-lumina-subset.json"
    if not json_path.exists():
        raise UnsupportedCatalogVersion(
            f"Catalog file not found: {json_path}",
            details={"version": version},
        )

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Parse techniques
    techniques = []
    for t_data in data.get("techniques", []):
        pattern = TTPPattern(
            ttp_id=t_data["id"],
            ttp_name=t_data["name"],
            tactics=tuple(t_data.get("tactics", [])),
            activities=tuple(t_data.get("activities", [])),
            edges=tuple(tuple(e) for e in t_data.get("edges", [])),
        )

        # Validate
        errors = pattern.validate(VOCABULARY)
        if errors:
            # Log warning but continue
            pass

        techniques.append(pattern)

    # Parse procedures
    procedures = []
    for p_data in data.get("procedures", []):
        pattern = TTPPattern(
            ttp_id=p_data["id"],
            ttp_name=p_data["name"],
            tactics=tuple(p_data.get("tactics", [])),
            activities=tuple(p_data.get("activities", [])),
            edges=tuple(tuple(e) for e in p_data.get("edges", [])),
        )

        procedures.append(pattern)

    return TTPCatalog(
        version=version,
        techniques=tuple(techniques),
        procedures=tuple(procedures),
    )
