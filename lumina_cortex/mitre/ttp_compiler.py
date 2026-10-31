"""
TTP to pattern compiler.

Compiles a MITRE ATT&CK TTP into an AttackPattern with activities
and edges derived from the OCSF vocabulary.
"""

from typing import FrozenSet, List, Tuple

from lumina_cortex.mitre.catalog import TTPPattern
from lumina_cortex.vocabulary.ocsf_to_activity import VOCABULARY


class AttackPattern:
    """
    A compiled attack pattern with validated activities and edges.
    
    Activities must be in the OCSF vocabulary.
    """

    def __init__(
        self,
        ttp_id: str,
        ttp_name: str,
        activities: Tuple[str, ...],
        edges: Tuple[Tuple[str, str], ...],
        tactics: Tuple[str, ...] = (),
    ):
        self.ttp_id = ttp_id
        self.ttp_name = ttp_name
        self.activities = activities
        self.edges = edges
        self.tactics = tactics
        
        # Validate at construction
        errors = self.validate(VOCABULARY)
        if errors:
            raise ValueError(
                f"Invalid attack pattern {ttp_id}: {'; '.join(errors)}"
            )

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

        return errors

    def __repr__(self) -> str:
        return f"AttackPattern({self.ttp_id}, {self.ttp_name!r})"


def ttp_to_pattern(ttp: TTPPattern) -> AttackPattern:
    """
    Compile a TTP into an AttackPattern.

    Validates that all activities in the TTP are in the OCSF vocabulary.

    Args:
        ttp: A TTPPattern from the MITRE catalog.

    Returns:
        A validated AttackPattern.

    Raises:
        ValueError: If the TTP contains activities not in vocabulary.
    """
    return AttackPattern(
        ttp_id=ttp.ttp_id,
        ttp_name=ttp.ttp_name,
        activities=ttp.activities,
        edges=ttp.edges,
        tactics=ttp.tactics,
    )
