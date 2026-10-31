"""Hunt card state for TypeSafe — named fields, human-readable, minimal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from lumina_cortex.models import ThreatAssessment


@dataclass
class HuntChatState:
    """What a smart analyst would look at — not raw IDs or full event dumps."""

    analyst_message: str
    hunt: dict[str, Any] = field(default_factory=dict)

    def to_typesafe_state(self) -> dict[str, Any]:
        return {
            "analyst_message": self.analyst_message.strip(),
            "hunt": self.hunt,
        }


def assessment_dict_to_hunt(
    assessment: dict[str, Any],
    *,
    hunt_id: str = "hunt-local",
) -> dict[str, Any]:
    """Map a serialized ThreatAssessment (or analyze result) → hunt card for handover."""
    scorer = assessment.get("scorer") or {}
    mitre = assessment.get("mitre") or {}
    drift = assessment.get("drift") or {}
    metadata = assessment.get("metadata") or {}
    top5 = scorer.get("top5") or []
    top = top5[0] if top5 else {}
    thesis = metadata.get("thesis_scorer") or assessment.get("scorer_3d") or {}

    vocab = int(
        metadata.get("unique_activities")
        or assessment.get("activity_vocabulary_size")
        or 0
    )
    hunt: dict[str, Any] = {
        "hunt_id": hunt_id,
        "verdict": assessment.get("verdict"),
        "confidence": assessment.get("confidence"),
        "drift_count": int(drift.get("count") or 0),
        "activity_vocabulary_size": vocab,
        "jaccard_inflation_risk": bool(
            metadata.get("jaccard_inflation_risk")
            or assessment.get("jaccard_inflation_risk")
        ),
        "mitre_threat_level": mitre.get("threat_level"),
        "mitre_models_above": mitre.get("models_above"),
        "tags": list(assessment.get("tags") or []),
    }
    if top.get("name") or top.get("ttp_id"):
        hunt["top_ttp"] = top.get("name") or top.get("ttp_id")
    combined = thesis.get("combined")
    if combined is None and scorer.get("top_score") is not None:
        combined = float(scorer["top_score"])
    if combined is not None:
        hunt["scorer_3d"] = {
            "combined": float(combined),
            "overlap": thesis.get("overlap"),
            "sequence": thesis.get("sequence"),
            "temporal": thesis.get("temporal"),
            "algorithm": thesis.get("algorithm") or "product_scorer",
            "confidence": thesis.get("confidence") or assessment.get("confidence"),
        }
    gaps = metadata.get("coverage_gap_list") or assessment.get("coverage_gaps")
    if gaps:
        hunt["coverage_gaps"] = gaps
    return hunt


def threat_assessment_to_hunt(
    assessment: "ThreatAssessment",
    *,
    hunt_id: str = "hunt-local",
    coverage_gaps: Optional[list[Any]] = None,
    one_line_summary: Optional[str] = None,
) -> dict[str, Any]:
    """Map Lumina ThreatAssessment → hunt card dict (for chat / TypeSafe state)."""
    data = assessment.to_dict()
    if coverage_gaps is not None:
        data.setdefault("metadata", {})["coverage_gap_list"] = coverage_gaps
    hunt = assessment_dict_to_hunt(data, hunt_id=hunt_id)
    if one_line_summary:
        hunt["summary"] = one_line_summary
    elif hunt.get("top_ttp"):
        hunt["summary"] = (
            f"{hunt['verdict']} via {hunt['top_ttp']} "
            f"(score={((hunt.get('scorer_3d') or {}).get('combined'))})"
        )
    return hunt


def build_hunt_chat_state(
    analyst_message: str,
    *,
    hunt_id: str,
    verdict: str,
    confidence: float,
    top_ttp: Optional[str] = None,
    scorer_combined: Optional[float] = None,
    scorer_overlap: Optional[float] = None,
    scorer_sequence: Optional[float] = None,
    scorer_temporal: Optional[float] = None,
    drift_count: int = 0,
    activities: int = 0,
    jaccard_inflation_risk: bool = False,
    coverage_gaps: Optional[list[Any]] = None,
    one_line_summary: Optional[str] = None,
    assessment: Optional["ThreatAssessment"] = None,
) -> HuntChatState:
    """Build state from assessment fields (code already knows these)."""
    if assessment is not None:
        hunt = threat_assessment_to_hunt(
            assessment,
            hunt_id=hunt_id,
            coverage_gaps=coverage_gaps,
            one_line_summary=one_line_summary,
        )
        return HuntChatState(analyst_message=analyst_message, hunt=hunt)

    hunt: dict[str, Any] = {
        "hunt_id": hunt_id,
        "verdict": verdict,
        "confidence": confidence,
        "drift_count": drift_count,
        "activity_vocabulary_size": activities,
        "jaccard_inflation_risk": jaccard_inflation_risk,
    }
    if top_ttp:
        hunt["top_ttp"] = top_ttp
    if scorer_combined is not None:
        hunt["scorer_3d"] = {
            "combined": scorer_combined,
            "overlap": scorer_overlap,
            "sequence": scorer_sequence,
            "temporal": scorer_temporal,
            "algorithm": "scorer_3d_v1",
        }
    if coverage_gaps:
        hunt["coverage_gaps"] = coverage_gaps
    if one_line_summary:
        hunt["summary"] = one_line_summary
    return HuntChatState(analyst_message=analyst_message, hunt=hunt)
