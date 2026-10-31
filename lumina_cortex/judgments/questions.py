"""
TypeSafe question bank for Lumina Cortex Board handover.

AUDIT THIS FILE — all question wording, options, criteria, and thresholds live here.
Primitive types (Choice / Noul / Score) follow docs.typesafe.ai.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

NOUL_YES = 0.7
NOUL_NO = 0.3


@dataclass(frozen=True)
class QuestionSpec:
    """One typed question. ``id`` is for our code only — not sent as model signal."""

    id: str
    kind: str  # "choice" | "noul" | "score"
    instructions: str
    criteria: dict[str, Any]


HANDOVER_VOCAB_FP = QuestionSpec(
    id="handover_vocab_fp",
    kind="noul",
    instructions=(
        "Given `hunt`, does the situation look like a false positive driven by "
        "a very small activity vocabulary (Jaccard / score inflation), "
        "rather than a real attack?"
    ),
    criteria={
        "true": (
            "Few distinct activities, high score, little or no drift, "
            "or hunt already flags jaccard_inflation_risk — classic FP shape."
        ),
        "false": (
            "Vocabulary is rich enough, drift supports change, or MITRE match "
            "looks like a real kill chain — not a narrow-vocab FP."
        ),
    },
)

HANDOVER_HAS_COVERAGE_GAP = QuestionSpec(
    id="handover_has_coverage_gap",
    kind="noul",
    instructions=(
        "Does `hunt` report a coverage gap (missing OCSF class or MITRE TTP "
        "the telemetry cannot support)?"
    ),
    criteria={
        "true": "A coverage gap is declared or clearly implied in hunt fields.",
        "false": "No coverage gap is indicated.",
    },
)


def handover_questions() -> list[QuestionSpec]:
    return [HANDOVER_VOCAB_FP, HANDOVER_HAS_COVERAGE_GAP]


def as_typesafe_question_dicts(specs: list[QuestionSpec]) -> list[dict[str, Any]]:
    """Serialize to a vendor-neutral shape for logging / future SDK mapping."""
    out = []
    for q in specs:
        out.append(
            {
                "id": q.id,
                "type": q.kind,
                "instructions": q.instructions,
                "criteria": q.criteria,
            }
        )
    return out
