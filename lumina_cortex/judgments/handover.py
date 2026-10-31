"""Board handover triage — Jev judges FP-vocab / coverage gap; code sets priority.

Does **not** recompute scorers or flip ATTACK_DETECTED. Only Board priority/tags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .client import (
    ask_live_handover,
    build_handover_request,
    parse_handover_fixture,
)
from .questions import NOUL_NO, NOUL_YES
from .state import HuntChatState


@dataclass
class HandoverAnswers:
    vocab_fp_p: Optional[float] = None
    coverage_gap_p: Optional[float] = None
    raw: Optional[dict[str, Any]] = None


@dataclass
class HandoverTriageResult:
    asked: bool
    priority: str  # high | normal | low
    tags: list[str] = field(default_factory=list)
    vocab_fp_p: Optional[float] = None
    coverage_gap_p: Optional[float] = None
    reason: str = ""
    skipped: bool = False


def needs_vocab_fp_check(hunt: dict[str, Any]) -> bool:
    """
    Gate: only spend a TypeSafe call when the numeric card looks FP-shaped.

    Triggers:
    - jaccard_inflation_risk already set, or
    - combined/top score high with narrow vocab, or
    - ATTACK_DETECTED with vocab < 5
    """
    if hunt.get("jaccard_inflation_risk"):
        return True
    vocab = int(hunt.get("activity_vocabulary_size") or 0)
    scorer = hunt.get("scorer_3d") or {}
    combined = float(scorer.get("combined") or 0.0)
    verdict = str(hunt.get("verdict") or "")
    if combined >= 0.55 and vocab < 5:
        return True
    if verdict == "ATTACK_DETECTED" and vocab < 5:
        return True
    return False


def apply_handover_judgments(
    hunt: dict[str, Any],
    answers: HandoverAnswers,
    *,
    asked: bool = True,
) -> HandoverTriageResult:
    """
    Truth table (código decide):

    | vocab_fp_p     | coverage_gap_p | → priority / tags
    | ≥ 0.7 (yes)    | *              | → low + review_fp
    | ≤ 0.3 (no)     | ≥ 0.7          | → normal/high + coverage_gap
    | ≤ 0.3          | *              | → high if ATTACK else normal
    | (0.3, 0.7)     | *              | → normal + review_manual
    | None (fail)    | *              | → normal + typesafe_unsettled (never treat as FP)
    """
    tags: list[str] = list(hunt.get("tags") or [])
    verdict = str(hunt.get("verdict") or "")
    fp = answers.vocab_fp_p
    gap = answers.coverage_gap_p

    if fp is None and gap is None:
        priority = "high" if verdict == "ATTACK_DETECTED" else "normal"
        if "typesafe_unsettled" not in tags:
            tags.append("typesafe_unsettled")
        result = HandoverTriageResult(
            asked=asked,
            priority=priority,
            tags=tags,
            reason="No handover judgments (API empty/fail) — not treating as FP.",
        )
        _write_hunt(hunt, result)
        return result

    if fp is not None and fp >= NOUL_YES:
        if "review_fp" not in tags:
            tags.append("review_fp")
        result = HandoverTriageResult(
            asked=asked,
            priority="low",
            tags=tags,
            vocab_fp_p=fp,
            coverage_gap_p=gap,
            reason=f"Jev vocab_fp_p={fp:.3f} ≥ {NOUL_YES} → demote Board priority (FP vocab).",
        )
        _write_hunt(hunt, result)
        return result

    if gap is not None and gap >= NOUL_YES:
        if "coverage_gap" not in tags:
            tags.append("coverage_gap")

    if fp is not None and NOUL_NO < fp < NOUL_YES:
        if "review_manual" not in tags:
            tags.append("review_manual")
        result = HandoverTriageResult(
            asked=asked,
            priority="normal",
            tags=tags,
            vocab_fp_p=fp,
            coverage_gap_p=gap,
            reason=f"vocab_fp_p={fp:.3f} unsettled — keep normal priority.",
        )
        _write_hunt(hunt, result)
        return result

    priority = "high" if verdict == "ATTACK_DETECTED" else "normal"
    result = HandoverTriageResult(
        asked=asked,
        priority=priority,
        tags=tags,
        vocab_fp_p=fp,
        coverage_gap_p=gap,
        reason=(
            f"vocab_fp_p={fp} not FP; priority={priority}."
            if fp is not None
            else f"No FP signal; priority={priority}."
        ),
    )
    _write_hunt(hunt, result)
    return result


def _write_hunt(hunt: dict[str, Any], result: HandoverTriageResult) -> None:
    hunt["board_priority"] = result.priority
    hunt["tags"] = list(result.tags)
    hunt["handover"] = {
        "asked": result.asked,
        "vocab_fp_p": result.vocab_fp_p,
        "coverage_gap_p": result.coverage_gap_p,
        "reason": result.reason,
        "skipped": result.skipped,
    }


def run_handover_triage(
    hunt: dict[str, Any],
    *,
    fixture: Optional[dict[str, Any]] = None,
    force: bool = False,
) -> HandoverTriageResult:
    """
    Dry-run / code path: apply fixture judgments when gate fires.

    If gate does not fire and force=False → skip (priority from verdict only).
    """
    if not force and not needs_vocab_fp_check(hunt):
        priority = "high" if hunt.get("verdict") == "ATTACK_DETECTED" else "normal"
        result = HandoverTriageResult(
            asked=False,
            priority=priority,
            tags=list(hunt.get("tags") or []),
            reason="Gate closed — numeric card not FP-shaped; TypeSafe not called.",
            skipped=True,
        )
        _write_hunt(hunt, result)
        return result

    if fixture is None:
        result = HandoverTriageResult(
            asked=False,
            priority="normal",
            tags=list(hunt.get("tags") or []) + ["awaiting_handover_jev"],
            reason="Gate open — awaiting TypeSafe handover judgments.",
            skipped=False,
        )
        _write_hunt(hunt, result)
        return result

    answers = parse_handover_fixture(fixture)
    return apply_handover_judgments(hunt, answers, asked=True)


def run_handover_triage_live(
    hunt: dict[str, Any],
    *,
    allow_live: bool = False,
    force: bool = False,
    analyst_message: str = "Board handover triage",
) -> HandoverTriageResult:
    """Opt-in live TypeSafe call for handover Nouls."""
    if not force and not needs_vocab_fp_check(hunt):
        return run_handover_triage(hunt, force=False)

    chat = HuntChatState(analyst_message=analyst_message, hunt=hunt)
    _ = build_handover_request(chat)
    live = ask_live_handover(chat, allow_live=allow_live)
    return apply_handover_judgments(hunt, live, asked=True)
