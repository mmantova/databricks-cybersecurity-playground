"""
TypeSafe client boundary (Board handover).

- build_handover_request: always available (log / audit)
- ask_live_handover: only with TYPESAFE_API_KEY + explicit allow_live=True
- Never treat API failure as a "no" judgment
- Never commit API keys; use env TYPESAFE_API_KEY only
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

from .questions import QuestionSpec, as_typesafe_question_dicts, handover_questions
from .state import HuntChatState


@dataclass
class BuiltRequest:
    state: dict[str, Any]
    questions: list[dict[str, Any]]
    meta: dict[str, Any]


def build_handover_request(chat: HuntChatState) -> BuiltRequest:
    return BuiltRequest(
        state=chat.to_typesafe_state(),
        questions=as_typesafe_question_dicts(handover_questions()),
        meta={
            "workflow": "hunt_board_handover_triage",
            "product": "lumina_cortex",
        },
    )


def parse_handover_fixture(fixture: dict[str, Any]) -> "HandoverAnswers":
    """Dry-run handover Nouls (ids from questions.py)."""
    from .handover import HandoverAnswers

    return HandoverAnswers(
        vocab_fp_p=fixture.get("handover_vocab_fp"),
        coverage_gap_p=fixture.get("handover_has_coverage_gap"),
        raw=fixture,
    )


def _specs_to_sdk_questions(specs: list[QuestionSpec]) -> dict[str, Any]:
    from typesafe_sdk import Choice, Noul

    out: dict[str, Any] = {}
    for q in specs:
        if q.kind == "noul":
            out[q.id] = Noul(instructions=q.instructions, criteria=q.criteria)
        elif q.kind == "choice":
            out[q.id] = Choice(instructions=q.instructions, criteria=q.criteria)
        else:
            raise ValueError(f"Unsupported question kind: {q.kind}")
    return out


def _live_system_one(
    chat: HuntChatState,
    specs: list[QuestionSpec],
    *,
    allow_live: bool,
    api_key: Optional[str],
) -> Any:
    if not allow_live:
        raise RuntimeError(
            "ask_live refused: pass allow_live=True after owner permission + budget. "
            "Use parse_handover_fixture() for dry-run."
        )
    key = (api_key or os.environ.get("TYPESAFE_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("TYPESAFE_API_KEY not set")
    try:
        from typesafe_sdk import TypeSafeClient
    except ImportError as e:
        raise RuntimeError(
            "Install the official SDK: pip install typesafe-sdk "
            "(not the unrelated PyPI package named 'typesafe')"
        ) from e
    questions = _specs_to_sdk_questions(specs)
    state = chat.to_typesafe_state()
    with TypeSafeClient(api_key=key) as client:
        return client.system_one(state=state, questions=questions)


def ask_live_handover(
    chat: HuntChatState,
    *,
    allow_live: bool = False,
    api_key: Optional[str] = None,
) -> "HandoverAnswers":
    """Call TypeSafe System One for Board handover Nouls (FP vocab / coverage gap)."""
    from .handover import HandoverAnswers

    response = _live_system_one(
        chat, handover_questions(), allow_live=allow_live, api_key=api_key
    )
    nouls = getattr(response, "nouls", None) or {}
    raw: dict[str, Any] = {"request_id": getattr(response, "request_id", None)}
    vocab_fp_p = None
    coverage_gap_p = None
    if "handover_vocab_fp" in nouls:
        vocab_fp_p = float(nouls["handover_vocab_fp"].noul)
        raw["handover_vocab_fp"] = vocab_fp_p
    if "handover_has_coverage_gap" in nouls:
        coverage_gap_p = float(nouls["handover_has_coverage_gap"].noul)
        raw["handover_has_coverage_gap"] = coverage_gap_p
    return HandoverAnswers(
        vocab_fp_p=vocab_fp_p, coverage_gap_p=coverage_gap_p, raw=raw
    )
