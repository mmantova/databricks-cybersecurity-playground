"""
The Thesis method's attack pattern scorer (thesis-v1).

Each catalog pattern gets three components and their combination (THESIS:37):

    combined = overlap×0.4 + sequence×0.4 + temporal×0.2

How each component is measured is interpretation (decision 11); see
``docs/thesis-method.md``, "Attack pattern scorer". The Product method keeps
``lumina_cortex.engine.scorer``.
"""

import time
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE, TIMESTAMP
from lumina_cortex.config.thresholds import THESIS_METHOD_V1, THESIS_THRESHOLDS_V1, ScorerConfidence, Thresholds
from lumina_cortex.engine.sampling import sample_scored_cases
from lumina_cortex.mitre.catalog import TTPCatalog, TTPPattern, load_attack_ttps
from lumina_cortex.models import ScorerResult

Edge = Tuple[str, str]

OVERLAP_WEIGHT = 0.4
SEQUENCE_WEIGHT = 0.4
TEMPORAL_WEIGHT = 0.2


def combine(overlap: float, sequence: float, temporal: float) -> float:
    """``overlap×0.4 + sequence×0.4 + temporal×0.2`` (THESIS:37)."""
    return (
        overlap * OVERLAP_WEIGHT
        + sequence * SEQUENCE_WEIGHT
        + temporal * TEMPORAL_WEIGHT
    )


def overlap_confidence(overlap: float, cut_offs: ScorerConfidence = THESIS_METHOD_V1.confidence) -> str:
    """A pattern's confidence from its overlap: high >= 0.7, medium >= 0.3, low below
    (the cut-offs of ``thesis-v1``, ``THESIS_METHOD_V1.confidence``).

    It is reported beside the pattern and never feeds the verdict (decision 11).
    """
    if overlap >= cut_offs.high_min:
        return "high"
    if overlap >= cut_offs.medium_min:
        return "medium"
    return "low"


def score_thesis_patterns(
    df: pd.DataFrame,
    catalog: Optional[TTPCatalog] = None,
    *,
    thresholds: Optional[Thresholds] = None,
    confidence: ScorerConfidence = THESIS_METHOD_V1.confidence,
) -> ScorerResult:
    """Score every catalog pattern by overlap, sequence and temporal (THESIS:37).

    The log is the whole (sampled) log, each case's events in time order:

    - overlap = the pattern's activities seen in the log ÷ the pattern's activities;
    - sequence = the pattern's directly-follows edges seen in some case ÷ its edges;
      a pattern with no edges takes its overlap (spec story 18);
    - temporal = among the pattern's edges whose two activities are both seen in the
      log, the share whose source occurs before its target in at least one case
      (eventually-follows); 0.0 when no edge has both activities seen.

    Each scored pattern carries ``overlap``, ``sequence``, ``temporal``, ``combined``
    (also its ``score``) and ``confidence``. ``top5`` holds the five best by combined
    score; ``top_score`` feeds the verdict rule as the Product method's score does.
    """
    start_time = time.perf_counter()
    t = thresholds or THESIS_THRESHOLDS_V1
    cat = catalog or load_attack_ttps()

    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")

    patterns = list(cat.techniques) + list(cat.procedures)
    if len(df) == 0 or not patterns:
        return ScorerResult(
            patterns_checked=0, top_score=0.0, top_name="", top5=(),
            time_s=time.perf_counter() - start_time,
        )

    sampled = sample_scored_cases(df, t.sample_max_events, t.sample_seed)
    if TIMESTAMP in sampled.columns:
        sampled = sampled.sort_values(TIMESTAMP, kind="stable")
    log = _LogFacts.of(sampled)

    scored = [_score_pattern(p, log, confidence) for p in patterns]
    scored.sort(key=lambda p: p["score"], reverse=True)

    best = scored[0]
    return ScorerResult(
        patterns_checked=len(patterns),
        top_score=best["score"],
        top_name=f"{best['name']} ({best['ttp_id']})",
        top5=tuple(scored[:5]),
        time_s=time.perf_counter() - start_time,
    )


class _LogFacts:
    """What the scorer reads from the log: activities, directly-follows and eventually-follows pairs."""

    def __init__(self, activities: FrozenSet[str], follows: FrozenSet[Edge], precedes: FrozenSet[Edge]):
        self.activities = activities
        self.follows = follows
        self.precedes = precedes

    @classmethod
    def of(cls, df: pd.DataFrame) -> "_LogFacts":
        activities: Set[str] = set()
        follows: Set[Edge] = set()
        precedes: Set[Edge] = set()
        for _, group in df.groupby(CASE, sort=False):
            trace = group[ACTIVITY].tolist()
            activities.update(trace)
            follows.update(zip(trace, trace[1:]))
            seen_before: Set[str] = set()
            for activity in trace:
                precedes.update((earlier, activity) for earlier in seen_before)
                seen_before.add(activity)
        return cls(frozenset(activities), frozenset(follows), frozenset(precedes))


def _score_pattern(pattern: TTPPattern, log: _LogFacts, confidence: ScorerConfidence) -> Dict[str, Any]:
    activities = frozenset(pattern.activities)
    edges = frozenset(pattern.edges)

    overlap = len(activities & log.activities) / len(activities) if activities else 0.0
    sequence = len(edges & log.follows) / len(edges) if edges else overlap
    observable = [e for e in edges if e[0] in log.activities and e[1] in log.activities]
    temporal = (
        sum(1 for e in observable if e in log.precedes) / len(observable)
        if observable else 0.0
    )
    combined = round(combine(overlap, sequence, temporal), 6)

    return {
        "ttp_id": pattern.ttp_id,
        "name": pattern.ttp_name,
        "tactics": tuple(pattern.tactics),
        "score": combined,
        "combined": combined,
        "overlap": round(overlap, 6),
        "sequence": round(sequence, 6),
        "temporal": round(temporal, 6),
        "confidence": overlap_confidence(overlap, confidence),
    }
