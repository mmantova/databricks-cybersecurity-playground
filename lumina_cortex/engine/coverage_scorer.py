"""
The Product method's scorer: pattern coverage × edge match (decision 5 of
.scratch/product-v2/decisions.md; spec stories 17-20).

Per eligible catalog pattern (at least 2 activities and 1 edge; a one-activity or
edgeless pattern would reach 1.0 by being a subset of any log):

- coverage: the pattern's activities seen in the log ÷ the pattern's activities;
- edge match: the pattern's edges seen as directly-follows pairs within a case ÷ the
  pattern's edges;
- score = coverage × edge match;
- with ``ProductThresholds.pattern_share_exponent`` k > 0 (ticket 10, off by default),
  times (1 - share) ** k, share being the fraction of the scored events whose activity
  is one of the pattern's: a pattern that is most of the log says little.

Extra activities in the log do not lower the score of a pattern that is fully present,
as Jaccard × edges (``score_attack_patterns``, kept as ``product-v1``) did. The candidate
patterns keep the shape of that scorer (ttp_id, name, tactics, score), so the Board and
the backend read them unchanged.
"""

import time
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE
from lumina_cortex.config.thresholds import PRODUCT_V2_THRESHOLDS, ProductThresholds
from lumina_cortex.engine.sampling import sample_scored_cases
from lumina_cortex.mitre.catalog import TTPCatalog, TTPPattern, load_attack_ttps
from lumina_cortex.models import ScorerResult


def is_eligible(pattern: TTPPattern) -> bool:
    """Whether the coverage scorer scores ``pattern``: at least 2 activities and 1 edge."""
    return len(set(pattern.activities)) >= 2 and len(pattern.edges) >= 1


def _log_activities_and_edges(df: pd.DataFrame) -> Tuple[FrozenSet[str], Set[Tuple[str, str]]]:
    """The activities of the log and its directly-follows pairs within a case."""
    activities = frozenset(df[ACTIVITY].unique())
    nxt = df.groupby(CASE, sort=False)[ACTIVITY].shift(-1)
    mask = nxt.notna()
    edges = set(zip(df.loc[mask, ACTIVITY], nxt[mask]))
    return activities, edges


def score_pattern_coverage(
    df: pd.DataFrame,
    catalog: Optional[TTPCatalog] = None,
    *,
    thresholds: Optional[ProductThresholds] = None,
) -> ScorerResult:
    """Score the eligible catalog patterns by coverage × edge match.

    The log is sampled as ``score_attack_patterns`` samples it (``sample_max_events``
    events of whole cases, ``sample_seed``). ``patterns_checked`` counts the eligible
    patterns; the top 5 are sorted by score, ties in catalog order. ``thresholds`` are the
    Product method's (default product-v2's), which carry the specificity weight.
    """
    start = time.perf_counter()
    t = thresholds or PRODUCT_V2_THRESHOLDS
    cat = catalog or load_attack_ttps()

    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")

    patterns = [p for p in (*cat.techniques, *cat.procedures) if is_eligible(p)]
    if len(df) == 0 or not patterns:
        return ScorerResult(
            patterns_checked=0 if len(df) == 0 else len(patterns),
            top_score=0.0, top_name="", top5=(), time_s=time.perf_counter() - start,
        )

    sample = sample_scored_cases(df, t.sample_max_events, t.sample_seed)
    seen, followed = _log_activities_and_edges(sample)
    # The specificity weight (ticket 10): (1 - share) ** k; k = 0 leaves the score unweighted.
    k = t.pattern_share_exponent
    counts = sample[ACTIVITY].value_counts() if k else None

    scored: List[Dict[str, Any]] = []
    for pattern in patterns:
        activities = frozenset(pattern.activities)
        edges = set(pattern.edges)
        coverage = len(activities & seen) / len(activities)
        edge_match = len(edges & followed) / len(edges)
        score = coverage * edge_match
        if counts is not None and score:
            share = sum(int(counts.get(a, 0)) for a in activities) / len(sample)
            score *= (1.0 - share) ** k
        scored.append({
            "ttp_id": pattern.ttp_id,
            "name": pattern.ttp_name,
            "tactics": tuple(pattern.tactics),
            "score": round(score, 6),
        })

    scored.sort(key=lambda p: p["score"], reverse=True)
    top = scored[0]
    return ScorerResult(
        patterns_checked=len(patterns),
        top_score=top["score"],
        top_name=f"{top['name']} ({top['ttp_id']})",
        top5=tuple(scored[:5]),
        time_s=time.perf_counter() - start,
    )
