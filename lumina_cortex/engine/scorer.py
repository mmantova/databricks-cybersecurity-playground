"""
Attack pattern scoring using Jaccard similarity and edge matching.

Scores variants against MITRE ATT&CK TTP patterns and returns
the top matching patterns.
"""

import time
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE
from lumina_cortex.config.thresholds import Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.engine.sampling import sample_scored_cases
from lumina_cortex.mitre.catalog import TTPCatalog, load_attack_ttps
from lumina_cortex.models import ScorerResult


def _jaccard_similarity(set1: FrozenSet[str], set2: FrozenSet[str]) -> float:
    """Calculate Jaccard similarity between two sets."""
    if not set1 and not set2:
        return 1.0
    if not set1 or not set2:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


def _edge_match_score(
    variant_edges: Set[Tuple[str, str]],
    pattern_edges: Set[Tuple[str, str]],
) -> float:
    """Calculate edge matching score between variant and pattern edges."""
    if not pattern_edges:
        return 1.0  # Empty pattern matches anything
    if not variant_edges:
        return 0.0
    
    # Count matching edges
    matches = len(variant_edges & pattern_edges)
    return matches / len(pattern_edges)


def score_attack_patterns(
    df: pd.DataFrame,
    catalog: Optional[TTPCatalog] = None,
    *,
    thresholds: Optional[Thresholds] = None,
) -> ScorerResult:
    """
    Score variants against MITRE ATT&CK TTP patterns.

    For each variant in the log, calculates:
    - Jaccard similarity with pattern activities
    - Edge matching score with pattern edges
    
    Combined score = Jaccard × edge_match

    Returns top 5 patterns sorted by score descending.

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name.
        catalog: MITRE ATT&CK TTP catalog (default: load_attack_ttps()).
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).

    Returns:
        ScorerResult with patterns_checked, top_score, top_name, top5.
    """
    start_time = time.perf_counter()
    
    t = thresholds or THESIS_THRESHOLDS_V1
    cat = catalog or load_attack_ttps()

    # Validate DataFrame
    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")
    if len(df) == 0:
        return ScorerResult(
            patterns_checked=0,
            top_score=0.0,
            top_name="",
            top5=(),
            time_s=time.perf_counter() - start_time,
        )

    # Sample if too large
    df_sampled = sample_scored_cases(df, t.sample_max_events, t.sample_seed)

    # Extract variants
    variant_activities: Dict[Tuple[str, ...], int] = {}
    variant_edges: Dict[Tuple[str, ...], Set[Tuple[str, str]]] = {}
    
    for case_id, group in df_sampled.groupby(CASE, sort=False):
        activities = tuple(group[ACTIVITY].tolist())
        variant_activities[activities] = variant_activities.get(activities, 0) + 1
        
        # Extract edges for this variant
        edges: Set[Tuple[str, str]] = set()
        for i in range(len(activities) - 1):
            edges.add((activities[i], activities[i + 1]))
        variant_edges[activities] = edges

    # Get unique activities from log
    log_activities: FrozenSet[str] = frozenset(
        a for variant in variant_activities for a in variant
    )

    # Get all patterns from catalog
    all_patterns = list(cat.techniques) + list(cat.procedures)
    
    if not all_patterns:
        return ScorerResult(
            patterns_checked=0,
            top_score=0.0,
            top_name="",
            top5=(),
            time_s=time.perf_counter() - start_time,
        )

    # Score each pattern
    pattern_scores: List[Dict[str, Any]] = []
    
    for pattern in all_patterns:
        pattern_activities = frozenset(pattern.activities)
        pattern_edges = set(pattern.edges)
        
        # Calculate scores for each variant, weighted by frequency
        total_weight = 0.0
        weighted_jaccard = 0.0
        weighted_edge_match = 0.0
        
        for variant, count in variant_activities.items():
            variant_act_set = frozenset(variant)
            variant_edge_set = variant_edges[variant]
            
            # Jaccard similarity
            jaccard = _jaccard_similarity(variant_act_set, pattern_activities)
            
            # Edge match score
            edge_match = _edge_match_score(variant_edge_set, pattern_edges)
            
            # Weight by count
            total_weight += count
            weighted_jaccard += jaccard * count
            weighted_edge_match += edge_match * count
        
        # Average scores
        avg_jaccard = weighted_jaccard / total_weight if total_weight > 0 else 0.0
        avg_edge_match = weighted_edge_match / total_weight if total_weight > 0 else 0.0
        
        # Combined score
        combined_score = avg_jaccard * avg_edge_match
        
        pattern_scores.append({
            "ttp_id": pattern.ttp_id,
            "name": pattern.ttp_name,
            "tactics": list(pattern.tactics),
            "score": round(combined_score, 6),
            "jaccard": round(avg_jaccard, 6),
            "edge_match": round(avg_edge_match, 6),
        })

    # Sort by score descending
    pattern_scores.sort(key=lambda x: x["score"], reverse=True)

    # Get top 5
    top5 = tuple(
        {
            "ttp_id": p["ttp_id"],
            "name": p["name"],
            "tactics": tuple(p["tactics"]),
            "score": p["score"],
        }
        for p in pattern_scores[:5]
    )

    # Get top score and name
    if pattern_scores:
        top_score = pattern_scores[0]["score"]
        top_name = f"{pattern_scores[0]['name']} ({pattern_scores[0]['ttp_id']})"
    else:
        top_score = 0.0
        top_name = ""

    return ScorerResult(
        patterns_checked=len(all_patterns),
        top_score=top_score,
        top_name=top_name,
        top5=top5,
        time_s=time.perf_counter() - start_time,
    )
