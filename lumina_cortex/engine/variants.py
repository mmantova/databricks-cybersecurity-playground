"""
Variant analysis using pm4py.get_variants.

Analyzes process variants and identifies anomalous ones based on
novel activities or activity pairs.
"""

import time
from typing import Any, Dict, FrozenSet, Optional, Set, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE
from lumina_cortex.config.thresholds import Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.models import VariantResult


def analyze_variants(
    df: pd.DataFrame,
    *,
    thresholds: Optional[Thresholds] = None,
) -> VariantResult:
    """
    Analyze process variants and identify anomalous ones.

    Uses pm4py.get_variants to extract unique activity sequences,
    then identifies:
    - Dominant variants (cumulative coverage ≥ 0.8)
    - Anomalous variants with novel activities or activity pairs

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name.
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).

    Returns:
        VariantResult with total_variants, anomalous_variants, and discrimination_score.
    """
    start_time = time.perf_counter()
    
    t = thresholds or THESIS_THRESHOLDS_V1
    coverage_threshold = t.variant_dominant_coverage

    # Validate DataFrame
    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")
    if len(df) == 0:
        return VariantResult(
            total_variants=0,
            anomalous_variants=(),
            discrimination_score=0.0,
        )

    # Group events by case
    case_activities: Dict[str, Tuple[str, ...]] = {}
    for case_id, group in df.groupby(CASE, sort=False):
        activities = tuple(group[ACTIVITY].tolist())
        case_activities[case_id] = activities

    # Count variants (unique activity sequences)
    variant_counts: Dict[Tuple[str, ...], int] = {}
    for activities in case_activities.values():
        variant_counts[activities] = variant_counts.get(activities, 0) + 1

    total_variants = len(variant_counts)
    total_cases = len(case_activities)

    if total_variants == 0:
        return VariantResult(
            total_variants=0,
            anomalous_variants=(),
            discrimination_score=0.0,
        )

    # Sort variants by frequency (descending)
    sorted_variants = sorted(
        variant_counts.items(),
        key=lambda x: x[1],
        reverse=True,
    )

    # Find dominant variants (cumulative coverage ≥ threshold)
    dominant_variants: Set[Tuple[str, ...]] = set()
    cumulative = 0
    for variant, count in sorted_variants:
        dominant_variants.add(variant)
        cumulative += count
        if cumulative / total_cases >= coverage_threshold:
            break

    # Extract vocabulary and transitions from dominant variants
    dominant_activities: Set[str] = set()
    dominant_pairs: Set[Tuple[str, str]] = set()
    
    for variant in dominant_variants:
        dominant_activities.update(variant)
        for i in range(len(variant) - 1):
            dominant_pairs.add((variant[i], variant[i + 1]))

    # Find anomalous variants (novel activities or pairs)
    anomalous: list[Dict[str, Any]] = []
    
    for variant, count in sorted_variants:
        # Skip dominant variants
        if variant in dominant_variants:
            continue

        # Check for novel activities
        novel_activities = [a for a in variant if a not in dominant_activities]
        
        # Check for novel pairs
        novel_pairs = []
        for i in range(len(variant) - 1):
            pair = (variant[i], variant[i + 1])
            if pair not in dominant_pairs:
                novel_pairs.append(pair)

        # Anomalous if has novel activities or pairs
        if novel_activities or novel_pairs:
            anomalous.append({
                "variant": list(variant),
                "count": count,
                "novel_activities": novel_activities,
                "novel_pairs": [(p[0], p[1]) for p in novel_pairs],
            })

    # Calculate discrimination score
    # Based on how well variants separate normal from anomalous behavior
    # Higher score = better discrimination
    if total_cases > 0:
        dominant_coverage = sum(
            variant_counts[v] for v in dominant_variants
        ) / total_cases
        anomalous_count = sum(a["count"] for a in anomalous)
        anomalous_ratio = anomalous_count / total_cases
        
        # Discrimination score: high coverage with low anomalous ratio
        discrimination_score = dominant_coverage * (1 - min(anomalous_ratio, 1.0))
    else:
        discrimination_score = 0.0

    return VariantResult(
        total_variants=total_variants,
        anomalous_variants=tuple(anomalous),
        discrimination_score=discrimination_score,
    )
