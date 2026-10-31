"""
Verdict classifier implementing the combined decision rule.

The combined rule (S3) from the thesis:
    ATTACK_DETECTED = score_high AND (mitre_match OR vocab_ok) AND drift_high
    SUSPICIOUS_DRIFT = drift_high AND NOT score_high AND NOT mitre_match
    SUSPICIOUS_SCORE = score_high AND NOT drift_high
    BENIGN = else

This rule achieved 0 false negatives on the thesis validation datasets.
"""

from typing import Any, Dict, Optional, Tuple

from lumina_cortex.config.thresholds import (
    THESIS_THRESHOLDS_V1,
    ProductThresholds,
    Thresholds,
)
from lumina_cortex.models import AnalysisResult, DriftMode, DriftResult, Verdict


def drift_fraction(drift: DriftResult) -> float:
    """The fraction of adjacent-window comparisons that drifted.

    The proportional drift reports it; for a fixed-window result it is the count over
    the n_windows - 1 comparisons. No comparison is a fraction of 0.
    """
    if drift.drift_fraction is not None:
        return drift.drift_fraction
    comparisons = drift.n_windows - 1
    return round(drift.count / comparisons, 6) if comparisons > 0 else 0.0


def decision_inputs(
    result: AnalysisResult,
    thresholds: Optional[Thresholds] = None,
) -> Dict[str, Any]:
    """
    Extract decision inputs from an AnalysisResult.

    Returns the boolean flags used by the combined rule:
    - score_high: top_score >= thresholds.scorer_top_min
    - mitre_match: models_above >= thresholds.mitre_models_min
    - vocab_ok: unique_activities >= thresholds.vocab_min
    - drift_high, by the drift mode: absolute, drift_count >= thresholds.drift_count_min;
      per_1k, drifts per 1,000 events >= thresholds.drift_per_1k_min; per_window, the
      fraction of adjacent-window comparisons that drifted >= drift_fraction_min, a field
      of ``ProductThresholds`` (the Product method's; per_window with plain thesis
      Thresholds is a ValueError)

    Also returns the raw values for debugging (in per_window mode also the drift
    fraction, the comparisons and the fraction threshold).

    Args:
        result: AnalysisResult from running engines.
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).

    Returns:
        Dict with boolean flags and raw values.
    """
    t = thresholds or THESIS_THRESHOLDS_V1

    # Extract raw values
    top_score = result.scorer.top_score
    models_above = result.mitre.models_above
    drift_count = result.drift.count

    # The vocabulary is the number of distinct activities in the analyzed log
    # (before 0.2.0 it was len(scorer.top5), which is always 5).
    vocab_count = result.unique_activities

    # The Product method's thresholds carry its own fields; the thesis ones do not.
    product = t if isinstance(t, ProductThresholds) else None

    # Boolean flags
    score_high = top_score >= t.scorer_top_min
    mitre_match = models_above >= t.mitre_models_min
    vocab_ok = vocab_count >= t.vocab_min
    
    # Drift: absolute, per 1,000 events, or the fraction of comparisons (per_window)
    per_window: Dict[str, Any] = {}
    if t.drift_mode is DriftMode.PER_WINDOW:
        if product is None:
            raise ValueError(
                "per_window drift mode needs ProductThresholds (drift_fraction_min): "
                "it is the Product method's condition"
            )
        fraction_min = product.drift_fraction_min
        fraction = drift_fraction(result.drift)
        drift_high = fraction >= fraction_min
        comparisons = result.drift.n_comparisons
        per_window = {
            "drift_fraction": fraction,
            "drift_comparisons": max(result.drift.n_windows - 1, 0) if comparisons is None else comparisons,
        }
    elif t.drift_mode is DriftMode.PER_1K and result.drift.n_events > 0:
        drift_value = result.drift.count / max(result.drift.n_events / 1000, 1)
        drift_high = drift_value >= t.drift_per_1k_min
    else:
        drift_high = drift_count >= t.drift_count_min

    used = {
        "scorer_top_min": t.scorer_top_min,
        "drift_count_min": t.drift_count_min,
        "vocab_min": t.vocab_min,
        "mitre_models_min": t.mitre_models_min,
        "drift_mode": t.drift_mode.value,
    }
    if per_window:
        used["drift_fraction_min"] = fraction_min

    return {
        # Boolean flags
        "score_high": score_high,
        "mitre_match": mitre_match,
        "vocab_ok": vocab_ok,
        "drift_high": drift_high,
        # Raw values
        "top_score": top_score,
        "models_above": models_above,
        "drift_count": drift_count,
        "vocab_count": vocab_count,
        **per_window,
        # Thresholds used
        "thresholds": used,
    }


def classify(
    result: AnalysisResult,
    thresholds: Optional[Thresholds] = None,
) -> Verdict:
    """
    Classify an AnalysisResult into a Verdict using the combined rule.

    The combined rule (S3) from the thesis:
        ATTACK_DETECTED = score_high AND (mitre_match OR vocab_ok) AND drift_high
        SUSPICIOUS_DRIFT = drift_high AND NOT score_high AND NOT mitre_match
        SUSPICIOUS_SCORE = score_high AND NOT drift_high
        BENIGN = else

    This implements the 16-row truth table for the four input flags.

    Args:
        result: AnalysisResult from running engines.
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).

    Returns:
        Verdict enum value.
    """
    # Get decision inputs
    inputs = decision_inputs(result, thresholds)
    
    score_high = inputs["score_high"]
    mitre_match = inputs["mitre_match"]
    vocab_ok = inputs["vocab_ok"]
    drift_high = inputs["drift_high"]

    # Combined rule (S3):
    # ATTACK_DETECTED = score_high AND (mitre_match OR vocab_ok) AND drift_high
    if score_high and (mitre_match or vocab_ok) and drift_high:
        return Verdict.ATTACK_DETECTED

    # SUSPICIOUS_DRIFT = drift_high AND NOT score_high AND NOT mitre_match
    if drift_high and not score_high and not mitre_match:
        return Verdict.SUSPICIOUS_DRIFT

    # SUSPICIOUS_SCORE = score_high AND NOT drift_high
    if score_high and not drift_high:
        return Verdict.SUSPICIOUS_SCORE

    # BENIGN = else
    return Verdict.BENIGN
