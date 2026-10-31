"""
Threat assessment orchestrator.

Runs all engines, builds AnalysisResult, classifies, and computes confidence.
Records errors in metadata.errors for non-rule-input failures.
"""

import time
from typing import Any, Dict, Optional, Set, Union

import pandas as pd

from lumina_cortex.config.thresholds import Thresholds
from lumina_cortex.engine.variants import analyze_variants
from lumina_cortex.engine.graph import extract_graph_metrics
from lumina_cortex.engine.dfg import discover_dfg
from lumina_cortex.engine.beacon import add_beacons, detect_beacons
from lumina_cortex.engine.mitre import assess_mitre
from lumina_cortex.evidence import collect_evidence
from lumina_cortex.mitre.catalog import TTPCatalog, load_attack_ttps
from lumina_cortex.mitre.coverage import list_coverage_gaps
from lumina_cortex.methods import MethodDescription, describe_method
from lumina_cortex.models import (
    AnalysisMethod,
    AnalysisResult,
    MITREResult,
    ThreatAssessment,
    Verdict,
)
from lumina_cortex.verdict.classifier import classify, decision_inputs
from lumina_cortex.columns import ACTIVITY


def assess_threat(
    df: pd.DataFrame,
    *,
    thresholds: Optional[Thresholds] = None,
    catalog: Optional[TTPCatalog] = None,
    source_type: Optional[str] = None,
    method: Union[AnalysisMethod, str, MethodDescription] = AnalysisMethod.PRODUCT,
) -> ThreatAssessment:
    """
    Assess threat level of an event log using all engines.

    Runs the analysis pipeline, with the engines the method's description
    (``lumina_cortex.methods.describe_method``) names:
    1. drift - concept drift detection (Product: chi-square over 10 windows proportional
       to the log; product-v1: over 500-event windows; thesis-v1: Jensen-Shannon between
       5-minute windows)
    2. analyze_variants - variant analysis
    3. extract_graph_metrics - graph metrics
    4. scorer - MITRE TTP scoring (Product: pattern coverage x edge match over the
       eligible patterns; product-v1: Jaccard x edges; thesis-v1: three components)
    5. discover_dfg - DFG edges (fitness/precision are opt-in, not computed here)
    6. assess_mitre - MITRE conformance (pm4py token-based replay, the method's values);
       then, for the Product method, the Beacon detector, whose beacon counts as
       "T1071 (beacon)" above even when the replay failed
    7. classify - combined verdict
    8. evidence - the Thesis method's experiment methods, after the verdict

    Records errors in metadata.errors for non-critical failures.

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name, time:timestamp.
        thresholds: Threshold configuration (Product method; default: the method's own, PRODUCT_V2_THRESHOLDS).
        catalog: MITRE ATT&CK TTP catalog (default: load_attack_ttps()).
        source_type: Source type for coverage gap analysis.
        method: The analysis method (``AnalysisMethod``; default the Product method).
            ``thesis-v1`` runs with the frozen thesis thresholds (THESIS_THRESHOLDS_V1,
            absolute drift mode) and refuses a ``thresholds`` override. A frozen
            version's description (``lumina_cortex.methods.PRODUCT_V1``, the evaluation
            only) runs as described and also refuses an override.

    Returns:
        ThreatAssessment with verdict, confidence, and all engine results.
    """
    start_time = time.perf_counter()
    
    described = describe_method(method)
    t = described.thresholds(thresholds)
    cat = catalog or load_attack_ttps()
    
    errors: list[str] = []
    metadata: Dict[str, Any] = {}

    # Run engines with error handling
    drift_result = None
    variants_result = None
    graph_result = None
    scorer_result = None
    dfg_result = None
    mitre_result = None
    gap_report = None

    # 1. Drift detection, the method's detector
    try:
        drift_result = described.detect_drift(df, t)
    except Exception as e:
        errors.append(f"drift: {str(e)}")

    # 2. Variant analysis
    try:
        variants_result = analyze_variants(df, thresholds=t)
    except Exception as e:
        errors.append(f"variants: {str(e)}")

    # 3. Graph metrics
    try:
        graph_result = extract_graph_metrics(df, thresholds=t)
    except Exception as e:
        errors.append(f"graph: {str(e)}")

    # 4. Attack pattern scoring, the method's scorer
    try:
        scorer_result = described.score(df, cat, t)
    except Exception as e:
        errors.append(f"scorer: {str(e)}")

    # 5. DFG discovery
    try:
        dfg_result = discover_dfg(df, thresholds=t)
    except Exception as e:
        errors.append(f"dfg: {str(e)}")

    # 6. MITRE conformance (token-based replay on each catalog pattern)
    try:
        mitre_result = assess_mitre(df, catalog=cat, thresholds=t, conformance=described.mitre)
    except Exception as e:
        errors.append(f"mitre: {str(e)}")
        # The replay could not run: nothing is above, and the result says why. A beacon
        # found below is still carried into it (spec story 21).
        mitre_result = MITREResult(
            threat_level=None, models_above=0, total_models=0, top_matches=(), time_s=0.0,
            conformance_error=f"mitre: {str(e)}",
        )

    # 6b. Beacons (the Product method v2 only): a beacon is "T1071 (beacon)" above,
    # whether or not the replay ran
    if described.beacon is not None:
        try:
            beacons = detect_beacons(df, described.beacon)
            mitre_result = add_beacons(mitre_result, beacons, described.mitre)
        except Exception as e:
            errors.append(f"beacon: {str(e)}")

    # 7. Coverage gaps
    try:
        gap_report = list_coverage_gaps(df, catalog=cat, source_type=source_type)
    except Exception as e:
        errors.append(f"coverage: {str(e)}")

    # Build placeholder results for failed engines
    from lumina_cortex.models import DriftResult, VariantResult, GraphResult
    from lumina_cortex.models import ScorerResult, DFGResult

    if drift_result is None:
        drift_result = DriftResult(count=0, first_ts=None, drift_points=(), time_s=0.0)
    if variants_result is None:
        variants_result = VariantResult(total_variants=0, anomalous_variants=(), discrimination_score=0.0)
    if graph_result is None:
        graph_result = GraphResult(top_hubs=(), hub_and_spoke_detected=False, compromised_nodes=())
    if scorer_result is None:
        scorer_result = ScorerResult(patterns_checked=0, top_score=0.0, top_name="", top5=(), time_s=0.0)
    if dfg_result is None:
        dfg_result = DFGResult(
            fitness=None, precision=None, f_score=None, edges=0, time_s=0.0,
            conformance_error="DFG engine failed; see errors",
        )

    # The verdict's vocabulary input: distinct activities in the analyzed log
    unique_activities = int(df[ACTIVITY].nunique()) if ACTIVITY in df.columns else 0

    # Build AnalysisResult
    analysis = AnalysisResult(
        dfg=dfg_result,
        mitre=mitre_result,
        scorer=scorer_result,
        drift=drift_result,
        variants=variants_result,
        graph=graph_result,
        unique_activities=unique_activities,
    )

    # Classify
    verdict = classify(analysis, thresholds=t)

    # Compute confidence
    # Based on how many engines ran successfully and the strength of signals
    confidence = _compute_confidence(
        verdict=verdict,
        analysis=analysis,
        errors=errors,
    )

    # Build metadata
    metadata["errors"] = errors
    metadata["total_time_s"] = time.perf_counter() - start_time
    metadata["n_events"] = len(df)
    metadata["source_type"] = source_type
    
    # The vocabulary as the stored assessment reports it (metadata.unique_activities, which
    # ThreatAssessment carries; AnalysisResult is not serialized): read from the analysis,
    # the one source the classifier also reads.
    if ACTIVITY in df.columns:
        metadata["unique_activities"] = analysis.unique_activities

    # The rule's inputs as the classifier saw them, so any verdict can be explained
    metadata["decision_inputs"] = decision_inputs(analysis, thresholds=t)
    
    # Add coverage gap info: the count, and the gaps themselves (TTP id, name, missing activities)
    if gap_report:
        metadata["coverage_gaps"] = len(gap_report.gaps)
        metadata["coverage_gap_list"] = [g.to_dict() for g in gap_report.gaps]

    # The experiment methods are evidence of the Thesis method only, after its verdict
    evidence = collect_evidence(df) if described.evidence else {}

    return ThreatAssessment(
        verdict=verdict,
        confidence=confidence,
        dfg=dfg_result,
        mitre=mitre_result,
        scorer=scorer_result,
        drift=drift_result,
        variants=variants_result,
        graph=graph_result,
        metadata=metadata,
        method=described.method,
        evidence=evidence,
    )


def _compute_confidence(
    verdict: Verdict,
    analysis: AnalysisResult,
    errors: list[str],
) -> float:
    """
    Compute confidence score for the verdict.

    Confidence is based on:
    - Number of engines that ran successfully
    - Strength of signals (drift count, score, etc.)
    - Consistency of signals across engines

    Returns:
        Float between 0.0 and 1.0.
    """
    # Base confidence from engine success
    engine_count = 6  # Total engines
    failed = len(errors)
    base_confidence = (engine_count - failed) / engine_count

    # Adjust based on verdict
    if verdict == Verdict.ATTACK_DETECTED:
        # High confidence if all signals agree
        inputs = decision_inputs(analysis)
        signal_count = sum([
            inputs["score_high"],
            inputs["drift_high"],
            inputs["mitre_match"] or inputs["vocab_ok"],
        ])
        confidence = base_confidence * (0.5 + 0.5 * signal_count / 3)
    
    elif verdict == Verdict.SUSPICIOUS_DRIFT:
        # Moderate confidence - drift detected but no scorer match
        confidence = base_confidence * 0.6
    
    elif verdict == Verdict.SUSPICIOUS_SCORE:
        # Moderate confidence - scorer match but no drift
        confidence = base_confidence * 0.6
    
    else:  # BENIGN
        # Lower confidence - absence of evidence is not evidence of absence
        # But still reasonable if many engines ran
        confidence = base_confidence * 0.4

    return round(min(confidence, 1.0), 3)
