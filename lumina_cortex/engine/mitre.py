"""
MITRE ATT&CK conformance by pm4py's token-based replay (TBR).

Each catalog pattern becomes a sequential Petri net: one transition per activity, in
the order its edges give (catalog order where the edges say nothing). Each case is
projected onto the pattern's activities, only cases holding at least two distinct
activities of the pattern are kept, and that projected log is replayed on the net with
``pm4py.fitness_token_based_replay``. A pattern is "above" when its log fitness reaches
``MitreConformance.fitness_min``; the threat level comes from the count of patterns
above and ``MitreConformance.level_bands``. Each method passes its own values
(``THESIS_METHOD_V1.mitre``, ``PRODUCT_MITRE_CONFORMANCE``).

Decisions 7-9 of ``.scratch/thesis/decisions.md`` (THESIS:691 recommends TBR over
alignments). The net's shape, the projection, the 0.8 threshold and the bands are
interpretation: the thesis defines none of them (see ``docs/thesis-method.md``).

A pattern with fewer than two activities never has a case to replay, so it can never
be above. Large logs are sampled by whole cases as the DFG samples them.
"""

import time
from typing import List, Optional, Sequence, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE, TIMESTAMP
from lumina_cortex.config.thresholds import MitreConformance, Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.engine.dfg import sample_cases
from lumina_cortex.mitre.catalog import TTPCatalog, TTPPattern, load_attack_ttps
from lumina_cortex.models import MITREResult


def assess_mitre(
    df: pd.DataFrame,
    catalog: Optional[TTPCatalog] = None,
    *,
    thresholds: Optional[Thresholds] = None,
    conformance: MitreConformance,
) -> MITREResult:
    """
    Replay the log on every catalog pattern and count the patterns above.

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name, time:timestamp.
        catalog: MITRE ATT&CK TTP catalog (default: load_attack_ttps()).
        thresholds: Threshold configuration, for sampling (default: THESIS_THRESHOLDS_V1).
        conformance: The method's fitness threshold and level bands.

    Returns:
        MITREResult with the patterns above and their fitness, every replayed pattern,
        and the threat level. If pm4py fails, ``conformance_error`` says why and no
        fitness or level is reported.
    """
    start_time = time.perf_counter()
    t = thresholds or THESIS_THRESHOLDS_V1
    cat = catalog or load_attack_ttps()
    patterns = list(cat.techniques) + list(cat.procedures)
    total_models = len(patterns)

    def failed(reason: str) -> MITREResult:
        return MITREResult(
            threat_level=None,
            models_above=0,
            total_models=total_models,
            top_matches=(),
            time_s=time.perf_counter() - start_time,
            conformance_error=reason,
        )

    for column in (CASE, ACTIVITY, TIMESTAMP):
        if column not in df.columns:
            return failed(f"DataFrame missing {column!r} column")

    log = sample_cases(df, t)[[CASE, ACTIVITY, TIMESTAMP]].copy()
    try:
        import pm4py

        if not pd.api.types.is_datetime64_any_dtype(log[TIMESTAMP]):
            log[TIMESTAMP] = pd.to_datetime(log[TIMESTAMP])
        replayed: List[Tuple[str, float, int]] = []
        for pattern in patterns:
            projected = _project(log, pattern.activities)
            if projected.empty:
                continue
            fitness = _replay(pm4py, projected, sequence_of(pattern))
            replayed.append((pattern.ttp_id, round(fitness, 6), int(projected[CASE].nunique())))
    except Exception as exc:  # pm4py missing or the replay itself failed
        return failed(f"conformance check failed: {exc}")

    above = sorted(
        ((ttp_id, fitness) for ttp_id, fitness, _ in replayed if fitness >= conformance.fitness_min),
        key=lambda m: (-m[1], m[0]),
    )
    return MITREResult(
        threat_level=threat_level(len(above), conformance),
        models_above=len(above),
        total_models=total_models,
        top_matches=tuple(above),
        time_s=time.perf_counter() - start_time,
        replayed=tuple(replayed),
    )


def threat_level(models_above: int, conformance: MitreConformance) -> str:
    """none, low, medium or high from the count of patterns above and the bands."""
    low, medium, high = conformance.level_bands
    if models_above >= high:
        return "high"
    if models_above >= medium:
        return "medium"
    if models_above >= low:
        return "low"
    return "none"


def sequence_of(pattern: TTPPattern) -> List[str]:
    """The pattern's activities in the order of its edges, catalog order breaking ties.

    Interpretation: the catalog lists edges, not a sequence. An activity comes as soon
    as every edge into it from a remaining activity has been placed (Kahn's order);
    a pattern without edges keeps the catalog's order of its activities.
    """
    remaining = list(dict.fromkeys(pattern.activities))
    order: List[str] = []
    while remaining:
        ready = next(
            (a for a in remaining if not any(dst == a and src in remaining for src, dst in pattern.edges)),
            remaining[0],  # a cycle in the edges: fall back to catalog order
        )
        order.append(ready)
        remaining.remove(ready)
    return order


def _project(log: pd.DataFrame, activities: Sequence[str]) -> pd.DataFrame:
    """The log's events of these activities, in cases holding at least two of them."""
    projected = log[log[ACTIVITY].isin(set(activities))]
    if projected.empty:
        return projected
    return projected[projected.groupby(CASE)[ACTIVITY].transform("nunique") >= 2]


def _replay(pm4py, projected: pd.DataFrame, sequence: List[str]) -> float:
    """pm4py's TBR log fitness of the projected log on the sequential net of ``sequence``."""
    from pm4py.objects.petri_net.obj import Marking, PetriNet
    from pm4py.objects.petri_net.utils import petri_utils

    net = PetriNet("mitre_pattern")
    places = [PetriNet.Place(f"p{i}") for i in range(len(sequence) + 1)]
    net.places.update(places)
    for i, activity in enumerate(sequence):
        transition = PetriNet.Transition(f"t{i}", activity)
        net.transitions.add(transition)
        petri_utils.add_arc_from_to(places[i], transition, net)
        petri_utils.add_arc_from_to(transition, places[i + 1], net)

    result = pm4py.fitness_token_based_replay(
        projected, net, Marking({places[0]: 1}), Marking({places[-1]: 1}),
        case_id_key=CASE, activity_key=ACTIVITY, timestamp_key=TIMESTAMP,
    )
    return float(result["log_fitness"])
