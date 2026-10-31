"""
The experiment's discovery layer, as evidence of the Thesis method.

Variants, the DFG with its token-based replay fitness and precision, the heuristics
net, the inductive models (tree, Petri net, BPMN), footprints, log skeleton and the
performance DFG, each from pm4py (decision 18; THESIS:657-671, 1028-1049). Each builder
returns a JSON-serialisable summary (counts, top-k, numbers), never a pm4py object, and
none of them feeds the verdict (decision 19).

Every builder runs on a sample of the log so that its cost is bounded: whole cases,
seeded, up to ``sample_max_events`` events of the frozen thesis thresholds (the
DFG's and MITRE conformance's sample, ``sample_cases``). The cost of the precision
replay and of the log skeleton grows with the square of a case's length (a 4,221-event
host case alone replays for minutes), so they further keep only whole cases whose
squared lengths fit a budget (``replay_sample``), and say so in their sample sizes.
"""

import time
from typing import Any, Dict, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE, TIMESTAMP
from lumina_cortex.config.thresholds import THESIS_THRESHOLDS_V1
from lumina_cortex.engine.dfg import sample_cases
from lumina_cortex.evidence import EVIDENCE_BUILDERS

#: How many entries a top-k list reports.
TOP_K = 10

_KEYS = dict(case_id_key=CASE, activity_key=ACTIVITY, timestamp_key=TIMESTAMP)


def _sample(df: pd.DataFrame) -> pd.DataFrame:
    """The event sample every discovery builder runs on, as pm4py receives it."""
    log = sample_cases(df, THESIS_THRESHOLDS_V1)[[CASE, ACTIVITY, TIMESTAMP]].copy()
    if not pd.api.types.is_datetime64_any_dtype(log[TIMESTAMP]):
        log[TIMESTAMP] = pd.to_datetime(log[TIMESTAMP])
    return log


def _size(log: pd.DataFrame) -> Dict[str, int]:
    return {"events": int(len(log)), "cases": int(log[CASE].nunique())}


def _top(items, k: int = TOP_K):
    """``(key, value)`` pairs by value descending, ties by key, at most ``k``."""
    return sorted(items, key=lambda kv: (-kv[1], kv[0]))[:k]


def build_variants(df: pd.DataFrame) -> Dict[str, Any]:
    """pm4py variants: how many, and the most frequent with their case counts."""
    import pm4py

    start = time.perf_counter()
    log = _sample(df)
    variants = pm4py.get_variants(log, **_KEYS)
    return {
        **_size(log),
        "total_variants": len(variants),
        "top": [{"variant": list(v), "count": int(c)} for v, c in _top(variants.items())],
        "time_s": round(time.perf_counter() - start, 6),
    }


def replay_sample(log: pd.DataFrame, budget: int) -> pd.DataFrame:
    """Whole cases, in a seeded order, whose squared lengths add up to at most ``budget``.

    A case too long for what is left of the budget is skipped, not cut: a prefix of a
    case would be measured as if it were the case. Empty when no case fits.
    """
    import random

    sizes = log[CASE].value_counts()
    cases = sorted(sizes.index.tolist(), key=str)
    random.Random(THESIS_THRESHOLDS_V1.sample_seed).shuffle(cases)
    kept, used = [], 0
    for case_id in cases:
        cost = int(sizes[case_id]) ** 2
        if used + cost <= budget:
            kept.append(case_id)
            used += cost
    return log[log[CASE].isin(kept)]


#: Budget of the precision replay, in squared case lengths. pm4py's precision replays
#: every prefix of every case, so its cost grows with the square of a case's length:
#: measured at about 35 us per unit, 50,000 is under 2 s.
PRECISION_REPLAY_BUDGET = 50_000


def _conformance(pm4py, log: pd.DataFrame, replay: pd.DataFrame):
    """Token-based replay fitness of ``log`` and precision of ``replay`` on the inductive
    net of ``log``; ``(fitness, precision, f_score, error)``, never a made-up value.

    The F-score needs both on the same cases, so it is ``None`` when precision only
    replayed part of the sample.
    """
    try:
        tree = pm4py.discover_process_tree_inductive(log, **_KEYS)
        net, initial, final = pm4py.convert_to_petri_net(tree)
        fitness = float(
            pm4py.fitness_token_based_replay(log, net, initial, final, **_KEYS)["log_fitness"]
        )
    except Exception as exc:
        return None, None, None, f"conformance check failed: {exc}"
    if not len(replay):
        longest = int(PRECISION_REPLAY_BUDGET ** 0.5)
        return round(fitness, 6), None, None, (
            f"precision not computed: every case is longer than the {longest} events "
            f"the precision replay budget allows"
        )
    try:
        precision = float(
            pm4py.precision_token_based_replay(replay, net, initial, final, **_KEYS)
        )
    except Exception as exc:
        return round(fitness, 6), None, None, f"precision check failed: {exc}"
    f_score = None
    if len(replay) == len(log):
        f_score = 2 * fitness * precision / (fitness + precision) if fitness + precision else 0.0
        f_score = round(f_score, 6)
    return round(fitness, 6), round(precision, 6), f_score, None


def build_dfg(df: pd.DataFrame) -> Dict[str, Any]:
    """The DFG; fitness and precision by token-based replay on its inductive net.

    Fitness replays the whole sample (its cost is linear, THESIS:680-681); precision
    replays the cases that fit ``PRECISION_REPLAY_BUDGET`` (``precision_sample``).
    """
    import pm4py

    start = time.perf_counter()
    log = _sample(df)
    dfg, starts, ends = pm4py.discover_dfg(log, **_KEYS)
    replay = replay_sample(log, PRECISION_REPLAY_BUDGET)
    fitness, precision, f_score, error = _conformance(pm4py, log, replay)
    return {
        **_size(log),
        "edges": len(dfg),
        "start_activities": {a: int(n) for a, n in starts.items()},
        "end_activities": {a: int(n) for a, n in ends.items()},
        "top_edges": [
            {"source": a, "target": b, "count": int(c)} for (a, b), c in _top(dfg.items())
        ],
        "precision_sample": _size(replay),
        "fitness": fitness,
        "precision": precision,
        "f_score": f_score,
        "conformance_error": error,
        "time_s": round(time.perf_counter() - start, 6),
    }


def _net_size(net) -> Dict[str, int]:
    return {"places": len(net.places), "transitions": len(net.transitions), "arcs": len(net.arcs)}


def _merged(activity_dicts) -> Dict[str, int]:
    """pm4py's heuristics net keeps start and end activities as a list of dicts."""
    merged: Dict[str, int] = {}
    for counts in activity_dicts:
        for activity, n in counts.items():
            merged[activity] = merged.get(activity, 0) + int(n)
    return merged


def build_heuristics_net(df: pd.DataFrame) -> Dict[str, Any]:
    """The heuristics net's dependencies, and the size of its Petri net."""
    import pm4py

    start = time.perf_counter()
    log = _sample(df)
    hn = pm4py.discover_heuristics_net(log, **_KEYS)
    net, _im, _fm = pm4py.discover_petri_net_heuristics(log, **_KEYS)
    dependencies: Dict[Tuple[str, str], float] = {
        (source, target.node_name): float(edges[0].dependency_value)
        for source, node in hn.nodes.items()
        for target, edges in node.output_connections.items()
    }
    return {
        **_size(log),
        "activities": len(hn.nodes),
        "edges": len(dependencies),
        "start_activities": _merged(hn.start_activities),
        "end_activities": _merged(hn.end_activities),
        "top_dependencies": [
            {"source": a, "target": b, "dependency": round(v, 6)}
            for (a, b), v in _top(dependencies.items())
        ],
        "petri_net": _net_size(net),
        "time_s": round(time.perf_counter() - start, 6),
    }


def build_inductive(df: pd.DataFrame) -> Dict[str, Any]:
    """The inductive miner's process tree, and the size of its Petri net and BPMN."""
    import pm4py

    start = time.perf_counter()
    log = _sample(df)
    tree = pm4py.discover_process_tree_inductive(log, **_KEYS)
    net, _im, _fm = pm4py.convert_to_petri_net(tree)
    bpmn = pm4py.convert_to_bpmn(tree)
    return {
        **_size(log),
        "process_tree": str(tree),
        "petri_net": _net_size(net),
        "bpmn": {"nodes": len(bpmn.get_nodes()), "flows": len(bpmn.get_flows())},
        "time_s": round(time.perf_counter() - start, 6),
    }


def build_footprints(df: pd.DataFrame) -> Dict[str, Any]:
    """The footprint matrix's relation sizes, start and end activities."""
    import pm4py

    start = time.perf_counter()
    log = _sample(df)
    footprints = pm4py.discover_footprints(log)  # the standard column names
    return {
        **_size(log),
        "activities": len(footprints["activities"]),
        "directly_follows": len(footprints["dfg"]),
        "sequence": len(footprints["sequence"]),
        "parallel": len(footprints["parallel"]),
        "start_activities": sorted(footprints["start_activities"]),
        "end_activities": sorted(footprints["end_activities"]),
        "min_trace_length": int(footprints["min_trace_length"]),
        "time_s": round(time.perf_counter() - start, 6),
    }


#: Budget of the log skeleton, in squared case lengths. Its cost also grows with the
#: square of a case's length, but far slower than the precision replay: 22.7 million
#: units (the seed-42 10k brute force by host) took 5.8 s, so 4 million is about 1 s.
LOG_SKELETON_BUDGET = 4_000_000

_SKELETON_RELATIONS = (
    "equivalence", "always_after", "always_before", "never_together", "directly_follows",
)


def build_log_skeleton(df: pd.DataFrame) -> Dict[str, Any]:
    """How many constraints of each kind the log skeleton holds, and activity bounds."""
    import pm4py

    start = time.perf_counter()
    log = replay_sample(_sample(df), LOG_SKELETON_BUDGET)
    if not len(log):
        longest = int(round(LOG_SKELETON_BUDGET ** 0.5))
        raise ValueError(
            f"not computed: every case is longer than the {longest} events the "
            f"log skeleton budget allows"
        )
    skeleton = pm4py.discover_log_skeleton(log, **_KEYS)
    return {
        **_size(log),
        "constraints": {name: len(skeleton[name]) for name in _SKELETON_RELATIONS},
        "activ_freq": {
            activity: {"min": int(min(counts)), "max": int(max(counts))}
            for activity, counts in skeleton["activ_freq"].items()
        },
        "time_s": round(time.perf_counter() - start, 6),
    }


def build_performance_dfg(df: pd.DataFrame) -> Dict[str, Any]:
    """The performance DFG's edges with the longest median time between activities."""
    import pm4py

    start = time.perf_counter()
    log = _sample(df)
    performance, _starts, _ends = pm4py.discover_performance_dfg(log, **_KEYS)
    medians = {pair: float(stats["median"]) for pair, stats in performance.items()}
    return {
        **_size(log),
        "edges": len(performance),
        "slowest_edges": [
            {
                "source": a,
                "target": b,
                "median_s": round(median, 6),
                "mean_s": round(float(performance[(a, b)]["mean"]), 6),
                "max_s": round(float(performance[(a, b)]["max"]), 6),
            }
            for (a, b), median in _top(medians.items())
        ],
        "time_s": round(time.perf_counter() - start, 6),
    }


EVIDENCE_BUILDERS["variants"] = build_variants
EVIDENCE_BUILDERS["dfg"] = build_dfg
EVIDENCE_BUILDERS["heuristics_net"] = build_heuristics_net
EVIDENCE_BUILDERS["inductive"] = build_inductive
EVIDENCE_BUILDERS["footprints"] = build_footprints
EVIDENCE_BUILDERS["log_skeleton"] = build_log_skeleton
EVIDENCE_BUILDERS["performance_dfg"] = build_performance_dfg
