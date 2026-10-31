"""
DFG discovery using pm4py.

Discovers the Directly-Follows Graph. Measuring the log against its inductive net with
pm4py's token-based replay (fitness and precision) is opt-in: on few, very long cases
(host or ip case strategies) the replay runs for minutes, the DFG does not feed the
verdict, and so the product analysis does not compute it.
"""

import time
from pathlib import Path
from typing import Optional, Union

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE, TIMESTAMP
from lumina_cortex.config.thresholds import Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.models import DFGResult

#: ``conformance_error`` when the caller did not opt in to the conformance check.
CONFORMANCE_NOT_COMPUTED = (
    "not computed: fitness and precision (token-based replay) are opt-in and "
    "not part of the product analysis"
)


def discover_dfg(
    df: pd.DataFrame,
    *,
    thresholds: Optional[Thresholds] = None,
    conformance: bool = False,
) -> DFGResult:
    """
    Discover Directly-Follows Graph from event log.

    Uses pm4py to discover the DFG. With ``conformance=True`` it also calculates
    fitness and precision using token-based replay on an inductive net; otherwise
    they are ``None`` and ``conformance_error`` is ``CONFORMANCE_NOT_COMPUTED``.

    Always samples if the log is large (>10k events) for performance.

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name, time:timestamp.
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).
        conformance: Opt in to pm4py's token-based replay (default off; it can run
            for minutes on long cases).

    Returns:
        DFGResult with fitness, precision, f_score, edges, and timing.
    """
    start_time = time.perf_counter()
    
    t = thresholds or THESIS_THRESHOLDS_V1

    # Validate DataFrame
    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")
    if TIMESTAMP not in df.columns:
        raise ValueError(f"DataFrame missing {TIMESTAMP!r} column")
    if len(df) == 0:
        return DFGResult(
            fitness=None,
            precision=None,
            f_score=None,
            edges=0,
            time_s=time.perf_counter() - start_time,
            conformance_error="empty log",
        )

    df_sampled = sample_cases(df, t)

    keys = dict(case_id_key=CASE, activity_key=ACTIVITY, timestamp_key=TIMESTAMP)
    try:
        import pm4py

        log = df_sampled[[CASE, ACTIVITY, TIMESTAMP]].copy()
        if not pd.api.types.is_datetime64_any_dtype(log[TIMESTAMP]):
            log[TIMESTAMP] = pd.to_datetime(log[TIMESTAMP])
        dfg, _start_activities, _end_activities = pm4py.discover_dfg(log, **keys)
    except Exception as exc:  # pm4py missing or the discovery itself failed
        return DFGResult(
            fitness=None,
            precision=None,
            f_score=None,
            edges=0,
            time_s=time.perf_counter() - start_time,
            conformance_error=f"DFG discovery failed: {exc}",
        )

    edges = len(dfg) if dfg else 0
    if conformance:
        fitness, precision, f_score, error = _conformance(pm4py, log, keys)
    else:
        fitness, precision, f_score, error = None, None, None, CONFORMANCE_NOT_COMPUTED
    return DFGResult(
        fitness=fitness,
        precision=precision,
        f_score=f_score,
        edges=edges,
        time_s=time.perf_counter() - start_time,
        conformance_error=error,
    )


def sample_cases(df: pd.DataFrame, thresholds: Thresholds) -> pd.DataFrame:
    """Whole cases, in a seeded random order, up to ``sample_max_events`` events.

    The log itself when it is no larger than that. Shared by the DFG and the MITRE
    conformance so that both replay the same sample of a large log.
    """
    t = thresholds
    if len(df) <= t.sample_max_events:
        return df

    cases = df[CASE].unique().tolist()
    import random
    rng = random.Random(t.sample_seed)
    rng.shuffle(cases)

    sizes = df[CASE].value_counts()
    sampled_cases: list = []
    total_events = 0
    for case_id in cases:
        case_len = int(sizes[case_id])
        if total_events + case_len > t.sample_max_events:
            break
        sampled_cases.append(case_id)
        total_events += case_len

    if sampled_cases:
        return df[df[CASE].isin(sampled_cases)]
    return df.head(t.sample_max_events)


def _conformance(pm4py, log: pd.DataFrame, keys: dict):
    """Fitness, precision and F-score of the log replayed on its inductive net.

    Both come from pm4py's token-based replay. When the check cannot run they are
    ``None`` and the error says why: a made-up value would read as a real measurement.
    """
    try:
        tree = pm4py.discover_process_tree_inductive(log, **keys)
        net, initial, final = pm4py.convert_to_petri_net(tree)
        fitness = float(pm4py.fitness_token_based_replay(log, net, initial, final, **keys)["log_fitness"])
        precision = float(pm4py.precision_token_based_replay(log, net, initial, final, **keys))
    except Exception as exc:
        return None, None, None, f"conformance check failed: {exc}"
    f_score = 2 * fitness * precision / (fitness + precision) if (fitness + precision) > 0 else 0.0
    return round(fitness, 6), round(precision, 6), round(f_score, 6), None


def dfg_top_edges(
    df: pd.DataFrame,
    *,
    limit: int = 25,
) -> list[tuple[str, str, int]]:
    """Top directly-follows edges as (source, target, count) for UI / forensic JSON."""
    if df is None or len(df) == 0:
        return []
    if ACTIVITY not in df.columns or CASE not in df.columns:
        return []
    keys = dict(case_id_key=CASE, activity_key=ACTIVITY, timestamp_key=TIMESTAMP)
    try:
        import pm4py

        log = df[[CASE, ACTIVITY, TIMESTAMP]].copy()
        if not pd.api.types.is_datetime64_any_dtype(log[TIMESTAMP]):
            log[TIMESTAMP] = pd.to_datetime(log[TIMESTAMP])
        dfg, _start, _end = pm4py.discover_dfg(log, **keys)
    except Exception:
        dfg = _manual_dfg(df)
    items = [
        (str(a), str(b), int(count))
        for (a, b), count in (dfg or {}).items()
    ]
    items.sort(key=lambda x: x[2], reverse=True)
    return items[:limit]


def _manual_dfg(df: pd.DataFrame) -> dict[tuple[str, str], int]:
    work = df.copy()
    if TIMESTAMP in work.columns:
        work = work.sort_values([CASE, TIMESTAMP])
    edges: dict[tuple[str, str], int] = {}
    for _, group in work.groupby(CASE, sort=False):
        acts = group[ACTIVITY].astype(str).tolist()
        for i in range(len(acts) - 1):
            pair = (acts[i], acts[i + 1])
            edges[pair] = edges.get(pair, 0) + 1
    return edges


def export_dfg_map(
    df: pd.DataFrame,
    path: Union[str, Path],
) -> tuple[DFGResult, Optional[str]]:
    """
    Discover DFG and export a forensic attack-flow PNG for Red/Blue handover.

    Encapsulates ``pm4py.save_vis_dfg`` — callers never import PM4Py.
    On failure, writes a Graphviz-less edge list beside ``path`` and returns that path.
    """
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    result = discover_dfg(df)

    if df is None or len(df) == 0:
        return result, None

    keys = dict(case_id_key=CASE, activity_key=ACTIVITY, timestamp_key=TIMESTAMP)
    try:
        import pm4py

        log = df[[CASE, ACTIVITY, TIMESTAMP]].copy()
        if not pd.api.types.is_datetime64_any_dtype(log[TIMESTAMP]):
            log[TIMESTAMP] = pd.to_datetime(log[TIMESTAMP])
        dfg, start_activities, end_activities = pm4py.discover_dfg(log, **keys)
        pm4py.save_vis_dfg(dfg, start_activities, end_activities, str(out))
        return result, str(out.resolve())
    except Exception:
        fallback = out.with_suffix(".edges.txt")
        try:
            import pm4py

            log = df[[CASE, ACTIVITY, TIMESTAMP]].copy()
            if not pd.api.types.is_datetime64_any_dtype(log[TIMESTAMP]):
                log[TIMESTAMP] = pd.to_datetime(log[TIMESTAMP])
            dfg, _, _ = pm4py.discover_dfg(log, **keys)
            lines = [
                f"{a} -> {b}\t{count}"
                for (a, b), count in sorted(dfg.items(), key=lambda x: -x[1])[:50]
            ]
        except Exception:
            lines = [f"edges={result.edges}"]
        fallback.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return result, str(fallback.resolve())
