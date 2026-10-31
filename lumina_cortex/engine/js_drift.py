"""
The Thesis method's concept drift: Jensen-Shannon divergence between time windows.

THESIS:58-64 detects drift by "Jensen-Shannon divergence entre janelas temporais" and
types each drift point sudden or gradual, with its divergence and the activities
affected. Everything the thesis leaves open is interpretation (decision 13 of
``.scratch/thesis/decisions.md``; ``docs/thesis-method.md``, "Concept drift"):

- the log is cut into consecutive windows of ``JsDrift.window_seconds`` (300 s in ``thesis-v1``) from
  its first event; empty windows are skipped, so each window is compared with the
  previous non-empty one;
- each window is its activities' relative frequencies; JS uses log base 2, so it lies
  in [0, 1] (disjoint windows give 1.0, as in the thesis's Zeek table);
- **sudden**: JS between a window and the previous one is >= ``js_min`` (0.2);
- **gradual**: no such jump, but JS between the regime's first window (the start of
  the log, or the window of the last drift) and the current one is >= ``js_min``
  with at least ``gradual_windows`` (3) windows between them;
- the drift's timestamp is the first event of the window where it is detected;
- the affected activities are the ``top_activities`` (3) largest terms of the
  divergence (each activity's term is >= 0 and the terms sum to the divergence).

The Product method keeps the chi-square detector of ``lumina_cortex.engine.drift``.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from datetime import datetime
from typing import Dict, List, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, TIMESTAMP
from lumina_cortex.config.thresholds import THESIS_METHOD_V1, JsDrift
from lumina_cortex.models import AffectedActivity, DriftPoint, DriftResult

DETECTOR = "jensen_shannon"
SUDDEN, GRADUAL = "sudden", "gradual"


def js_terms(p: Dict[str, float], q: Dict[str, float]) -> Dict[str, float]:
    """Each activity's term of the base-2 Jensen-Shannon divergence of ``p`` and ``q``."""
    terms: Dict[str, float] = {}
    for a in set(p) | set(q):
        pa, qa = p.get(a, 0.0), q.get(a, 0.0)
        m = (pa + qa) / 2
        term = 0.0
        if pa > 0:
            term += 0.5 * pa * math.log2(pa / m)
        if qa > 0:
            term += 0.5 * qa * math.log2(qa / m)
        terms[a] = max(term, 0.0)
    return terms


def _distribution(activities: List[str]) -> Dict[str, float]:
    counts = Counter(activities)
    total = sum(counts.values())
    return {a: n / total for a, n in counts.items()}


def detect_js_drift(df: pd.DataFrame, *, params: JsDrift = THESIS_METHOD_V1.js_drift) -> DriftResult:
    """Drift points of the log by Jensen-Shannon divergence between time windows."""
    start = time.perf_counter()
    t = params
    window_s = t.window_seconds

    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if TIMESTAMP not in df.columns:
        raise ValueError(f"DataFrame missing {TIMESTAMP!r} column")

    def result(first_ts, points: Tuple[DriftPoint, ...], n_windows: int) -> DriftResult:
        n = len(df)
        return DriftResult(
            count=len(points),
            first_ts=first_ts,
            drift_points=tuple(p.timestamp for p in points),
            time_s=time.perf_counter() - start,
            n_events=n,
            n_windows=n_windows,
            per_1k_events=round(len(points) * 1000 / n, 6) if n else 0.0,
            detector=DETECTOR,
            points=points,
            window_seconds=window_s,
        )

    if len(df) == 0:
        return result(None, (), 0)

    ordered = pd.DataFrame({
        TIMESTAMP: pd.to_datetime(df[TIMESTAMP]),
        ACTIVITY: df[ACTIVITY].astype(str),
    }).sort_values(TIMESTAMP, kind="stable")
    t0 = ordered[TIMESTAMP].iloc[0]
    index = ((ordered[TIMESTAMP] - t0).dt.total_seconds() // window_s).astype(int)

    windows: List[Tuple[datetime, Dict[str, float]]] = [
        (group[TIMESTAMP].iloc[0].to_pydatetime(), _distribution(list(group[ACTIVITY])))
        for _, group in ordered.groupby(index, sort=True)
    ]

    points: List[DriftPoint] = []
    regime = 0  # index of the regime's first window
    for i in range(1, len(windows)):
        ts, current = windows[i]
        terms = js_terms(windows[i - 1][1], current)
        kind, before = SUDDEN, windows[i - 1][1]
        if sum(terms.values()) < t.js_min:
            if i - regime < t.gradual_windows:
                continue
            terms = js_terms(windows[regime][1], current)
            kind, before = GRADUAL, windows[regime][1]
            if sum(terms.values()) < t.js_min:
                continue
        top = sorted(terms.items(), key=lambda kv: (-kv[1], kv[0]))[: t.top_activities]
        points.append(DriftPoint(
            timestamp=ts,
            type=kind,
            divergence=min(sum(terms.values()), 1.0),
            affected_activities=tuple(
                AffectedActivity(a, c, before.get(a, 0.0), current.get(a, 0.0))
                for a, c in top if c > 0
            ),
        ))
        regime = i

    return result(t0.to_pydatetime(), tuple(points), len(windows))
