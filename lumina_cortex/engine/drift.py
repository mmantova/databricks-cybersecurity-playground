"""
Concept drift detection using a chi-square test on the activity distribution.

``detect_proportional_drift`` cuts the log into windows proportional to its length.
That is the Product method's drift. Thesis-v1 uses Jensen-Shannon in ``js_drift``.
"""

import time
from datetime import datetime

import numpy as np
import pandas as pd
from scipy import stats

from lumina_cortex.columns import ACTIVITY, TIMESTAMP
from lumina_cortex.config.thresholds import PRODUCT_V2_DRIFT, ProportionalDrift
from lumina_cortex.models import DriftResult


PROPORTIONAL_DETECTOR = "chi_square_proportional"


def detect_proportional_drift(
    df: pd.DataFrame,
    params: ProportionalDrift = PRODUCT_V2_DRIFT,
) -> DriftResult:
    """The Product method's drift: chi-square over windows proportional to the log.

    The log, in time order, is cut into ``params.windows`` consecutive windows of
    len(log) // ``params.windows`` events, at least ``params.min_window_events`` each
    (fewer windows then); the events left over join the last window. Each pair of
    adjacent windows is compared by the chi-square test on their activity counts, a
    drift at p < ``params.sensitivity``, dated at the second window's first event. A
    log too short for two windows reports its events and 0 comparisons.
    """
    start_time = time.perf_counter()
    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if TIMESTAMP not in df.columns:
        raise ValueError(f"DataFrame missing {TIMESTAMP!r} column")

    n_events = len(df)
    window_events = max(params.min_window_events, n_events // params.windows)
    n_windows = n_events // window_events
    if n_windows < 2:
        return DriftResult(
            count=0,
            first_ts=pd.Timestamp(df[TIMESTAMP].min()).to_pydatetime() if n_events else None,
            drift_points=(),
            time_s=time.perf_counter() - start_time,
            n_events=n_events,
            n_windows=n_windows,
            detector=PROPORTIONAL_DETECTOR,
            window_events=window_events,
            n_comparisons=0,
            drift_fraction=0.0,
        )

    ordered = df.sort_values(TIMESTAMP, kind="stable").reset_index(drop=True)
    timestamps = ordered[TIMESTAMP].values
    codes, _ = pd.factorize(ordered[ACTIVITY])
    n_activities = int(codes.max()) + 1
    bounds = [i * window_events for i in range(n_windows)] + [n_events]
    counts = [
        np.bincount(codes[bounds[i]:bounds[i + 1]], minlength=n_activities)
        for i in range(n_windows)
    ]

    drift_points: list[datetime] = []
    for i in range(n_windows - 1):
        if _drifted(counts[i], counts[i + 1], params.sensitivity):
            drift_points.append(pd.Timestamp(timestamps[bounds[i + 1]]).to_pydatetime())

    n_comparisons = n_windows - 1
    return DriftResult(
        count=len(drift_points),
        first_ts=pd.Timestamp(timestamps[0]).to_pydatetime(),
        drift_points=tuple(drift_points),
        time_s=time.perf_counter() - start_time,
        n_events=n_events,
        n_windows=n_windows,
        per_1k_events=round(len(drift_points) * 1000 / n_events, 6),
        detector=PROPORTIONAL_DETECTOR,
        window_events=window_events,
        n_comparisons=n_comparisons,
        drift_fraction=round(len(drift_points) / n_comparisons, 6),
    )


def _drifted(before: np.ndarray, after: np.ndarray, alpha: float) -> bool:
    """Whether two windows' activity counts differ by the chi-square test (p < alpha).

    Activities absent from both are left out; fewer than two activities left, or a
    test that cannot run, is no drift.
    """
    table = np.vstack([before, after])
    table = table[:, table.sum(axis=0) > 0]
    if table.shape[1] < 2:
        return False
    try:
        _, p_value, _, _ = stats.chi2_contingency(table)
    except ValueError:
        return False
    return bool(p_value < alpha)
