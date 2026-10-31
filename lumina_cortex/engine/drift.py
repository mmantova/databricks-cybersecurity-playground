"""
Concept drift detection using chi-square test on activity distribution.

Implements detect_drift() with consecutive non-overlapping fixed-size windows (the
Product method of 0.2.1, kept as ``product-v1``) and detect_proportional_drift() with
10 windows proportional to the log (the Product method v2, decision 4).
Drift points mark where the activity distribution changes significantly.
"""

import time
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats

from lumina_cortex.columns import ACTIVITY, TIMESTAMP
from lumina_cortex.config.thresholds import (
    PRODUCT_V2_DRIFT,
    THESIS_THRESHOLDS_V1,
    ProportionalDrift,
    Thresholds,
)
from lumina_cortex.models import DriftResult, DriftMode


def detect_drift(
    df: pd.DataFrame,
    window_size: Optional[int] = None,
    sensitivity: Optional[float] = None,
    *,
    thresholds: Optional[Thresholds] = None,
) -> DriftResult:
    """
    Detect concept drift in activity distribution using chi-square test.

    Splits the log into consecutive non-overlapping windows and compares
    the activity distribution between adjacent windows using a chi-square
    test on the contingency table.

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name, time:timestamp.
        window_size: Number of events per window (default: thresholds.drift_window_size).
        sensitivity: P-value threshold for drift detection (default: thresholds.drift_sensitivity).
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).

    Returns:
        DriftResult with count, first_ts, drift_points, and timing.
    """
    start_time = time.perf_counter()
    
    t = thresholds or THESIS_THRESHOLDS_V1
    win_size = window_size if window_size is not None else t.drift_window_size
    alpha = sensitivity if sensitivity is not None else t.drift_sensitivity

    # Validate DataFrame
    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if TIMESTAMP not in df.columns:
        raise ValueError(f"DataFrame missing {TIMESTAMP!r} column")
    if len(df) == 0:
        return DriftResult(
            count=0,
            first_ts=None,
            drift_points=(),
            time_s=time.perf_counter() - start_time,
        )

    # Sort by timestamp
    df_sorted = df.sort_values(TIMESTAMP).reset_index(drop=True)

    # Get timestamps as array
    timestamps = df_sorted[TIMESTAMP].values
    first_ts = pd.Timestamp(timestamps[0]).to_pydatetime()

    # Calculate number of windows
    n_events = len(df_sorted)
    n_windows = max(1, n_events // win_size)

    # If only one window, no drift can be detected; still report what was seen, so a log
    # too short to compare two windows does not read as an empty one
    if n_windows < 2:
        return DriftResult(
            count=0,
            first_ts=first_ts,
            drift_points=(),
            time_s=time.perf_counter() - start_time,
            n_events=n_events,
            n_windows=n_events // win_size,
        )

    # Get activities
    activities = df_sorted[ACTIVITY].values

    # Build contingency tables for each window
    drift_points: list[datetime] = []
    
    # Get unique activities for consistent indexing
    unique_activities = np.unique(activities)
    n_activities = len(unique_activities)
    activity_to_idx = {a: i for i, a in enumerate(unique_activities)}

    # Process consecutive window pairs
    for i in range(n_windows - 1):
        # Window boundaries
        start_w1 = i * win_size
        end_w1 = (i + 1) * win_size
        start_w2 = end_w1
        end_w2 = min((i + 2) * win_size, n_events)

        # Get activities for each window
        w1_activities = activities[start_w1:end_w1]
        w2_activities = activities[start_w2:end_w2]

        # Build contingency table
        contingency = np.zeros((2, n_activities), dtype=np.int64)
        
        for a in w1_activities:
            contingency[0, activity_to_idx[a]] += 1
        for a in w2_activities:
            contingency[1, activity_to_idx[a]] += 1

        # Remove activities with zero counts in both windows
        mask = contingency.sum(axis=0) > 0
        contingency = contingency[:, mask]

        # Skip if not enough variation
        if contingency.shape[1] < 2:
            continue

        # Chi-square test
        try:
            chi2, p_value, dof, expected = stats.chi2_contingency(contingency)
            
            # Drift detected if p-value < sensitivity
            if p_value < alpha:
                # Get timestamp at the boundary
                drift_ts = pd.Timestamp(timestamps[end_w1]).to_pydatetime()
                drift_points.append(drift_ts)
        except ValueError:
            # Chi-square fails with small expected counts
            continue

    # Calculate normalized drift count
    n_events_actual = len(df)
    n_windows_actual = n_windows
    per_1k = (len(drift_points) * 1000 / n_events_actual) if n_events_actual > 0 else 0.0
    
    return DriftResult(
        count=len(drift_points),
        first_ts=first_ts,
        drift_points=tuple(drift_points),
        time_s=time.perf_counter() - start_time,
        n_events=n_events_actual,
        n_windows=n_windows_actual,
        per_1k_events=round(per_1k, 6),
    )


PROPORTIONAL_DETECTOR = "chi_square_proportional"


def detect_proportional_drift(
    df: pd.DataFrame,
    params: ProportionalDrift = PRODUCT_V2_DRIFT,
) -> DriftResult:
    """The Product method v2's drift: chi-square over windows proportional to the log.

    The log, in time order, is cut into ``params.windows`` consecutive windows of
    len(log) // ``params.windows`` events, at least ``params.min_window_events`` each
    (fewer windows then); the events left over join the last window. Each pair of
    adjacent windows is compared by the chi-square test on their activity counts, a
    drift at p < ``params.sensitivity``, dated at the second window's first event. A
    log too short for two windows reports its events and 0 comparisons.

    ``detect_drift`` (fixed 500-event windows) is what ``product-v1`` keeps running.
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
