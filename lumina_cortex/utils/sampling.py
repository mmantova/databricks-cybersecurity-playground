"""
Sampling utilities for large datasets.

Provides deterministic sampling using seeded random.
"""

import random
from typing import Set

import pandas as pd

from lumina_cortex.columns import CASE


def sample_cases(
    df: pd.DataFrame,
    max_events: int,
    seed: int = 0,
) -> pd.DataFrame:
    """
    Sample cases from a DataFrame to fit within max_events.

    Uses deterministic sampling with a seeded random number generator.
    Samples complete cases (does not split cases).

    Args:
        df: PM4Py DataFrame with case:concept:name.
        max_events: Maximum number of events to include.
        seed: Random seed for deterministic sampling.

    Returns:
        Sampled DataFrame with at most max_events events.

    Raises:
        ValueError: If DataFrame is missing case:concept:name column.
    """
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")

    if len(df) <= max_events:
        return df

    rng = random.Random(seed)

    # Get unique cases sorted for determinism
    cases = sorted(df[CASE].unique().tolist())

    # Shuffle cases
    rng.shuffle(cases)

    # Select cases until we reach max_events
    selected_cases: list = []
    total_events = 0

    for case_id in cases:
        case_len = len(df[df[CASE] == case_id])
        if total_events + case_len > max_events:
            break
        selected_cases.append(case_id)
        total_events += case_len

    if not selected_cases:
        # If even one case is too large, just take the first case
        selected_cases = cases[:1]

    return df[df[CASE].isin(selected_cases)].copy()
