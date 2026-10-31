"""
The sample the attack pattern scorers read on a large log.

Shared by the Product method's coverage scorer, product-v1's Jaccard x edges scorer and
the Thesis method's scorer, so all three score the same sample.
"""

import random
from typing import List

import pandas as pd

from lumina_cortex.columns import CASE


def sample_scored_cases(df: pd.DataFrame, max_events: int, seed: int) -> pd.DataFrame:
    """Whole cases, in a seeded random order (``seed``), up to ``max_events`` events; the
    log itself when it is no larger. When even the first case drawn is larger, that one
    case.

    Not ``lumina_cortex.engine.dfg.sample_cases`` (the DFG's and MITRE conformance's
    sample), which falls back to the log's first ``max_events`` events instead: the
    scorers keep their own fallback, so their scores are unchanged.
    """
    if len(df) <= max_events:
        return df

    rng = random.Random(seed)

    # Get unique cases
    cases = df[CASE].unique().tolist()

    # Sample cases until we reach max_events
    rng.shuffle(cases)
    sampled_cases: List[str] = []
    total_events = 0

    for case_id in cases:
        case_len = len(df[df[CASE] == case_id])
        if total_events + case_len > max_events:
            break
        sampled_cases.append(case_id)
        total_events += case_len

    if not sampled_cases:
        sampled_cases = cases[:1]  # At least one case

    return df[df[CASE].isin(sampled_cases)]
