"""Deterministic SOAR / policy-block audit (not MITRE conformance)."""

from __future__ import annotations

import time
from typing import Optional

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE
from lumina_cortex.models import SoarAuditResult

DEFAULT_SOAR_COLUMN = "status_infra"
DEFAULT_SOAR_VALUE = "Bloqueado_Pelo_SOAR"


def audit_soar_blocks(
    df: pd.DataFrame,
    *,
    column: str = DEFAULT_SOAR_COLUMN,
    value: str = DEFAULT_SOAR_VALUE,
    sample_n: int = 10,
    detail_columns: Optional[list[str]] = None,
) -> SoarAuditResult:
    """
    Report rows matching a SOAR/policy block marker.

    Missing column → empty result, never raises.
    """
    t0 = time.perf_counter()
    if df is None or len(df) == 0 or column not in df.columns:
        return SoarAuditResult(
            filter_column=column,
            filter_value=value,
            time_s=round(time.perf_counter() - t0, 4),
        )

    viol = df[df[column].astype(str) == str(value)]
    if viol.empty:
        return SoarAuditResult(
            filter_column=column,
            filter_value=value,
            time_s=round(time.perf_counter() - t0, 4),
        )

    cases = 0
    if CASE in viol.columns:
        cases = int(viol[CASE].nunique())

    top_acts: list[tuple[str, int]] = []
    if ACTIVITY in viol.columns:
        vc = viol[ACTIVITY].astype(str).value_counts()
        top_acts = [(str(k), int(v)) for k, v in vc.head(10).items()]

    cols = detail_columns or [
        c
        for c in (CASE, ACTIVITY, "time:timestamp", "detalhe", column)
        if c in viol.columns
    ]
    sample = viol[cols].head(sample_n).to_dict(orient="records")
    for row in sample:
        for k, v in list(row.items()):
            if hasattr(v, "isoformat"):
                row[k] = v.isoformat()

    return SoarAuditResult(
        violation_count=len(viol),
        cases_affected=cases,
        top_activities=tuple(top_acts),
        sample_rows=tuple(sample),
        filter_column=column,
        filter_value=value,
        time_s=round(time.perf_counter() - t0, 4),
    )
