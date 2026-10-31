"""Forensic handover brief: DFG map + SOAR audit (code decides, not Jev)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional, Union

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE
from lumina_cortex.engine.audit import audit_soar_blocks
from lumina_cortex.engine.dfg import discover_dfg, dfg_top_edges, export_dfg_map
from lumina_cortex.models import ForensicBrief, SoarAuditResult


def build_forensic_brief(
    df: pd.DataFrame,
    *,
    map_path: Optional[Union[str, Path]] = None,
    soar_column: str = "status_infra",
    soar_value: str = "Bloqueado_Pelo_SOAR",
    export_map: bool = True,
) -> ForensicBrief:
    """
    Build a Red/Blue forensic handover package.

    - DFG discovery (+ optional PNG via ``export_dfg_map``)
    - Top edges for the Board SVG (always)
    - SOAR block audit (deterministic filter)
    - One-line summary for the hunt card
    """
    t0 = time.perf_counter()
    if df is None or len(df) == 0:
        empty = pd.DataFrame(columns=[CASE, ACTIVITY, "time:timestamp"])
        return ForensicBrief(
            dfg=discover_dfg(empty),
            soar=SoarAuditResult(filter_column=soar_column, filter_value=soar_value),
            summary="empty event log",
        )

    events = len(df)
    cases = int(df[CASE].nunique()) if CASE in df.columns else 0
    activities = int(df[ACTIVITY].nunique()) if ACTIVITY in df.columns else 0
    edges = tuple(dfg_top_edges(df))

    path = Path(map_path) if map_path else Path("/tmp/lumina_forensic_dfg.png")
    map_out: Optional[str] = None
    if export_map:
        dfg, map_out = export_dfg_map(df, path)
    else:
        dfg = discover_dfg(df)

    soar = audit_soar_blocks(df, column=soar_column, value=soar_value)

    parts = [
        f"DFG edges={dfg.edges}",
        f"fitness={dfg.fitness}",
        f"SOAR blocks={soar.violation_count}",
    ]
    if map_out:
        parts.append(f"map={map_out}")

    return ForensicBrief(
        dfg=dfg,
        soar=soar,
        map_path=map_out,
        summary="; ".join(parts),
        cases=cases,
        events=events,
        activities=activities,
        time_s=round(time.perf_counter() - t0, 4),
        top_edges=edges,
    )
