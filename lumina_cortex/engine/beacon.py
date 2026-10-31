"""
The Beacon detector (GLOSSARY.md; decisions 6 and 11 of .scratch/product-v2/decisions.md).

Every event that carries both endpoints (a source IP and a destination IP: NetFlow,
Sysmon 3, Security 5156) is grouped by source -> destination:port, with no exceptions
(no allow-list for DNS, NTP or proxies). The inter-arrival intervals of each group are
measured; a group is a beacon when it has at least ``min_connections`` connections and
the coefficient of variation of its intervals (population standard deviation over mean)
is at most ``cv_max``. A group whose connections all share one instant (mean interval 0)
is no beacon.

A beacon counts as the MITRE pattern above "T1071 (beacon)" (Application Layer
Protocol), so the verdict's MITRE condition reads it without changing the rule's shape
(``add_beacons``). Only the Product method v2 runs this detector.

The cost is bounded on large logs: the whole log is only scanned for events with both
endpoints; the first ``max_events`` of them in the log's order (by position, not by time:
choosing the earliest in time would mean parsing and sorting them all) are the only ones
parsed, sorted and grouped, and at most ``max_beacons`` beacons are reported, most
connections first.
"""

from typing import Tuple

import numpy as np
import pandas as pd

from lumina_cortex.columns import TIMESTAMP
from lumina_cortex.config.thresholds import BeaconParams, MitreConformance
from lumina_cortex.engine.mitre import threat_level
from lumina_cortex.models import Beacon, MITREResult

BEACON_PATTERN = "T1071 (beacon)"

SRC = "ocsf.src_endpoint.ip"
DST = "ocsf.dst_endpoint.ip"
PORT = "ocsf.dst_endpoint.port"

_NO_PORT = -1


def detect_beacons(df: pd.DataFrame, params: BeaconParams) -> Tuple[Beacon, ...]:
    """The beacons of ``df``, most connections first (lowest CV breaking ties)."""
    if TIMESTAMP not in df.columns or SRC not in df.columns or DST not in df.columns:
        return ()
    # The bound first: the only pass over the whole log is this null check; every parse,
    # cast and sort below runs on at most max_events rows (the first, by position).
    both = (df[SRC].notna() & df[DST].notna()).to_numpy()
    rows = df.iloc[np.flatnonzero(both)[: params.max_events]]
    if rows.empty:
        return ()

    events = pd.DataFrame({
        "src": rows[SRC].astype(str),
        "dst": rows[DST].astype(str),
        "port": (
            pd.to_numeric(rows[PORT], errors="coerce").fillna(_NO_PORT).astype("int64")
            if PORT in rows.columns else _NO_PORT
        ),
        "t": _seconds(rows[TIMESTAMP]),
    }).dropna(subset=["t"])

    keys = ["src", "dst", "port"]
    sizes = events.groupby(keys, sort=False)["t"].transform("size")
    events = events[sizes >= params.min_connections]
    if events.empty:
        return ()

    events = events.sort_values(keys + ["t"], kind="stable")
    same = (events[keys] == events[keys].shift()).all(axis=1)
    events = events.assign(interval=events["t"].diff().where(same))

    groups = events.groupby(keys, sort=False)
    stats = pd.DataFrame({
        "connections": groups.size(),
        "mean": groups["interval"].mean(),
        "std": groups["interval"].std(ddof=0),
    }).reset_index()
    stats = stats[stats["mean"] > 0]
    stats = stats.assign(cv=stats["std"] / stats["mean"])
    stats = stats[stats["cv"] <= params.cv_max]
    stats = stats.sort_values(
        ["connections", "cv", "src", "dst", "port"], ascending=[False, True, True, True, True],
    ).head(params.max_beacons)

    return tuple(
        Beacon(
            source=row.src,
            destination=row.dst,
            port=None if row.port == _NO_PORT else int(row.port),
            connections=int(row.connections),
            mean_interval_s=float(row.mean),
            cv=float(row.cv),
        )
        for row in stats.itertuples(index=False)
    )


def add_beacons(
    mitre: MITREResult, beacons: Tuple[Beacon, ...], conformance: MitreConformance,
) -> MITREResult:
    """``mitre`` with "T1071 (beacon)" among the patterns above when any beacon was found.

    The pattern counts once whatever the number of beacons. It has no replay fitness; it
    is listed with 1.0, a pattern found, and the beacons are attached to the result.
    """
    if not beacons:
        return mitre
    above = sorted(
        tuple(mitre.top_matches) + ((BEACON_PATTERN, 1.0),), key=lambda m: (-m[1], m[0]),
    )
    models_above = mitre.models_above + 1
    return MITREResult(
        threat_level=threat_level(models_above, conformance),
        models_above=models_above,
        total_models=mitre.total_models,
        top_matches=tuple(above),
        time_s=mitre.time_s,
        replayed=mitre.replayed,
        conformance_error=mitre.conformance_error,
        beacons=tuple(beacons),
    )


def _seconds(ts: pd.Series) -> pd.Series:
    """Timestamps as float seconds since the epoch (NaN where unparseable)."""
    parsed = pd.to_datetime(ts, utc=True, errors="coerce")
    return (parsed - pd.Timestamp(0, tz="UTC")).dt.total_seconds()
