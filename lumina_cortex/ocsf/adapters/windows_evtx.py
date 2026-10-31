"""
Windows EVTX / Security+Sysmon CSV|JSONL → OCSF adapter.

Reads EventID-shaped rows (exported EVTX CSV or JSONL) and converts them to OCSF
using the same EventID → OCSF class/activity map as Sysmon. Does **not** write
``concept:name`` — that stays exclusive to ``ocsf_to_pm4py``.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterator, Union

from lumina_cortex.models import ParseStats
from lumina_cortex.ocsf.adapters.sysmon import Adapter as SysmonAdapter


def _coerce_event_id(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize EventID to int when present as string (CSV exports)."""
    out = dict(row)
    eid = out.get("EventID")
    if eid is not None and not isinstance(eid, int):
        try:
            out["EventID"] = int(str(eid).strip())
        except (TypeError, ValueError):
            pass
    return out


def _iter_rows(source: Union[str, dict, list]) -> list[dict[str, Any]]:
    if isinstance(source, dict):
        return [source]
    if isinstance(source, list):
        return [r for r in source if isinstance(r, dict)]
    path = Path(source)
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()
    if suffix == ".csv":
        reader = csv.DictReader(text.splitlines())
        return [dict(row) for row in reader]
    # JSONL or JSON array
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    if lines[0].startswith("["):
        data = json.loads(text)
        return [r for r in data if isinstance(r, dict)]
    rows: list[dict[str, Any]] = []
    for ln in lines:
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


class Adapter:
    """Windows EVTX export (CSV/JSONL) → OCSF via Sysmon EventID map."""

    def __init__(self) -> None:
        self._sysmon = SysmonAdapter()

    def iter_events(
        self,
        source: Union[str, dict, list],
    ) -> tuple[Iterator[dict], ParseStats]:
        rows = _iter_rows(source)
        parsed = 0
        malformed = 0
        unmapped = 0
        events: list[dict] = []
        for raw in rows:
            event = _coerce_event_id(raw)
            ocsf_event = self._sysmon._convert_event(event)
            if ocsf_event is None:
                eid = event.get("EventID")
                if eid not in self._sysmon.SUPPORTED_EVENT_IDS:
                    unmapped += 1
                else:
                    malformed += 1
                continue
            parsed += 1
            events.append(ocsf_event)
        final = ParseStats(
            total_lines=len(rows),
            parsed_events=parsed,
            skipped_malformed=malformed,
            skipped_unmapped=unmapped,
            bytes_read=0,
        )
        return iter(events), final
