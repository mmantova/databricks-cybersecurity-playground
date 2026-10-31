"""
Normalizers module - shortcuts for adapter → ocsf_to_pm4py.

Provides convenience functions for normalizing various log sources.
"""

from typing import Iterator, Optional, Union

from lumina_cortex.config.limits import InputLimits, DEFAULT_LIMITS
from lumina_cortex.config.thresholds import Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.errors import UnsupportedSourceError
from lumina_cortex.models import CaseStrategy, ParseStats
from lumina_cortex.ocsf.converter import ocsf_to_pm4py

import pandas as pd


def normalize(
    source: Union[str, dict, list],
    source_type: str,
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
    *,
    time_window_seconds: Optional[int] = None,
    thresholds: Optional[Thresholds] = None,
    limits: InputLimits = DEFAULT_LIMITS,
) -> tuple[pd.DataFrame, ParseStats]:
    """
    Normalize a log source to PM4Py DataFrame.

    This is the main entry point for normalization. It selects the
    appropriate adapter based on source_type and converts to PM4Py.

    Args:
        source: Log source (file path, dict, or list).
        source_type: Type of source (sysmon, netflow, cloudtrail, ocsf_jsonl, etc.).
        case_strategy: Strategy for case grouping.
        time_window_seconds: Time window for time_window strategy.
        thresholds: Thresholds configuration.
        limits: Input limits.

    Returns:
        Tuple of (DataFrame, ParseStats).

    Raises:
        UnsupportedSourceError: If source_type is not supported.
    """
    # Import adapters lazily to avoid circular imports
    events, stats = to_ocsf(source, source_type)

    df, converter_stats = ocsf_to_pm4py(
        events,
        case_strategy=case_strategy,
        time_window_seconds=time_window_seconds,
        thresholds=thresholds,
        limits=limits,
    )

    # Merge stats
    merged_stats = ParseStats(
        total_lines=stats.total_lines,
        parsed_events=converter_stats.parsed_events,
        skipped_malformed=stats.skipped_malformed + converter_stats.skipped_malformed,
        skipped_unmapped=stats.skipped_unmapped + converter_stats.skipped_unmapped,
        bytes_read=stats.bytes_read + converter_stats.bytes_read,
    )

    return df, merged_stats


def normalize_sysmon(
    source: Union[str, dict, list],
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
    **kwargs,
) -> tuple[pd.DataFrame, ParseStats]:
    """Normalize Sysmon logs to PM4Py DataFrame."""
    return normalize(source, "sysmon", case_strategy, **kwargs)


def normalize_netflow(
    source: Union[str, dict, list],
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
    **kwargs,
) -> tuple[pd.DataFrame, ParseStats]:
    """Normalize NetFlow logs to PM4Py DataFrame."""
    return normalize(source, "netflow", case_strategy, **kwargs)


def normalize_cloudtrail(
    source: Union[str, dict, list],
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
    **kwargs,
) -> tuple[pd.DataFrame, ParseStats]:
    """Normalize CloudTrail logs to PM4Py DataFrame."""
    return normalize(source, "cloudtrail", case_strategy, **kwargs)


def normalize_windows_evtx(
    source: Union[str, dict, list],
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
    **kwargs,
) -> tuple[pd.DataFrame, ParseStats]:
    """Normalize Windows EVTX exports (CSV/JSONL EventID rows) via OCSF → PM4Py."""
    return normalize(source, "windows_evtx", case_strategy, **kwargs)


def to_ocsf(
    source: Union[str, dict, list],
    source_type: str,
) -> tuple[Iterator[dict], ParseStats]:
    """
    Convert a log source to OCSF events without PM4Py conversion.

    Args:
        source: Log source (file path, dict, or list).
        source_type: Type of source.

    Returns:
        Tuple of (OCSF event iterator, parse stats).
    """
    if source_type == "sysmon":
        from lumina_cortex.ocsf.adapters.sysmon import Adapter
    elif source_type == "netflow":
        from lumina_cortex.ocsf.adapters.netflow import Adapter
    elif source_type == "cloudtrail":
        from lumina_cortex.ocsf.adapters.cloudtrail import Adapter
    elif source_type == "ocsf_jsonl":
        from lumina_cortex.ocsf.adapters.ocsf_jsonl import Adapter
    elif source_type == "windows_evtx":
        from lumina_cortex.ocsf.adapters.windows_evtx import Adapter
    else:
        raise UnsupportedSourceError(
            f"Unknown source type: {source_type}",
            details={"source_type": source_type},
        )

    adapter = Adapter()
    return adapter.iter_events(source)
