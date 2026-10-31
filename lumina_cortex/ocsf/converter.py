"""
OCSF to PM4Py converter.

This is the ONLY module that writes the 'concept:name' column.
All normalization must go through this converter to ensure canonical
activity names and vocabulary compliance.
"""

from datetime import datetime, timezone
from typing import Iterator, Optional, Union

import pandas as pd

from lumina_cortex.columns import CASE, ACTIVITY, TIMESTAMP, RESOURCE
from lumina_cortex.config.limits import InputLimits, DEFAULT_LIMITS
from lumina_cortex.config.thresholds import Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.errors import EmptyLogError, InputLimitError
from lumina_cortex.models import CaseStrategy, ParseStats
from lumina_cortex.ocsf.schema import OCSF_VERSION
from lumina_cortex.vocabulary.ocsf_to_activity import (
    VOCABULARY_VERSION,
    activity_for,
    is_canonical,
)


def ocsf_to_pm4py(
    events: Iterator[dict],
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
    *,
    time_window_seconds: Optional[int] = None,
    thresholds: Optional[Thresholds] = None,
    limits: InputLimits = DEFAULT_LIMITS,
) -> tuple[pd.DataFrame, ParseStats]:
    """
    Convert OCSF events to a PM4Py DataFrame.

    This is the ONLY writer of the 'concept:name' column in the codebase.
    All normalization must go through this function.

    Args:
        events: Iterator of OCSF event dictionaries.
        case_strategy: Strategy for grouping events into cases.
        time_window_seconds: Time window for time_window strategy (default from thresholds).
        thresholds: Thresholds configuration.
        limits: Input limits for safety bounds.

    Returns:
        Tuple of (DataFrame, ParseStats).

    Raises:
        InputLimitError: If event count exceeds max_events.
        EmptyLogError: If no valid events are produced.

    The resulting DataFrame has columns:
        - case:concept:name: Case identifier
        - concept:name: Activity name (from vocabulary)
        - time:timestamp: tz-aware datetime64[ns, UTC]
        - org:resource: Resource identifier
        - ocsf.*: OCSF metadata columns

    DataFrame.attrs contains:
        - vocabulary_version: The vocabulary version used
        - ocsf_version: The OCSF schema version
        - case_strategy: The case grouping strategy
    """
    thresholds = thresholds or THESIS_THRESHOLDS_V1
    time_window_seconds = time_window_seconds or thresholds.time_window_seconds

    rows = []
    stats = ParseStats(
        total_lines=0,
        parsed_events=0,
        skipped_malformed=0,
        skipped_unmapped=0,
        bytes_read=0,
    )

    for event in events:
        stats = ParseStats(
            total_lines=stats.total_lines + 1,
            parsed_events=stats.parsed_events,
            skipped_malformed=stats.skipped_malformed,
            skipped_unmapped=stats.skipped_unmapped,
            bytes_read=stats.bytes_read,
        )

        # Check event limit
        if stats.total_lines > limits.max_events:
            raise InputLimitError(
                f"Event count exceeds {limits.max_events}",
                details={"count": stats.total_lines, "limit": limits.max_events},
            )

        # Get canonical activity name
        activity_name = activity_for(event)
        if activity_name is None:
            stats = ParseStats(
                total_lines=stats.total_lines,
                parsed_events=stats.parsed_events,
                skipped_malformed=stats.skipped_malformed,
                skipped_unmapped=stats.skipped_unmapped + 1,
                bytes_read=stats.bytes_read,
            )
            continue

        # Validate activity is canonical
        if not is_canonical(activity_name):
            stats = ParseStats(
                total_lines=stats.total_lines,
                parsed_events=stats.parsed_events,
                skipped_malformed=stats.skipped_malformed,
                skipped_unmapped=stats.skipped_unmapped + 1,
                bytes_read=stats.bytes_read,
            )
            continue

        # Extract timestamp (must be tz-aware UTC)
        timestamp = _parse_timestamp(event.get("time"))
        if timestamp is None:
            stats = ParseStats(
                total_lines=stats.total_lines,
                parsed_events=stats.parsed_events,
                skipped_malformed=stats.skipped_malformed + 1,
                skipped_unmapped=stats.skipped_unmapped,
                bytes_read=stats.bytes_read,
            )
            continue

        # Build case identifier based on strategy
        case_id = _build_case_id(event, case_strategy, timestamp, time_window_seconds)

        # Extract resource
        resource = _extract_resource(event)

        # Build row with OCSF metadata
        row = {
            CASE: case_id,
            ACTIVITY: activity_name,  # This is the ONLY place we write concept:name
            TIMESTAMP: timestamp,
            RESOURCE: resource,
            "ocsf.class_uid": event.get("class_uid"),
            "ocsf.category_uid": event.get("category_uid"),
            "ocsf.category_name": event.get("category_name"),
            "ocsf.activity_id": event.get("activity_id"),
            "ocsf.activity_name": event.get("activity_name"),
            "ocsf.time": event.get("time"),
            "ocsf.metadata.version": event.get("metadata", {}).get("version"),
            **_extract_entities(event),
        }

        rows.append(row)
        stats = ParseStats(
            total_lines=stats.total_lines,
            parsed_events=stats.parsed_events + 1,
            skipped_malformed=stats.skipped_malformed,
            skipped_unmapped=stats.skipped_unmapped,
            bytes_read=stats.bytes_read,
        )

    # Raise if no valid events
    if not rows:
        raise EmptyLogError(
            "No valid events after conversion",
            details={"stats": stats.to_dict()},
        )

    # Build DataFrame with explicit tz-aware datetime
    df = pd.DataFrame(rows)
    df[TIMESTAMP] = pd.to_datetime(df[TIMESTAMP], utc=True)

    # Set DataFrame attributes
    df.attrs["vocabulary_version"] = VOCABULARY_VERSION
    df.attrs["ocsf_version"] = OCSF_VERSION
    df.attrs["case_strategy"] = case_strategy.value

    return df, stats


def _parse_timestamp(time_val: Optional[Union[str, int, float, datetime]]) -> Optional[datetime]:
    """
    Parse timestamp from OCSF event.

    OCSF uses ISO 8601 or epoch (seconds or milliseconds).

    Returns:
        tz-aware datetime in UTC, or None if invalid.
    """
    if time_val is None:
        return None

    if isinstance(time_val, datetime):
        if time_val.tzinfo is None:
            return time_val.replace(tzinfo=timezone.utc)
        return time_val.astimezone(timezone.utc)

    if isinstance(time_val, (int, float)):
        # OCSF uses epoch in seconds (can be fractional)
        # If value is > 10^12, it's likely milliseconds
        if time_val > 1e12:
            time_val = time_val / 1000
        try:
            return datetime.fromtimestamp(time_val, tz=timezone.utc)
        except (OSError, OverflowError):
            return None

    if isinstance(time_val, str):
        # Try ISO 8601 parsing
        try:
            dt = datetime.fromisoformat(time_val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            return None

    return None


def _build_case_id(
    event: dict,
    strategy: CaseStrategy,
    timestamp: datetime,
    time_window_seconds: int,
) -> str:
    """
    Build a case identifier based on the grouping strategy.

    Strategies:
        - host: Group by device/host name
        - ip: Group by source IP address
        - time_window: Group by time window (default)
    """
    if strategy == CaseStrategy.HOST:
        # Use device name or hostname
        device = event.get("device", {})
        hostname = device.get("hostname", device.get("name", "unknown"))
        return f"host:{hostname}"

    if strategy == CaseStrategy.IP:
        # Use source IP address
        src_endpoint = event.get("src_endpoint", {})
        ip = src_endpoint.get("ip", "unknown")
        return f"ip:{ip}"

    # time_window strategy (default)
    # Group events into time windows
    epoch_seconds = timestamp.timestamp()
    window_index = int(epoch_seconds // time_window_seconds)
    return f"window:{window_index}"


def _extract_entities(event: dict) -> dict:
    """The ENTITY_COLUMNS of one OCSF event: host, user and endpoints, None when absent.

    The user is the event's ``user`` (the account acted on, as the adapters map
    authentication), else its ``actor.user``, else ``unmapped.user``; the source address
    is ``src_endpoint``, else ``unmapped.src_endpoint``. ``unmapped`` holds who and where
    an adapter keeps out of the case and resource detection groups by (CloudTrail).
    """
    def _get(obj: object, *keys: str) -> object:
        for key in keys:
            obj = obj.get(key) if isinstance(obj, dict) else None
        return obj

    return {
        "ocsf.device.hostname": _get(event, "device", "hostname") or _get(event, "device", "name"),
        "ocsf.user.name": (_get(event, "user", "name") or _get(event, "actor", "user", "name")
                           or _get(event, "unmapped", "user", "name")),
        "ocsf.src_endpoint.ip": _get(event, "src_endpoint", "ip") or _get(event, "unmapped", "src_endpoint", "ip"),
        "ocsf.dst_endpoint.ip": _get(event, "dst_endpoint", "ip"),
        "ocsf.dst_endpoint.port": _get(event, "dst_endpoint", "port"),
    }


def _extract_resource(event: dict) -> str:
    """
    Extract resource identifier from OCSF event.

    Falls back to 'unknown' if no suitable resource is found.
    """
    # Try actor process
    actor = event.get("actor", {})
    if actor:
        process = actor.get("process", {})
        if process:
            name = process.get("name")
            if name:
                return name

    # Try device name
    device = event.get("device", {})
    if device:
        name = device.get("name", device.get("hostname"))
        if name:
            return name

    # Try user name
    user = event.get("user", {})
    if user:
        name = user.get("name")
        if name:
            return name

    return "unknown"
