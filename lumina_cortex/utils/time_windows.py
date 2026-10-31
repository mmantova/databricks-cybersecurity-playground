"""
Time window utilities.

Provides helpers for working with time windows in case grouping.
"""

from datetime import datetime


def window_index(ts: datetime, t0: datetime, seconds: int) -> int:
    """
    Calculate the window index for a timestamp.

    Given a timestamp ts and a reference time t0, returns the index
    of the time window that ts falls into, where windows are
    [t0 + n*seconds, t0 + (n+1)*seconds).

    Args:
        ts: The timestamp to classify.
        t0: The reference time (start of window 0).
        seconds: The window size in seconds.

    Returns:
        The window index (integer >= 0).

    Example:
        >>> t0 = datetime(2024, 1, 1, 0, 0, 0)
        >>> ts = datetime(2024, 1, 1, 0, 7, 30)
        >>> window_index(ts, t0, 300)  # 5-minute windows
        1
    """
    delta = ts - t0
    total_seconds = delta.total_seconds()
    return max(0, int(total_seconds // seconds))
