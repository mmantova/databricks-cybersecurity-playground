"""
Input limits for safe parsing.

These limits prevent resource exhaustion from malformed or oversized inputs.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class InputLimits:
    """
    Limits for input processing.

    These are safety bounds to prevent resource exhaustion.
    """

    max_line_bytes: int = 65_536  # 64KB per line
    max_events: int = 200_000  # Maximum events per file
    max_file_bytes: int = 50 * 1024 * 1024  # 50MB per file


DEFAULT_LIMITS = InputLimits()
