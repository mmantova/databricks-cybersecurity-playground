"""
OCSF readers for bounded file parsing.

Provides utilities for reading log files with safety limits.
"""

import json
from io import IOBase
from pathlib import Path
from typing import Iterator, Union

from lumina_cortex.config.limits import InputLimits, DEFAULT_LIMITS
from lumina_cortex.errors import InputLimitError


def iter_lines(
    path_or_fileobj: Union[str, Path, IOBase],
    limits: InputLimits = DEFAULT_LIMITS,
) -> Iterator[str]:
    """
    Iterate over lines in a file with bounded reading.

    Args:
        path_or_fileobj: File path or file-like object.
        limits: Input limits for safety bounds.

    Yields:
        Lines from the file.

    Raises:
        InputLimitError: If limits are exceeded.
    """
    bytes_read = 0

    if isinstance(path_or_fileobj, (str, Path)):
        with open(path_or_fileobj, "r", encoding="utf-8", errors="replace") as f:
            yield from _iter_lines_impl(f, limits, bytes_read)
    else:
        yield from _iter_lines_impl(path_or_fileobj, limits, bytes_read)


def _iter_lines_impl(
    f: IOBase,
    limits: InputLimits,
    bytes_read: int,
) -> Iterator[str]:
    """Implementation of iter_lines."""
    for line in f:
        bytes_read += len(line.encode("utf-8"))

        if bytes_read > limits.max_file_bytes:
            raise InputLimitError(
                f"File exceeds {limits.max_file_bytes} bytes",
                details={"bytes_read": bytes_read, "limit": limits.max_file_bytes},
            )

        if len(line) > limits.max_line_bytes:
            continue  # Skip oversized lines

        yield line.rstrip("\n\r")


def read_json_document(
    path_or_fileobj: Union[str, Path, IOBase],
    limits: InputLimits = DEFAULT_LIMITS,
) -> list[dict]:
    """
    Read a JSON document (array or NDJSON) with bounded reading.

    Args:
        path_or_fileobj: File path or file-like object.
        limits: Input limits for safety bounds.

    Returns:
        List of JSON objects.

    Raises:
        InputLimitError: If limits are exceeded.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    if isinstance(path_or_fileobj, (str, Path)):
        with open(path_or_fileobj, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(limits.max_file_bytes)
    else:
        content = path_or_fileobj.read(limits.max_file_bytes)

    if len(content) >= limits.max_file_bytes:
        raise InputLimitError(
            f"File exceeds {limits.max_file_bytes} bytes",
            details={"limit": limits.max_file_bytes},
        )

    # Try to parse as JSON array first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        # Try NDJSON (newline-delimited JSON)
        events = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if line:
                events.append(json.loads(line))
        return events
