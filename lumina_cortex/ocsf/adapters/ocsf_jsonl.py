"""
OCSF JSONL adapter.

Reads events that are already in OCSF format.
Validates that required fields are present.
"""

from typing import Iterator, Union

from lumina_cortex.models import ParseStats
from lumina_cortex.ocsf.readers import read_json_document
from lumina_cortex.ocsf.schema import REQUIRED_OCSF_KEYS, OCSF_VERSION


class Adapter:
    """OCSF JSONL adapter (pass-through with validation)."""

    def iter_events(
        self,
        source: Union[str, dict, list],
    ) -> tuple[Iterator[dict], ParseStats]:
        """
        Iterate over OCSF events from JSONL source.

        Args:
            source: File path, JSON object, or list of OCSF events.

        Returns:
            Tuple of (event iterator, parse stats).
        """
        if isinstance(source, str):
            events = read_json_document(source)
        elif isinstance(source, list):
            events = source
        else:
            events = [source]

        stats = ParseStats(
            total_lines=len(events) if isinstance(events, list) else 1,
            parsed_events=0,
            skipped_malformed=0,
            skipped_unmapped=0,
            bytes_read=0,
        )

        def _generate():
            for event in events:
                validated = self._validate_event(event)
                if validated is not None:
                    yield validated

        return _generate(), stats

    def _validate_event(self, event: dict) -> dict | None:
        """Validate that an event has required OCSF fields."""
        # Check required keys
        for key in REQUIRED_OCSF_KEYS:
            if key not in event:
                return None

        # Ensure metadata has version
        metadata = event.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {"version": OCSF_VERSION}
            event["metadata"] = metadata

        if "version" not in metadata:
            event["metadata"]["version"] = OCSF_VERSION

        return event
