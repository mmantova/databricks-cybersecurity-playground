"""
CloudTrail to OCSF adapter.

Converts AWS CloudTrail events to OCSF format.
"""

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Iterator, Union

from lumina_cortex.models import ParseStats
from lumina_cortex.ocsf.readers import read_json_document
from lumina_cortex.ocsf.schema import (
    CLASS_UIDS,
    CATEGORY_UIDS,
    ACTIVITY_IDS,
    OCSF_VERSION,
)

# ARN validation pattern
_ARN_PATTERN = re.compile(r"^arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^/]+.*$")


def _sanitize_arn(arn: str) -> str:
    """Validate and sanitize AWS ARN."""
    if _ARN_PATTERN.match(arn):
        return arn
    return f"redacted-{hashlib.sha256(arn.encode()[:64]).hexdigest()[:8]}"


class Adapter:
    """CloudTrail to OCSF adapter."""

    def iter_events(
        self,
        source: Union[str, dict, list],
    ) -> tuple[Iterator[dict], ParseStats]:
        """
        Iterate over OCSF events from CloudTrail source.

        Args:
            source: File path (JSON), JSON object, or list of events.

        Returns:
            Tuple of (event iterator, parse stats).
        """
        if isinstance(source, str):
            data = read_json_document(source)
            # A CloudTrail log file is one {"Records": [...]} object, which
            # read_json_document returns wrapped in a list.
            if len(data) == 1 and isinstance(data[0], dict) and "Records" in data[0]:
                events = data[0]["Records"]
            else:
                events = data
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
                ocsf_event = self._convert_event(event)
                if ocsf_event is not None:
                    yield ocsf_event

        return _generate(), stats

    def _convert_event(self, event: dict) -> dict | None:
        """Convert a CloudTrail event to OCSF format."""
        event_name = event.get("eventName", "")
        event_source = event.get("eventSource", "")

        # Determine OCSF class based on event source
        if "iam" in event_source or "signin" in event_source:
            ocsf_event = self._convert_auth(event)
        elif "ec2" in event_source or "s3" in event_source:
            ocsf_event = self._convert_cloud_activity(event)
        else:
            ocsf_event = self._convert_api_call(event)
        # Who and where, for a reader of the events (the converter's entity columns) only:
        # kept under "unmapped" so they never change the case or resource detection groups by.
        entities: dict = {"user": {"name": event.get("userIdentity", {}).get("userName", "unknown")}}
        # The caller's address, when CloudTrail recorded an IP (not "AWS Internal" or a
        # service name).
        try:
            entities["src_endpoint"] = {"ip": str(ipaddress.ip_address(str(event.get("sourceIPAddress", ""))))}
        except ValueError:
            pass
        ocsf_event["unmapped"] = entities
        return ocsf_event

    def _convert_auth(self, event: dict) -> dict:
        """Convert authentication event to OCSF."""
        event_name = event.get("eventName", "")
        is_failure = event.get("errorCode") is not None

        if is_failure:
            activity_id = ACTIVITY_IDS["authentication"]["logon_failure"]
        else:
            activity_id = ACTIVITY_IDS["authentication"]["logon"]

        # Parse timestamp
        event_time = event.get("eventTime")
        if isinstance(event_time, str):
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                time_val = dt.timestamp()
            except ValueError:
                time_val = datetime.now().timestamp()
        else:
            time_val = datetime.now().timestamp()

        user_identity = event.get("userIdentity", {})

        return {
            "class_uid": CLASS_UIDS["authentication"],
            "category_uid": CATEGORY_UIDS["iam"],
            "activity_id": activity_id,
            "time": time_val,
            "metadata": {
                "version": OCSF_VERSION,
                "correlation_id": event.get("requestID"),
            },
            "user": {
                "name": user_identity.get("userName", "unknown"),
                "uid": user_identity.get("principalId"),
                "type": user_identity.get("type"),
            },
            "api": {
                "operation": event_name,
                "service": event.get("eventSource"),
            },
        }

    def _convert_cloud_activity(self, event: dict) -> dict:
        """Convert cloud activity to OCSF."""
        event_time = event.get("eventTime")
        if isinstance(event_time, str):
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                time_val = dt.timestamp()
            except ValueError:
                time_val = datetime.now().timestamp()
        else:
            time_val = datetime.now().timestamp()

        user_identity = event.get("userIdentity", {})

        return {
            "class_uid": CLASS_UIDS["cloud_activity"],
            "category_uid": CATEGORY_UIDS["application_activity"],
            "activity_id": 1,  # Generic activity
            "time": time_val,
            "metadata": {
                "version": OCSF_VERSION,
                "correlation_id": event.get("requestID"),
            },
            "user": {
                "name": user_identity.get("userName", "unknown"),
                "uid": user_identity.get("principalId"),
            },
            "cloud": {
                "provider": "aws",
                "region": event.get("awsRegion"),
                "account_uid": event.get("recipientAccountId"),
            },
            "api": {
                "operation": event.get("eventName"),
                "service": event.get("eventSource"),
            },
        }

    def _convert_api_call(self, event: dict) -> dict:
        """Convert API call to OCSF."""
        event_time = event.get("eventTime")
        if isinstance(event_time, str):
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                time_val = dt.timestamp()
            except ValueError:
                time_val = datetime.now().timestamp()
        else:
            time_val = datetime.now().timestamp()

        return {
            "class_uid": CLASS_UIDS["api_activity"],
            "category_uid": CATEGORY_UIDS["application_activity"],
            "activity_id": ACTIVITY_IDS.get("api_activity", {}).get("call", 1),
            "time": time_val,
            "metadata": {
                "version": OCSF_VERSION,
                "correlation_id": event.get("requestID"),
            },
            "api": {
                "operation": event.get("eventName"),
                "service": event.get("eventSource"),
                "version": event.get("apiVersion"),
            },
        }
