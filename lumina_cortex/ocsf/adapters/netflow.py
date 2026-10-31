"""
NetFlow to OCSF adapter.

Converts NetFlow binetflow CSV to OCSF format.
"""

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Iterator, Union

from lumina_cortex.models import ParseStats
from lumina_cortex.ocsf.readers import iter_lines
from lumina_cortex.ocsf.schema import (
    CLASS_UIDS,
    CATEGORY_UIDS,
    ACTIVITY_IDS,
    OCSF_VERSION,
)

# Hostname validation regex
_HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@:/\\-]{1,255}$")


def _sanitize_ip(ip_str: str) -> str:
    """Sanitize IP address through ipaddress module."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return str(ip)
    except ValueError:
        return f"redacted-{hashlib.sha256(ip_str.encode()[:64]).hexdigest()[:8]}"


def _sanitize_hostname(hostname: str) -> str:
    """Sanitize hostname through regex validation."""
    if _HOSTNAME_PATTERN.match(hostname):
        return hostname
    return f"redacted-{hashlib.sha256(hostname.encode()[:64]).hexdigest()[:8]}"


class Adapter:
    """NetFlow to OCSF adapter."""

    def iter_events(
        self,
        source: Union[str, dict, list],
    ) -> tuple[Iterator[dict], ParseStats]:
        """
        Iterate over OCSF events from NetFlow source.

        Args:
            source: File path (CSV) or list of flow records.

        Returns:
            Tuple of (event iterator, parse stats).
        """
        if isinstance(source, str):
            # Parse CSV file
            events, stats = self._parse_csv(source)
        elif isinstance(source, list):
            events = source
            stats = ParseStats(
                total_lines=len(source),
                parsed_events=0,
                skipped_malformed=0,
                skipped_unmapped=0,
                bytes_read=0,
            )
        else:
            events = [source]
            stats = ParseStats(
                total_lines=1,
                parsed_events=0,
                skipped_malformed=0,
                skipped_unmapped=0,
                bytes_read=0,
            )

        def _generate():
            for event in events:
                ocsf_event = self._convert_flow(event)
                if ocsf_event is not None:
                    yield ocsf_event

        return _generate(), stats

    def _parse_csv(self, path: str) -> tuple[list[dict], ParseStats]:
        """Parse binetflow CSV file."""
        import csv

        events = []
        stats = ParseStats(
            total_lines=0,
            parsed_events=0,
            skipped_malformed=0,
            skipped_unmapped=0,
            bytes_read=0,
        )

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(row)

        return events, ParseStats(
            total_lines=len(events),
            parsed_events=0,
            skipped_malformed=0,
            skipped_unmapped=0,
            bytes_read=0,
        )

    def _convert_flow(self, flow: dict) -> dict | None:
        """Convert a NetFlow record to OCSF format."""
        # Determine if this is DNS or regular network
        dst_port = flow.get("DstPt", flow.get("dst_port"))
        protocol = flow.get("Proto", flow.get("protocol", "tcp")).lower()

        # Check if DNS (port 53)
        if str(dst_port) == "53" or protocol == "udp":
            return self._convert_dns(flow)

        return self._convert_network(flow)

    def _convert_network(self, flow: dict) -> dict:
        """Convert a network flow to OCSF Network Activity."""
        class_uid = CLASS_UIDS["network_activity"]
        activity_id = ACTIVITY_IDS["network_activity"]["open"]

        # Parse timestamp
        ts = flow.get("StartTime", flow.get("ts"))
        if isinstance(ts, (int, float)):
            time_val = ts
        elif isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                time_val = dt.timestamp()
            except ValueError:
                time_val = datetime.now().timestamp()
        else:
            time_val = datetime.now().timestamp()

        return {
            "class_uid": class_uid,
            "category_uid": CATEGORY_UIDS["network_activity"],
            "activity_id": activity_id,
            "time": time_val,
            "metadata": {
                "version": OCSF_VERSION,
            },
            "src_endpoint": {
                "ip": _sanitize_ip(flow.get("SrcAddr", flow.get("src_ip", "0.0.0.0"))),
                "port": int(flow.get("SrcPt", flow.get("src_port", 0))),
            },
            "dst_endpoint": {
                "ip": _sanitize_ip(flow.get("DstAddr", flow.get("dst_ip", "0.0.0.0"))),
                "port": int(flow.get("DstPt", flow.get("dst_port", 0))),
            },
            "protocol_name": flow.get("Proto", flow.get("protocol", "tcp")),
            "duration": float(flow.get("Dur", flow.get("duration", 0))),
            "bytes": int(flow.get("TotBytes", flow.get("bytes", 0))),
        }

    def _convert_dns(self, flow: dict) -> dict:
        """Convert a DNS flow to OCSF DNS Activity."""
        class_uid = CLASS_UIDS["dns_activity"]
        activity_id = ACTIVITY_IDS["dns_activity"]["query"]

        ts = flow.get("StartTime", flow.get("ts"))
        if isinstance(ts, (int, float)):
            time_val = ts
        elif isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                time_val = dt.timestamp()
            except ValueError:
                time_val = datetime.now().timestamp()
        else:
            time_val = datetime.now().timestamp()

        return {
            "class_uid": class_uid,
            "category_uid": CATEGORY_UIDS["network_activity"],
            "activity_id": activity_id,
            "time": time_val,
            "metadata": {
                "version": OCSF_VERSION,
            },
            "src_endpoint": {
                "ip": _sanitize_ip(flow.get("SrcAddr", flow.get("src_ip", "0.0.0.0"))),
                "port": int(flow.get("SrcPt", flow.get("src_port", 0))),
            },
            "dst_endpoint": {
                "ip": _sanitize_ip(flow.get("DstAddr", flow.get("dst_ip", "0.0.0.0"))),
                "port": int(flow.get("DstPt", flow.get("dst_port", 53))),
            },
        }
