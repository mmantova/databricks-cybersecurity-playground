"""
Sysmon to OCSF adapter.

Converts Sysmon JSON events, and the Windows Security events that travel with them, to
OCSF format. ``EVENT_ID_MAPPING`` names, for each EventID the adapter knows, the OCSF
class and activity and the record keys of the acting process (and user) and of a target
process (ADR 0005 added Sysmon 7, 9, 10 and 22 and Security 4634, 4656, 4663, 5156 and
5158); any other EventID is unmapped. What depends on the OCSF class only (the file,
the query, the registry key, the user, the endpoints) is built per class.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple, Union

from lumina_cortex.models import ParseStats
from lumina_cortex.ocsf.readers import iter_lines, read_json_document
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
        # Invalid IP - return redacted hash
        return f"redacted-{hashlib.sha256(ip_str.encode()[:64]).hexdigest()[:8]}"


def _sanitize_hostname(hostname: str) -> str:
    """Sanitize hostname/user through regex validation."""
    if _HOSTNAME_PATTERN.match(hostname):
        return hostname
    # Invalid hostname - return redacted hash
    return f"redacted-{hashlib.sha256(hostname.encode()[:64]).hexdigest()[:8]}"


@dataclass(frozen=True)
class Actor:
    """The record keys of the process that acted (``name_key``, ``pid_key``) and of its
    user (``user_key``); a record without ``name_key`` has no actor."""

    name_key: str
    pid_key: str = "ProcessId"
    user_key: Optional[str] = None


@dataclass(frozen=True)
class EventKind:
    """What the adapter makes of one EventID: the OCSF class and activity (as named in
    lumina_cortex.ocsf.schema), the acting process when the record names one, and the
    target process's (name, pid) keys for an event that acts on a process (Sysmon 10).
    A process event without a target is about its own process, its parent the actor."""

    ocsf_class: str
    activity: str
    actor: Optional[Actor] = None
    target_process: Optional[Tuple[str, str]] = None


EVENT_ID_MAPPING: dict[int, EventKind] = {
    1: EventKind("process_activity", "launch"),         # Sysmon: Process Create
    3: EventKind("network_activity", "open"),           # Sysmon: Network Connection
    5: EventKind("process_activity", "terminate"),      # Sysmon: Process Terminate
    7: EventKind("module_activity", "load", Actor("Image")),  # Sysmon: Image Loaded
    9: EventKind("file_activity", "read", Actor("Image")),    # Sysmon: RawAccessRead
    10: EventKind(                                      # Sysmon: Process Access
        "process_activity", "open", Actor("SourceImage", "SourceProcessId"),
        target_process=("TargetImage", "TargetProcessId"),
    ),
    11: EventKind("file_activity", "write"),            # Sysmon: File Create
    12: EventKind("registry_activity", "create"),       # Sysmon: Registry Create/Delete Key
    13: EventKind("registry_activity", "modify"),       # Sysmon: Registry Set Value
    22: EventKind("dns_activity", "query", Actor("Image")),   # Sysmon: DNS Query
    23: EventKind("file_activity", "delete"),           # Sysmon: File Delete
    4624: EventKind("authentication", "logon"),         # Security: Successful Logon
    4625: EventKind("authentication", "logon_failure"), # Security: Failed Logon
    4634: EventKind("authentication", "logoff"),        # Security: Logoff
    4656: EventKind(                                    # Security: Handle to an Object Requested
        "file_activity", "access", Actor("ProcessName", user_key="SubjectUserName"),
    ),
    4663: EventKind(                                    # Security: Attempt to Access an Object
        "file_activity", "access", Actor("ProcessName", user_key="SubjectUserName"),
    ),
    4688: EventKind("process_activity", "launch"),      # Security: Process Create
    5156: EventKind("network_activity", "open", Actor("Application")),  # Security: WFP Permitted a Connection
    5158: EventKind("network_activity", "open", Actor("Application")),  # Security: WFP Permitted a Bind
}


def _port(value) -> int | None:
    """A port as an int; Windows Security records carry it as a string."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _actor(event: dict, keys: Actor) -> dict | None:
    """The process that acted (and its user), from the record's keys; None without its name."""
    if keys.name_key not in event:
        return None
    actor = {"process": {"name": event[keys.name_key], "pid": event.get(keys.pid_key)}}
    if keys.user_key is not None and keys.user_key in event:
        actor["user"] = {"name": _sanitize_hostname(event[keys.user_key])}
    return actor


class Adapter:
    """Sysmon to OCSF adapter."""

    SUPPORTED_EVENT_IDS = frozenset(EVENT_ID_MAPPING)

    def iter_events(
        self,
        source: Union[str, dict, list],
    ) -> tuple[Iterator[dict], ParseStats]:
        """
        Iterate over OCSF events from Sysmon source.

        Args:
            source: File path, JSON object, or list of JSON objects.

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
            parsed = 0
            malformed = 0
            unmapped = 0

            for event in events:
                ocsf_event = self._convert_event(event)
                if ocsf_event is None:
                    if event.get("EventID") not in self.SUPPORTED_EVENT_IDS:
                        unmapped += 1
                    else:
                        malformed += 1
                else:
                    parsed += 1
                    yield ocsf_event

            # Update stats (this is a bit awkward but we need final counts)
            # In practice, we'd use a mutable counter or callback

        # Return generator and stats (stats won't be accurate until generator is exhausted)
        return _generate(), stats

    def _convert_event(self, event: dict) -> dict | None:
        """Convert a single Sysmon event to OCSF format."""
        event_id = event.get("EventID")
        if event_id not in self.SUPPORTED_EVENT_IDS:
            return None

        kind = EVENT_ID_MAPPING[event_id]
        class_name, activity_name = kind.ocsf_class, kind.activity
        class_uid = CLASS_UIDS.get(f"{class_name}")
        activity_id = ACTIVITY_IDS.get(class_name, {}).get(activity_name)

        if class_uid is None or activity_id is None:
            return None

        # Build OCSF event
        ocsf_event = {
            "class_uid": class_uid,
            "category_uid": CATEGORY_UIDS.get("system_activity", 1),
            "activity_id": activity_id,
            "time": event.get("TimeCreated") or event.get("@timestamp"),
            "metadata": {
                "version": OCSF_VERSION,
                "correlation_id": event.get("ExecutionProcessID"),
            },
        }

        # Add device/actor info
        if "Computer" in event:
            ocsf_event["device"] = {
                "hostname": _sanitize_hostname(event["Computer"]),
            }

        # An event acting on a process (Sysmon 10, process access): the target process
        if kind.target_process is not None:
            name_key, pid_key = kind.target_process
            ocsf_event["process"] = {
                "name": event.get(name_key, "unknown"),
                "pid": event.get(pid_key),
            }

        # Add process info for the other process events: their own process, the parent acting
        elif class_name == "process_activity":
            process_info = {}
            if "Image" in event:
                process_info["name"] = event["Image"]
            if "CommandLine" in event:
                process_info["cmd_line"] = event["CommandLine"]
            if "ProcessId" in event:
                process_info["pid"] = event["ProcessId"]
            ocsf_event["process"] = process_info

            # Actor (parent process)
            if "ParentImage" in event or "ParentProcessId" in event:
                ocsf_event["actor"] = {
                    "process": {
                        "name": event.get("ParentImage", "unknown"),
                        "pid": event.get("ParentProcessId"),
                    }
                }

        # Add module info for image loads (Sysmon 7)
        if class_name == "module_activity":
            ocsf_event["module"] = {
                "file": {
                    "name": event.get("ImageLoaded", "unknown"),
                    "path": event.get("ImageLoaded"),
                },
            }

        # Add file info for file events: the target file (Sysmon 11, 23), the object
        # (Security 4656, 4663) or the device read raw (Sysmon 9)
        if class_name == "file_activity":
            target = event.get("TargetFilename") or event.get("ObjectName") or event.get("Device")
            ocsf_event["file"] = {
                "name": target or "unknown",
                "path": target,
            }
            if "ObjectType" in event:
                ocsf_event["file"]["type"] = event["ObjectType"]

        # Add the query for DNS events (Sysmon 22)
        if class_name == "dns_activity":
            ocsf_event["query"] = {"hostname": event.get("QueryName", "unknown")}

        # The acting process the EventID's record names
        actor = _actor(event, kind.actor) if kind.actor is not None else None
        if actor:
            ocsf_event["actor"] = actor

        # Add registry info for registry events
        if class_name == "registry_activity":
            ocsf_event["registry"] = {
                "key": event.get("TargetObject", "unknown"),
                "value": event.get("Details"),
            }

        # Add user info for authentication events
        if class_name == "authentication":
            ocsf_event["user"] = {
                "name": _sanitize_hostname(event.get("TargetUserName", "unknown")),
                "domain": event.get("TargetDomainName"),
            }
            if "IpAddress" in event:
                ocsf_event["src_endpoint"] = {
                    "ip": _sanitize_ip(event["IpAddress"]),
                }

        # Add network info for network events
        if class_name == "network_activity":
            if "SourceIp" in event or "DestinationIp" in event:
                ocsf_event["src_endpoint"] = {
                    "ip": _sanitize_ip(event.get("SourceIp", "0.0.0.0")),
                    "port": event.get("SourcePort"),
                }
                ocsf_event["dst_endpoint"] = {
                    "ip": _sanitize_ip(event.get("DestinationIp", "0.0.0.0")),
                    "port": event.get("DestinationPort"),
                }
            # Security 5156 and 5158 (Windows Filtering Platform); 5158 is a bind and
            # has no destination
            if "SourceAddress" in event:
                ocsf_event["src_endpoint"] = {
                    "ip": _sanitize_ip(event["SourceAddress"]),
                    "port": _port(event.get("SourcePort")),
                }
            if "DestAddress" in event:
                ocsf_event["dst_endpoint"] = {
                    "ip": _sanitize_ip(event["DestAddress"]),
                    "port": _port(event.get("DestPort")),
                }

        return ocsf_event
