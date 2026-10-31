"""
Synthetic event log generator.

Generates deterministic synthetic logs for testing and evaluation.
All scenarios are reproducible with a fixed seed.
"""

import hashlib
import io
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from lumina_cortex.ocsf.schema import OCSF_VERSION

# OCSF category per class_uid used by the scenarios
_CLASS_TO_CATEGORY = {1001: 1, 1002: 1, 1003: 1, 3002: 3, 4001: 4, 4003: 4, 5001: 6, 5002: 6}

# Base time for all scenarios (2024-01-01T00:00:00Z)
BASE_TIME = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

# Hosts
HOSTS = [f"ws-{i:02d}" for i in range(1, 9)]

# Users
USERS = [f"user{i:02d}" for i in range(1, 9)]

# IPs in 10.0.0.0/24
IPS = [f"10.0.0.{i}" for i in range(1, 251)]

# C2 server IP
C2_IP = "203.0.113.10"

# Activity types for different sources
SYSMON_ACTIVITIES = [
    "Process: Launch",
    "Process: Terminate",
    "File: Read",
    "File: Write",
    "File: Delete",
    "Registry: Modify",
    "Authentication: Logon",
    "Authentication: Logon Failure",
]

NETFLOW_ACTIVITIES = [
    "Network: Connection Open",
    "Network: Connection Close",
    "DNS: Query",
    "DNS: Response",
]

# The Atomic Threat Coverage scenarios and their builders in lumina_cortex.synthetic.atc.
_ATC_SCENARIOS = {
    "atc_t1053": "generate_t1053",
    "atc_post_wifi": "generate_post_wifi",
    "atc_benign_lookalikes": "generate_benign_lookalikes",
}

CLOUDTRAIL_ACTIVITIES = [
    "API: Call",
    "Cloud: Activity",
    "Authentication: Logon",
    "Authentication: Logon Failure",
]


def generate(
    scenario: str,
    fmt: str = "jsonl",
    *,
    seed: int = 0,
    events: int = 5000,
) -> bytes:
    """
    Generate a synthetic event log for a scenario.

    Scenarios:
        - benign_baseline: Normal activity with no attack patterns
        - attack_bruteforce: Brute force attack pattern (T1110)
        - drift_only: High drift but no attack pattern
        - score_only: High score but low drift
        - benign_rich: Benign with many activity types
        - benign_netflow: NetFlow-only benign traffic
        - attack_beacon: C2 beacon pattern (NetFlow)
        - benign_cloudtrail: CloudTrail benign activity
        - attack_cloud: Cloud-based attack pattern
        - atc_t1053: ATC's interactive AT job (T1053) amid benign background
        - atc_post_wifi: ATC's post-WiFi kill chain (T1046, T1210, T1090, T1020, T1048)
        - atc_benign_lookalikes: ATC's benign look-alike commands, no attack
          (the three ATC scenarios: lumina_cortex/synthetic/atc.py)

    Args:
        scenario: The scenario name.
        fmt: Output format ("jsonl", "csv", "df").
        seed: Random seed for deterministic generation.
        events: Number of events to generate.

    Returns:
        Bytes containing the generated log.

    Raises:
        ValueError: If scenario or format is unknown.
    """
    rng = random.Random(seed)

    # Generate events based on scenario
    if scenario == "benign_baseline":
        log_events = _generate_benign_baseline(rng, events)
    elif scenario == "attack_bruteforce":
        log_events = _generate_attack_bruteforce(rng, events)
    elif scenario == "drift_only":
        log_events = _generate_drift_only(rng, events)
    elif scenario == "score_only":
        log_events = _generate_score_only(rng, events)
    elif scenario == "benign_rich":
        log_events = _generate_benign_rich(rng, events)
    elif scenario == "benign_netflow":
        log_events = _generate_benign_netflow(rng, events)
    elif scenario == "attack_beacon":
        log_events = _generate_attack_beacon(rng, events)
    elif scenario == "benign_cloudtrail":
        log_events = _generate_benign_cloudtrail(rng, events)
    elif scenario == "attack_cloud":
        log_events = _generate_attack_cloud(rng, events)
    elif scenario in _ATC_SCENARIOS:
        from lumina_cortex.synthetic import atc
        log_events = getattr(atc, _ATC_SCENARIOS[scenario])(rng, events)
    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    # Complete the OCSF envelope (category_uid, metadata.version) so the output is
    # readable by the ocsf_jsonl adapter and the real normalizer.
    for event in log_events:
        event.setdefault("category_uid", _CLASS_TO_CATEGORY.get(event.get("class_uid"), 0))
        event.setdefault("metadata", {"version": OCSF_VERSION})

    # Format output
    if fmt == "jsonl":
        return _format_jsonl(log_events)
    elif fmt == "csv":
        return _format_csv(log_events)
    elif fmt == "df":
        # Return JSONL for df format (will be parsed by normalizer)
        return _format_jsonl(log_events)
    else:
        raise ValueError(f"Unknown format: {fmt}")


def _generate_benign_baseline(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """Generate benign baseline: normal user activity with no attack."""
    events = []
    t = BASE_TIME
    
    # Normal activity distribution
    activities = [
        ("Process: Launch", 0.4),
        ("Process: Terminate", 0.3),
        ("File: Read", 0.15),
        ("File: Write", 0.1),
        ("Authentication: Logon", 0.05),
    ]
    
    for i in range(n_events):
        # Select activity based on weights
        activity = _weighted_choice(rng, activities)
        
        # Random host and user
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        
        # Increment time
        t += timedelta(seconds=rng.randint(1, 60))
    
    return events


def _generate_attack_bruteforce(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """
    Generate brute force attack pattern.
    
    Pattern: T1110 - Brute Force
    Activities: Authentication: Logon Failure → Authentication: Logon
    """
    events = []
    t = BASE_TIME
    
    # Attack parameters
    attack_start = n_events // 3  # Start attack at 1/3 of log
    attack_duration = n_events // 3
    attack_host = rng.choice(HOSTS)
    attacker_ip = C2_IP
    target_user = rng.choice(USERS)
    
    # Pre-attack: normal activity
    for i in range(attack_start):
        activity = rng.choice(["Process: Launch", "File: Read", "File: Write"])
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    # Attack phase: high failure rate
    failures = 0
    successes = 0
    for i in range(attack_duration):
        # 90% failures, 10% success (brute force pattern)
        if rng.random() < 0.9:
            activity = "Authentication: Logon Failure"
            failures += 1
        else:
            activity = "Authentication: Logon"
            successes += 1
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": attack_host},
            "actor": {
                "user": {"name": target_user},
                "session": {"uid": f"session-{attacker_ip}"},
            },
            "src_endpoint": {"ip": attacker_ip},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 10))  # Faster during attack
    
    # Post-attack: normal activity continues
    remaining = n_events - len(events)
    for i in range(remaining):
        activity = rng.choice(["Process: Launch", "File: Read", "File: Write"])
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    return events


def _generate_drift_only(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """
    Generate high drift but no attack pattern.
    
    Simulates environment change (new software deployment, etc.)
    """
    events = []
    t = BASE_TIME
    
    # Phase 1: Normal activity (first half)
    phase1_activities = [
        ("Process: Launch", 0.5),
        ("File: Read", 0.3),
        ("Authentication: Logon", 0.2),
    ]
    
    for i in range(n_events // 2):
        activity = _weighted_choice(rng, phase1_activities)
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    # Phase 2: Different activity distribution (drift)
    phase2_activities = [
        ("File: Write", 0.4),
        ("File: Delete", 0.3),
        ("Registry: Modify", 0.2),
        ("Authentication: Logoff", 0.1),
    ]
    
    for i in range(n_events - len(events)):
        activity = _weighted_choice(rng, phase2_activities)
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    return events


def _generate_score_only(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """
    Generate high scorer match but low drift.
    
    Simulates attack-like activity concentrated in one window.
    """
    events = []
    t = BASE_TIME
    
    # Most events: normal activity (concentrated in time = low drift)
    for i in range(n_events - 50):
        activity = rng.choice(["Process: Launch", "File: Read"])
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(0, 2))  # Very fast
    
    # Attack-like activity (T1562 - Disable Security)
    attack_host = rng.choice(HOSTS)
    for i in range(50):
        activity = rng.choice([
            "Registry: Modify",
            "Process: Terminate",
            "File: Delete",
        ])
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": attack_host},
            "actor": {"user": {"name": "SYSTEM"}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(0, 2))
    
    return events


def _generate_benign_rich(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """Generate benign activity with many activity types."""
    events = []
    t = BASE_TIME
    
    activities = SYSMON_ACTIVITIES
    
    for i in range(n_events):
        activity = rng.choice(activities)
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "device": {"hostname": host},
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    return events


def _generate_benign_netflow(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """Generate NetFlow-only benign traffic."""
    events = []
    t = BASE_TIME
    
    for i in range(n_events):
        activity = rng.choice(NETFLOW_ACTIVITIES)
        src_ip = rng.choice(IPS)
        dst_ip = rng.choice(IPS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "src_endpoint": {"ip": src_ip},
            "dst_endpoint": {"ip": dst_ip},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 30))
    
    return events


def _generate_attack_beacon(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """
    Generate C2 beacon pattern (NetFlow).
    
    Pattern: Regular connections to C2 server.
    All 5 NetFlow activities present.
    """
    events = []
    t = BASE_TIME
    
    # All 5 NetFlow activities
    activities = NETFLOW_ACTIVITIES
    
    beacon_host = rng.choice(IPS)
    
    for i in range(n_events):
        # 70% normal traffic, 30% beacon traffic
        if rng.random() < 0.7:
            src_ip = rng.choice(IPS)
            dst_ip = rng.choice(IPS)
            activity = rng.choice(activities)
        else:
            src_ip = beacon_host
            dst_ip = C2_IP
            # Beacon: regular DNS queries
            activity = rng.choice(["DNS: Query", "Network: Connection Open"])
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "src_endpoint": {"ip": src_ip},
            "dst_endpoint": {"ip": dst_ip},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 30))
    
    return events


def _generate_benign_cloudtrail(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """Generate CloudTrail benign activity."""
    events = []
    t = BASE_TIME
    
    for i in range(n_events):
        activity = rng.choice(CLOUDTRAIL_ACTIVITIES)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "actor": {"user": {"name": user}},
            "resources": [{"name": "s3://bucket-" + rng.choice(["prod", "dev", "test"])}],
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    return events


def _generate_attack_cloud(
    rng: random.Random,
    n_events: int,
) -> List[Dict[str, Any]]:
    """
    Generate cloud-based attack pattern.
    
    Pattern: T1078 - Valid Accounts, T1098 - Account Manipulation
    """
    events = []
    t = BASE_TIME
    
    attacker_user = "attacker"
    
    # Normal activity (first half)
    for i in range(n_events // 2):
        activity = rng.choice(CLOUDTRAIL_ACTIVITIES)
        user = rng.choice(USERS)
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "actor": {"user": {"name": user}},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 60))
    
    # Attack phase
    for i in range(n_events - len(events)):
        # Attack activities
        activity = rng.choice([
            "Authentication: Logon",
            "API: Call",
            "Cloud: Activity",
        ])
        
        event = {
            "class_uid": _activity_to_class_uid(activity),
            "activity_id": _activity_to_activity_id(activity),
            "time": t.isoformat(),
            "actor": {"user": {"name": attacker_user}},
            "src_endpoint": {"ip": C2_IP},
        }
        events.append(event)
        t += timedelta(seconds=rng.randint(1, 30))
    
    return events


def _activity_to_class_uid(activity: str) -> int:
    """Map activity name to OCSF class_uid."""
    mapping = {
        "Process: Launch": 1001,
        "Process: Terminate": 1001,
        "File: Read": 1002,
        "File: Write": 1002,
        "File: Delete": 1002,
        "File: Create": 1002,
        "File: Access": 1002,
        "Registry: Modify": 1003,
        "Registry: Create": 1003,
        "Registry: Delete": 1003,
        "Authentication: Logon": 3002,
        "Authentication: Logon Failure": 3002,
        "Authentication: Logoff": 3002,
        "Network: Connection Open": 4001,
        "Network: Connection Close": 4001,
        "DNS: Query": 4003,
        "DNS: Response": 4003,
        "API: Call": 5001,
        "Cloud: Activity": 5002,
    }
    return mapping.get(activity, 0)


def _activity_to_activity_id(activity: str) -> int:
    """Map activity name to OCSF activity_id."""
    mapping = {
        "Process: Launch": 1,
        "Process: Terminate": 2,
        "File: Read": 1,
        "File: Write": 2,
        "File: Delete": 3,
        "File: Create": 4,
        "File: Access": 5,
        "Registry: Modify": 1,
        "Registry: Create": 2,
        "Registry: Delete": 3,
        "Authentication: Logon": 1,
        "Authentication: Logon Failure": 2,
        "Authentication: Logoff": 3,
        "Network: Connection Open": 1,
        "Network: Connection Close": 2,
        "DNS: Query": 1,
        "DNS: Response": 2,
        "API: Call": 1,
        "Cloud: Activity": 1,
    }
    return mapping.get(activity, 0)


def _weighted_choice(
    rng: random.Random,
    choices: List[Tuple[str, float]],
) -> str:
    """Choose from a weighted list of options."""
    total = sum(weight for _, weight in choices)
    r = rng.random() * total
    
    cumulative = 0.0
    for choice, weight in choices:
        cumulative += weight
        if r <= cumulative:
            return choice
    
    return choices[-1][0]


def _format_jsonl(events: List[Dict[str, Any]]) -> bytes:
    """Format events as JSONL."""
    lines = [json.dumps(e) for e in events]
    return "\n".join(lines).encode("utf-8")


def _format_csv(events: List[Dict[str, Any]]) -> bytes:
    """Format events as CSV."""
    if not events:
        return b""
    
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=sorted(events[0].keys()))
    writer.writeheader()
    writer.writerows(events)
    
    return output.getvalue().encode("utf-8")
