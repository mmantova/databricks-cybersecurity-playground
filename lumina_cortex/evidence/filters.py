"""
Point techniques of the thesis: eventually-follows chains per host, play_out, alignments.

- ``eventually_follows`` (evidence builder): the thesis's kill-chain filters
  (THESIS:87-97, 169-182), each chain counted per host with pm4py's
  ``filter_eventually_follows_relation``.
- ``play_out`` (evidence builder): the difference signature of THESIS:852-916, the
  played-out language of an observed model minus that of a baseline model.
- ``align_single_case`` (library function, never a builder): pm4py alignments for one
  small case, the forensic use THESIS:692 reserves them for. They are intractable on a
  whole attack log (THESIS:676-683), so a full analysis never runs them.

Every choice the thesis does not state is documented in docs/thesis-method.md
("Evidence: filters and point techniques").
"""

from __future__ import annotations

import random
import time
from copy import copy
from typing import Any, Dict, List, NamedTuple, Tuple

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE, TIMESTAMP
from lumina_cortex.evidence import EVIDENCE_BUILDERS

# The entity a chain is counted on (lumina_cortex.columns.ENTITY_COLUMNS).
HOST_COLUMN = "ocsf.device.hostname"

LOGON = "Authentication: Logon"
CONNECT = "Network: Connection Open"
DNS = "DNS: Query"
WRITE = "File: Write"
READ = "File: Read"
DELETE = "File: Delete"
LAUNCH = "Process: Launch"
REGISTRY = "Registry: Modify"


class Chain(NamedTuple):
    """A thesis chain, with the app's activities read for each of its two steps."""

    name: str
    techniques: str
    source: str
    target: str


# The chains of THESIS:93-97 and 175-182, in that order. The thesis names steps
# ("Logon", "C2", "Drop"), not activities; the activity behind each step is
# interpretation, read from the DFG labels of THESIS:74-82 where they exist.
CHAINS: Tuple[Chain, ...] = (
    Chain("Logon -> C2", "T1071", LOGON, CONNECT),
    Chain("Download -> Drop", "T1105", CONNECT, WRITE),
    Chain("DNS -> C2", "T1071/T1568", DNS, CONNECT),
    Chain("Logon -> Collection", "T1005", LOGON, READ),
    Chain("Drop -> Exfil", "T1048/T1041", WRITE, CONNECT),
    Chain("Exec -> Persist", "T1112", LAUNCH, REGISTRY),
    Chain("Exec -> Exec", "T1059", LAUNCH, LAUNCH),
    Chain("Exec -> C2", "T1059->T1071", LAUNCH, CONNECT),
    Chain("Exec -> Drop", "T1105", LAUNCH, WRITE),
    Chain("Logon -> Persist", "T1547", LOGON, REGISTRY),
    Chain("Exec -> Cleanup", "T1070", LAUNCH, DELETE),
    Chain("Logon -> Exec", "T1021", LOGON, LAUNCH),
)

_KEYS = dict(case_id_key=CASE, activity_key=ACTIVITY, timestamp_key=TIMESTAMP)


def eventually_follows(df: pd.DataFrame) -> Dict[str, Any]:
    """Each chain of ``CHAINS`` counted per host: the hosts where its source is
    eventually followed by its target, and how many events those hosts hold."""
    import pm4py

    start = time.perf_counter()
    if HOST_COLUMN not in df.columns or df[HOST_COLUMN].isna().all():
        raise ValueError(f"no host in the log ({HOST_COLUMN} is empty): chains are counted per host")

    by_host = df[df[HOST_COLUMN].notna()][[HOST_COLUMN, ACTIVITY, TIMESTAMP]]
    by_host = by_host.assign(**{CASE: by_host[HOST_COLUMN].astype(str)})
    events_per_host = by_host[CASE].value_counts()
    present = set(by_host[ACTIVITY].unique())

    chains: List[Dict[str, Any]] = []
    for chain in CHAINS:
        hosts: List[str] = []
        if chain.source in present and chain.target in present:
            # Projecting onto the chain's two activities keeps the relation and bounds
            # the cost of the filter to the events that can take part in it.
            projected = by_host[by_host[ACTIVITY].isin({chain.source, chain.target})]
            kept = pm4py.filter_eventually_follows_relation(
                projected, [(chain.source, chain.target)], retain=True, **_KEYS
            )
            hosts = sorted(kept[CASE].unique().tolist())
        chains.append({
            "name": chain.name,
            "techniques": chain.techniques,
            "source": chain.source,
            "target": chain.target,
            "hosts": hosts,
            "n_hosts": len(hosts),
            "n_events": int(sum(events_per_host[h] for h in hosts)),
        })

    return {
        "entity": HOST_COLUMN,
        "n_hosts": int(len(events_per_host)),
        "chains": chains,
        "time_s": round(time.perf_counter() - start, 6),
    }


# play_out: the thesis played 1,000 traces of each model (THESIS:854). The trace length
# cap is ours, so that a model with a loop cannot play an unbounded trace.
PLAY_OUT_TRACES = 1000
PLAY_OUT_MAX_TRACE_LENGTH = 100
# The play-out's random choices are seeded so that the same log gives the same evidence
# (the batch report is byte-identical for the same input, tests/lib/test_batch_report.py).
PLAY_OUT_SEED = 42


def play_out(df: pd.DataFrame) -> Dict[str, Any]:
    """The difference signature of THESIS:852-916.

    The baseline (expected) model is discovered from the first half of the log's time
    span, the observed model from the whole log (the thesis split by a ground truth it
    had, THESIS:900; a time window is the first alternative it names). Each inductive
    net is played out and the signature is what the observed model plays that the
    baseline does not: activities, directly-follows transitions (with their count in
    the observed play-out) and trace variants. pm4py's basic play-out picks transitions
    at random; here the same walk is seeded (``_seeded_play_out``), so the same log gives
    the same counts.
    """
    import pm4py

    from lumina_cortex.config.thresholds import THESIS_THRESHOLDS_V1
    from lumina_cortex.engine.dfg import sample_cases

    start = time.perf_counter()
    log = sample_cases(df[[CASE, ACTIVITY, TIMESTAMP]], THESIS_THRESHOLDS_V1)
    first, last = log[TIMESTAMP].min(), log[TIMESTAMP].max()
    split = first + (last - first) / 2
    baseline = log[log[TIMESTAMP] < split]
    if baseline.empty:
        raise ValueError("the log spans no time: there is no baseline window to play out")

    expected = _play(pm4py, baseline)
    observed = _play(pm4py, log)
    new_transitions = [
        {"source": src, "target": dst, "count": count}
        for (src, dst), count in sorted(observed.pop("_edges").items(), key=lambda kv: (-kv[1], kv[0]))
        if (src, dst) not in expected["_edges"]
    ]
    expected.pop("_edges")
    new_variants = observed.pop("_variants") - expected.pop("_variants")
    return {
        "baseline": "first half of the log's time span",
        "split_time": split.isoformat(),
        "expected": expected,
        "observed": observed,
        "signature": {
            "new_activities": sorted(set(observed["activities"]) - set(expected["activities"])),
            "new_transitions": new_transitions,
            "new_variants": len(new_variants),
        },
        "time_s": round(time.perf_counter() - start, 6),
    }


def _seeded_play_out(net, initial, final) -> List[Tuple[str, ...]]:
    """pm4py's basic play-out (``pm4py.play_out`` with its default variant), seeded.

    The same walk as pm4py's: from the initial marking, fire a transition picked
    uniformly among the enabled ones (at the final marking, stopping is one more
    choice), until no transition is enabled or the trace holds
    PLAY_OUT_MAX_TRACE_LENGTH visible activities; PLAY_OUT_TRACES traces. pm4py draws
    from the global ``random`` over a set ordered by object id, so it cannot be seeded;
    here the enabled transitions are put in a structural order (label, input and output
    places, which the inductive miner names by counter) and drawn from
    ``random.Random(PLAY_OUT_SEED)``. Returns the visible labels of each trace.
    """
    from pm4py.objects.petri_net import semantics

    def order(t):
        return (
            t.label is None, t.label or "",
            sorted(a.source.name for a in t.in_arcs), sorted(a.target.name for a in t.out_arcs),
            t.name if t.label is None else "",
        )

    rng = random.Random(PLAY_OUT_SEED)
    traces: List[Tuple[str, ...]] = []
    for _ in range(PLAY_OUT_TRACES):
        marking = copy(initial)
        visible: List[str] = []
        while len(visible) < PLAY_OUT_MAX_TRACE_LENGTH:
            enabled = sorted(semantics.enabled_transitions(net, marking), key=order)
            if not enabled:
                break
            options = enabled + [None] if final is not None and final == marking else enabled
            trans = rng.choice(options)
            if trans is None:
                break
            if trans.label is not None:
                visible.append(trans.label)
            marking = semantics.execute(trans, net, marking)
        traces.append(tuple(visible))
    return traces


def _play(pm4py, log: pd.DataFrame) -> Dict[str, Any]:
    """The inductive net of ``log``, played out; what it played, with its edges and
    variants under private keys for the caller to diff."""
    net, initial, final = pm4py.discover_petri_net_inductive(log, **_KEYS)
    played = _seeded_play_out(net, initial, final)
    edges: Dict[Tuple[str, str], int] = {}
    variants = set()
    activities = set()
    for acts in played:
        variants.add(acts)
        activities.update(acts)
        for pair in zip(acts, acts[1:]):
            edges[pair] = edges.get(pair, 0) + 1
    return {
        "n_events_in": int(len(log)),
        "places": len(net.places),
        "transitions": len(net.transitions),
        "n_traces": len(played),
        "n_variants": len(variants),
        "activities": sorted(activities),
        "_edges": edges,
        "_variants": variants,
    }


# Alignments are NP-hard: the thesis killed them after 11 minutes on a 2,000-event sample
# (THESIS:679). One case of at most this many events keeps a forensic request in the
# seconds; the number is ours, not the thesis's.
MAX_ALIGNMENT_EVENTS = 50


def align_single_case(case: pd.DataFrame, net, initial_marking, final_marking) -> Dict[str, Any]:
    """pm4py's alignments of one case on a model, for forensics of an isolated case.

    Never an evidence builder and never run by an analysis (THESIS:692). Refuses a log
    with more than one case, or a case above ``MAX_ALIGNMENT_EVENTS`` events.
    """
    import pm4py

    cases = case[CASE].unique()
    if len(cases) != 1:
        raise ValueError(
            f"alignments run on exactly one case, got {len(cases)}: they are intractable "
            "on a whole log (THESIS:676-683)"
        )
    if len(case) > MAX_ALIGNMENT_EVENTS:
        raise ValueError(
            f"the case has {len(case)} events; alignments run on at most "
            f"{MAX_ALIGNMENT_EVENTS} (MAX_ALIGNMENT_EVENTS)"
        )

    start = time.perf_counter()
    result = pm4py.conformance_diagnostics_alignments(
        case[[CASE, ACTIVITY, TIMESTAMP]], net, initial_marking, final_marking, **_KEYS
    )[0]
    return {
        "case": str(cases[0]),
        "n_events": int(len(case)),
        "alignment": [list(move) for move in result["alignment"]],
        "cost": result["cost"],
        "fitness": result["fitness"],
        "time_s": round(time.perf_counter() - start, 6),
    }


EVIDENCE_BUILDERS["eventually_follows"] = eventually_follows
EVIDENCE_BUILDERS["play_out"] = play_out
