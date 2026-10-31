"""
Host graph and OCEL evidence of the Thesis method (THESIS:737-1024, decision 18).

The log's entity columns (``columns.ENTITY_COLUMNS``) make an object-centric event log:
each event relates to the hosts it names (hostname, source IP, destination IP, all of
object type ``host``) and to its user (object type ``user``). The port is an attribute
of the endpoint, not an object. From that OCEL four builders report evidence:

- ``host_graph``: hosts linked when they share an event, weighted by the events they
  share; degree, strength, betweenness and PageRank, the top hosts by each, and the
  hub-and-spoke hosts (THESIS:781-850, 917-1002).
- ``connected_components``: pm4py's split of the OCEL by connected components of its
  object interaction graph (THESIS:737-779).
- ``ocel_features``: pm4py's ``extract_ocel_features`` for the hosts (THESIS:1015-1018).
- ``ocdfg``: pm4py's ``discover_ocdfg`` (THESIS:1014).

None of them feeds the verdict. A log with no entity value raises, so that the builder
reports an error instead of an empty graph posing as a result.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE, TIMESTAMP
from lumina_cortex.config.thresholds import THESIS_THRESHOLDS_V1
from lumina_cortex.engine.dfg import sample_cases
from lumina_cortex.evidence import EVIDENCE_BUILDERS

#: Entity column -> OCEL object type.
OBJECT_TYPES: Dict[str, str] = {
    "ocsf.device.hostname": "host",
    "ocsf.src_endpoint.ip": "host",
    "ocsf.dst_endpoint.ip": "host",
    "ocsf.user.name": "user",
}

HOST = "host"

#: How many hosts each top list names (the thesis reads top 10, THESIS:806-832).
TOP_N = 10

#: Hub-and-spoke (interpretation, docs/thesis-method.md): a host with at least this many
#: neighbours, at least half of which touch no other host.
HUB_MIN_SPOKES = 3
HUB_MIN_LEAF_FRACTION = 0.5

#: Above this many hosts, betweenness is estimated from this many seeded pivots.
BETWEENNESS_EXACT_MAX = 1000
BETWEENNESS_SEED = 42

_EID, _OID, _OTYPE = "ocel:eid", "ocel:oid", "ocel:type"
_ACT, _TS = "ocel:activity", "ocel:timestamp"


def _oid(object_type: str, value: Any) -> str:
    return f"{object_type}:{value}"


def _name(oid: str) -> str:
    return oid.split(":", 1)[1]


def _sample(df: pd.DataFrame) -> pd.DataFrame:
    """Whole cases up to the DFG's sample size, as the DFG and MITRE conformance sample."""
    if CASE in df.columns:
        return sample_cases(df, THESIS_THRESHOLDS_V1)
    return df.head(THESIS_THRESHOLDS_V1.sample_max_events)


def build_ocel(df: pd.DataFrame):
    """The pm4py OCEL of ``df``'s entity columns (sampled like the DFG on a large log).

    Raises ``ValueError`` when the log carries no entity value at all.
    """
    from pm4py.objects.ocel.obj import OCEL

    present = [c for c in OBJECT_TYPES if c in df.columns and df[c].notna().any()]
    if not present:
        raise ValueError(
            "no entity columns: the log names no host or user "
            f"({', '.join(OBJECT_TYPES)} are all absent or empty)"
        )
    log = _sample(df).reset_index(drop=True)
    events = pd.DataFrame({
        _EID: "e" + log.index.astype(str),
        _ACT: log[ACTIVITY].astype(str) if ACTIVITY in log.columns else "event",
        _TS: pd.to_datetime(log[TIMESTAMP]) if TIMESTAMP in log.columns else pd.Timestamp(0),
    })
    parts = []
    for column in present:
        values = log[column]
        mask = values.notna() & (values.astype(str) != "")
        object_type = OBJECT_TYPES[column]
        parts.append(pd.DataFrame({
            _EID: events.loc[mask, _EID],
            _OID: values[mask].astype(str).map(lambda v, t=object_type: _oid(t, v)),
            _OTYPE: object_type,
        }))
    relations = pd.concat(parts, ignore_index=True).drop_duplicates([_EID, _OID])
    relations = relations.merge(events, on=_EID)
    objects = relations[[_OID, _OTYPE]].drop_duplicates(_OID).reset_index(drop=True)
    return OCEL(events=events, objects=objects, relations=relations)


def _host_relations(ocel) -> pd.DataFrame:
    relations = ocel.relations
    hosts = relations[relations[_OTYPE] == HOST][[_EID, _OID]]
    if hosts.empty:
        raise ValueError("no host column: the log names users but no hostname or IP")
    return hosts


def host_graph(ocel):
    """The undirected host graph: hosts sharing an event, weighted by shared events."""
    import networkx as nx

    hosts = _host_relations(ocel)
    graph = nx.Graph()
    graph.add_nodes_from(hosts[_OID].unique())
    pairs = hosts.merge(hosts, on=_EID)
    pairs = pairs[pairs[f"{_OID}_x"] < pairs[f"{_OID}_y"]]
    weights = pairs.groupby([f"{_OID}_x", f"{_OID}_y"]).size()
    for (a, b), weight in weights.items():
        graph.add_edge(a, b, weight=int(weight))
    return graph


def _top(values: Dict[str, float], n: int = TOP_N) -> List[Dict[str, Any]]:
    ranked = sorted(values.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
    return [{"host": _name(oid), "value": round(float(v), 6)} for oid, v in ranked]


def _hubs(graph) -> List[Dict[str, Any]]:
    hubs = []
    for node, degree in graph.degree():
        if degree < HUB_MIN_SPOKES:
            continue
        leaves = sum(1 for nb in graph.neighbors(node) if graph.degree(nb) == 1)
        if leaves / degree >= HUB_MIN_LEAF_FRACTION:
            hubs.append({
                "host": _name(node),
                "spokes": int(degree),
                "leaf_spokes": int(leaves),
                "strength": int(graph.degree(node, weight="weight")),
            })
    return sorted(hubs, key=lambda h: (-h["spokes"], -h["strength"], h["host"]))


def build_host_graph(df: pd.DataFrame) -> Dict[str, Any]:
    import networkx as nx

    start = time.perf_counter()
    ocel = build_ocel(df)
    graph = host_graph(ocel)
    n = graph.number_of_nodes()
    exact = n <= BETWEENNESS_EXACT_MAX
    betweenness = nx.betweenness_centrality(
        graph, k=None if exact else BETWEENNESS_EXACT_MAX, seed=BETWEENNESS_SEED,
    )
    degrees = dict(graph.degree())
    metrics = {
        "degree": degrees,
        "strength": dict(graph.degree(weight="weight")),
        "betweenness": betweenness,
        "pagerank": nx.pagerank(graph, weight="weight"),
    }
    degree_values = pd.Series(list(degrees.values()), dtype=float)
    return {
        "n_hosts": n,
        "n_edges": graph.number_of_edges(),
        "n_events": len(ocel.events),
        "sampled": len(ocel.events) < len(df),
        "degree_median": float(degree_values.median()),
        "degree_p95": float(degree_values.quantile(0.95)),
        "betweenness_exact": exact,
        "top": {name: _top(values) for name, values in metrics.items()},
        "hubs": _hubs(graph),
        "time_s": round(time.perf_counter() - start, 3),
    }


def _names(oids, object_type: str, n: int = TOP_N) -> List[str]:
    prefix = f"{object_type}:"
    return sorted(_name(o) for o in oids if o.startswith(prefix))[:n]


def build_connected_components(df: pd.DataFrame) -> Dict[str, Any]:
    """pm4py's split of the OCEL by the connected components of its object interaction
    graph (objects linked when they share an event). An object that never shares an
    event with another one is in no component; it is counted as isolated."""
    from pm4py.algo.transformation.ocel.split_ocel import algorithm as split_ocel

    start = time.perf_counter()
    ocel = build_ocel(df)
    parts = split_ocel.apply(ocel, variant=split_ocel.Variants.CONNECTED_COMPONENTS)
    components = []
    in_components = 0
    for part in parts:
        oids = part.objects[_OID].tolist()
        in_components += len(oids)
        components.append({
            "events": len(part.events),
            "objects": len(oids),
            "hosts": _names(oids, HOST),
            "users": _names(oids, "user"),
        })
    components.sort(key=lambda c: (-c["events"], -c["objects"], c["hosts"], c["users"]))
    return {
        "n_components": len(components),
        "isolated_objects": len(ocel.objects) - in_components,
        "n_objects": len(ocel.objects),
        "n_events": len(ocel.events),
        "sampled": len(ocel.events) < len(df),
        "components": components[:TOP_N],
        "time_s": round(time.perf_counter() - start, 3),
    }


def build_ocel_features(df: pd.DataFrame) -> Dict[str, Any]:
    """pm4py's object features of the hosts: the mean of each, and the hosts with the
    shortest and longest lifecycle (the thesis's signal, THESIS:1018)."""
    import pm4py

    start = time.perf_counter()
    ocel = build_ocel(df)
    _host_relations(ocel)
    table = pm4py.extract_ocel_features(ocel, obj_type=HOST, include_obj_id=True)
    features = table.drop(columns=[_OID])
    lifecycle = [
        {"host": _name(oid), "length": int(length)}
        for oid, length in zip(table[_OID], table["@@object_lifecycle_length"])
    ]
    return {
        "object_type": HOST,
        "n_objects": len(table),
        "n_features": features.shape[1],
        "feature_means": {name: round(float(features[name].mean()), 6) for name in features.columns},
        "shortest_lifecycle": sorted(lifecycle, key=lambda r: (r["length"], r["host"]))[:TOP_N],
        "longest_lifecycle": sorted(lifecycle, key=lambda r: (-r["length"], r["host"]))[:TOP_N],
        "n_events": len(ocel.events),
        "sampled": len(ocel.events) < len(df),
        "time_s": round(time.perf_counter() - start, 3),
    }


def build_ocdfg(df: pd.DataFrame) -> Dict[str, Any]:
    """pm4py's object-centric DFG: per object type, each directly-follows edge with the
    number of event couples behind it and of objects that took it."""
    import pm4py

    start = time.perf_counter()
    ocel = build_ocel(df)
    ocdfg = pm4py.discover_ocdfg(ocel)
    couples = ocdfg["edges"]["event_couples"]
    objects = ocdfg["edges"]["unique_objects"]
    edges = {
        object_type: sorted(
            (
                {
                    "source": source,
                    "target": target,
                    "events": len(pairs),
                    "objects": len(objects[object_type][(source, target)]),
                }
                for (source, target), pairs in by_edge.items()
            ),
            key=lambda e: (-e["events"], e["source"], e["target"]),
        )
        for object_type, by_edge in couples.items()
    }
    return {
        "object_types": sorted(ocdfg["object_types"]),
        "activities": sorted(ocdfg["activities"]),
        "edges": {ot: edges.get(ot, []) for ot in sorted(ocdfg["object_types"])},
        "start_activities": {
            ot: {a: len(objs) for a, objs in sorted(by_act.items())}
            for ot, by_act in sorted(ocdfg["start_activities"]["unique_objects"].items())
        },
        "end_activities": {
            ot: {a: len(objs) for a, objs in sorted(by_act.items())}
            for ot, by_act in sorted(ocdfg["end_activities"]["unique_objects"].items())
        },
        "n_events": len(ocel.events),
        "sampled": len(ocel.events) < len(df),
        "time_s": round(time.perf_counter() - start, 3),
    }


EVIDENCE_BUILDERS["host_graph"] = build_host_graph
EVIDENCE_BUILDERS["connected_components"] = build_connected_components
EVIDENCE_BUILDERS["ocel_features"] = build_ocel_features
EVIDENCE_BUILDERS["ocdfg"] = build_ocdfg
