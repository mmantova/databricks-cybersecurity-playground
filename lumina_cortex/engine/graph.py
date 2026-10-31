"""
Graph metrics extraction using NetworkX.

Builds a graph from activity transitions and extracts:
- Degree centrality for hub detection
- Hub-and-spoke topology detection
"""

import time
from collections import Counter
from typing import Dict, List, Optional, Tuple

import networkx as nx
import pandas as pd

from lumina_cortex.columns import ACTIVITY, CASE
from lumina_cortex.config.thresholds import Thresholds, THESIS_THRESHOLDS_V1
from lumina_cortex.models import GraphResult


def extract_graph_metrics(
    df: pd.DataFrame,
    *,
    thresholds: Optional[Thresholds] = None,
) -> GraphResult:
    """
    Extract graph metrics from activity transitions.

    Builds a NetworkX graph where nodes are activities and edges
    represent transitions between activities in the log.

    Extracts:
    - Degree centrality for each node
    - Top hubs by centrality
    - Hub-and-spoke topology detection

    Args:
        df: PM4Py DataFrame with case:concept:name, concept:name.
        thresholds: Threshold configuration (default: THESIS_THRESHOLDS_V1).

    Returns:
        GraphResult with top_hubs, hub_and_spoke_detected, and compromised_nodes.
    """
    start_time = time.perf_counter()
    
    t = thresholds or THESIS_THRESHOLDS_V1

    # Validate DataFrame
    if ACTIVITY not in df.columns:
        raise ValueError(f"DataFrame missing {ACTIVITY!r} column")
    if CASE not in df.columns:
        raise ValueError(f"DataFrame missing {CASE!r} column")
    if len(df) == 0:
        return GraphResult(
            top_hubs=(),
            hub_and_spoke_detected=False,
            compromised_nodes=(),
        )

    # Build transition graph
    G = nx.DiGraph()
    
    # Count transitions
    transition_counts: Counter[Tuple[str, str]] = Counter()
    
    for case_id, group in df.groupby(CASE, sort=False):
        activities = group[ACTIVITY].tolist()
        for i in range(len(activities) - 1):
            transition_counts[(activities[i], activities[i + 1])] += 1

    # Add nodes and edges
    for (src, dst), count in transition_counts.items():
        G.add_edge(src, dst, weight=count)

    if G.number_of_nodes() == 0:
        return GraphResult(
            top_hubs=(),
            hub_and_spoke_detected=False,
            compromised_nodes=(),
        )

    # Calculate degree centrality
    # Use total degree (in + out) for hub detection
    degree_centrality = nx.degree_centrality(G)

    # Get top hubs by centrality
    sorted_nodes = sorted(
        degree_centrality.items(),
        key=lambda x: x[1],
        reverse=True,
    )
    
    top_hubs: List[Tuple[str, float]] = []
    for node, centrality in sorted_nodes[:10]:
        top_hubs.append((node, round(centrality, 6)))

    # Detect hub-and-spoke topology
    # Hub-and-spoke: one or few nodes have much higher degree than average
    hub_and_spoke_detected = False
    
    if len(sorted_nodes) >= t.hub_min_nodes:
        # Calculate average degree
        degrees = [G.degree(n) for n in G.nodes()]
        avg_degree = sum(degrees) / len(degrees)
        
        if avg_degree > 0:
            # Check if top node has degree much higher than average
            top_node = sorted_nodes[0][0]
            top_degree = G.degree(top_node)
            degree_ratio = top_degree / avg_degree
            
            # Also check centrality threshold
            top_centrality = sorted_nodes[0][1]
            
            if (
                degree_ratio >= t.hub_degree_ratio_min
                and top_centrality >= t.hub_centrality_min
            ):
                hub_and_spoke_detected = True

    # Note: compromised_nodes is not determined by this engine
    # It requires ground truth labels from the investigation
    compromised_nodes: Tuple[str, ...] = ()

    return GraphResult(
        top_hubs=tuple(top_hubs),
        hub_and_spoke_detected=hub_and_spoke_detected,
        compromised_nodes=compromised_nodes,
    )
