"""
Engine module - Analysis engines for Lumina Cortex.

The notebook runs two methods:
- product: proportional chi-square drift, pattern coverage, DFG, graph, variants, MITRE, beacon
- thesis-v1: Jensen-Shannon drift and the three-component scorer, then the thesis evidence
"""

from lumina_cortex.engine.drift import detect_proportional_drift
from lumina_cortex.engine.variants import analyze_variants
from lumina_cortex.engine.graph import extract_graph_metrics
from lumina_cortex.engine.dfg import discover_dfg
from lumina_cortex.engine.mitre import assess_mitre
from lumina_cortex.engine.beacon import detect_beacons

__all__ = [
    "detect_proportional_drift",
    "analyze_variants",
    "extract_graph_metrics",
    "discover_dfg",
    "assess_mitre",
    "detect_beacons",
]
