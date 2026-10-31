"""
Engine module - Analysis engines for Lumina Cortex.

Implements the Top 5 engines from the thesis:
- drift: Concept drift detection (#1)
- variants: Variant analysis (#3)
- graph: Graph metrics extraction (#2)
- scorer: Attack pattern scoring (#4)
- dfg: DFG discovery (#8)
- mitre: MITRE conformance (pm4py token-based replay)
- beacon: the Beacon detector (the Product method v2's "T1071 (beacon)")
"""

from lumina_cortex.engine.drift import detect_drift
from lumina_cortex.engine.variants import analyze_variants
from lumina_cortex.engine.graph import extract_graph_metrics
from lumina_cortex.engine.scorer import score_attack_patterns
from lumina_cortex.engine.dfg import discover_dfg, export_dfg_map
from lumina_cortex.engine.mitre import assess_mitre
from lumina_cortex.engine.beacon import detect_beacons
from lumina_cortex.engine.forensic import build_forensic_brief
from lumina_cortex.engine.audit import audit_soar_blocks

__all__ = [
    "detect_drift",
    "analyze_variants",
    "extract_graph_metrics",
    "score_attack_patterns",
    "discover_dfg",
    "export_dfg_map",
    "assess_mitre",
    "detect_beacons",
    "build_forensic_brief",
    "audit_soar_blocks",
]
