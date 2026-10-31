"""
Evidence the Thesis method reports beside its verdict.

Each experiment method of the thesis (variants, discovery models, host graph, OCEL,
eventually-follows filters...) registers one builder here under its evidence key. The
Thesis method runs every builder after its verdict; none of them feeds the verdict
(docs/adr/0003-thesis-method-beside-product-method.md). A builder that raises reports
``{"error": ...}`` under its own key and leaves the others alone.
"""

from typing import Any, Callable, Dict

import pandas as pd

EvidenceBuilder = Callable[[pd.DataFrame], Dict[str, Any]]

# Evidence key -> builder. Each experiment method adds its own entry.
EVIDENCE_BUILDERS: Dict[str, EvidenceBuilder] = {}


def collect_evidence(df: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
    """Run every registered builder on ``df``; a failure is that builder's error only."""
    evidence: Dict[str, Dict[str, Any]] = {}
    for key, build in EVIDENCE_BUILDERS.items():
        try:
            evidence[key] = build(df)
        except Exception as exc:
            evidence[key] = {"error": str(exc)}
    return evidence


# Each experiment module registers its builders on import.
from lumina_cortex.evidence import graph as _graph  # noqa: E402,F401  (ticket 08)
from lumina_cortex.evidence import filters  # noqa: E402,F401  (eventually_follows, play_out)
from lumina_cortex.evidence import discovery as _discovery  # noqa: E402,F401  (ticket 07)
