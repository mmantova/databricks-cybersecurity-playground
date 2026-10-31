"""
Lumina Cortex - Autonomous threat hunting via process mining.

Be The Hunter, not the Hunted.
"""

__version__ = "0.4.1"

from lumina_cortex.columns import (
    CASE,
    ACTIVITY,
    TIMESTAMP,
    RESOURCE,
    OCSF_COLUMNS,
)
from lumina_cortex.errors import (
    LuminaError,
    NonCanonicalLogError,
    EmptyLogError,
    UnsupportedSourceError,
    UnsupportedCatalogVersion,
    InputLimitError,
    InvalidConfigError,
    AnalysisError,
)
from lumina_cortex.models import (
    Verdict,
    AnalysisMethod,
    CaseStrategy,
    DriftMode,
    ParseStats,
    DFGResult,
    MITREResult,
    ScorerResult,
    DriftResult,
    VariantResult,
    GraphResult,
    GapEntry,
    GapReport,
    AnalysisResult,
    ThreatAssessment,
    DataSource,
    DatasetReport,
    PipelineReport,
)
from lumina_cortex.engine import (
    detect_drift,
    analyze_variants,
    extract_graph_metrics,
    score_attack_patterns,
    discover_dfg,
    assess_mitre,
)
from lumina_cortex.verdict import (
    classify,
    assess_threat,
)
from lumina_cortex.pipeline import LuminaPipeline, run_batch

__all__ = [
    "__version__",
    # Columns
    "CASE",
    "ACTIVITY",
    "TIMESTAMP",
    "RESOURCE",
    "OCSF_COLUMNS",
    # Errors
    "LuminaError",
    "NonCanonicalLogError",
    "EmptyLogError",
    "UnsupportedSourceError",
    "UnsupportedCatalogVersion",
    "InputLimitError",
    "InvalidConfigError",
    "AnalysisError",
    # Models
    "Verdict",
    "AnalysisMethod",
    "CaseStrategy",
    "DriftMode",
    "ParseStats",
    "DFGResult",
    "MITREResult",
    "ScorerResult",
    "DriftResult",
    "VariantResult",
    "GraphResult",
    "GapEntry",
    "GapReport",
    "AnalysisResult",
    "ThreatAssessment",
    "DataSource",
    "DatasetReport",
    "PipelineReport",
    # Engines
    "detect_drift",
    "analyze_variants",
    "extract_graph_metrics",
    "score_attack_patterns",
    "discover_dfg",
    "assess_mitre",
    # Verdict
    "classify",
    "assess_threat",
    # Pipeline
    "LuminaPipeline",
    "run_batch",
]
