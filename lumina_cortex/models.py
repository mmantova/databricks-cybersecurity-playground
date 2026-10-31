"""
Data models for Lumina Cortex results.

All dataclasses are frozen (immutable) and provide to_dict() methods
with ISO-8601 Z dates, 6dp floats, and NaN→None conversion.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import math


def _sanitize_value(v: Any) -> Any:
    """Convert value for JSON serialization: ISO dates, 6dp floats, NaN→None."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        return round(v, 6)
    if isinstance(v, Enum):
        return v.value
    return v


def _sanitize_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Apply sanitization to all values in a dict."""
    return {k: _sanitize_value(v) for k, v in d.items()}


class Verdict(str, Enum):
    """Threat assessment verdict."""

    ATTACK_DETECTED = "ATTACK_DETECTED"
    SUSPICIOUS_DRIFT = "SUSPICIOUS_DRIFT"
    SUSPICIOUS_SCORE = "SUSPICIOUS_SCORE"
    BENIGN = "BENIGN"


class CaseStrategy(str, Enum):
    """Strategy for grouping events into cases."""

    HOST = "host"
    IP = "ip"
    TIME_WINDOW = "time_window"


class DriftMode(str, Enum):
    """Mode for drift count calculation."""

    ABSOLUTE = "absolute"
    PER_1K = "per_1k"
    PER_WINDOW = "per_window"


class AnalysisMethod(str, Enum):
    """The method an analysis runs (GLOSSARY.md; ADR 0003).

    PRODUCT gives the verdicts the analyst sees and is the default. THESIS_V1 is the
    Thesis method, frozen under its version name: a change makes a new version.
    The backend contract (``backend/contract.py``) carries the same values.
    """

    PRODUCT = "product"
    THESIS_V1 = "thesis-v1"

    @classmethod
    def parse(cls, value: Union["AnalysisMethod", str]) -> "AnalysisMethod":
        """The method for a name; ValueError lists the valid names."""
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"method must be one of: {', '.join(m.value for m in cls)}") from None


@dataclass(frozen=True)
class ParseStats:
    """Statistics from parsing a log source."""

    total_lines: int
    parsed_events: int
    skipped_malformed: int
    skipped_unmapped: int
    bytes_read: int

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "skipped_malformed": self.skipped_malformed,
            "skipped_unmapped": self.skipped_unmapped,
            "bytes_read": self.bytes_read,
        })


@dataclass(frozen=True)
class DFGResult:
    """Result from DFG discovery.

    ``fitness`` and ``precision`` are pm4py's token-based replay of the log on its
    inductive net. That conformance check is opt-in (``discover_dfg(conformance=True)``);
    the product analysis does not run it. Whenever it is not run or cannot run they are
    ``None`` and ``conformance_error`` says why ("not computed: ..." when not opted in,
    the failure otherwise), never a made-up value.
    """

    fitness: Optional[float]
    precision: Optional[float]
    f_score: Optional[float]
    edges: int
    time_s: float
    conformance_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "fitness": self.fitness,
            "precision": self.precision,
            "f_score": self.f_score,
            "edges": self.edges,
            "time_s": self.time_s,
            "conformance_error": self.conformance_error,
        })


@dataclass(frozen=True)
class MITREResult:
    """Result from MITRE ATT&CK conformance checking (pm4py token-based replay).

    ``top_matches`` are the patterns above the fitness threshold as (TTP id, fitness),
    best first. ``replayed`` lists every pattern that had cases to replay as
    (TTP id, fitness, cases replayed), above or not. When the check could not run,
    ``conformance_error`` says why, ``threat_level`` is None and nothing is above.
    """

    threat_level: Optional[str]  # "none" | "low" | "medium" | "high"; None when not computed
    models_above: int
    total_models: int
    top_matches: Tuple[Tuple[str, float], ...]
    time_s: float
    replayed: Tuple[Tuple[str, float, int], ...] = ()
    conformance_error: Optional[str] = None
    # The Beacons found (Product method only): when any, "T1071 (beacon)" is one of the
    # patterns above (``lumina_cortex.engine.beacon``).
    beacons: Tuple["Beacon", ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "threat_level": self.threat_level,
            "models_above": self.models_above,
            "total_models": self.total_models,
            "top_matches": [list(m) for m in self.top_matches],
            "replayed": [list(r) for r in self.replayed],
            "time_s": self.time_s,
            "conformance_error": self.conformance_error,
        }
        # Only when a beacon was found, so a result without one serializes as before.
        if self.beacons:
            d["beacons"] = [b.to_dict() for b in self.beacons]
        return _sanitize_dict(d)


@dataclass(frozen=True)
class Beacon:
    """A Beacon (GLOSSARY.md): repeated connections from ``source`` to ``destination``
    on ``port`` (None when the events carry none) at regular intervals."""

    source: str
    destination: str
    port: Optional[int]
    connections: int
    mean_interval_s: float
    cv: float  # coefficient of variation of the intervals (std / mean)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "connections": self.connections,
            "mean_interval_s": round(self.mean_interval_s, 6),
            "cv": round(self.cv, 6),
        }


@dataclass(frozen=True)
class ScorerResult:
    """Result from attack pattern scoring."""

    patterns_checked: int
    top_score: float
    top_name: str
    top5: Tuple[Dict[str, Any], ...]
    time_s: float

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "patterns_checked": self.patterns_checked,
            "top_score": self.top_score,
            "top_name": self.top_name,
            "top5": list(self.top5),
            "time_s": self.time_s,
        })


@dataclass(frozen=True)
class AffectedActivity:
    """An activity's share of a drift point's Jensen-Shannon divergence.

    ``contribution`` is the activity's term of the divergence (the terms sum to it);
    ``before`` and ``after`` its relative frequency in the two windows compared.
    """

    activity: str
    contribution: float
    before: float
    after: float

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "activity": self.activity,
            "contribution": self.contribution,
            "before": self.before,
            "after": self.after,
        })


@dataclass(frozen=True)
class DriftPoint:
    """One drift of the Thesis method's Jensen-Shannon detector.

    ``type`` is "sudden" (one window to the next) or "gradual" (built up over several
    windows); ``divergence`` is the JS divergence that crossed the threshold.
    """

    timestamp: datetime
    type: str
    divergence: float
    affected_activities: Tuple[AffectedActivity, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": _sanitize_value(self.timestamp),
            "type": self.type,
            "divergence": _sanitize_value(self.divergence),
            "affected_activities": [a.to_dict() for a in self.affected_activities],
        }


@dataclass(frozen=True)
class DriftResult:
    """Result from concept drift detection.

    The fixed-window chi-square detector (``product-v1``) fills the fields up to
    ``per_1k_events`` and leaves ``detector`` None, and its serialization is unchanged.
    The Product method v2's proportional chi-square detector names itself in
    ``detector`` and adds the window size, the comparisons and the drift fraction. The
    Thesis method's Jensen-Shannon detector names itself in ``detector`` and adds the
    typed ``points`` and the window length it used.
    """

    count: int
    first_ts: Optional[datetime]
    drift_points: Tuple[datetime, ...]
    time_s: float
    n_events: int = 0
    n_windows: int = 0
    per_1k_events: float = 0.0
    detector: Optional[str] = None
    points: Tuple[DriftPoint, ...] = ()
    window_seconds: Optional[int] = None
    # The Product method v2's proportional chi-square drift (detector
    # "chi_square_proportional"): events per window, adjacent-window comparisons made
    # (0 when the log is too short for two windows) and the fraction that drifted.
    window_events: Optional[int] = None
    n_comparisons: Optional[int] = None
    drift_fraction: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d = _sanitize_dict({
            "count": self.count,
            "first_ts": self.first_ts,
            "drift_points": list(self.drift_points),
            "time_s": self.time_s,
            "n_events": self.n_events,
            "n_windows": self.n_windows,
            "per_1k_events": self.per_1k_events,
        })
        if self.n_comparisons is not None:
            d["detector"] = self.detector
            d["window_events"] = self.window_events
            d["n_comparisons"] = self.n_comparisons
            d["drift_fraction"] = self.drift_fraction
        elif self.detector is not None:
            d["detector"] = self.detector
            d["window_seconds"] = self.window_seconds
            d["points"] = [p.to_dict() for p in self.points]
        return d


@dataclass(frozen=True)
class VariantResult:
    """Result from variant analysis."""

    total_variants: int
    anomalous_variants: Tuple[Dict[str, Any], ...]
    discrimination_score: float

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "total_variants": self.total_variants,
            "anomalous_variants": list(self.anomalous_variants),
            "discrimination_score": self.discrimination_score,
        })


@dataclass(frozen=True)
class GraphResult:
    """Result from graph metrics extraction."""

    top_hubs: Tuple[Tuple[str, float], ...]
    hub_and_spoke_detected: bool
    compromised_nodes: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "top_hubs": list(self.top_hubs),
            "hub_and_spoke_detected": self.hub_and_spoke_detected,
            "compromised_nodes": list(self.compromised_nodes),
        })


@dataclass(frozen=True)
class GapEntry:
    """A coverage gap entry."""

    ttp_id: str
    ttp_name: str
    required_activities: Tuple[str, ...]
    missing_activities: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ttp_id": self.ttp_id,
            "ttp_name": self.ttp_name,
            "required_activities": list(self.required_activities),
            "missing_activities": list(self.missing_activities),
        }


@dataclass(frozen=True)
class GapReport:
    """Report of coverage gaps in the vocabulary."""

    gaps: Tuple[GapEntry, ...]
    vocabulary_version: str
    attack_version: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gaps": [g.to_dict() for g in self.gaps],
            "vocabulary_version": self.vocabulary_version,
            "attack_version": self.attack_version,
        }


@dataclass(frozen=True)
class AnalysisResult:
    """Consolidated analysis result from multiple engines."""

    dfg: DFGResult
    mitre: MITREResult
    scorer: ScorerResult
    drift: DriftResult
    variants: Optional[VariantResult] = None
    graph: Optional[GraphResult] = None
    # Distinct activities in the analyzed log: the verdict's vocabulary input.
    unique_activities: int = 0

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "dfg": self.dfg.to_dict(),
            "mitre": self.mitre.to_dict(),
            "scorer": self.scorer.to_dict(),
            "drift": self.drift.to_dict(),
            "unique_activities": self.unique_activities,
        }
        if self.variants is not None:
            result["variants"] = self.variants.to_dict()
        if self.graph is not None:
            result["graph"] = self.graph.to_dict()
        return result


@dataclass(frozen=True)
class ThreatAssessment:
    """Complete threat assessment with verdict."""

    verdict: Verdict
    confidence: float
    dfg: DFGResult
    mitre: MITREResult
    scorer: ScorerResult
    drift: DriftResult
    variants: Optional[VariantResult] = None
    graph: Optional[GraphResult] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    # The method that produced this assessment, and its evidence: empty for the Product
    # method; for the Thesis method one entry per experiment method, run after the
    # verdict and never a verdict input (lumina_cortex.evidence): process discovery
    # (variants, dfg, heuristics_net, inductive, footprints, log_skeleton,
    # performance_dfg), host graph and OCEL (host_graph, connected_components,
    # ocel_features, ocdfg), filters and play-out (eventually_follows, play_out). A
    # failed entry holds only its own ``error``. The agent may cite it in a diagnosis
    # (spec story 42).
    method: AnalysisMethod = AnalysisMethod.PRODUCT
    evidence: Dict[str, Any] = field(default_factory=dict)

    def analysis(self) -> AnalysisResult:
        """The engines' results this assessment carries, as the classifier reads them
        (``lumina_cortex.verdict.classifier``): what classifying it again with other
        thresholds starts from (the evaluation's threshold sweep)."""
        return AnalysisResult(
            dfg=self.dfg, mitre=self.mitre, scorer=self.scorer, drift=self.drift,
            variants=self.variants, graph=self.graph,
            unique_activities=self.metadata.get("unique_activities", 0),
        )

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "method": self.method.value,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "dfg": self.dfg.to_dict(),
            "mitre": self.mitre.to_dict(),
            "scorer": self.scorer.to_dict(),
            "drift": self.drift.to_dict(),
        }
        if self.variants is not None:
            result["variants"] = self.variants.to_dict()
        if self.graph is not None:
            result["graph"] = self.graph.to_dict()
        result["metadata"] = _sanitize_dict(self.metadata)
        result["evidence"] = _sanitize_dict(self.evidence)
        return result


@dataclass(frozen=True)
class SoarAuditResult:
    """Deterministic SOAR / policy-block audit — not MITRE conformance."""

    violation_count: int = 0
    cases_affected: int = 0
    top_activities: Tuple[Tuple[str, int], ...] = ()
    sample_rows: Tuple[Dict[str, Any], ...] = ()
    filter_column: str = ""
    filter_value: str = ""
    time_s: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return _sanitize_dict({
            "violation_count": self.violation_count,
            "cases_affected": self.cases_affected,
            "top_activities": [list(a) for a in self.top_activities],
            "sample_rows": list(self.sample_rows),
            "filter_column": self.filter_column,
            "filter_value": self.filter_value,
            "time_s": self.time_s,
        })


@dataclass(frozen=True)
class ForensicBrief:
    """Handover artifact: DFG map + optional SOAR audit + hunt summary."""

    dfg: DFGResult
    soar: SoarAuditResult
    map_path: Optional[str] = None
    summary: str = ""
    cases: int = 0
    events: int = 0
    activities: int = 0
    time_s: float = 0.0
    # Top DFG edges for the Board UI (source → target, count); PNG is optional offline art.
    top_edges: Tuple[Tuple[str, str, int], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dfg": self.dfg.to_dict(),
            "soar": self.soar.to_dict(),
            "map_path": self.map_path,
            "summary": self.summary,
            "cases": self.cases,
            "events": self.events,
            "activities": self.activities,
            "time_s": _sanitize_value(self.time_s),
            "top_edges": [list(e) for e in self.top_edges],
        }


@dataclass(frozen=True)
class DataSource:
    """A telemetry source for the pipeline."""

    name: str
    source_type: str  # "zeek" | "sysmon" | "cloudtrail" | "netflow" | ...
    path: str
    case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW
    expected_verdict: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source_type": self.source_type,
            "path": self.path,
            "case_strategy": self.case_strategy.value,
            "expected_verdict": self.expected_verdict,
        }


_WALL_CLOCK_KEYS = frozenset({"time_s", "total_time_s"})


def _without_wall_clock(value: Any) -> Any:
    """Drop the engines' measured durations, which differ from run to run."""
    if isinstance(value, dict):
        return {k: _without_wall_clock(v) for k, v in value.items() if k not in _WALL_CLOCK_KEYS}
    if isinstance(value, list):
        return [_without_wall_clock(v) for v in value]
    return value


@dataclass(frozen=True)
class DatasetReport:
    """One source's entry in a pipeline report: its assessment, or why it has none.

    The assessment is written without the engines' wall-clock durations (``time_s``,
    ``total_time_s``) so that the same input gives the same report.
    """

    source: DataSource
    method: AnalysisMethod
    assessment: Optional[ThreatAssessment] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "method": self.method.value,
            "verdict": self.assessment.verdict.value if self.assessment else None,
            "error": self.error,
            "assessment": _without_wall_clock(self.assessment.to_dict()) if self.assessment else None,
        }


@dataclass(frozen=True)
class PipelineReport:
    """Report from running the full pipeline over a batch of sources (thesis stage 4).

    ``timestamp`` is whatever the caller passes (None by default) so that the same
    input gives the same document.
    """

    timestamp: Optional[str]
    datasets_analyzed: int
    summary: Dict[str, Any]
    datasets: Tuple[DatasetReport, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "datasets_analyzed": self.datasets_analyzed,
            "summary": _sanitize_dict(self.summary),
            "datasets": [d.to_dict() for d in self.datasets],
        }
