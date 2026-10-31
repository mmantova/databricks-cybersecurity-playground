"""
Threshold configuration for the combined verdict.

The thesis thresholds (THESIS_THRESHOLDS_V1) are FROZEN and versioned.
Changes to these values require a new tag and validation.

This commit will be tagged: thesis-thresholds-v1

The Thesis method runs with its own frozen configuration version, THESIS_METHOD_V1
(``thesis-v1``): those thresholds plus the interpretation values the thesis does not
give (MITRE fitness and bands, Jensen-Shannon drift, scorer confidence cut-offs). The
Product method has its own MITRE values (PRODUCT_MITRE_CONFORMANCE).
"""

from dataclasses import dataclass, fields, replace
from typing import Any, Dict, Mapping, Optional, Tuple

from lumina_cortex.models import DriftMode


# The Product method v2's drift fraction threshold, frozen in product-v2 (ticket 08 of
# .scratch/product-v2/): the middle of the sweep's passing range on the tuning set
# (0.1 to 0.7; CTU-13 Neris, 7 of 9 comparisons, is lost above 0.78). 0.4 reads "at
# least 4 of the 9 adjacent-window comparisons drifted". docs/verification.md, "Tuning
# and freezing product-v2". (0.3 was the provisional value of tickets 03 to 10.)
PRODUCT_V2_DRIFT_FRACTION_MIN = 0.4


@dataclass(frozen=True)
class Thresholds:
    """
    Thresholds for the combined verdict and engine parameters.

    These values were validated in the thesis on 23 empirical evidences.
    DO NOT change the defaults without creating a new version tag.
    """

    # Scorer threshold
    scorer_top_min: float = 0.3  # Minimum top score for ATTACK_DETECTED

    # Drift thresholds
    drift_count_min: int = 10  # Minimum drift count for ATTACK_DETECTED
    vocab_min: int = 5  # Minimum vocabulary size for meaningful verdict
    mitre_models_min: int = 1  # Minimum MITRE models above threshold

    # Drift mode and parameters
    drift_mode: DriftMode = DriftMode.ABSOLUTE
    drift_per_1k_min: float = 0.5  # Alternative: drifts per 1000 events
    drift_window_size: int = 500  # Window size for drift detection
    drift_sensitivity: float = 0.05  # Sensitivity for drift detection

    # Sampling parameters
    sample_max_events: int = 10_000  # Max events for sampling
    sample_seed: int = 0  # Seed for reproducible sampling

    # Time window for case grouping
    time_window_seconds: int = 300  # 5 minutes

    # Variant analysis
    variant_dominant_coverage: float = 0.8  # Dominant variant coverage threshold

    # Graph analysis (hub-and-spoke detection)
    hub_centrality_min: float = 0.5  # Minimum centrality for hub
    hub_degree_ratio_min: float = 3.0  # Hub degree / avg degree ratio
    hub_min_nodes: int = 5  # Minimum nodes for hub-and-spoke detection

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "scorer_top_min": self.scorer_top_min,
            "drift_count_min": self.drift_count_min,
            "vocab_min": self.vocab_min,
            "mitre_models_min": self.mitre_models_min,
            "drift_mode": self.drift_mode.value,
            "drift_per_1k_min": self.drift_per_1k_min,
            "drift_window_size": self.drift_window_size,
            "drift_sensitivity": self.drift_sensitivity,
            "sample_max_events": self.sample_max_events,
            "sample_seed": self.sample_seed,
            "time_window_seconds": self.time_window_seconds,
            "variant_dominant_coverage": self.variant_dominant_coverage,
            "hub_centrality_min": self.hub_centrality_min,
            "hub_degree_ratio_min": self.hub_degree_ratio_min,
            "hub_min_nodes": self.hub_min_nodes,
        }

    @classmethod
    def from_mapping(cls, d: Mapping[str, Any]) -> "Thresholds":
        """
        Create Thresholds from a mapping (dict, etc.).

        A key the mapping leaves out takes the dataclass default; unknown keys are
        ignored. Validates that the values are within acceptable ranges.

        Raises:
            ValueError: If any value is out of range.
        """
        names = {f.name for f in fields(cls)}
        values: Dict[str, Any] = {k: v for k, v in d.items() if k in names}
        if "drift_mode" in values:
            try:
                values["drift_mode"] = DriftMode(values["drift_mode"])
            except ValueError:
                raise ValueError(f"Invalid drift_mode: {values['drift_mode']}") from None
        t = replace(cls(), **values)

        if not 0 <= t.scorer_top_min <= 1:
            raise ValueError(f"scorer_top_min must be in [0, 1], got {t.scorer_top_min}")
        for name in ("drift_count_min", "vocab_min", "drift_per_1k_min"):
            if getattr(t, name) < 0:
                raise ValueError(f"{name} must be >= 0, got {getattr(t, name)}")
        return t


@dataclass(frozen=True)
class ProductThresholds(Thresholds):
    """The Product method v2's thresholds: the thesis fields plus the per_window drift
    threshold, which is not a thesis value (the thesis Thresholds stay exactly the
    tagged ones). ``drift_fraction_min`` is the minimum fraction of adjacent-window
    comparisons that drifted, read only in ``per_window`` drift mode; by default
    product-v2's (PRODUCT_V2_DRIFT_FRACTION_MIN). A field, so the sweep can name it.
    The other defaults are the thesis values: product-v2's own (a higher
    ``scorer_top_min``) are in PRODUCT_METHOD_V2.

    ``pattern_share_exponent`` (k) is the specificity weight of the coverage scorer
    (ticket 10; decision 5's second step): each pattern's score is multiplied by
    (1 - share) ** k, share being the fraction of the scored log's events whose activity
    is one of the pattern's, so a pattern that is most of the log says little. 0 (the
    default, and product-v2's: decision 15) leaves the score as it was: no value met the
    tuning target on its own (docs/verification.md, "Specificity-weighted score").
    """

    drift_fraction_min: float = PRODUCT_V2_DRIFT_FRACTION_MIN
    pattern_share_exponent: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            **super().to_dict(),
            "drift_fraction_min": self.drift_fraction_min,
            "pattern_share_exponent": self.pattern_share_exponent,
        }

    @classmethod
    def of(cls, t: Thresholds) -> "ProductThresholds":
        """``t`` as ProductThresholds: itself when it is one, else its thesis fields with
        this class's defaults for the Product fields (product-v2's)."""
        if isinstance(t, ProductThresholds):
            return t
        return cls(**{f.name: getattr(t, f.name) for f in fields(Thresholds)})

    @classmethod
    def from_mapping(cls, d: Mapping[str, Any]) -> "ProductThresholds":
        t = super().from_mapping(d)
        if not 0 <= t.drift_fraction_min <= 1:
            raise ValueError(f"drift_fraction_min must be in [0, 1], got {t.drift_fraction_min}")
        if t.pattern_share_exponent < 0:
            raise ValueError(f"pattern_share_exponent must be >= 0, got {t.pattern_share_exponent}")
        return t


@dataclass(frozen=True)
class MitreConformance:
    """MITRE conformance interpretation values (decision 8 of .scratch/thesis/decisions.md).

    A pattern is "above" when pm4py's token-based replay fitness is at least
    ``fitness_min``; the threat level is low / medium / high from these counts of
    patterns above (``level_bands``: 1 -> low, 2-3 -> medium, 4+ -> high with
    (1, 2, 4)). The thesis defines neither.
    """

    fitness_min: float
    level_bands: Tuple[int, int, int]

    def __post_init__(self) -> None:
        if not 0 <= self.fitness_min <= 1:
            raise ValueError(f"mitre fitness_min must be in [0, 1], got {self.fitness_min}")
        bands = tuple(self.level_bands)
        if len(bands) != 3 or not 1 <= bands[0] <= bands[1] <= bands[2]:
            raise ValueError(
                f"mitre level_bands must be three increasing counts >= 1 (low, medium, high), got {bands}"
            )
        object.__setattr__(self, "level_bands", bands)

    def to_dict(self) -> Dict[str, Any]:
        return {"fitness_min": self.fitness_min, "level_bands": list(self.level_bands)}


@dataclass(frozen=True)
class JsDrift:
    """The Thesis method's drift (interpretation, decision 13).

    Jensen-Shannon divergence (base 2) between adjacent time windows of
    ``window_seconds``, a drift at JS >= ``js_min`` (THESIS:58-64 names the measure, not
    the values); gradual when the divergence from the regime's first window reaches it
    over at least ``gradual_windows`` windows; a drift names its ``top_activities``
    largest contributors.
    """

    window_seconds: int
    js_min: float
    gradual_windows: int
    top_activities: int

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError(f"js window_seconds must be > 0, got {self.window_seconds}")
        if not 0 < self.js_min <= 1:
            raise ValueError(f"js_min must be in (0, 1], got {self.js_min}")
        if self.gradual_windows < 2:
            raise ValueError(f"js gradual_windows must be >= 2, got {self.gradual_windows}")
        if self.top_activities < 1:
            raise ValueError(f"js top_activities must be >= 1, got {self.top_activities}")

    def to_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass(frozen=True)
class ScorerConfidence:
    """The Thesis method scorer's confidence from a pattern's overlap (spec story 19):
    high from ``high_min``, medium from ``medium_min``, low below. Never a verdict input."""

    high_min: float
    medium_min: float

    def __post_init__(self) -> None:
        if not 0 <= self.medium_min <= self.high_min <= 1:
            raise ValueError(
                f"confidence cut-offs must satisfy 0 <= medium_min <= high_min <= 1, "
                f"got {self.medium_min}, {self.high_min}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {"high_min": self.high_min, "medium_min": self.medium_min}


@dataclass(frozen=True)
class ThesisMethodConfig:
    """A frozen configuration version of the Thesis method (spec, "Thresholds").

    The frozen thesis thresholds (tag thesis-thresholds-v1) plus the interpretation
    values the thesis does not give. A change to any of them is a new version, never
    an edit of an existing one.
    """

    version: str
    thresholds: Thresholds
    mitre: MitreConformance
    js_drift: JsDrift
    confidence: ScorerConfidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "thresholds": self.thresholds.to_dict(),
            "mitre": self.mitre.to_dict(),
            "js_drift": self.js_drift.to_dict(),
            "confidence": self.confidence.to_dict(),
        }


# FROZEN thesis thresholds - DO NOT MODIFY
# This instance is validated against the thesis results.
THESIS_THRESHOLDS_V1 = Thresholds()

# Tag for version tracking
THRESHOLDS_TAG = "thesis-thresholds-v1"


# The Thesis method v1: FROZEN - DO NOT MODIFY. A change makes a new version.
THESIS_METHOD_V1 = ThesisMethodConfig(
    version="thesis-v1",
    thresholds=THESIS_THRESHOLDS_V1,
    mitre=MitreConformance(fitness_min=0.8, level_bands=(1, 2, 4)),
    js_drift=JsDrift(window_seconds=300, js_min=0.2, gradual_windows=3, top_activities=3),
    confidence=ScorerConfidence(high_min=0.7, medium_min=0.3),
)

# The Product method's own MITRE conformance values (decision 9: it uses the same
# conformance). Equal to the Thesis method's today, but its own: a Product change
# goes through the H5 gate and never edits thesis-v1.
PRODUCT_MITRE_CONFORMANCE = MitreConformance(fitness_min=0.8, level_bands=(1, 2, 4))


@dataclass(frozen=True)
class BeaconParams:
    """The Beacon detector's values (GLOSSARY.md; decisions 6 and 11 of
    .scratch/product-v2/decisions.md).

    A source -> destination:port is a beacon when it has at least ``min_connections``
    connections and the coefficient of variation (population standard deviation over
    mean) of their inter-arrival intervals is at most ``cv_max``. The cost is bounded:
    only the first ``max_events`` events with both endpoints, in the log's order (by
    position), are looked at, and at most ``max_beacons`` beacons are reported (most
    connections first).
    """

    min_connections: int
    cv_max: float
    max_events: int = 200_000
    max_beacons: int = 20

    def __post_init__(self) -> None:
        if self.min_connections < 3:
            raise ValueError(
                f"beacon min_connections must be >= 3 (two intervals), got {self.min_connections}"
            )
        if self.cv_max < 0:
            raise ValueError(f"beacon cv_max must be >= 0, got {self.cv_max}")
        if self.max_events < self.min_connections:
            raise ValueError(
                f"beacon max_events must be >= min_connections, got {self.max_events}"
            )
        if self.max_beacons < 1:
            raise ValueError(f"beacon max_beacons must be >= 1, got {self.max_beacons}")

    def to_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass(frozen=True)
class ProportionalDrift:
    """The Product method v2's drift (decision 4 of .scratch/product-v2/decisions.md).

    The log is cut into ``windows`` consecutive windows of len(log) / ``windows`` events,
    at least ``min_window_events`` each; adjacent windows are compared by the chi-square
    test on their activity counts, a drift at p < ``sensitivity``. In ``per_window``
    drift mode the verdict's drift condition is "fraction of the comparisons that
    drifted >= ``ProductThresholds.drift_fraction_min``".
    """

    windows: int
    min_window_events: int
    sensitivity: float

    def __post_init__(self) -> None:
        if self.windows < 2:
            raise ValueError(f"drift windows must be >= 2, got {self.windows}")
        if self.min_window_events < 1:
            raise ValueError(f"drift min_window_events must be >= 1, got {self.min_window_events}")
        if not 0 < self.sensitivity < 1:
            raise ValueError(f"drift sensitivity must be in (0, 1), got {self.sensitivity}")

    def to_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass(frozen=True)
class ProductMethodConfig:
    """A configuration version of the Product method: the verdict's thresholds, the MITRE
    values and, from v2 on, the detectors' own values (the proportional drift's windows
    and the Beacon detector's). A frozen one is pinned in a test (product-v1 as an
    evaluation column only, decision 10 of .scratch/product-v2/decisions.md); a change
    to any value is a new version, never an edit.

    The detectors' values are kept apart from ``thresholds`` (the verdict rule's inputs)
    on purpose: the threshold sweep (``eval/run_eval.py``) varies a configuration as a
    whole, naming a threshold by its field (``drift_fraction_min``) and a Beacon value as
    ``beacon.<field>`` (``beacon.cv_max``).
    """

    version: str
    thresholds: Thresholds
    mitre: MitreConformance
    drift: Optional[ProportionalDrift] = None  # None: the fixed-window drift (product-v1)
    beacon: Optional[BeaconParams] = None  # None: no Beacon detector (product-v1)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "version": self.version,
            "thresholds": self.thresholds.to_dict(),
            "mitre": self.mitre.to_dict(),
        }
        if self.drift is not None:
            d["drift"] = self.drift.to_dict()
        if self.beacon is not None:
            d["beacon"] = self.beacon.to_dict()
        return d


# The Product method v2: FROZEN - DO NOT MODIFY. What ``product`` means since ticket 08
# of .scratch/product-v2/ (a change is a new version, product-v3). The verdict rule's
# thresholds are the thesis values with the drift condition on the fraction of
# comparisons (per_window); drift_fraction_min, scorer_top_min and the Beacon values are
# the middle of the sweep's passing range on the tuning set (decisions 13 and 15:
# every tuning attack detected, no more benign hunts than product-v1), measured
# 2026-10-26, docs/verification.md "Tuning and freezing product-v2":
#   drift_fraction_min 0.4  (passing 0.1-0.7 of the grid; CTU-13 Neris lost above 7/9)
#   scorer_top_min 0.6      (passing 0.3-0.9; every deciding score is 1.0)
#   beacon cv_max 0.4       (passing from 0.2; the Neris channels' lowest CV is 0.19)
#   beacon min_connections 15 (passing up to 25; the Neris channel with most is 27)
# The specificity weight stays off (decision 15). The drift's
# windows are decision 4's (10 windows of at least 50 events, the thesis sensitivity).
PRODUCT_METHOD_V2 = ProductMethodConfig(
    version="product-v2",
    thresholds=ProductThresholds(
        drift_mode=DriftMode.PER_WINDOW,
        drift_fraction_min=PRODUCT_V2_DRIFT_FRACTION_MIN,
        scorer_top_min=0.6,
    ),
    mitre=PRODUCT_MITRE_CONFORMANCE,
    drift=ProportionalDrift(
        windows=10,
        min_window_events=50,
        sensitivity=THESIS_THRESHOLDS_V1.drift_sensitivity,
    ),
    beacon=BeaconParams(min_connections=15, cv_max=0.4),
)

# product-v2's parts under the names the library reads them by. PRODUCT_V2_THRESHOLDS is
# what the Product method analyzes with when no thresholds are given; the backend builds
# the same (``backend.engine.thresholds_in_force()``).
PRODUCT_V2_THRESHOLDS = PRODUCT_METHOD_V2.thresholds
PRODUCT_V2_DRIFT = PRODUCT_METHOD_V2.drift
PRODUCT_BEACON = PRODUCT_METHOD_V2.beacon


# The Product method of 0.2.1: FROZEN - DO NOT MODIFY. What ``product`` analyzed with
# (``backend.engine.thresholds_in_force()``: the thesis thresholds in per_1k drift mode)
# and its MITRE values, as its own copies, so a later Product change leaves it as is.
PRODUCT_METHOD_V1 = ProductMethodConfig(
    version="product-v1",
    thresholds=replace(THESIS_THRESHOLDS_V1, drift_mode=DriftMode.PER_1K),
    mitre=MitreConformance(fitness_min=0.8, level_bands=(1, 2, 4)),
)
