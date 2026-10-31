"""
What each analysis method runs, described once (GLOSSARY.md; ADR 0003).

``describe_method`` looks the description up from an ``AnalysisMethod`` (or its name);
the analysis (``assess_threat``), the file entry point (``LuminaPipeline.analyze_path``),
the backend engine and the analyze route read it instead of switching on the method.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union

import pandas as pd

from lumina_cortex.config.thresholds import (
    PRODUCT_BEACON,
    PRODUCT_METHOD_V1,
    PRODUCT_MITRE_CONFORMANCE,
    PRODUCT_V2_DRIFT,
    PRODUCT_V2_THRESHOLDS,
    THESIS_METHOD_V1,
    THESIS_THRESHOLDS_V1,
    BeaconParams,
    MitreConformance,
    ProductThresholds,
    Thresholds,
)
from lumina_cortex.engine.coverage_scorer import score_pattern_coverage
from lumina_cortex.engine.drift import detect_drift, detect_proportional_drift
from lumina_cortex.engine.js_drift import detect_js_drift
from lumina_cortex.engine.scorer import score_attack_patterns
from lumina_cortex.engine.thesis_scorer import score_thesis_patterns
from lumina_cortex.mitre.catalog import TTPCatalog
from lumina_cortex.models import AnalysisMethod, DriftResult, ScorerResult

DriftDetector = Callable[[pd.DataFrame, Thresholds], DriftResult]
Scorer = Callable[[pd.DataFrame, TTPCatalog, Thresholds], ScorerResult]


@dataclass(frozen=True)
class MethodDescription:
    """One analysis method: its thresholds, engines, evidence and whether its verdict is stored.

    ``frozen_thresholds`` is None when the method takes the caller's thresholds (the
    Product method, which runs them as ``ProductThresholds``); otherwise the method runs
    only with those and refuses others.
    """

    method: AnalysisMethod
    frozen_thresholds: Optional[Thresholds]
    mitre: MitreConformance
    detect_drift: DriftDetector
    score: Scorer
    evidence: bool  # the Thesis method's experiment methods, after the verdict
    stores_verdict: bool  # the verdict lands on the signal and the hunt (the Board)
    # The name of this configuration: the method's own name, or a frozen version of it
    # kept for the evaluation only (``product-v1``). Empty means the method's name.
    version: str = ""
    # What a method that takes the caller's thresholds runs with when given none.
    default_thresholds: Thresholds = THESIS_THRESHOLDS_V1
    # The Beacon detector's values, for the method that looks for beacons (the Product
    # method v2 only); None: no beacon detection, the MITRE result is the replay's alone.
    beacon: Optional[BeaconParams] = None

    @property
    def name(self) -> str:
        """The configuration's name: its version, else the method's name."""
        return self.version or self.method.value

    def thresholds(
        self, requested: Optional[Thresholds], default: Optional[Thresholds] = None,
    ) -> Thresholds:
        """The thresholds an analysis by this method runs with.

        A method with frozen thresholds refuses any other (ValueError); otherwise (the
        Product method) ``requested``, else ``default`` (a pipeline's own), else the
        method's ``default_thresholds``, as ``ProductThresholds``: a plain thesis
        ``Thresholds`` takes product-v2's values for the Product fields
        (``ProductThresholds.of``), so the classifier and the scorer read them as fields.
        """
        if self.frozen_thresholds is None:
            return ProductThresholds.of(requested or default or self.default_thresholds)
        if requested is not None and requested != self.frozen_thresholds:
            raise ValueError(
                f"{self.name} is frozen: it runs only with its own thresholds"
            )
        return self.frozen_thresholds


_DESCRIPTIONS: Dict[AnalysisMethod, MethodDescription] = {
    # The Product method runs product-v2 (PRODUCT_METHOD_V2, frozen in ticket 08 of
    # .scratch/product-v2/): its thresholds by default, its drift windows, MITRE and
    # Beacon values.
    AnalysisMethod.PRODUCT: MethodDescription(
        method=AnalysisMethod.PRODUCT,
        frozen_thresholds=None,
        mitre=PRODUCT_MITRE_CONFORMANCE,
        # Chi-square over 10 windows proportional to the log (decision 4 of
        # .scratch/product-v2/decisions.md); the caller's drift_mode picks the condition.
        detect_drift=lambda df, t: detect_proportional_drift(df, params=PRODUCT_V2_DRIFT),
        # Pattern coverage x edge match over the eligible patterns (decision 5).
        score=lambda df, cat, t: score_pattern_coverage(df, catalog=cat, thresholds=t),
        evidence=False,
        stores_verdict=True,
        default_thresholds=PRODUCT_V2_THRESHOLDS,
        beacon=PRODUCT_BEACON,  # v2: a beacon counts as "T1071 (beacon)" above
    ),
    # Frozen as thesis-v1 (THESIS_METHOD_V1): absolute drift mode (THESIS:1160), the
    # Jensen-Shannon drift (decision 13) and the three-component scorer (THESIS:37).
    AnalysisMethod.THESIS_V1: MethodDescription(
        method=AnalysisMethod.THESIS_V1,
        frozen_thresholds=THESIS_METHOD_V1.thresholds,
        mitre=THESIS_METHOD_V1.mitre,
        detect_drift=lambda df, t: detect_js_drift(df, params=THESIS_METHOD_V1.js_drift),
        score=lambda df, cat, t: score_thesis_patterns(
            df, catalog=cat, thresholds=t, confidence=THESIS_METHOD_V1.confidence,
        ),
        evidence=True,
        stores_verdict=False,  # the analyst never sees a Thesis method verdict
    ),
}


# The Product method of 0.2.1, frozen as ``product-v1`` (PRODUCT_METHOD_V1; decision 10 of
# .scratch/product-v2/decisions.md): the per_1k thesis thresholds, the chi-square drift
# over fixed windows and the Jaccard x edges scorer. An evaluation column only: it is
# not an AnalysisMethod, so no selector (app, MCP, CLI) can name it; the evaluation
# passes this description itself. Its assessment names the Product method.
PRODUCT_V1 = MethodDescription(
    method=AnalysisMethod.PRODUCT,
    frozen_thresholds=PRODUCT_METHOD_V1.thresholds,
    mitre=PRODUCT_METHOD_V1.mitre,
    detect_drift=lambda df, t: detect_drift(df, thresholds=t),
    score=lambda df, cat, t: score_attack_patterns(df, catalog=cat, thresholds=t),
    evidence=False,
    stores_verdict=False,
    version=PRODUCT_METHOD_V1.version,
)


def describe_method(method: Union[AnalysisMethod, str, MethodDescription]) -> MethodDescription:
    """The description of ``method``; ValueError naming the valid methods for an unknown one.

    A description (``PRODUCT_V1``) is returned as is: the evaluation runs a frozen
    version by passing its description, never by name.
    """
    if isinstance(method, MethodDescription):
        return method
    return _DESCRIPTIONS[AnalysisMethod.parse(method)]
