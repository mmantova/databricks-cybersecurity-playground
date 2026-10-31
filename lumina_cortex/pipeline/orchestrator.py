"""
Pipeline orchestrator for Lumina Cortex.

Provides a high-level API for analyzing log files.
"""

from pathlib import Path
from typing import Optional, Union

import pandas as pd

from lumina_cortex.config.thresholds import Thresholds
from lumina_cortex.mitre.catalog import TTPCatalog, load_attack_ttps
from lumina_cortex.models import AnalysisMethod, CaseStrategy, ThreatAssessment
from lumina_cortex.normalizers import normalize
from lumina_cortex.methods import MethodDescription, describe_method
from lumina_cortex.verdict.assessment import assess_threat


class LuminaPipeline:
    """
    High-level pipeline for threat analysis.

    Usage:
        pipeline = LuminaPipeline()
        result = pipeline.analyze_path("apt29.jsonl", source_type="sysmon")
        print(result.verdict)
    """

    def __init__(
        self,
        thresholds: Optional[Thresholds] = None,
        catalog: Optional[TTPCatalog] = None,
    ):
        """
        Initialize the pipeline.

        Args:
            thresholds: Threshold configuration for the Product method (default: the
                method's own, ``PRODUCT_V2_THRESHOLDS``: the thesis values with the
                per_window drift condition).
            catalog: MITRE ATT&CK TTP catalog (default: load_attack_ttps()).
        """
        self.thresholds = thresholds
        self.catalog = catalog or load_attack_ttps()

    def analyze_path(
        self,
        path: Union[str, Path],
        source_type: str,
        case_strategy: CaseStrategy = CaseStrategy.TIME_WINDOW,
        *,
        thresholds: Optional[Thresholds] = None,
        method: Union[AnalysisMethod, str, MethodDescription] = AnalysisMethod.PRODUCT,
        time_window_seconds: Optional[int] = None,
    ) -> ThreatAssessment:
        """
        Analyze a log file for threats.

        Args:
            path: Path to the log file.
            source_type: Source type ("sysmon", "netflow", "cloudtrail", etc.).
            case_strategy: Strategy for grouping events into cases.
            time_window_seconds: The case window of the time_window strategy (default:
                the thresholds' ``time_window_seconds``, 300 s); the evaluation passes
                60 for CTU-13, the thesis's 1-minute window.
            thresholds: Override thresholds for this analysis (Product method only).
            method: The analysis method: "product" (default, the Product method) or
                "thesis-v1" (the Thesis method, with the frozen thesis thresholds in
                absolute drift mode, whatever this pipeline's thresholds are); or a
                frozen version's description, which only the evaluation passes
                (``lumina_cortex.methods.PRODUCT_V1``).

        Returns:
            ThreatAssessment with verdict and all engine results, naming the method.

        Raises:
            ValueError: for an unknown method, or a thresholds override with thesis-v1.
        """
        described = describe_method(method)
        t = described.thresholds(thresholds, default=self.thresholds)

        # Read and normalize the log
        df, _parse_stats = normalize(
            source=str(path),
            source_type=source_type,
            case_strategy=case_strategy,
            time_window_seconds=time_window_seconds,
            thresholds=t,
        )

        # Run assessment
        return assess_threat(
            df,
            thresholds=t,
            catalog=self.catalog,
            source_type=source_type,
            method=described,
        )
