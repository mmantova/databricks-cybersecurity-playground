"""
Batch run: stage 4 of the thesis pipeline (THESIS:1145-1160).

Analyzes a list of sources with ``LuminaPipeline.analyze_path`` and consolidates
the assessments into one ``PipelineReport``.
"""

import json
from pathlib import Path
from typing import List, Optional, Sequence, Union

from lumina_cortex.models import (
    AnalysisMethod,
    CaseStrategy,
    DatasetReport,
    DataSource,
    PipelineReport,
    Verdict,
)
from lumina_cortex.pipeline.orchestrator import LuminaPipeline


def run_batch(
    sources: Sequence[DataSource],
    *,
    method: Union[AnalysisMethod, str] = AnalysisMethod.PRODUCT,
    pipeline: Optional[LuminaPipeline] = None,
    timestamp: Optional[str] = None,
) -> PipelineReport:
    """
    Analyze each source with one method and build the consolidated report.

    A source that cannot be analyzed (missing or unreadable file, unknown type, a
    log the engines refuse) is reported with its error, and the others still run.
    The report has no wall-clock field unless ``timestamp`` is given, so the same
    input gives the same JSON document.

    Raises:
        ValueError: for an unknown method (before any source is read).
    """
    method = AnalysisMethod.parse(method)
    pipeline = pipeline or LuminaPipeline()

    entries = []
    for source in sources:
        try:
            assessment = pipeline.analyze_path(
                source.path,
                source_type=source.source_type,
                case_strategy=source.case_strategy,
                method=method,
            )
        except Exception as exc:  # one bad source must not stop the batch
            entries.append(DatasetReport(
                source=source, method=method, error=f"{type(exc).__name__}: {exc}",
            ))
        else:
            entries.append(DatasetReport(source=source, method=method, assessment=assessment))

    return PipelineReport(
        timestamp=timestamp,
        datasets_analyzed=len(entries),
        summary=_summary(entries, method),
        datasets=tuple(entries),
    )


def load_sources(manifest: Union[str, Path]) -> List[DataSource]:
    """
    Read a batch manifest: ``{"sources": [{"name", "source_type", "path",
    "case_strategy"?, "expected_verdict"?}, ...]}``. A relative ``path`` is
    resolved against the manifest's directory.
    """
    manifest = Path(manifest)
    entries = json.loads(manifest.read_text(encoding="utf-8"))["sources"]
    sources = []
    for e in entries:
        path = Path(e["path"])
        if not path.is_absolute():
            path = manifest.parent / path
        sources.append(DataSource(
            name=e["name"],
            source_type=e["source_type"],
            path=str(path),
            case_strategy=CaseStrategy(e.get("case_strategy", CaseStrategy.TIME_WINDOW.value)),
            expected_verdict=e.get("expected_verdict", "unknown"),
        ))
    return sources


def report_json(report: PipelineReport) -> str:
    """The report as a JSON document: sorted keys, two-space indent, final newline.

    Values ``to_dict`` leaves nested (timestamps inside engine results) are written
    as the backend writes them (``backend/engine.py``): ISO format, else ``str``.
    """
    return json.dumps(
        report.to_dict(), indent=2, sort_keys=True, ensure_ascii=False, default=_json_default,
    ) + "\n"


def _json_default(value):
    isoformat = getattr(value, "isoformat", None)
    return isoformat() if isoformat else str(value)


def _summary(entries: Sequence[DatasetReport], method: AnalysisMethod) -> dict:
    verdicts = {v.value: 0 for v in Verdict}
    compared = matched = 0
    for entry in entries:
        if entry.assessment is None:
            continue
        verdict = entry.assessment.verdict.value
        verdicts[verdict] += 1
        if entry.source.expected_verdict != "unknown":
            compared += 1
            matched += verdict == entry.source.expected_verdict
    return {
        "method": method.value,
        "verdicts": verdicts,
        "errors": sum(e.error is not None for e in entries),
        "expected": {"compared": compared, "matched": matched},
    }
