"""
CLI for the batch run: one consolidated JSON report over a list of sources.

Usage:
    python -m lumina_cortex.pipeline sources.json --method thesis-v1 --out report.json
"""

import argparse
import sys
from typing import List, Optional

from lumina_cortex.models import AnalysisMethod
from lumina_cortex.pipeline.batch import load_sources, report_json, run_batch


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lumina_cortex.pipeline",
        description="Analyze every source in a manifest and write one consolidated JSON report",
    )
    parser.add_argument("manifest", help='JSON file: {"sources": [{"name", "source_type", "path", '
                        '"case_strategy"?, "expected_verdict"?}, ...]}')
    parser.add_argument("--method", default=AnalysisMethod.PRODUCT.value,
                        choices=[m.value for m in AnalysisMethod],
                        help="Analysis method (default: product)")
    parser.add_argument("--out", help="Output file (default: stdout)")
    parser.add_argument("--timestamp", default=None,
                        help="Value of the report's timestamp field (default: null, so runs compare byte for byte)")
    args = parser.parse_args(argv)

    report = run_batch(load_sources(args.manifest), method=args.method, timestamp=args.timestamp)
    text = report_json(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
