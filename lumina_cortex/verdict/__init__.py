"""
Verdict module - Combined decision rule for threat assessment.

Implements the S3 combined rule from the thesis:
    ATTACK_DETECTED = score_high AND (mitre_match OR vocab_ok) AND drift_high
    SUSPICIOUS_DRIFT = drift_high AND NOT score_high AND NOT mitre_match
    SUSPICIOUS_SCORE = score_high AND NOT drift_high
    BENIGN = else
"""

from lumina_cortex.verdict.classifier import classify, decision_inputs
from lumina_cortex.verdict.assessment import assess_threat

__all__ = [
    "classify",
    "decision_inputs",
    "assess_threat",
]
