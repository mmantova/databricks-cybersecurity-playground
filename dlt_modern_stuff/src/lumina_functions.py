# Databricks notebook source
"""Lumina Cortex functions available to the playground pipelines.

The library lives at the repository root (`lumina_cortex/`, AGPL-3.0).
These names are the ones a notebook calls after the OCSF projection:
`activity_for` turns `(class_uid, activity_id)` into the frozen hunting
label, and `assess_threat` runs the thesis and product verdicts.
"""

import sys
from pathlib import Path

_here = Path(__file__).resolve() if globals().get("__file__") else Path.cwd()
for _parent in (_here, *_here.parents):
    if (_parent / "lumina_cortex" / "__init__.py").is_file():
        _root = str(_parent)
        if _root not in sys.path:
            sys.path.insert(0, _root)
        break

from lumina_cortex import (
    ACTIVITY,
    CASE,
    TIMESTAMP,
    assess_threat,
    classify,
)
from lumina_cortex.vocabulary.ocsf_to_activity import (
    VOCABULARY,
    VOCABULARY_VERSION,
    activity_for,
)

__all__ = [
    "ACTIVITY",
    "CASE",
    "TIMESTAMP",
    "VOCABULARY",
    "VOCABULARY_VERSION",
    "activity_for",
    "assess_threat",
    "classify",
]
