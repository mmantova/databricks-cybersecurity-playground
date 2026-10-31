"""
Synthetic data generator for testing and evaluation.

Provides deterministic, seeded generation of synthetic event logs
for testing engines and the verdict classifier.
"""

from lumina_cortex.synthetic.generator import generate

__all__ = ["generate"]
