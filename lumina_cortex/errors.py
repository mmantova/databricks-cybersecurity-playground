"""
Exception hierarchy for Lumina Cortex.

All custom exceptions inherit from LuminaError for easy catching.
"""

from typing import Optional


class LuminaError(Exception):
    """Base exception for all Lumina Cortex errors."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NonCanonicalLogError(LuminaError):
    """Raised when an activity name does not match the canonical vocabulary."""

    pass


class EmptyLogError(LuminaError):
    """Raised when processing results in zero events."""

    pass


class UnsupportedSourceError(LuminaError):
    """Raised when an unsupported source type is requested."""

    pass


class UnsupportedCatalogVersion(LuminaError):
    """Raised when an unsupported MITRE ATT&CK catalog version is requested."""

    pass


class UnknownProfileAbility(LuminaError):
    """Raised when a profile names an ability id outside the subset."""

    pass


class InputLimitError(LuminaError):
    """Raised when input exceeds configured limits."""

    pass


class InvalidConfigError(LuminaError):
    """Raised when configuration is invalid."""

    pass


class AnalysisError(LuminaError):
    """Raised when analysis fails."""

    pass
