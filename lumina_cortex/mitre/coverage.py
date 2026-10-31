"""
Coverage gap analysis for MITRE ATT&CK TTPs.

Analyzes which TTPs are covered, blind (impossible due to missing source
capabilities), or simply not observed in the telemetry.
"""

import time
from typing import FrozenSet, Optional

import pandas as pd

from lumina_cortex.columns import ACTIVITY
from lumina_cortex.mitre.catalog import TTPCatalog, load_attack_ttps
from lumina_cortex.models import GapEntry, GapReport
# Which activities each source type can produce: one table, the OCSF mappings'.
from lumina_cortex.ocsf.mappings import SOURCE_CAPABILITIES
from lumina_cortex.vocabulary.ocsf_to_activity import (
    VOCABULARY,
    VOCABULARY_VERSION,
)


def list_coverage_gaps(
    df: pd.DataFrame,
    catalog: Optional[TTPCatalog] = None,
    *,
    source_type: Optional[str] = None,
) -> GapReport:
    """
    List coverage gaps for MITRE ATT&CK TTPs.

    For each TTP in the catalog, determines:
    - covered: all required activities are observed in the log
    - blind: at least one required activity is outside source capabilities
    - not_observed: required activity missing from log but within capabilities

    Args:
        df: PM4Py DataFrame with concept:name (activity).
        catalog: MITRE ATT&CK TTP catalog (default: load_attack_ttps()).
        source_type: Source type to determine capabilities (e.g., "netflow", "sysmon").

    Returns:
        GapReport with gaps, vocabulary_version, and attack_version.
    """
    start_time = time.perf_counter()
    
    cat = catalog or load_attack_ttps()
    
    # Get source capabilities (a source type with none listed may produce anything)
    src_type = (source_type or "unknown").lower()
    capabilities = SOURCE_CAPABILITIES.get(src_type, VOCABULARY)

    # Get observed activities from log
    if ACTIVITY not in df.columns or len(df) == 0:
        observed: FrozenSet[str] = frozenset()
    else:
        observed = frozenset(df[ACTIVITY].unique())

    # Analyze each TTP
    gaps: list[GapEntry] = []
    
    for ttp in cat.techniques:
        required = frozenset(ttp.activities)
        
        # Check which activities are missing
        missing = required - observed
        
        if not missing:
            # All activities observed - covered
            continue
        
        # Check if missing activities are outside capabilities
        blind_activities = missing - capabilities
        not_observed_activities = missing & capabilities
        
        if blind_activities:
            # Blind: can never observe this TTP with current source
            gaps.append(GapEntry(
                ttp_id=ttp.ttp_id,
                ttp_name=ttp.ttp_name,
                required_activities=ttp.activities,
                missing_activities=tuple(sorted(missing)),
            ))
        elif not_observed_activities:
            # Not observed: could observe with current source, but didn't
            # This is still a gap worth reporting, but less severe
            pass  # For now, only report blind gaps

    return GapReport(
        gaps=tuple(gaps),
        vocabulary_version=VOCABULARY_VERSION,
        attack_version=cat.version,
    )
