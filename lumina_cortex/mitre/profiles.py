"""Hunt profile catalog.

SPEC-hunt.md slice 1. Abilities come from the pinned ATT&CK subset.
A profile whose ordering names any other id fails the load.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from lumina_cortex.errors import UnknownProfileAbility
from lumina_cortex.mitre.catalog import TTPPattern, load_attack_ttps

_DATA_DIR = Path(__file__).parent / "data"
_PROFILES_PATH = _DATA_DIR / "profiles.json"


@dataclass(frozen=True)
class Profile:
    """One Profile: a name and an ordering of subset ability ids."""

    id: str
    name: str
    objective: str
    atomic_ordering: tuple[str, ...]


@dataclass(frozen=True)
class HuntCatalog:
    """Abilities in subset file order, then profiles in profiles.json order."""

    abilities: tuple[TTPPattern, ...]
    profiles: tuple[Profile, ...]


def load_hunt_catalog(profiles_path: Path | None = None) -> HuntCatalog:
    """Load abilities and profiles.

    Abilities are subset techniques, then procedures, in file order.
    Raises UnknownProfileAbility when an ordering id is not in that set.
    """
    attack = load_attack_ttps()
    abilities = attack.techniques + attack.procedures
    known = {pattern.ttp_id for pattern in abilities}

    path = _PROFILES_PATH if profiles_path is None else Path(profiles_path)
    with open(path, encoding="utf-8") as handle:
        rows = json.load(handle)

    profiles: list[Profile] = []
    for row in rows:
        ordering = tuple(row["atomic_ordering"])
        unknown = [ability_id for ability_id in ordering if ability_id not in known]
        if unknown:
            raise UnknownProfileAbility(
                f"Profile {row['id']!r} names unknown ability ids",
                details={"id": row["id"], "unknown": unknown},
            )
        profiles.append(
            Profile(
                id=row["id"],
                name=row["name"],
                objective=row["objective"],
                atomic_ordering=ordering,
            )
        )

    return HuntCatalog(abilities=abilities, profiles=tuple(profiles))
