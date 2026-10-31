"""OCSF 1.3.0 ids, logon failure via status_id, MITRE names and Zeek coverage (0.5.0)."""

import pytest

from lumina_cortex.mitre.catalog import load_attack_ttps
from lumina_cortex.ocsf.mappings import get_capabilities
from lumina_cortex.vocabulary.ocsf_to_activity import (
    VOCABULARY,
    _OCSF_TO_ACTIVITY,
    activity_for,
)

# (class_uid, activity_id) -> activity, from https://schema.ocsf.io/api/1.3.0/classes/<name>
OCSF_1_3_0 = {
    (4001, 1): "Network: Connection Open",
    (4001, 2): "Network: Connection Close",
    (4003, 1): "DNS: Query",
    (4003, 2): "DNS: Response",
    (1007, 1): "Process: Launch",
    (1007, 2): "Process: Terminate",
    (1007, 3): "Process: Open",
    (1005, 1): "Module: Load",
    (1001, 1): "File: Create",
    (1001, 2): "File: Read",
    (1001, 3): "File: Write",
    (1001, 4): "File: Delete",
    (1001, 14): "File: Access",
    (201001, 1): "Registry: Create",
    (201001, 3): "Registry: Modify",
    (201001, 4): "Registry: Delete",
    (201002, 2): "Registry: Modify",
    (201002, 4): "Registry: Delete",
    (3002, 1): "Authentication: Logon",
    (3002, 2): "Authentication: Logoff",
    (6003, 2): "API: Call",
}


@pytest.mark.parametrize("key,activity", sorted(OCSF_1_3_0.items()))
def test_ocsf_ids(key, activity):
    class_uid, activity_id = key
    assert activity_for({"class_uid": class_uid, "activity_id": activity_id}) == activity


@pytest.mark.parametrize("key", [(1002, 1), (1003, 1), (5001, 1), (5002, 1), (3002, 3)])
def test_old_wrong_ids_are_gone(key):
    # 1002 Kernel Extension, 1003 Kernel, 5001/5002 Device Inventory/Config, 3002/3 Authentication Ticket
    assert activity_for({"class_uid": key[0], "activity_id": key[1]}) is None


def test_logon_failure_comes_from_status_id():
    assert activity_for({"class_uid": 3002, "activity_id": 1, "status_id": 2}) == "Authentication: Logon Failure"
    assert activity_for({"class_uid": 3002, "activity_id": 1, "status_id": 1}) == "Authentication: Logon"
    assert activity_for({"class_uid": 3002, "activity_id": 2, "status_id": 2}) == "Authentication: Logoff"


def test_every_mapped_activity_is_canonical():
    assert set(_OCSF_TO_ACTIVITY.values()) <= VOCABULARY


def test_attack_entries_v15_1():
    catalog = load_attack_ttps()
    assert catalog.get_technique("T1070").ttp_name == "Indicator Removal"
    assert set(catalog.get_technique("T1078").tactics) == {"TA0001", "TA0003", "TA0004", "TA0005"}


def test_zeek_covers_what_the_loader_emits():
    caps = get_capabilities("zeek")
    for activity in ("Authentication: Logon", "Authentication: Logon Failure", "File: Read", "File: Write"):
        assert activity in caps
    assert "Authentication: Logon" not in get_capabilities("netflow")
