from copy import deepcopy
from unittest.mock import Mock

import pytest

from cloud_soc.portal.reader_maintenance import ROLE, HISTORY, digest, history_plan, restore_history_reader


def existing():
    return {"cluster": [], "indices": [{"names": ["soc-host-raw-*", "soc-normalized-v1"],
            "privileges": ["read", "view_index_metadata"], "allow_restricted_indices": False}],
            "applications": [], "run_as": [], "metadata": {"owner": "synthetic"},
            "transient_metadata": {"enabled": True}}


def test_repair_only_appends_exact_history_reads_preserving_existing_policy():
    role = existing();before = deepcopy(role)
    plan = history_plan(role)
    assert role == before and plan["before_sha256"] == digest(before)
    assert plan["added_indices"] == list(HISTORY)
    assert plan["role"]["indices"][:-1] == before["indices"]
    assert plan["role"]["indices"][-1] == {"names": list(HISTORY), "privileges": ["read", "view_index_metadata"]}
    for key in ("cluster", "applications", "run_as", "metadata"):
        assert plan["role"][key] == before[key]


def test_already_readable_and_split_grants_do_not_write_again():
    role = existing();role["indices"].extend([
        {"names": list(HISTORY), "privileges": ["read"]},
        {"names": ["soc-*-history-v1"], "privileges": ["view_index_metadata"]}])
    client = Mock();client.security.get_role.return_value = {ROLE: role}
    result = restore_history_reader(client, digest(role))
    assert result["added_indices"] == []
    client.security.put_role.assert_not_called()


def test_stale_review_hash_refuses_mutation_and_users_are_never_changed():
    client = Mock();role = existing();client.security.get_role.return_value = {ROLE: role}
    with pytest.raises(ValueError):restore_history_reader(client, "0" * 64)
    client.security.put_role.assert_not_called()
    restore_history_reader(client, digest(role))
    client.security.put_role.assert_called_once()
    client.security.put_user.assert_not_called()
    client.security.change_password.assert_not_called()
    client.security.create_api_key.assert_not_called()


def test_unknown_role_fields_cannot_be_silently_dropped():
    role = existing();role["future_grant"] = {"private_canary": True}
    with pytest.raises(ValueError):history_plan(role)


@pytest.mark.parametrize("restriction", [{"query": {"term": {"organization.id": "school"}}},
                                        {"field_security": {"grant": ["@timestamp"]}}])
def test_existing_document_or_field_restrictions_are_never_overridden(restriction):
    role = existing();role["indices"].append({"names": list(HISTORY), "privileges": ["read"], **restriction})
    original = deepcopy(role)
    with pytest.raises(ValueError):history_plan(role)
    assert role == original
