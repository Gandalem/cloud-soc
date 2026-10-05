import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
from cloud_soc.portal.reprocessing_history import history, INDEX
from cloud_soc.portal.log_query import LogQueryError
from cloud_soc.portal.auth import permitted


def fake():
    client = Mock()
    client.indices.get_mapping.return_value = {INDEX: {"mappings": {"_meta": {"contract": "ubuntu-linux-parser-757-v3"}}}}
    source = {"@timestamp": "2026-10-05T04:00:00Z", "host": {"name": "test-host"},
        "message": "PRIVATE_CANARY", "event": {"action": "http_access", "outcome": "unknown"},
        "cloud_soc": {"parse_status": "partial", "detail": {"adapter": "linux_operational_v1", "body": "PRIVATE_CANARY"},
            "provenance": {"raw": {"index": "soc-host-raw-linux-9.5.2-2026.10.05", "id": "test-id"}, "time": {"basis": "collector_timestamp"}},
            "historical_replay": {"job": "ubuntu-linux-parser-757-v3", "history_only": True,
                "timezone_correction": {"applied": "+09:00", "raw_modified": False}}}}
    client.search.return_value = {"hits": {"total": {"value": 1, "relation": "eq"},
        "hits": [{"_index": INDEX, "_id": "a" * 64, "_source": source}]}}
    return client


def test_summary_and_metadata_allowlist():
    client = fake()
    result = history(client, [])
    assert "PRIVATE_CANARY" not in result
    data = json.loads(result)
    assert (data["total"], data["recognized"], data["partial"], data["timezone_corrected"]) == (1, 0, 1, 1)
    assert data["rows"][0]["raw"]["id"] == "test-id"
    assert client.search.call_args.kwargs["index"] == INDEX
    client.create.assert_not_called()


@pytest.mark.parametrize("bad", ["timeout", "partial", "overflow", "contract", "scope"])
def test_fail_closed_on_incomplete_or_untrusted_results(bad):
    client = fake()
    result = deepcopy(client.search.return_value)
    if bad == "timeout": result["timed_out"] = True
    if bad == "partial": result["_shards"] = {"failed": 1}
    if bad == "overflow": result["hits"]["total"]["value"] = 2001
    if bad == "contract": client.indices.get_mapping.return_value = {INDEX: {"mappings": {}}}
    if bad == "scope": result["hits"]["hits"][0]["_source"]["cloud_soc"]["historical_replay"]["history_only"] = False
    client.search.return_value = result
    with pytest.raises(LogQueryError) as error:
        history(client, [])
    assert error.value.status == 503


def test_request_cannot_select_another_index():
    client = fake()
    with pytest.raises(LogQueryError) as error:
        history(client, [("index", "security-alerts")])
    assert error.value.status == 400
    client.search.assert_not_called()


def test_all_portal_roles_read_but_cannot_write_history():
    for role in ("viewer", "analyst"):
        assert permitted("reprocessing_history", "GET", role)
        assert not permitted("reprocessing_history", "POST", role)
