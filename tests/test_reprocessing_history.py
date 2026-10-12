import json
from copy import deepcopy
from unittest.mock import Mock

import pytest
from cloud_soc.portal.reprocessing_history import history, INDEX
from cloud_soc.portal.log_query import LogQueryError
from cloud_soc.portal.auth import permitted
from elasticsearch import NotFoundError, AuthorizationException
from elastic_transport import ApiResponseMeta, HttpHeaders, NodeConfig


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


def test_server_filter_and_paging_preserve_every_matching_row():
    client = fake()
    template = client.search.return_value["hits"]["hits"][0]
    rows = []
    for number in range(57):
        row = deepcopy(template)
        row["_id"] = f"{number:064d}"
        row["_source"]["cloud_soc"]["parse_status"] = "partial" if number < 53 else "recognized"
        rows.append(row)
    client.search.return_value["hits"] = {"total": {"value": len(rows), "relation": "eq"}, "hits": rows}
    seen = []
    for page in (1, 2):
        result = json.loads(history(client, [("q", " test-host "), ("status", "partial"), ("page", str(page))]))
        assert result["filtered_total"] == 53
        assert result["pages"] == 2
        seen.extend(row["id"] for row in result["rows"])
    assert len(seen) == len(set(seen)) == 53
    assert json.loads(history(client, [("q", "no-match")]))["rows"] == []


@pytest.mark.parametrize("pairs", [[("page", "0")], [("limit", "101")], [("status", "invalid")],
                                   [("q", "password=PRIVATE_CANARY")], [("page", "1"), ("page", "2")]])
def test_invalid_filters_fail_before_search(pairs):
    client = fake()
    with pytest.raises(LogQueryError) as error:
        history(client, pairs)
    assert error.value.status == 400
    client.search.assert_not_called()


@pytest.mark.parametrize('pairs', [[], [('page', '2'), ('limit', '10')]])
def test_missing_history_is_explicit_without_creating_or_searching(pairs):
    client = fake()
    meta = ApiResponseMeta(404, '1.1', HttpHeaders(), 0, NodeConfig('https', 'example.test', 9200))
    client.indices.get_mapping.side_effect = NotFoundError('missing', meta,
        {'error': {'type': 'index_not_found_exception', 'index': INDEX}})
    result = json.loads(history(client, pairs))
    assert result['state'] == 'no_index' and result['total'] == 0 and result['rows'] == []
    if pairs:
        assert (result['page'], result['limit'], result['pages'], result['filtered_total']) == (2, 10, 1, 0)
    client.search.assert_not_called()
    client.indices.create.assert_not_called()


@pytest.mark.parametrize('status,error_type,index', [(403, 'security_exception', INDEX),
    (404, 'index_not_found_exception', 'other-index'), (404, 'resource_not_found_exception', INDEX)])
def test_history_permission_and_unrelated_missing_errors_remain_unavailable(status, error_type, index):
    client = fake()
    meta = ApiResponseMeta(status, '1.1', HttpHeaders(), 0, NodeConfig('https', 'example.test', 9200))
    error = AuthorizationException if status == 403 else NotFoundError
    client.indices.get_mapping.side_effect = error('private failure', meta,
        {'error': {'type': error_type, 'index': index}})
    with pytest.raises(LogQueryError) as failed:
        history(client, [])
    assert failed.value.status == 503
    client.search.assert_not_called()
