"""Isolated API and pagination tests; the Elasticsearch client is a mock."""

import base64
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from elasticsearch import NotFoundError
from werkzeug.security import generate_password_hash
from cloud_soc.portal.app import create_app
from cloud_soc.portal.log_contract import SOURCE_FIELDS, parse_filters
from cloud_soc.portal.log_query import LogReader, LogQueryError, bounded_json

FIXTURE = json.loads((ROOT / "tests/fixtures/log_intake.json").read_text(encoding="utf-8"))["hits"][0]


def hits(count=1, start=0):
    return [{**deepcopy(FIXTURE), "_id": str(i), "sort": [1790000000000, i]} for i in range(start, start + count)]


def response(rows=None):
    return {"pit_id": "rotated-pit", "_shards": {"failed": 0}, "timed_out": False,
            "hits": {"hits": hits() if rows is None else rows}}


def client():
    result = Mock()
    result.options.return_value = result
    result.indices.resolve_index.return_value = {"indices": [{"name": FIXTURE["_index"]}], "aliases": [], "data_streams": []}
    result.field_caps.return_value = {"fields": {
        "event.ingested": {"date": {"searchable": True, "aggregatable": True}},
        "@timestamp": {"date": {"searchable": True, "aggregatable": True}},
        "host.name": {"keyword": {"searchable": True}}, "agent.type": {"keyword": {"searchable": True}},
    }}
    result.open_point_in_time.return_value = {"id": "initial-pit", "_shards": {"failed": 0}}
    result.search.return_value = response()
    result.get.return_value = deepcopy(FIXTURE)
    return result


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.client = client()
        self.reader = LogReader(self.client, secret="synthetic-key", principal="admin", clock=lambda: 100)

    def state(self):
        return {"v": 1, "principal": "admin", "pit": "initial-pit",
                "filters": asdict(parse_filters([])), "after": [1790000000000, 24], "expires": 700}

    def test_read_only_bounded_source_and_response(self):
        result = json.loads(self.reader.page([]))
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["raw_access"], "restricted")
        self.assertIsNone(result["total"])
        self.assertIsNone(result["next_cursor"])
        self.assertNotIn('"message"', json.dumps(result))
        self.client.options.assert_called_with(request_timeout=5, max_retries=0)
        request = self.client.search.call_args.kwargs
        self.assertFalse(request["allow_partial_search_results"])
        self.assertEqual(request["body"]["size"], 26)
        self.assertEqual(request["body"]["timeout"], "4s")
        self.assertEqual(request["body"]["_source"], list(SOURCE_FIELDS))
        self.assertEqual(request["body"]["sort"][-1], {"_shard_doc": "asc"})
        self.client.close_point_in_time.assert_called_with(id="rotated-pit")
        self.client.index.assert_not_called()

    def test_lookahead_does_not_skip_a_document_and_reuses_rotated_pit(self):
        self.client.search.side_effect = [response(hits(26)), response(hits(2, 25))]
        first = json.loads(self.reader.page([]))
        state, filters = self.reader.decode(first["next_cursor"])
        self.assertEqual(state["after"], [1790000000000, 24])
        self.assertEqual(state["pit"], "rotated-pit")
        self.client.close_point_in_time.assert_not_called()
        second = json.loads(self.reader.page([("cursor", first["next_cursor"])]))
        self.assertEqual(second["rows"][0]["reference"]["id"], "25")
        self.assertEqual(first["filters"], second["filters"])
        self.assertIsNone(second["next_cursor"])
        self.client.open_point_in_time.assert_called_once()
        self.assertEqual(self.client.search.call_args.kwargs["body"]["search_after"], state["after"])

    def test_signature_tamper_wrong_principal_expiration_and_schema(self):
        token = self.reader.encode(self.state())
        wrong = LogReader(self.client, secret="synthetic-key", principal="other", clock=lambda: 100)
        for reader, value, code in [
            (self.reader, token + "x", "invalid_log_query"),
            (self.reader, "!bad!", "invalid_log_query"),
            (self.reader, "x" * 8193, "invalid_log_query"),
            (wrong, token, "invalid_log_query"),
            (self.reader, self.reader.encode({**self.state(), "expires": 100}), "cursor_expired"),
            (self.reader, self.reader.encode({**self.state(), "after": [True, 0]}), "invalid_log_query"),
            (self.reader, self.reader.encode({**self.state(), "filters": {}}), "invalid_log_query"),
        ]:
            with self.subTest(code=code), self.assertRaises(LogQueryError) as raised:
                reader.page([("cursor", value)])
            self.assertEqual(raised.exception.code, code)
        self.client.search.assert_not_called()

    def test_cursor_cannot_change_filters_or_repeat(self):
        token = self.reader.encode(self.state())
        for extra in [("host", "other"), ("cursor", token), ("page_size", "50")]:
            with self.assertRaises(LogQueryError) as raised:
                self.reader.page([("cursor", token), extra])
            self.assertEqual(raised.exception.status, 400)
        self.client.search.assert_not_called()

    def test_plain_queries_are_rejected_before_es(self):
        for pairs in [[("index", "*")], [("q", "*:* ")], [("host", "a"), ("host", "b")]]:
            with self.assertRaises(LogQueryError) as raised:
                self.reader.page(pairs)
            self.assertEqual(raised.exception.status, 400)
        self.client.indices.resolve_index.assert_not_called()

    def test_no_indices_is_empty_without_pit_and_aliases_fail_closed(self):
        self.client.indices.resolve_index.return_value = {"indices": [], "aliases": [], "data_streams": []}
        self.assertEqual(json.loads(self.reader.page([]))["rows"], [])
        self.client.open_point_in_time.assert_not_called()
        for resolved in [{"indices": [{"name": ".security"}]}, {"indices": [], "aliases": [{"name": "soc-host-raw-alias"}]}]:
            self.client.indices.resolve_index.return_value = resolved
            with self.assertRaises(LogQueryError):
                self.reader.page([])

    def test_runtime_filters_and_literal_host_use_no_query_string(self):
        self.reader.page([("host", "literal*host"), ("os", "linux"), ("collector", "filebeat"), ("ip", "2001:db8::1")])
        body = self.client.search.call_args.kwargs["body"]
        self.assertEqual(set(body["runtime_mappings"]), {"soc_query_os", "soc_query_ip"})
        self.assertIn({"term": {"host.name": "literal*host"}}, body["query"]["bool"]["filter"])
        self.assertNotIn("query_string", json.dumps(body))

    def test_partial_timeout_terminated_and_invalid_order_fail_and_close(self):
        bad_results = [response(hits(27)), {**response(), "timed_out": True},
                       {**response(), "terminated_early": True}, {**response(), "_shards": {"failed": 1}},
                       response([hits()[0], hits()[0]]), response([{**hits()[0], "sort": []}]), {}]
        for result in bad_results:
            with self.subTest(result=result):
                self.client.search.return_value = result
                with self.assertRaises(LogQueryError):
                    self.reader.page([])
                self.assertGreater(self.client.close_point_in_time.call_count, 0)

    def test_partial_open_is_closed_without_search(self):
        self.client.open_point_in_time.return_value = {"id": "partial", "_shards": {"failed": 1}}
        with self.assertRaises(LogQueryError):
            self.reader.page([])
        self.client.close_point_in_time.assert_called_with(id="partial")
        self.client.search.assert_not_called()

    def test_nonadvancing_cursor_and_es_expiration(self):
        token = self.reader.encode(self.state())
        self.client.search.return_value = response(hits(1, 24))
        with self.assertRaises(LogQueryError):
            self.reader.page([("cursor", token)])
        self.client.search.side_effect = NotFoundError("private upstream", None, None)
        with self.assertRaises(LogQueryError) as raised:
            self.reader.page([("cursor", token)])
        self.assertEqual(raised.exception.status, 410)
        self.assertNotIn("private", str(raised.exception))

    def test_mapping_conflict_is_failure_not_zero(self):
        self.client.field_caps.return_value = {"fields": {"event.ingested": {"keyword": {"searchable": True, "aggregatable": True}}}}
        with self.assertRaises(LogQueryError):
            self.reader.page([])
        self.client.open_point_in_time.assert_not_called()

    def test_detail_never_fetches_raw_and_preserves_reference(self):
        result = json.loads(self.reader.detail([("index", FIXTURE["_index"]), ("id", FIXTURE["_id"])]))
        self.assertEqual(result["row"]["reference"]["id"], FIXTURE["_id"])
        self.assertEqual(result["raw_access"], "restricted")
        self.assertNotIn("message", self.client.get.call_args.kwargs["source_includes"])

    def test_detail_bad_refs_missing_and_alias_substitution(self):
        with self.assertRaises(LogQueryError) as raised:
            self.reader.detail([("index", "*"), ("id", "1")])
        self.assertEqual(raised.exception.status, 400)
        self.client.get.assert_not_called()
        pairs = [("index", FIXTURE["_index"]), ("id", FIXTURE["_id"])]
        self.client.get.return_value = {**FIXTURE, "_index": "soc-host-raw-substituted"}
        with self.assertRaises(LogQueryError) as raised:
            self.reader.detail(pairs)
        self.assertEqual(raised.exception.status, 503)
        self.client.indices.resolve_index.return_value = {"indices": []}
        with self.assertRaises(LogQueryError) as raised:
            self.reader.detail(pairs)
        self.assertEqual(raised.exception.status, 404)

    def test_utf8_serialized_limit_and_upstream_error_redaction(self):
        with self.assertRaises(LogQueryError) as raised:
            bounded_json({"data": "한" * 100}, limit=250)
        self.assertEqual(raised.exception.status, 413)
        self.client.search.side_effect = RuntimeError("SECRET_CANARY")
        with self.assertRaises(LogQueryError) as raised:
            self.reader.page([])
        self.assertNotIn("SECRET_CANARY", str(raised.exception))

    def test_oversized_page_fails_and_closes_snapshot(self):
        rows = hits(51)
        for hit in rows:
            source = hit['_source']
            for name in ('organization', 'agent', 'host', 'event', 'user', 'network', 'winlog'):
                source[name] = {key: '가' * 512 for key in ('id', 'name', 'type', 'code', 'action', 'dataset', 'protocol', 'transport', 'channel')}
            source['host']['os'] = {'name': '가' * 512}
        self.client.search.return_value = response(rows)
        with self.assertRaises(LogQueryError) as raised:
            self.reader.page([('page_size', '50')])
        self.assertEqual(raised.exception.status, 413)
        self.client.close_point_in_time.assert_called_with(id='rotated-pit')


class APITests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="soc-log-query-test-")
        self.addCleanup(folder.cleanup)
        self.es, self.issuer = client(), Mock()
        self.settings = {"STATE_DIR": Path(folder.name), "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": b"synthetic",
                         "PUBLIC_URL": "http://localhost", "ENDPOINT": "https://soc.example.test:9200", "ADMIN_USER": "admin",
                         "ADMIN_HASH": generate_password_hash("synthetic", method="pbkdf2:sha256:1000")}
        self.client = create_app(self.settings, issuer=self.issuer, monitor=self.es).test_client()
        self.auth = {"Authorization": "Basic " + base64.b64encode(b"admin:synthetic").decode()}

    def test_auth_host_origin_and_cache_apply_to_both_routes(self):
        for path in ("/api/logs", "/api/logs/detail"):
            self.assertEqual(self.client.get(path).status_code, 401)
            for headers in ({"Host": "evil.test"}, {"Origin": "https://evil.test"}, {"Sec-Fetch-Site": "cross-site"}):
                self.assertIn(self.client.get(path, headers={**self.auth, **headers}).status_code, (400, 403))
        result = self.client.get('/api/logs', headers=self.auth)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["Cache-Control"], "no-store")
        self.assertEqual(result.mimetype, "application/json")
        self.issuer.search.assert_not_called()
        self.issuer.options.assert_not_called()

    def test_errors_are_json_and_never_raw_upstream(self):
        self.assertEqual(self.client.get('/api/logs?index=*', headers=self.auth).status_code, 400)
        self.es.search.side_effect = RuntimeError("SECRET_CANARY")
        response = self.client.get('/api/logs', headers=self.auth)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("SECRET_CANARY", response.get_data(as_text=True))
        self.assertNotIn("rows", response.json)

    def test_missing_monitor_and_detail_filters(self):
        client_without_monitor = create_app(self.settings, issuer=self.issuer).test_client()
        response = client_without_monitor.get('/api/logs', headers=self.auth)
        self.assertEqual(response.json["code"], "monitor_not_configured")
        self.assertEqual(response.status_code, 503)
        for query in ('index=soc-host-raw-test&id=a&id=b', 'index=soc-host-raw-test&id=a&raw=true'):
            self.assertEqual(self.client.get('/api/logs/detail?' + query, headers=self.auth).status_code, 400)


if __name__ == '__main__':
    unittest.main()
