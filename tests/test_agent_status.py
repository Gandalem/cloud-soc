"""Activity and authorization tests without real agents or packet capture."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from werkzeug.security import generate_password_hash
from cloud_soc.portal.agent_status import (
    INDICES, PAGE_SIZE, SOURCE_FIELDS, activity, decode_cursor, encode_cursor,
    iso, parse_time, row_from_bucket, snapshot,
)
from cloud_soc.portal.app import create_app
from cloud_soc.portal.status_setup import (
    PIPELINE, PIPELINE_ID, configure_reader, configure_template,
    inspect_existing, install_receipt_pipeline,
)

NOW = datetime(2026, 9, 21, 6, tzinfo=timezone.utc)
KEY = {"organization": "school", "agent_id": "collector-1", "agent_type": "filebeat"}


def bucket(received=NOW, key=None):
    return {"key": key or KEY, "doc_count": 7, "latest": {"hits": {"hits": [{"_source": {
        "host": {"name": "test-pc", "ip": ["192.0.2.1", "bad-address"], "os": {"name": "Windows"}},
        "agent": {"version": "9.5.2"}, "event": {"ingested": iso(received)} if received else {},
        "@timestamp": "2020-01-01T00:00:00Z", "message": "RAW_LOG_CANARY",
    }}]}}}


def response(buckets=None, after_key=None):
    return {"timed_out": False, "_shards": {"failed": 0, "total": 2}, "aggregations": {
        "agents": {"buckets": buckets or [], "after_key": after_key}, "unidentified": {"doc_count": 3},
    }}


class ActivityTests(unittest.TestCase):
    def test_boundaries_missing_and_future_timestamp(self):
        for seconds, expected in [(-61, "unknown"), (-60, "recent"), (0, "recent"),
                                  (300, "recent"), (301, "delayed"), (900, "delayed"), (901, "silent")]:
            with self.subTest(seconds=seconds):
                self.assertEqual(activity(NOW - timedelta(seconds=seconds), NOW)[0], expected)
        self.assertEqual(activity(None, NOW), ("unknown", "missing_ingestion_time"))

    def test_only_aware_timestamps_are_accepted(self):
        for value in (None, {}, "bad", "2026-09-21T06:00:00"):
            self.assertIsNone(parse_time(value))
        self.assertEqual(parse_time("2026-09-21T15:00:00+09:00"), NOW)

    def test_old_source_event_does_not_look_disconnected(self):
        row = row_from_bucket(bucket(), NOW)
        self.assertEqual(row["status"], "recent")
        self.assertEqual(row["last_received"], iso(NOW))
        self.assertEqual(row["last_event"], "2020-01-01T00:00:00Z")
        self.assertEqual(row["host_ips"], ["192.0.2.1"])
        self.assertNotIn("RAW_LOG_CANARY", json.dumps(row))

    def test_legacy_event_never_implies_online(self):
        data = bucket(None)
        data["latest"]["hits"]["hits"][0]["_source"]["@timestamp"] = iso(NOW)
        self.assertEqual(row_from_bucket(data, NOW)["status"], "unknown")

    def test_sparse_or_malformed_metadata_is_not_an_error(self):
        data = bucket()
        data["latest"]["hits"]["hits"][0]["_source"] = {"host": [], "agent": "bad", "event": None}
        row = row_from_bucket(data, NOW)
        self.assertIsNone(row["host_name"])
        self.assertEqual(row["host_ips"], [])
        self.assertEqual(row["status"], "unknown")

    def test_cursor_round_trip_and_invalid_inputs(self):
        for key in (KEY, {**KEY, "organization": None, "agent_type": None}):
            self.assertEqual(decode_cursor(encode_cursor(key)), key)
        self.assertIsNone(decode_cursor(None))
        for value in ("not-base64!", "x" * 4097, encode_cursor([]), encode_cursor({}),
                      encode_cursor({**KEY, "agent_id": None}), encode_cursor({**KEY, "agent_id": 1}),
                      encode_cursor({**KEY, "extra": "injection"})):
            with self.subTest(value=value[:50]), self.assertRaises(ValueError):
                decode_cursor(value)

    def test_bounded_query_filters_projection_and_composite_pagination(self):
        client = Mock()
        client.search.return_value = response([bucket(key={**KEY, "agent_id": str(i)}) for i in range(PAGE_SIZE)], KEY)
        result = snapshot(client, after=KEY, now=NOW)
        self.assertEqual(len(result["agents"]), PAGE_SIZE)
        self.assertEqual(decode_cursor(result["next_cursor"]), KEY)
        self.assertEqual(result["unidentified_documents"], 3)
        args = client.search.call_args.kwargs
        self.assertEqual(args["index"], INDICES)
        self.assertFalse(args["allow_partial_search_results"])
        body = args["body"]
        self.assertEqual(body["size"], 0)
        self.assertEqual(body["timeout"], "4s")
        self.assertEqual(body["aggs"]["agents"]["composite"]["size"], 50)
        self.assertEqual(body["aggs"]["agents"]["composite"]["after"], KEY)
        self.assertEqual(body["aggs"]["agents"]["aggs"]["latest"]["top_hits"]["_source"]["includes"], SOURCE_FIELDS)
        self.assertNotIn("message", SOURCE_FIELDS)
        self.assertIn("2026-08-22T06:00:00Z", json.dumps(body["query"]))

    def test_no_indices_is_empty_but_partial_results_are_failure(self):
        client = Mock()
        client.search.return_value = {"_shards": {"total": 0, "failed": 0}, "timed_out": False}
        self.assertEqual(snapshot(client, now=NOW)["agents"], [])
        for result in ({**response(), "timed_out": True}, {**response(), "_shards": {"failed": 1}}, {}):
            client.search.return_value = result
            with self.assertRaises((RuntimeError, KeyError)):
                snapshot(client, now=NOW)


class SetupTests(unittest.TestCase):
    def test_pipeline_overwrites_source_supplied_receipt_time(self):
        processor = PIPELINE["processors"][0]["set"]
        self.assertEqual(processor, {"field": "event.ingested", "value": "{{{_ingest.timestamp}}}", "override": True})
        client = Mock()
        install_receipt_pipeline(client, ["soc-network-test"])
        client.indices.put_settings.assert_called_once_with(index="soc-network-test", settings={"index.final_pipeline": PIPELINE_ID})
        client.indices.put_mapping.assert_called_once()
        client.reindex.assert_not_called()

    def test_all_existing_indices_are_checked_before_setup(self):
        client = Mock()
        client.indices.get_settings.return_value = {"soc-host-raw-test": {"settings": {"index.final_pipeline": "custom-pipeline"}}}
        client.indices.get_mapping.return_value = {}
        with self.assertRaisesRegex(RuntimeError, "manual review"):
            inspect_existing(client)
        client.ingest.put_pipeline.assert_not_called()
        client.indices.get_settings.return_value = {"soc-host-raw-test": {"settings": {}}}
        client.indices.get_mapping.return_value = {"soc-host-raw-test": {"mappings": {"properties": {
            "event": {"properties": {"ingested": {"type": "keyword"}}},
        }}}}
        with self.assertRaisesRegex(RuntimeError, "mapping"):
            inspect_existing(client)
        client.indices.get_mapping.return_value = {}
        self.assertEqual(inspect_existing(client), ["soc-host-raw-test"])
        self.assertNotIn("name", client.indices.get_settings.call_args.kwargs)

    def test_central_templates_only_and_read_only_role(self):
        for filename in ("index-template.json", "network-index-template.json"):
            source = json.loads((ROOT / "deploy/agents" / filename).read_text(encoding="utf-8"))
            changed = configure_template(deepcopy(source))
            self.assertNotIn("index.final_pipeline", source["template"]["settings"])
            self.assertEqual(changed["template"]["settings"]["index.final_pipeline"], PIPELINE_ID)
            self.assertEqual(changed["template"]["mappings"]["properties"]["event"]["properties"]["ingested"]["type"], "date")
        client = Mock()
        configure_reader(client, "synthetic-password")
        role = client.security.put_role.call_args.kwargs
        self.assertEqual(role["cluster"], [])
        self.assertEqual(role["indices"], [{"names": INDICES.split(","), "privileges": ["read", "view_index_metadata"]}])
        self.assertEqual(client.security.put_user.call_args.kwargs["roles"], ["cloud_soc_agent_monitor"])

    def test_compose_only_mounts_reader_secret_into_bootstrap_and_portal(self):
        import yaml
        config = yaml.safe_load((ROOT / "deploy/server/compose.yaml").read_text(encoding="utf-8"))
        for name, service in config["services"].items():
            self.assertEqual("monitor_password" in service.get("secrets", []), name in ("portal", "bootstrap"))
        portal = config["services"]["portal"]
        self.assertEqual(portal["environment"]["SOC_MONITOR_PASSWORD_FILE"], "/run/secrets/monitor_password")
        self.assertNotIn("elastic_password", portal["secrets"])
        self.assertNotIn("analyst_password", portal["secrets"])


class StatusAPITests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="soc-status-test-")
        self.addCleanup(folder.cleanup)
        self.issuer, self.monitor = Mock(), Mock()
        self.monitor.search.return_value = response([bucket()])
        self.settings = {"STATE_DIR": Path(folder.name), "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": b"synthetic",
                         "PUBLIC_URL": "http://localhost", "ENDPOINT": "https://soc.example.test:9200", "ADMIN_USER": "admin",
                         "ADMIN_HASH": generate_password_hash("synthetic", method="pbkdf2:sha256:1000")}
        self.client = create_app(self.settings, issuer=self.issuer, monitor=self.monitor).test_client()
        self.auth = {"Authorization": "Basic " + base64.b64encode(b"admin:synthetic").decode()}

    def test_status_and_assets_require_admin_and_correct_origin(self):
        for path in ("/api/agents/status", "/agent-status.html", "/agent-status.js", "/agent-status.css"):
            self.assertEqual(self.client.get(path).status_code, 401)
            with self.client.get(path, headers=self.auth) as result:
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.headers["Cache-Control"], "no-store")
        for extra in ({"Host": "attacker.test"}, {"Origin": "https://attacker.test"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertIn(self.client.get("/api/agents/status", headers={**self.auth, **extra}).status_code, (400, 403))
        self.issuer.search.assert_not_called()

    def test_bad_cursor_rejected_before_search(self):
        for query in ("?cursor=invalid!", "?cursor=a&cursor=b", "?index=secrets", "?size=100000"):
            self.assertEqual(self.client.get("/api/agents/status" + query, headers=self.auth).status_code, 400)
        self.monitor.search.assert_not_called()

    def test_failure_never_returns_stale_or_sensitive_results(self):
        self.monitor.search.side_effect = RuntimeError("UPSTREAM_SECRET_CANARY")
        result = self.client.get("/api/agents/status", headers=self.auth)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.json["code"], "status_unavailable")
        self.assertNotIn("CANARY", result.get_data(as_text=True))
        self.assertNotIn("agents", result.json)

    def test_old_deployment_returns_actionable_unknown_not_fake_empty(self):
        client = create_app(self.settings, issuer=self.issuer).test_client()
        result = client.get("/api/agents/status", headers=self.auth)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.json["code"], "monitor_not_configured")


if __name__ == "__main__":
    unittest.main()
