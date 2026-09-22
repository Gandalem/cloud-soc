"""Synthetic normalization and crash/replay contract tests; no network."""
import copy
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.processing.contract import normalize, NORMALIZED, RECORDS, STATUS
from cloud_soc.processing.worker import run_once, scan
from cloud_soc.processing.__main__ import main
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.log_query import LogQueryError

START = "2026-09-22T01:00:00Z"
NOW = datetime(2026, 9, 22, 1, 20, tzinfo=timezone.utc)


def fixture():
    return {"_index": "soc-host-raw-test", "_id": "synthetic", "_source": {
        "@timestamp": "2020-01-01T00:00:00Z", "organization": {"id": "fixture"},
        "event": {"ingested": "2026-09-22T01:01:00Z", "code": "4625"},
        "winlog": {"channel": "Security", "event_id": "4625", "provider_name": "Microsoft-Windows-Security-Auditing",
                   "event_data": {"TargetUserName": "fixture-user", "LogonType": "3", "IpAddress": "192.0.2.1", "Password": "PRIVATE_CANARY"}},
        "message": "PRIVATE_CANARY", "event.original": "PRIVATE_CANARY"}}


class ProcessingTests(unittest.TestCase):
    def test_windows_late_event_has_raw_lineage_no_body(self):
        key, record, event = normalize(fixture(), START)
        self.assertEqual(record["status"], "normalized")
        self.assertEqual(event["@timestamp"], "2020-01-01T00:00:00Z")
        self.assertEqual(event["event"]["outcome"], "failure")
        self.assertEqual(event["cloud_soc"]["provenance"]["raw"], {"index": "soc-host-raw-test", "id": "synthetic"})
        self.assertNotIn("PRIVATE_CANARY", json.dumps(event))
        self.assertEqual(key, normalize(fixture(), "2026-09-23T01:00:00Z")[0])

    def test_invalid_and_unsupported_have_only_metadata(self):
        hit = fixture(); del hit["_source"]["organization"]
        self.assertEqual(normalize(hit, START)[1]["status"], "invalid")
        hit = fixture(); hit["_source"]["winlog"]["provider_name"] = "fake"
        key, record, event = normalize(hit, START)
        self.assertEqual(record["status"], "unsupported"); self.assertIsNone(event)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(record))

    def test_linux_timezone_not_guessed(self):
        hit = fixture(); source = hit["_source"]; del source["winlog"]
        source.update({"@timestamp": START, "labels": {"log_source": "linux_file"},
                       "message": "Sep 22 01:00:00 host sshd[100]: Failed password for fixture from 192.0.2.1 port 12345 ssh2"})
        self.assertEqual(normalize(hit, START)[1]["reason"], "ssh_timezone_missing")
        source["event"]["timezone"] = "UTC"
        event = normalize(hit, START)[2]
        self.assertEqual(event["network"]["protocol"], "ssh")
        self.assertEqual(event["@timestamp"], START)

    def test_packetbeat_cloud_adapters(self):
        for provider in ("aws", "oci", "network"):
            hit = fixture(); s = hit["_source"]; del s["winlog"]
            if provider == "network":
                hit["_index"] = "soc-network-test"
                s.update(agent={"type": "packetbeat"}, labels={"log_source": "network_packetbeat"}, source={"ip": "192.0.2.1"}, destination={"ip": "192.0.2.2"})
            else:
                hit["_index"] = "soc-cloud-" + provider + "-test"
                s.update(cloud={"provider": provider}, labels={"log_source": "aws_cloudtrail" if provider == "aws" else "oci_audit"})
                s[provider] = {"cloudtrail": {"schema": 1, "management_only": True}} if provider == "aws" else {"audit": {"schema": 1}}
            self.assertEqual(normalize(hit, START)[1]["status"], "normalized")

    def test_source_family_and_engine_evidence_contract(self):
        from cloud_soc.detection.engine import event_evidence
        hit = fixture(); key, record, event = normalize(hit, START)
        event["_cloud_soc_meta"] = {"index": NORMALIZED, "document_id": key}
        self.assertTrue(event_evidence(event)["complete"])
        hit["_index"] = "soc-cloud-aws-test"
        self.assertEqual(normalize(hit, START)[1]["reason"], "source_scope_mismatch")

    def test_checkpoint_replay_failure_and_start_lock(self):
        client = Mock(); client.options.return_value = client
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite"
            first = run_once(client, path, START, now=NOW, scanner=lambda *_: [fixture()])
            self.assertEqual(first["checkpoint"], "2026-09-22T01:05:00Z")
            self.assertEqual(client.create.call_count, 2)
            def failure(*_):
                yield fixture()
                raise RuntimeError("PRIVATE_CANARY")
            with self.assertRaisesRegex(RuntimeError, "checkpoint retained"):
                run_once(client, path, START, now=NOW, scanner=failure)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT checkpoint FROM state").fetchone()[0], first["checkpoint"])
            self.assertEqual(client.index.call_args.kwargs["document"]["state"], "failed")
            with self.assertRaises(ValueError):
                run_once(client, path, "2026-09-22T01:01:00Z", now=NOW)
            second = run_once(client, path, START, now=NOW, scanner=lambda *_: [])
            self.assertEqual(second["checkpoint"], "2026-09-22T01:10:00Z")
            self.assertEqual(second["range"]["start"], START)

    def test_partial_search_and_cursor_failure_close_pit(self):
        for response in ({"timed_out": True}, {"_shards": {"failed": 1}}, {"hits": {"hits": [{"sort": None}]}}):
            client = Mock()
            client.indices.resolve_index.return_value = {"indices": [{"name": "soc-host-raw-test"}]}
            client.field_caps.return_value = {"fields": {"event.ingested": {"date": {}}}}
            client.open_point_in_time.return_value = {"id": "pit"}
            client.search.return_value = response
            with self.assertRaises(RuntimeError):
                list(scan(client, START, "2026-09-22T01:05:00Z"))
            client.close_point_in_time.assert_called_once_with(id="pit")

    def test_same_state_is_locked_and_waiting_is_not_success(self):
        client = Mock(); client.options.return_value = client
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite"
            def scanner(*_):
                with self.assertRaises(sqlite3.OperationalError):
                    run_once(client, path, START, now=NOW, scanner=lambda *_: [])
                return []
            run_once(client, path, START, now=NOW, scanner=scanner)
        with tempfile.TemporaryDirectory() as directory:
            status = run_once(client, Path(directory) / "state.sqlite", "2026-09-22T01:19:50Z", now=NOW, scanner=Mock())
            self.assertEqual(status["state"], "waiting")
            self.assertIsNone(status["last_success"])

    def test_offline_cli_no_connection(self):
        with patch("cloud_soc.processing.__main__.Elasticsearch") as client:
            self.assertEqual(main(["--start", START]), 0)
            client.assert_not_called()


class OperationsTests(unittest.TestCase):
    def test_unconfigured_and_bad_query(self):
        reader = Operations(None)
        result = json.loads(reader.summary([]))
        self.assertTrue(all(row["state"] == "unavailable" for row in result["sections"].values()))
        for pairs in ([("host", "x")], [("start", START), ("start", START)]):
            with self.assertRaises(LogQueryError): reader.summary(pairs)

    def test_partial_result_does_not_look_zero(self):
        client = Mock(); client.options.return_value = client
        client.indices.resolve_index.return_value = {"indices": [{"name": "security-alerts"}]}
        client.field_caps.return_value = {"fields": {"@timestamp": {"date": {}}}}
        client.search.return_value = {"timed_out": True}
        result = json.loads(Operations(client).summary([]))
        self.assertEqual(result["sections"]["alerts"]["state"], "unavailable")
        self.assertNotIn("count", result["sections"]["alerts"])

    def test_reference_states_and_no_nearby_search(self):
        reader = Operations(Mock())
        raw = {"index": "soc-host-raw-test", "id": "fixture"}
        ref = {"raw": raw, "normalized": {"index": NORMALIZED, "id": "fixture"}}
        with patch.object(reader, "get", return_value=None):
            self.assertEqual(reader.evidence(ref)["state"], "normalized_missing_or_expired")
        norm = {"cloud_soc": {"provenance": {"raw": raw}}}
        with patch.object(reader, "get", side_effect=[norm, None]):
            self.assertEqual(reader.evidence(ref)["state"], "raw_missing_or_expired")
        with patch.object(reader, "get", return_value={}):
            self.assertEqual(reader.evidence(ref)["state"], "provenance_mismatch")
        bad = copy.deepcopy(ref); bad["raw"]["index"] = ".security"
        self.assertEqual(reader.evidence(bad)["state"], "unsupported_or_invalid_reference")
        reader.client.search.assert_not_called()

    def test_stale_pipeline_not_healthy(self):
        reader = Operations(Mock())
        with patch.object(reader, "get", return_value={"@timestamp": "2020-01-01T00:00:00Z", "state": "success"}):
            self.assertEqual(reader.pipeline()["state"], "stale")

    def test_legacy_alert_has_no_invented_evidence(self):
        reader = Operations(Mock())
        with patch.object(reader, "get", return_value={"@timestamp": START, "rule": {"id": "AUTH-001"}}):
            result = json.loads(reader.detail([("id", "fixture")]))
            self.assertEqual(result["evidence_state"], "legacy_missing_provenance")
            self.assertEqual(result["evidence_count"], 0)


if __name__ == "__main__": unittest.main()
