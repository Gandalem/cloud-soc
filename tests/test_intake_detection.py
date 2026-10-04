"""Synthetic integration tests: real normalizer, rule engine and portal; fake ES IO."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from elasticsearch import ConflictError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.detection.__main__ import main
from cloud_soc.detection.setup import ROLE, prepare, main as setup_main
from cloud_soc.detection.worker import run_once
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import SECURITY_ALERTS_MAPPING
from cloud_soc.portal.operations import Operations
from cloud_soc.processing.contract import normalize, NORMALIZED, STATUS


def raw(number, *, seconds=None, organization="team-a"):
    stamp = datetime.fromtimestamp(1790899200 + (number if seconds is None else seconds), timezone.utc)
    return {"_index": "soc-host-raw-demo", "_id": str(number), "_source": {
        "@timestamp": stamp.isoformat(), "organization": {"id": organization},
        "event": {"ingested": stamp.isoformat(), "timezone": "UTC"},
        "labels": {"log_source": "linux_file"},
        "message": stamp.strftime("%b %d %H:%M:%S") +
        " host sshd[100]: Failed password for fixture from 192.0.2.10 port 12345 ssh2"}}


def normalized(raw_hit):
    key, record, event = normalize(raw_hit, "2026-10-02T00:00:00Z")
    assert record["status"] == "normalized", record
    return {"_index": NORMALIZED, "_id": key, "_source": event}


def client_for(hits):
    client = Mock()
    client.options.return_value = client
    client.indices.resolve_index.return_value = {"indices": [{"name": NORMALIZED}]}
    client.indices.get_mapping.return_value = {"security-alerts": {"mappings": SECURITY_ALERTS_MAPPING}}
    client.open_point_in_time.return_value = {"id": "pit"}
    client.search.side_effect = [{"hits": {"hits": [dict(h, sort=[i]) for i, h in enumerate(hits)]}},
                                 {"hits": {"hits": []}}] if hits else [{"hits": {"hits": []}}]
    client.create.return_value = {"result": "created"}
    return client


class IntakeDetectionTests(unittest.TestCase):
    def test_real_normalizer_engine_alert_and_portal_evidence(self):
        sources = [raw(i) for i in range(10)]
        hits = [normalized(row) for row in sources]
        client = client_for(hits)
        self.assertEqual(run_once(client), {"events": 10, "created": 1, "existing": 0})
        kwargs = client.create.call_args.kwargs
        self.assertEqual(kwargs["index"], "security-alerts")
        alert = kwargs["document"]
        evidence = alert["cloud_soc"]["provenance"]["evidence"]
        self.assertEqual(len(evidence), 10)
        self.assertTrue(all(row["complete"] for row in evidence))
        stored = {(h["_index"], h["_id"]): h["_source"] for h in sources + hits}
        stored[("security-alerts", kwargs["id"])] = alert
        reader = Operations(client)
        with patch.object(reader, "get", side_effect=lambda index, doc_id, fields: stored.get((index, doc_id))):
            detail = json.loads(reader.detail([("id", kwargs["id"]), ("evidence", "0")]))
        self.assertEqual(detail["evidence"]["state"], "exact_reference")
        self.assertEqual(detail["condition"]["threshold"], 10)
        self.assertEqual(alert["organization"]["id"], "team-a")
        self.assertEqual(client.index.call_args.kwargs["document"]["state"], "success")

    def test_threshold_across_normalizer_batches(self):
        first = client_for([normalized(raw(i)) for i in range(9)])
        self.assertEqual(run_once(first)["created"], 0)
        second = client_for([normalized(raw(i)) for i in range(10)])
        self.assertEqual(run_once(second)["created"], 1)

    def test_beyond_window_does_not_alert(self):
        client = client_for([normalized(raw(i, seconds=i * 40)) for i in range(10)])
        self.assertEqual(run_once(client)["created"], 0)

    def test_organizations_do_not_mix(self):
        client = client_for([normalized(raw(i, organization="a" if i < 5 else "b")) for i in range(10)])
        self.assertEqual(run_once(client)["created"], 0)

    def test_existing_cooldown_and_second_window(self):
        self.assertEqual(run_once(client_for([normalized(raw(i)) for i in range(20)]))["created"], 1)
        hits = [normalized(raw(i, seconds=i if i < 10 else i + 300)) for i in range(20)]
        self.assertEqual(run_once(client_for(hits))["created"], 2)

    def test_partial_alert_write_replay_finishes_missing_alert(self):
        hits = [normalized(raw(i, seconds=i if i < 10 else i + 300)) for i in range(20)]
        client = client_for(hits)
        client.create.side_effect = [{"result": "created"}, RuntimeError("connection lost")]
        with self.assertRaises(RuntimeError): run_once(client)
        first_ids = [call.kwargs["id"] for call in client.create.call_args_list]
        retry = client_for(hits)
        retry.create.side_effect = [ConflictError("conflict", meta=Mock(status=409), body={}), {"result": "created"}]
        self.assertEqual(run_once(retry), {"events": 20, "created": 1, "existing": 1})
        self.assertEqual(first_ids, [call.kwargs["id"] for call in retry.create.call_args_list])

    def test_snapshot_order_does_not_change_id(self):
        hits = [normalized(raw(i)) for i in range(10)]
        ids = []
        for ordered in (hits, list(reversed(hits))):
            client = client_for(ordered)
            run_once(client)
            ids.append(client.create.call_args.kwargs["id"])
        self.assertEqual(ids[0], ids[1])

    def test_replay_does_not_overwrite_alert(self):
        client = client_for([normalized(raw(i)) for i in range(10)])
        client.create.side_effect = ConflictError("conflict", meta=Mock(status=409), body={})
        self.assertEqual(run_once(client)["existing"], 1)
        self.assertTrue(all(c.kwargs["index"] == STATUS for c in client.index.call_args_list))

    def test_no_source_mutation(self):
        hits = [normalized(raw(i)) for i in range(10)]
        before = deepcopy(hits)
        run_once(client_for(hits))
        self.assertEqual(hits, before)

    def test_empty_snapshot_is_success_without_alerts(self):
        client = client_for([])
        self.assertEqual(run_once(client)["events"], 0)
        client.create.assert_not_called()

    def test_partial_snapshot_fails_without_alerts(self):
        for response in ({"timed_out": True}, {"_shards": {"failed": 1}},
                         {"terminated_early": True}, {"hits": {"hits": [{"sort": None}]}}):
            with self.subTest(response=response):
                client = client_for([])
                client.search.side_effect = [response]
                with self.assertRaisesRegex(RuntimeError, "detection_cycle_failed"):
                    run_once(client)
                client.create.assert_not_called()
                client.close_point_in_time.assert_called_once()
                self.assertEqual(client.index.call_args.kwargs["document"]["state"], "failed")

    def test_limit_is_not_silent_truncation(self):
        client = client_for([normalized(raw(i)) for i in range(10)])
        with self.assertRaises(RuntimeError):
            run_once(client, max_documents=9)
        client.create.assert_not_called()
        client.close_point_in_time.assert_called_once()
        self.assertEqual(run_once(client_for([normalized(raw(0))]), max_documents=1)["events"], 1)

    def test_pagination_and_changed_pit_close_latest(self):
        client = client_for([])
        client.search.side_effect = [
            {"pit_id": "new", "hits": {"hits": [{"sort": [1]}, {"sort": [2]}]}},
            {"hits": {"hits": [{"sort": [3]}]}}, {"hits": {"hits": []}}]
        self.assertEqual(len(fetch_all_hits(client, index=NORMALIZED, page_size=2, max_documents=3)), 3)
        self.assertEqual(client.search.call_args_list[1].kwargs["search_after"], [2])
        client.close_point_in_time.assert_called_once_with(id="new")

    def test_wrong_index_or_missing_provenance_fails(self):
        for field in ("index", "provenance", "timestamp", "raw"):
            hit = normalized(raw(1))
            if field == "index": hit["_index"] = "normalized-events"
            elif field == "provenance": del hit["_source"]["cloud_soc"]["provenance"]
            elif field == "timestamp": hit["_source"]["@timestamp"] = "invalid"
            else: hit["_source"]["cloud_soc"]["provenance"]["raw"]["index"] = ".security"
            client = client_for([hit])
            with self.assertRaises(RuntimeError): run_once(client)
            client.create.assert_not_called()

    def test_alias_is_rejected(self):
        client = client_for([])
        client.indices.resolve_index.return_value["aliases"] = [{"name": NORMALIZED}]
        with self.assertRaises(RuntimeError): run_once(client)
        client.open_point_in_time.assert_not_called()

    def test_write_failure_can_be_replayed(self):
        hits = [normalized(raw(i)) for i in range(10)]
        failed = client_for(hits)
        failed.create.side_effect = RuntimeError("PRIVATE_CANARY")
        with self.assertRaisesRegex(RuntimeError, "^detection_cycle_failed;"):
            run_once(failed)
        retry = client_for(hits)
        run_once(retry)
        self.assertEqual(failed.create.call_args.kwargs["id"], retry.create.call_args.kwargs["id"])

    def test_detector_status_is_independent_of_normalizer(self):
        reader = Operations(Mock())
        now = datetime.now(timezone.utc).isoformat()
        with patch.object(reader, "get", side_effect=[None, {"@timestamp": now, "state": "success"}]):
            result = reader.pipeline()
        self.assertEqual(result["state"], "not_started")
        self.assertEqual(result["detector"]["state"], "success")
        with patch.object(reader, "get", side_effect=[None, RuntimeError()]):
            self.assertEqual(reader.pipeline()["detector"]["state"], "unavailable")
        with patch.object(reader, "get", side_effect=[RuntimeError(), {"@timestamp": now, "state": "success"}]):
            result = reader.pipeline()
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["detector"]["state"], "success")

    def test_cli_default_never_connects_and_invalid_once_fails(self):
        with patch("cloud_soc.detection.__main__.Elasticsearch") as es:
            self.assertEqual(main([]), 0)
            self.assertEqual(main(["--once"]), 1)
            self.assertEqual(main(["--max-documents", "0"]), 1)
            es.assert_not_called()

    def test_setup_refuses_to_overwrite_key(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "key"
            existing.write_text("original", encoding="utf-8")
            with patch("cloud_soc.detection.setup.Elasticsearch") as es:
                self.assertEqual(setup_main(["--es-url", "https://localhost:9200", "--ca-file", str(existing),
                    "--password-file", str(existing), "--key-file", str(existing)]), 1)
                es.assert_not_called()
            self.assertEqual(existing.read_text(), "original")

    def test_least_privilege_no_raw_access_or_index_creation(self):
        self.assertEqual(ROLE["cluster"], [])
        privileges = {p for row in ROLE["indices"] for p in row["privileges"]}
        self.assertNotIn("create_index", privileges)
        self.assertNotIn("manage", privileges)
        self.assertFalse(any("*" in name for row in ROLE["indices"] for name in row["names"]))
        self.assertEqual(ROLE["indices"][1]["privileges"], ["create_doc", "view_index_metadata"])

    def test_setup_writes_key_without_starting_worker(self):
        for worker in ("detector", "normalizer"):
            with tempfile.TemporaryDirectory() as directory:
                password = Path(directory) / "password"
                password.write_text("private-password", encoding="utf-8")
                password.chmod(0o600)
                key = Path(directory) / "key"
                client = Mock()
                client.__enter__ = Mock(return_value=client)
                client.__exit__ = Mock(return_value=False)
                client.security.create_api_key.return_value = {"id": "id", "encoded": "private-key"}
                with patch("cloud_soc.detection.setup.Elasticsearch", return_value=client), \
                     patch("cloud_soc.detection.setup.prepare") as prepared:
                    self.assertEqual(setup_main(["--es-url", "https://localhost:9200", "--ca-file", str(password),
                        "--password-file", str(password), "--key-file", str(key), "--worker", worker]), 0)
                self.assertEqual(key.read_text().strip(), "private-key")
                self.assertEqual(client.security.create_api_key.call_args.kwargs["expiration"], "30d")
                self.assertIn("intake_" + worker, client.security.create_api_key.call_args.kwargs["role_descriptors"])
                prepared.assert_called_once_with(client)

    def test_prepare_rejects_unexpected_processing_contract(self):
        client = Mock()
        client.indices.get_mapping.return_value = {NORMALIZED: {"mappings": {}}}
        with self.assertRaises(ValueError): prepare(client)
        client.security.create_api_key.assert_not_called()

    def test_alert_alias_rejected_before_writes(self):
        client = client_for([normalized(raw(i)) for i in range(10)])
        client.indices.get_mapping.return_value = {"unexpected-alert-index": {"mappings": SECURITY_ALERTS_MAPPING}}
        with self.assertRaises(RuntimeError): run_once(client)
        client.create.assert_not_called()

    def test_explicit_processing_preparation_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            password = Path(directory) / "password"
            password.write_text("private-password", encoding="utf-8")
            password.chmod(0o600)
            client = Mock()
            client.__enter__ = Mock(return_value=client)
            client.__exit__ = Mock(return_value=False)
            client.security.create_api_key.return_value = {"id": "id", "encoded": "key"}
            with patch("cloud_soc.detection.setup.Elasticsearch", return_value=client), \
                 patch("cloud_soc.detection.setup.prepare"), \
                 patch("cloud_soc.detection.setup.prepare_processing") as processing:
                self.assertEqual(setup_main(["--es-url", "https://localhost:9200", "--ca-file", str(password),
                    "--password-file", str(password), "--key-file", str(Path(directory) / "key"),
                    "--prepare-processing"]), 0)
                processing.assert_called_once_with(client)


if __name__ == "__main__":
    unittest.main()
