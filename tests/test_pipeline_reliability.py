"""Offline regression tests: no sockets, live indices, or installed agents required."""

from copy import deepcopy
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from io import StringIO
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from elastic_transport import ApiResponseMeta, NodeConfig
from elasticsearch import ApiError, ConflictError, ConnectionError

from cloud_soc import main as pipeline
from cloud_soc.detection.engine import detect_events, fetch_normalized_events
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.elastic.pagination import IncompleteSearchError, fetch_all_hits
from cloud_soc.elastic.repository import (
    PROVENANCE_MAPPING, ProvenanceMappingError, ensure_provenance_mapping,
    fetch_raw_events, save_normalized_event, save_security_alert,
)
from cloud_soc.normalizers.ecs import parse_syslog_timestamp
from cloud_soc.normalizers.time_context import parse_utc_offset, raw_time_context


def api_error(status, exception=ApiError):
    meta = ApiResponseMeta(status, "1.1", {}, 0.0, NodeConfig("http", "localhost", 9200))
    return exception("synthetic error", meta=meta, body={"error": {"type": "test_error"}})


def event(number=0, *, org="school-a", failure=True):
    return {
        "@timestamp": f"2026-09-03T01:00:{number % 60:02d}+00:00",
        "event": {"category": ["authentication"], "outcome": "failure" if failure else "success"},
        "network": {"protocol": "ssh"}, "source": {"ip": "203.0.113.10"},
        "organization": {"id": org},
        "cloud_soc": {"provenance": {"raw": {"index": "raw-logs-test", "id": str(number)}}},
        "_cloud_soc_meta": {"index": "normalized-events", "document_id": str(number)},
    }


def raw_hit(number=0, *, date="Sep  3 01:00:00"):
    return {
        "_index": "raw-logs-test", "_id": str(number),
        "_source": {
            "@timestamp": "2026-09-03T01:05:00Z",
            "labels": {"log_source": "linux_auth"},
            "organization": {"id": "school-a"},
            "message": f"{date} host sshd[123]: Failed password for ubuntu from 203.0.113.10 port 50000 ssh2",
        },
    }


class SnapshotClient:
    def __init__(self, hits):
        self.hits = deepcopy(hits)
        self.requests = []
        self.indices = Mock()
        self.indices.exists.return_value = True
        self.close_point_in_time = Mock(return_value={"succeeded": True})

    def open_point_in_time(self, **kwargs):
        assert kwargs["allow_partial_search_results"] is False
        return {"id": "pit-0", "_shards": {"failed": 0}}

    def search(self, **kwargs):
        assert "index" not in kwargs
        assert kwargs["allow_partial_search_results"] is False
        assert kwargs["pit"]["id"] == f"pit-{len(self.requests)}"
        start = kwargs.get("search_after", [-1])[0] + 1
        self.requests.append(deepcopy(kwargs))
        page = deepcopy(self.hits[start:start + kwargs["size"]])
        for ordinal, hit in enumerate(page, start):
            hit["sort"] = [ordinal]
        return {
            "pit_id": f"pit-{len(self.requests)}", "timed_out": False,
            "_shards": {"failed": 0}, "hits": {"hits": page},
        }


class MemoryElasticsearch:
    """Exercise the full batch with create conflicts and isolated PIT snapshots."""

    def __init__(self, hits):
        self.documents = {"raw-logs-test": {hit["_id"]: deepcopy(hit["_source"]) for hit in hits}}
        self.mappings = {"raw-logs-test": {"properties": {}}}
        self.snapshots = {}
        self.indices = Mock()
        self.indices.exists.side_effect = lambda *, index: any(fnmatchcase(name, index) for name in self.documents)
        self.indices.create.side_effect = self.create_index
        self.indices.get_mapping.side_effect = lambda *, index: {index: {"mappings": self.mappings[index]}}
        self.indices.refresh.return_value = {"_shards": {"failed": 0}}
        self.close = Mock()

    def create_index(self, *, index, mappings):
        self.documents[index] = {}
        self.mappings[index] = deepcopy(mappings)

    def create(self, *, index, id, document, refresh):
        if id in self.documents[index]:
            raise api_error(409, ConflictError)
        self.documents[index][id] = deepcopy(document)
        return {"result": "created"}

    def open_point_in_time(self, *, index, keep_alive, allow_partial_search_results):
        identifier = str(len(self.snapshots))
        self.snapshots[identifier] = [
            {"_index": name, "_id": id, "_source": deepcopy(source)}
            for name, documents in self.documents.items() if fnmatchcase(name, index)
            for id, source in documents.items()
        ]
        return {"id": identifier, "_shards": {"failed": 0}}

    def search(self, *, pit, size, query, sort, track_total_hits,
               allow_partial_search_results, search_after=None):
        start = search_after[0] + 1 if search_after else 0
        # Small pages ensure one alert can span many page boundaries.
        page = deepcopy(self.snapshots[pit["id"]][start:start + min(size, 3)])
        for number, hit in enumerate(page, start):
            hit["sort"] = [number]
        return {"hits": {"hits": page}, "_shards": {"failed": 0}, "timed_out": False}

    def close_point_in_time(self, *, id):
        del self.snapshots[id]
        return {"succeeded": True}


class PaginationTests(unittest.TestCase):
    def test_raw_more_than_ten_thousand(self):
        client = SnapshotClient([raw_hit(number) for number in range(10010)])
        hits = fetch_raw_events(client)
        self.assertEqual(len(hits), 10010)
        self.assertEqual(len({hit["_id"] for hit in hits}), 10010)
        self.assertEqual(hits[-1]["_id"], "10009")
        client.close_point_in_time.assert_called_once_with(id=f"pit-{len(client.requests)}")

    def test_detection_reads_failures_after_ten_thousand_successes(self):
        hits = [{"_index": "normalized-events", "_id": str(number),
                 "_source": event(number, failure=number >= 10000)} for number in range(10010)]
        client = SnapshotClient(hits)
        events = fetch_normalized_events(client)
        detections = detect_events(events, load_rules())
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["event_count"], 10)
        self.assertEqual(len(detections[0]["evidence"]), 10)
        self.assertEqual(events[-1]["_cloud_soc_meta"]["index"], "normalized-events")

    def test_no_raw_index_is_an_empty_initial_batch(self):
        client = Mock()
        client.indices.exists.return_value = False
        self.assertEqual(fetch_raw_events(client), [])
        client.open_point_in_time.assert_not_called()

    def test_exact_page_boundary_is_not_truncated(self):
        client = SnapshotClient([raw_hit(number) for number in range(10)])
        self.assertEqual(len(fetch_all_hits(client, index="test", page_size=5)), 10)
        self.assertEqual(len(client.requests), 3)

    def test_rejects_partial_and_non_advancing_pages(self):
        for extra in ({"timed_out": True}, {"_shards": {"failed": 1}},
                      {"terminated_early": True}, {}):
            with self.subTest(extra=extra):
                client = Mock()
                client.open_point_in_time.return_value = {"id": "old"}
                client.search.return_value = {"pit_id": "new", "hits": {"hits": [raw_hit()]}, **extra}
                with self.assertRaises(IncompleteSearchError):
                    fetch_all_hits(client, index="test")
                client.close_point_in_time.assert_called_once_with(id="new")

    def test_repeated_cursor_fails_closed(self):
        client = Mock()
        client.open_point_in_time.return_value = {"id": "pit"}
        client.search.return_value = {"hits": {"hits": [{**raw_hit(), "sort": [0]}]}}
        with self.assertRaises(IncompleteSearchError):
            fetch_all_hits(client, index="test")
        self.assertEqual(client.search.call_count, 2)

    def test_second_page_failure_does_not_return_partial_data(self):
        client = Mock()
        client.open_point_in_time.return_value = {"id": "old"}
        client.search.side_effect = [
            {"pit_id": "new", "hits": {"hits": [{**raw_hit(), "sort": [0]}]}},
            RuntimeError("read failed"),
        ]
        client.close_point_in_time.side_effect = RuntimeError("cleanup failed")
        with self.assertLogs("cloud_soc.elastic.pagination", level="WARNING"):
            with self.assertRaisesRegex(RuntimeError, "read failed"):
                fetch_all_hits(client, index="test")
        client.close_point_in_time.assert_called_once_with(id="new")

    def test_failed_shard_on_open_is_rejected_and_closed(self):
        client = Mock()
        client.open_point_in_time.return_value = {"id": "pit", "_shards": {"failed": 1}}
        with self.assertRaises(IncompleteSearchError):
            fetch_all_hits(client, index="test")
        client.search.assert_not_called()
        client.close_point_in_time.assert_called_once_with(id="pit")

    def test_invalid_page_size_does_not_open_pit(self):
        for size in (0, -1, True, 10001):
            client = Mock()
            with self.assertRaises(ValueError):
                fetch_all_hits(client, index="test", page_size=size)
            client.open_point_in_time.assert_not_called()


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.rules = load_rules()
        self.events = [event(number) for number in range(10)]

    def test_two_organizations_cannot_pool_threshold(self):
        events = [event(number, org="school-a" if number < 5 else "school-b") for number in range(10)]
        # Engine isolation also applies to rules which omit organization.id.
        self.rules[0]["group_by"] = ["source.ip"]
        self.assertEqual(detect_events(events, self.rules), [])

    def test_scope_and_exact_evidence_reach_alert(self):
        result = detect_events(self.events, self.rules)[0]
        alert = pipeline.build_security_alert(result)
        self.assertEqual(alert["organization"]["id"], "school-a")
        provenance = alert["cloud_soc"]["provenance"]
        self.assertEqual(provenance["evidence_status"], "complete")
        self.assertEqual(len(provenance["evidence"]), 10)
        self.assertEqual({item["raw"]["id"] for item in provenance["evidence"]}, {str(n) for n in range(10)})
        self.assertEqual(provenance["rule_snapshot"], self.rules[0])
        self.assertEqual(len(provenance["rule_version"]), 64)

    def test_legacy_evidence_is_explicitly_incomplete(self):
        for item in self.events:
            del item["cloud_soc"]
        result = detect_events(self.events, self.rules)[0]
        self.assertEqual(result["evidence_status"], "incomplete_legacy")
        self.assertEqual(len(result["evidence"]), 10)

    def test_missing_org_and_naive_time_are_rejected_and_counted(self):
        bad_org, bad_time = event(11), event(12)
        del bad_org["organization"]
        bad_time["@timestamp"] = "2026-09-03T01:00:00"
        rejected = []
        results = detect_events([bad_org, bad_time, *self.events], self.rules, rejected=rejected)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(rejected), 2)

    def test_same_timestamp_order_does_not_change_alert_identity(self):
        events = [event(number) for number in range(11)]
        for item in events:
            item["@timestamp"] = "2026-09-03T01:00:00Z"
        first = detect_events(events, self.rules)[0]
        replay = detect_events(list(reversed(events)), self.rules)[0]
        self.assertEqual(pipeline.make_alert_id(first), pipeline.make_alert_id(replay))

    def test_rule_change_or_evidence_change_gets_new_identity(self):
        first = detect_events(self.events, self.rules)[0]
        self.rules[0]["description"] += " changed"
        revised = detect_events(self.events, self.rules)[0]
        self.assertNotEqual(pipeline.make_alert_id(first), pipeline.make_alert_id(revised))
        self.events[0]["message"] = "changed source"
        updated = detect_events(self.events, self.rules)[0]
        self.assertNotEqual(pipeline.make_alert_id(revised), pipeline.make_alert_id(updated))

    def test_window_boundary_and_cooldown(self):
        self.rules[0]["threshold"]["count"] = 2
        self.events = [event(number) for number in range(4)]
        for item, value in zip(self.events, ("01:00:00", "01:05:00", "01:05:01", "01:10:00")):
            item["@timestamp"] = f"2026-09-03T{value}Z"
        results = detect_events(self.events, self.rules)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["event_count"], 2)
        self.assertEqual(results[1]["event_count"], 3)


class TimeTests(unittest.TestCase):
    def test_raw_reference_and_explicit_timezone(self):
        source = raw_hit()["_source"]
        source["event"] = {"created": "2026-09-03T01:01:00Z", "timezone": "+09:00"}
        reference, zone, metadata = raw_time_context(source)
        self.assertEqual(reference.minute, 1)
        self.assertEqual(metadata["reference_field"], "event.created")
        self.assertEqual(metadata["timezone_source"], "event.timezone")
        timestamp = parse_syslog_timestamp("Sep  3 10:00:00", reference_time=reference, source_timezone=zone)
        self.assertEqual(timestamp.astimezone(timezone.utc).isoformat(), "2026-09-03T01:00:00+00:00")

    def test_year_rollover_uses_source_local_year(self):
        reference = datetime.fromisoformat("2026-12-31T15:05:00+00:00")
        zone = parse_utc_offset("+09:00")
        result = parse_syslog_timestamp("Jan  1 00:04:00", reference_time=reference, source_timezone=zone)
        self.assertEqual(result.year, 2027)
        previous = parse_syslog_timestamp("Dec 31 23:59:00", reference_time=reference, source_timezone=zone)
        self.assertEqual(previous.year, 2026)

    def test_leap_year_and_invalid_date(self):
        reference = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(parse_syslog_timestamp("Feb 29 00:00:00", reference_time=reference).year, 2024)
        with self.assertRaises(ValueError):
            parse_syslog_timestamp("Sep 31 00:00:00", reference_time=reference)

    def test_missing_naive_or_invalid_reference_is_not_replaced_with_now(self):
        for value in (None, "2026-09-03T01:00:00", "not-a-date"):
            source = raw_hit()["_source"]
            source["@timestamp"] = value
            with self.assertRaises(ValueError):
                raw_time_context(source)
        with self.assertRaises(ValueError):
            parse_syslog_timestamp("Sep  3 01:00:00")

    def test_bad_timezones_are_not_silently_treated_as_utc(self):
        for value in (None, "+24:00", "+09:99", "Asia/Seoul", "local"):
            with self.assertRaises(ValueError):
                parse_utc_offset(value)


class PersistenceTests(unittest.TestCase):
    def test_replay_is_create_only_for_events_and_alerts(self):
        client = Mock()
        client.create.side_effect = api_error(409, ConflictError)
        for save, name in ((save_normalized_event, "event"), (save_security_alert, "alert")):
            result = save(client, **{name: {"original": "unchanged"}}, document_id="known", index_prepared=True)
            self.assertEqual(result["result"], "existing")
        client.index.assert_not_called()
        self.assertEqual(client.create.call_count, 2)

    def test_write_failure_is_not_swallowed(self):
        client = Mock()
        client.create.side_effect = api_error(403)
        with self.assertRaises(ApiError):
            save_security_alert(client, {}, document_id="known", index_prepared=True)

    def test_missing_mapping_requires_explicit_application(self):
        client = Mock()
        client.indices.get_mapping.return_value = {"existing": {"mappings": {"properties": {}}}}
        with self.assertRaises(ProvenanceMappingError):
            ensure_provenance_mapping(client, "existing")
        client.indices.put_mapping.assert_not_called()
        ensure_provenance_mapping(client, "existing", apply=True)
        client.indices.put_mapping.assert_called_once_with(
            index="existing", properties={"cloud_soc": {"properties": {"provenance": PROVENANCE_MAPPING}}},
        )
        client.indices.delete.assert_not_called()

    def test_existing_opaque_mapping_is_not_changed(self):
        client = Mock()
        client.indices.get_mapping.return_value = {"existing": {"mappings": {
            "properties": {"cloud_soc": {"properties": {"provenance": PROVENANCE_MAPPING}}},
        }}}
        ensure_provenance_mapping(client, "existing", apply=True)
        client.indices.put_mapping.assert_not_called()

    def test_conflicting_mapping_is_not_overwritten(self):
        client = Mock()
        client.indices.get_mapping.return_value = {"existing": {"mappings": {
            "properties": {"cloud_soc": {"properties": {"provenance": {"type": "keyword"}}}},
        }}}
        with self.assertRaises(ProvenanceMappingError):
            ensure_provenance_mapping(client, "existing", apply=True)
        client.indices.put_mapping.assert_not_called()


class PipelineTests(unittest.TestCase):
    def test_invalid_date_does_not_block_next_valid_record(self):
        client = Mock()
        client.indices.refresh.return_value = {"_shards": {"failed": 0}}
        hits = [raw_hit(0, date="Sep 31 01:00:00"), raw_hit(1)]
        with patch.object(pipeline, "fetch_raw_events", return_value=hits), \
                patch.object(pipeline, "save_normalized_event", return_value={"result": "created"}) as save, \
                self.assertLogs(pipeline.LOGGER, level="ERROR") as logs:
            stats = pipeline.process_raw_logs(client)
        self.assertEqual((stats.created, stats.invalid), (1, 1))
        saved = save.call_args.kwargs["event"]
        self.assertEqual(saved["@timestamp"], "2026-09-03T01:00:00+00:00")
        self.assertEqual(saved["cloud_soc"]["provenance"]["raw"]["id"], "1")
        self.assertNotIn("Failed password", " ".join(logs.output))

    def test_missing_org_is_invalid_not_defaulted(self):
        hit = raw_hit()
        del hit["_source"]["organization"]
        with patch.object(pipeline, "fetch_raw_events", return_value=[hit]), \
                patch.object(pipeline, "save_normalized_event") as save, \
                self.assertLogs(pipeline.LOGGER, level="ERROR"):
            stats = pipeline.process_raw_logs(Mock())
        self.assertEqual(stats.invalid, 1)
        save.assert_not_called()

    def test_infrastructure_failure_is_not_record_validation_failure(self):
        with patch.object(pipeline, "fetch_raw_events", return_value=[raw_hit()]), \
                patch.object(pipeline, "save_normalized_event", side_effect=ConnectionError("unavailable")):
            with self.assertRaises(ConnectionError):
                pipeline.process_raw_logs(Mock())

    def test_partial_refresh_is_not_reported_as_success(self):
        client = Mock()
        client.indices.refresh.return_value = {"_shards": {"failed": 1}}
        with self.assertRaises(IncompleteSearchError):
            pipeline.refresh_complete(client, "normalized-events")

    def test_full_pipeline_replay_preserves_documents_and_exact_evidence(self):
        client = MemoryElasticsearch([raw_hit(number) for number in range(10)])
        with patch.object(sys, "stdout", StringIO()):
            first = pipeline.run_pipeline_once(client)
            snapshot = deepcopy(client.documents)
            second = pipeline.run_pipeline_once(client)
        self.assertEqual((first.raw.created, first.alerts_created), (10, 1))
        self.assertEqual((second.raw.created, second.raw.existing, second.alerts_created), (0, 10, 0))
        self.assertEqual(client.documents, snapshot)
        self.assertFalse(client.snapshots)
        client.indices.put_mapping.assert_not_called()
        alert = next(iter(client.documents["security-alerts"].values()))
        for item in alert["cloud_soc"]["provenance"]["evidence"]:
            self.assertIn(item["normalized"]["id"], client.documents[item["normalized"]["index"]])
            self.assertIn(item["raw"]["id"], client.documents[item["raw"]["index"]])

    def test_legacy_document_is_not_rewritten_to_claim_complete_evidence(self):
        client = MemoryElasticsearch([raw_hit(number) for number in range(10)])
        with patch.object(sys, "stdout", StringIO()):
            pipeline.run_pipeline_once(client)
        legacy_id = pipeline.make_stable_id("raw-logs-test", "0")
        del client.documents["normalized-events"][legacy_id]["cloud_soc"]["provenance"]
        legacy = deepcopy(client.documents["normalized-events"][legacy_id])
        with patch.object(sys, "stdout", StringIO()):
            pipeline.run_pipeline_once(client)
        self.assertEqual(client.documents["normalized-events"][legacy_id], legacy)
        self.assertIn("incomplete_legacy", [
            alert["cloud_soc"]["provenance"]["evidence_status"]
            for alert in client.documents["security-alerts"].values()
        ])

    def test_mapping_setup_does_not_process_documents(self):
        client = MemoryElasticsearch([raw_hit()])
        with patch.object(sys, "argv", ["cloud-soc", "--prepare-lineage-mappings"]), \
                patch.object(sys, "stdout", StringIO()), \
                patch.object(pipeline, "create_elasticsearch_client", return_value=client):
            self.assertEqual(pipeline.main(), 0)
        self.assertEqual(client.documents["normalized-events"], {})
        self.assertEqual(client.documents["security-alerts"], {})
        client.close.assert_called_once()

    def run_main(self, outcomes, arguments=(), create_error=None, sleep_error=None):
        client = Mock()
        with patch.object(sys, "argv", ["cloud-soc", *arguments]), \
                patch.object(sys, "stdout", StringIO()), \
                patch.object(pipeline, "create_elasticsearch_client", return_value=client, side_effect=create_error), \
                patch.object(pipeline, "run_pipeline_once", side_effect=outcomes) as run, \
                patch.object(pipeline.time, "sleep", side_effect=sleep_error) as sleep, \
                patch.object(pipeline.LOGGER, "error"), patch.object(pipeline.LOGGER, "warning"):
            code = pipeline.main()
        return code, client, run, sleep

    def test_success_and_degraded_exit_codes(self):
        for invalid, expected in ((0, 0), (1, 2)):
            code, client, _, _ = self.run_main([pipeline.PipelineStats(pipeline.ProcessingStats(invalid=invalid))])
            self.assertEqual(code, expected)
            client.close.assert_called_once()

    def test_fatal_watch_failure_is_nonzero_and_not_retried(self):
        code, client, run, sleep = self.run_main([RuntimeError("failed")], ["--watch"])
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()
        client.close.assert_called_once()

    def test_client_initialization_failure_is_nonzero(self):
        code, client, run, _ = self.run_main([], create_error=ValueError("bad config"))
        self.assertEqual(code, 1)
        client.close.assert_not_called()
        run.assert_not_called()

    def test_watch_transport_retries_are_bounded(self):
        code, client, run, sleep = self.run_main([ConnectionError("offline")] * 3, ["--watch", "--interval", "2"])
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2, 4])
        client.close.assert_called_once()

    def test_authorization_and_partial_search_errors_are_not_retried(self):
        for error in (api_error(401), api_error(403), IncompleteSearchError("partial")):
            code, _, run, sleep = self.run_main([error], ["--watch"])
            self.assertEqual(code, 1)
            self.assertEqual(run.call_count, 1)
            sleep.assert_not_called()

    def test_interrupt_closes_client(self):
        code, client, _, _ = self.run_main([KeyboardInterrupt()], ["--watch"])
        self.assertEqual(code, 130)
        client.close.assert_called_once()

    def test_degraded_watch_keeps_processing_subsequent_batches(self):
        outcomes = [pipeline.PipelineStats(pipeline.ProcessingStats(invalid=1)),
                    pipeline.PipelineStats(pipeline.ProcessingStats())]
        code, _, run, _ = self.run_main(outcomes, ["--watch"], sleep_error=[None, KeyboardInterrupt()])
        self.assertEqual(code, 130)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
