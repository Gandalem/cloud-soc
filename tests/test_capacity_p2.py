import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from cloud_soc.capacity import collect, compare
from cloud_soc.snapshot_checks import inspect_snapshot, verify_fixture_restore

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
INDEX = "soc-host-raw-test"
COMPLETE = {"total": 1, "successful": 1, "failed": 0}


def client():
    es = Mock()
    es.options.return_value = es
    es.info.return_value = {"cluster_uuid": "cluster-one", "cluster_name": "NOT_EXPORTED"}
    es.indices.stats.return_value = {
        "_shards": dict(COMPLETE), "indices": {INDEX: {
            "uuid": "uuid-one", "primaries": {"store": {"size_in_bytes": 100}, "indexing": {"index_total": 10}},
            "total": {"store": {"size_in_bytes": 200}}}}}
    es.search.return_value = {
        "_shards": dict(COMPLETE), "timed_out": False,
        "hits": {"total": {"value": 10, "relation": "eq"}},
        "aggregations": {"received": {"doc_count": 3}, "missing_receipt": {"doc_count": 1}}}
    es.nodes.stats.return_value = {"_nodes": dict(COMPLETE), "nodes": {
        "node-one": {"name": "NOT_EXPORTED", "fs": {"total": {"total_in_bytes": 1000, "available_in_bytes": 100}}}}}
    es.snapshot.get.return_value = {"snapshots": [{
        "snapshot": "backup-one", "state": "SUCCESS", "end_time": "2026-10-06T23:00:00Z",
        "indices": [INDEX], "shards": dict(COMPLETE), "failures": []}]}
    return es


class CapacityTests(unittest.TestCase):
    def test_report_is_read_only_receipt_count_not_lucene_or_wire(self):
        es = client()
        report = collect(es, now=NOW)
        self.assertEqual(report["summary"]["received_documents"], 3)
        self.assertEqual(report["summary"]["documents"], 10)
        self.assertEqual(report["disks"][0]["advisory"], "critical")
        self.assertFalse(report["approved"])
        self.assertFalse(report["automatic_deletion"])
        self.assertNotIn("NOT_EXPORTED", json.dumps(report))
        args = es.search.call_args.kwargs
        self.assertIs(args["source"], False)
        self.assertEqual(args["size"], 0)
        self.assertTrue(args["track_total_hits"])
        self.assertFalse(args["allow_partial_search_results"])
        self.assertEqual(args["aggs"]["received"]["filter"]["range"]["event.ingested"], {
            "gte": "2026-10-06T00:00:00Z", "lt": "2026-10-07T00:00:00Z"})
        self.assertEqual([call[0] for call in es.mock_calls], [
            "options", "info", "indices.stats", "search", "nodes.stats"])

    def test_invalid_windows_thresholds_and_timezone_before_network(self):
        for params in ({"hours": True}, {"hours": 0}, {"hours": 169}, {"warning": 90, "critical": 85},
                       {"critical": 100}, {"warning": True}, {"now": NOW.replace(tzinfo=None)}):
            es = client()
            with self.subTest(params=params), self.assertRaises(ValueError):
                collect(es, **params)
            es.options.assert_not_called()

    def test_partial_or_missing_shard_and_node_status_fails(self):
        for service in ("indices", "nodes", "search"):
            for status in (None, {"total": 2, "successful": 1, "failed": 0}, {"total": 1, "successful": 0, "failed": 1}):
                es = client()
                response = (es.indices.stats if service == "indices" else es.nodes.stats if service == "nodes" else es.search).return_value
                response["_nodes" if service == "nodes" else "_shards"] = status
                with self.subTest(service=service, status=status), self.assertRaises(ValueError):
                    collect(es, now=NOW)

    def test_timeout_approximate_negative_and_boolean_counts_fail(self):
        mutations = (lambda r: r.update(timed_out=True),
                     lambda r: r["hits"]["total"].update(relation="gte"),
                     lambda r: r["hits"]["total"].update(value=-1),
                     lambda r: r["aggregations"]["received"].update(doc_count=True),
                     lambda r: r["aggregations"]["received"].update(doc_count=10))
        for mutate in mutations:
            es = client()
            mutate(es.search.return_value)
            with self.assertRaises(ValueError):
                collect(es, now=NOW)

    def test_scope_limit_and_time_budget(self):
        es = client()
        es.indices.stats.return_value["indices"]["security-alerts"] = {}
        with self.assertRaises(ValueError):
            collect(es, now=NOW)
        es = client()
        with patch("cloud_soc.capacity.MAX_INDICES", 0), self.assertRaises(ValueError):
            collect(es, now=NOW)
        es.search.assert_not_called()
        es = client()
        with patch("cloud_soc.capacity.time.monotonic", side_effect=[0, 61]), self.assertRaises(ValueError):
            collect(es, now=NOW)
        es.indices.stats.assert_not_called()

    def test_missing_uuid_and_invalid_disk_or_store(self):
        for kind in ("uuid", "disk", "store", "cluster"):
            es = client()
            if kind == "uuid":
                es.indices.stats.return_value["indices"][INDEX]["uuid"] = None
            elif kind == "disk":
                es.nodes.stats.return_value["nodes"]["node-one"]["fs"]["total"]["available_in_bytes"] = 1001
            elif kind == "cluster":
                es.info.return_value["cluster_uuid"] = "_na_"
            else:
                es.indices.stats.return_value["indices"][INDEX]["total"]["store"]["size_in_bytes"] = 99
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                collect(es, now=NOW)

    def samples(self):
        first = collect(client(), now=NOW - timedelta(days=1))
        second = collect(client(), now=NOW)
        second["indices"][0].update(primary_bytes=200, total_bytes=400, index_operations=20)
        return first, second

    def test_growth_and_long_retention_are_unapproved_net_estimate(self):
        first, second = self.samples()
        report = compare(first, second, proposed_days=1825)
        self.assertEqual(report["net_primary_bytes_per_day"], 100)
        self.assertEqual(report["proposed_net_primary_bytes"], 182500)
        self.assertFalse(report["approved"])
        self.assertIn("snapshots", report["excludes"])

    def test_changed_cluster_deleted_recreated_reset_and_short_sample_unknown(self):
        for kind, reason in (("cluster", "cluster_changed"), ("delete", "indices_removed_or_recreated"),
                             ("uuid", "indices_removed_or_recreated"), ("reset", "index_counter_reset"),
                             ("shrink", "index_shrink_or_document_removal"), ("short", "sample_under_one_hour")):
            first, second = self.samples()
            if kind == "cluster":
                second["cluster_uuid"] = "two"
            elif kind == "delete":
                second["indices"] = []
            elif kind == "uuid":
                second["indices"][0]["uuid"] = "two"
            elif kind == "reset":
                second["indices"][0]["index_operations"] = 0
            elif kind == "shrink":
                second["indices"][0]["primary_bytes"] = 90
                second["indices"].append(dict(second["indices"][0], index="soc-network-new", primary_bytes=900, total_bytes=1000))
            else:
                second["measured_at"] = first["measured_at"].replace("00:00:00", "00:01:00")
            self.assertEqual(compare(first, second)["reason"], reason)

    def test_untrusted_report_duplicate_type_and_dates_fail(self):
        for kind in ("schema", "duplicate", "boolean", "date", "approved", "retention"):
            first, second = self.samples()
            if kind == "schema":
                first["schema"] = 1
            elif kind == "duplicate":
                first["indices"].append(copy.deepcopy(first["indices"][0]))
            elif kind == "boolean":
                first["indices"][0]["primary_bytes"] = True
            elif kind == "date":
                second["measured_at"] = first["measured_at"]
            elif kind == "approved":
                first["approved"] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                compare(first, second, proposed_days=True if kind == "retention" else 30)


class SnapshotTests(unittest.TestCase):
    def inspect(self, es):
        return inspect_snapshot(es, repository="repo-one", snapshot="backup-one", expected_indices=[INDEX], now=NOW)

    def test_metadata_is_not_restore_or_integrity_proof(self):
        es = client()
        result = self.inspect(es)
        self.assertEqual(result["status"], "metadata_ok")
        self.assertFalse(result["restore_verified"])
        self.assertFalse(result["repository_integrity_verified"])
        self.assertEqual([call[0] for call in es.mock_calls], ["options", "snapshot.get"])

    def test_partial_stale_future_missing_scope_and_failures_report_attention(self):
        for kind in ("partial", "stale", "future", "scope", "failure", "end", "shards"):
            es = client()
            row = es.snapshot.get.return_value["snapshots"][0]
            if kind == "partial":
                row["state"] = "PARTIAL"
            elif kind == "stale":
                row["end_time"] = "2026-01-01T00:00:00Z"
            elif kind == "future":
                row["end_time"] = "2026-10-08T00:00:00Z"
            elif kind == "scope":
                row["indices"] = []
            elif kind == "failure":
                row["failures"] = [{"reason": "SECRET_MUST_NOT_EXPORT"}]
            elif kind == "end":
                row.pop("end_time")
            else:
                row["shards"] = {"total": 2, "successful": 1, "failed": 1}
            result = self.inspect(es)
            self.assertEqual(result["status"], "attention")
            self.assertNotIn("SECRET_MUST_NOT_EXPORT", json.dumps(result))

    def test_wildcard_and_unapproved_index_rejected_before_network(self):
        for repository, snapshot, indices in (("*", "backup-one", [INDEX]), ("repo-one", "_all", [INDEX]),
                                               ("repo-one", "backup-one", ["security-alerts"]),
                                               ("repo-one", "backup-one", [INDEX, INDEX])):
            es = client()
            with self.assertRaises(ValueError):
                inspect_snapshot(es, repository=repository, snapshot=snapshot, expected_indices=indices, now=NOW)
            es.options.assert_not_called()

    def test_ambiguous_snapshot_fails(self):
        for rows in ([], [{"snapshot": "wrong"}], [dict(), dict()]):
            es = client()
            es.snapshot.get.return_value["snapshots"] = rows
            with self.assertRaises(ValueError):
                self.inspect(es)

    def test_restore_only_accepts_one_exact_synthetic_document(self):
        es = client()
        index, identifier = "soc-host-raw-p2-restore-" + "a" * 12, "p2-fixture-" + "b" * 32
        es.count.return_value = {"count": 1, "_shards": dict(COMPLETE)}
        es.get.return_value = {"_index": index, "_id": identifier, "found": True, "_source": {"p2_fixture": identifier}}
        self.assertEqual(verify_fixture_restore(es, restored_index=index, fixture_id=identifier)["status"], "synthetic_restore_verified")
        es.get.return_value["_source"]["secret"] = "NOT_EXPORTED"
        with self.assertRaises(ValueError):
            verify_fixture_restore(es, restored_index=index, fixture_id=identifier)
        es.count.return_value["count"] = 2
        with self.assertRaises(ValueError):
            verify_fixture_restore(es, restored_index=index, fixture_id=identifier)
        for invalid in ("soc-host-raw-production", "soc-host-raw-p2-restore-*"):
            with self.assertRaises(ValueError):
                verify_fixture_restore(es, restored_index=invalid, fixture_id=identifier)
        es.snapshot.restore.assert_not_called()


class CommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("capacity_report_cli", ROOT / "deploy/server/capacity-report.py")
        cls.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cli)

    def test_offline_compare_does_not_connect(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = CapacityTests().samples()
            paths = [Path(folder) / "a.json", Path(folder) / "b.json"]
            for path, report in zip(paths, [first, second]):
                path.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(self.cli, "connect") as connect, patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(self.cli.main(["compare", "--previous", str(paths[0]), "--current", str(paths[1])]), 0)
                self.assertEqual(json.loads(output.getvalue())["status"], "estimate")
                connect.assert_not_called()

    def test_unsafe_urls_rejected_before_key_file_open(self):
        args = Mock(ca_file=Path("not-a-ca"), api_key_file=Path("not-a-key"))
        for url in ("http://localhost:9200", "https://user:secret@server", "https://server/path", "https://server?secret=x"):
            args.endpoint = url
            with self.assertRaises(ValueError):
                self.cli.connect(args)

    def test_oversized_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "huge.json"
            path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                self.cli.read_json(path)

    def test_unavailable_estimate_has_nonzero_exit_without_network(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = CapacityTests().samples()
            second["cluster_uuid"] = "another-cluster"
            paths = [Path(folder) / "a.json", Path(folder) / "b.json"]
            for path, report in zip(paths, [first, second]):
                path.write_text(json.dumps(report), encoding="utf-8")
            with patch.object(self.cli, "connect") as connect, patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(self.cli.main(["compare", "--previous", str(paths[0]), "--current", str(paths[1])]), 2)
                connect.assert_not_called()

    def test_key_file_type_size_and_line_injection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "reader.key"
            with self.assertRaises(ValueError):
                self.cli.read_private_key(Path(folder))
            for content in (b"", b"x" * 4097, b"encoded\nINJECT", b"\xff"):
                path.write_bytes(content)
                path.chmod(0o600)
                with self.assertRaises(ValueError):
                    self.cli.read_private_key(path)
            path.write_bytes(b"U1lOVEhFVElD\n")
            path.chmod(0o600)
            self.assertEqual(self.cli.read_private_key(path), "U1lOVEhFVElD")

    def test_cli_failure_does_not_export_secret_or_traceback(self):
        result = subprocess.run([sys.executable, str(ROOT / "deploy/server/capacity-report.py"), "measure",
                                 "--endpoint", "https://user:SECRET_SENTINEL@server",
                                 "--ca-file", "absent", "--api-key-file", "absent"],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("SECRET_SENTINEL", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_role_has_no_write_or_key_management(self):
        role = json.loads((ROOT / "deploy/server/capacity-reader-role.json").read_text())
        self.assertEqual(set(role["cluster"]), {"monitor", "monitor_snapshot"})
        self.assertEqual(set(role["indices"][0]["privileges"]), {"read", "monitor"})
        self.assertFalse(role["indices"][0]["allow_restricted_indices"])


if __name__ == "__main__":
    unittest.main()
