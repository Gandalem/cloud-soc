import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from cloud_soc.backup_readiness import (
    backup_health, balanced_capacity, CRON_UTC, expected_collection_indices, next_measurement,
    plan, POLICY_ID, PROFILE, repository_candidate, slm_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 7, 3, tzinfo=timezone.utc)
REPOSITORY = "cloud-soc-p2-backup"
INDICES = ["soc-host-raw-test", "soc-network-test", "soc-agent-health-test"]


def samples():
    old = {"schema": 2, "cluster_uuid": "cluster-one", "measured_at": "2026-10-06T03:00:00Z",
           "approved": False, "automatic_deletion": False, "indices": []}
    for i, name in enumerate(INDICES):
        old["indices"].append({"index": name, "uuid": "uuid-" + str(i), "documents": 10,
                               "received_documents": 3, "missing_receipt_documents": 0,
                               "primary_bytes": 100, "total_bytes": 200, "index_operations": 10})
    new = copy.deepcopy(old)
    new["measured_at"] = "2026-10-07T03:00:00Z"
    for row in new["indices"]:
        row.update(primary_bytes=200, total_bytes=400, index_operations=20, documents=20)
    return old, new


def snapshot(*, name="cloud-soc-p2-test", state="SUCCESS", start=None, end=None):
    return {"snapshot": name, "repository": REPOSITORY,
            "metadata": {"policy": POLICY_ID, "cloud_soc_profile": PROFILE},
            "start_time": (start or NOW - timedelta(hours=2)).isoformat(),
            "end_time": (end or NOW - timedelta(hours=1)).isoformat(), "state": state,
            "indices": list(INDICES), "shards": {"total": 3, "successful": 3, "failed": 0},
            "failures": []}


def client(*rows):
    es = Mock()
    es.options.return_value = es
    es.snapshot.get.return_value = {"snapshots": list(rows)}
    return es


def load_cli():
    spec = importlib.util.spec_from_file_location("p2_backup_cli", ROOT / "deploy/server/backup-readiness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PlanTests(unittest.TestCase):
    def test_unconfigured_plan_is_blocked_without_activation_or_all_index_scope(self):
        report = plan()
        self.assertEqual(report["backup_retention_days"], 14)
        self.assertFalse(report["activation_ready"])
        self.assertFalse(report["writes_performed"])
        self.assertFalse(report["automatic_log_deletion"])
        self.assertIsNone(report["repository_candidate"])
        self.assertIn("backup_destination_not_configured", report["blockers"])
        self.assertEqual(report["log_retention_days"], {"host": 30, "network": 14, "health": 14, "alerts_cases": 90})
        config = report["slm_candidate"]["config"]
        self.assertEqual(config["indices"], [prefix + "*" for prefix in ("soc-host-raw-", "soc-network-", "soc-agent-health-")])
        self.assertFalse(config["partial"])
        self.assertFalse(config["ignore_unavailable"])
        self.assertFalse(config["include_global_state"])
        self.assertEqual(config["feature_states"], ["none"])
        self.assertIn("minimum_snapshot_floor_may_exceed_14_days", report["limitations"])

    def test_utc_schedule_matches_next_day_kst_3am(self):
        self.assertEqual(CRON_UTC, "0 0 18 * * ?")
        kst = datetime(2026, 10, 7, 18, tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=9)))
        self.assertEqual((kst.day, kst.hour, kst.minute), (8, 3, 0))

    def test_shared_filesystem_and_s3_candidates_have_no_credentials(self):
        fs = plan({"type": "fs", "location": "/mnt/independent-backups/cloud-soc"})
        self.assertEqual(fs["repository_candidate"]["type"], "fs")
        self.assertFalse(fs["activation_ready"])
        s3 = plan({"type": "s3", "bucket": "example-cloud-soc-backups", "base_path": "cloud-soc/p2"})
        self.assertTrue(s3["repository_candidate"]["settings"]["server_side_encryption"])
        self.assertNotIn("endpoint", s3["repository_candidate"]["settings"])
        self.assertNotIn("max_count", s3["slm_candidate"]["retention"])

    def test_settings_reject_secrets_unknown_fields_and_unsafe_locations(self):
        for value in (None, [], {}, {"type": "azure"}, {"type": "unconfigured", "secret": "PRIVATE_CANARY"},
                      {"type": "fs", "location": "/mnt/../secrets"}, {"type": "fs", "location": "/"},
                      {"type": "fs", "location": "relative"}, {"type": "fs", "location": "/mnt/a;touch-b"},
                      {"type": "fs", "location": "/mnt//backup"},
                      {"type": "s3", "bucket": "backup-bucket", "base_path": "soc", "access_key": "PRIVATE_CANARY"},
                      {"type": "s3", "bucket": "backup-bucket", "base_path": "soc", "endpoint": "http://evil.test"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                repository_candidate(value)

    def test_bucket_and_prefix_validation(self):
        for bucket in ("ab", "192.168.1.1", "a..b", "a.-b", "xn--bucket", "name--x-s3", "a" * 64, "CAPITAL"):
            with self.subTest(bucket=bucket), self.assertRaises(ValueError):
                plan({"type": "s3", "bucket": bucket, "base_path": "soc/p2"})
        for base in ("/soc", "soc/../secret", "soc//p2", "soc/", "", "soc?secret", "soc\np2"):
            with self.subTest(base=base), self.assertRaises(ValueError):
                plan({"type": "s3", "bucket": "backup-bucket", "base_path": base})

    def test_repository_exact_and_mutation_does_not_change_future_plans(self):
        for name in ("*", "_all", "a,b", "../bad", "bad\n", True):
            with self.assertRaises(ValueError):
                plan(repository=name)
        report = plan()
        report["slm_candidate"]["config"]["indices"].append("*")
        self.assertEqual(len(plan()["slm_candidate"]["config"]["indices"]), 3)


class BalancedCapacityTests(unittest.TestCase):
    def test_source_specific_estimates_exclude_cloud_and_unmeasured_case_capacity(self):
        old, new = samples()
        for report in (old, new):
            report["indices"].append(dict(report["indices"][0], index="soc-cloud-oci-test"))
        result = balanced_capacity(old, new)
        self.assertEqual(result["status"], "estimate")
        self.assertEqual([row["retention_days"] for row in result["sources"]], [30, 14, 14])
        self.assertEqual(result["projected_net_primary_bytes"], 5800)
        self.assertEqual(result["excluded_index_count"], 1)
        self.assertNotIn("soc-cloud-oci-test", json.dumps(result))
        self.assertFalse(result["automatic_log_deletion"])

    def test_under_24_hours_is_not_accepted_as_representative(self):
        old, new = samples()
        new["measured_at"] = "2026-10-06T05:00:00Z"
        result = balanced_capacity(old, new)
        self.assertEqual(result["status"], "incomplete")
        self.assertIsNone(result["projected_net_primary_bytes"])
        self.assertEqual(result["sources"][0]["estimate"]["reason"], "sample_under_24_hours")

    def test_missing_source_and_hidden_shrink_prevent_total_estimate(self):
        old, new = samples()
        new["indices"][0].update(primary_bytes=50)
        new["indices"][1].update(primary_bytes=10000, total_bytes=20000)
        result = balanced_capacity(old, new)
        self.assertEqual(result["sources"][0]["estimate"]["reason"], "index_shrink_or_document_removal")
        self.assertIsNone(result["projected_net_primary_bytes"])
        old, new = samples()
        new["indices"].pop()
        result = balanced_capacity(old, new)
        self.assertEqual(result["sources"][2]["estimate"]["reason"], "source_not_observed_in_both_samples")

    def test_cluster_replacement_and_invalid_order_are_not_estimates(self):
        old, new = samples()
        new["cluster_uuid"] = "cluster-two"
        self.assertTrue(all(row["estimate"]["reason"] == "cluster_changed" for row in balanced_capacity(old, new)["sources"]))
        with self.assertRaises(ValueError):
            balanced_capacity(new, old)
        old["indices"], new["indices"] = [], []
        with self.assertRaises(ValueError):
            balanced_capacity(new, old)

    def test_inventory_is_exact_scoped_and_next_sample_crosses_kst_day(self):
        _, new = samples()
        new["indices"].append(dict(new["indices"][0], index="soc-cloud-aws-test"))
        self.assertEqual(set(expected_collection_indices(new)), set(INDICES))
        result = next_measurement(new)
        self.assertEqual(result["not_before_utc"], "2026-10-08T03:00:00Z")
        self.assertEqual(result["not_before_kst"], "2026-10-08T12:00:00+09:00")
        new["indices"] = []
        with self.assertRaises(ValueError):
            expected_collection_indices(new)


class HealthTests(unittest.TestCase):
    def health(self, es):
        return backup_health(es, repository=REPOSITORY, expected_indices=INDICES, now=NOW)

    def test_recent_success_is_metadata_only_bounded_read_only(self):
        es = client(snapshot())
        result = self.health(es)
        self.assertEqual(result["status"], "metadata_ok")
        self.assertEqual(result["age_hours"], 2)
        self.assertFalse(result["restore_verified"])
        self.assertFalse(result["notification_sent"])
        self.assertFalse(result["alert_required"])
        self.assertEqual([call[0] for call in es.mock_calls], ["options", "snapshot.get"])
        args = es.snapshot.get.call_args.kwargs
        self.assertEqual(args["slm_policy_filter"], POLICY_ID)
        self.assertEqual(args["size"], 10)
        self.assertEqual(args["repository"], REPOSITORY)
        self.assertTrue(args["verbose"])
        self.assertIn("snapshots.metadata.policy", args["filter_path"])
        self.assertNotIn("snapshots.metadata", args["filter_path"])
        self.assertNotIn("snapshots.reason", args["filter_path"])
        self.assertNotIn("indices", result)

    def test_latest_failure_alerts_without_leaking_upstream_reason(self):
        failure = snapshot(name="cloud-soc-p2-failed", state="FAILED", start=NOW - timedelta(minutes=20), end=NOW - timedelta(minutes=10))
        failure["reason"] = "PRIVATE_CANARY"
        result = self.health(client(failure, snapshot()))
        self.assertIn("latest_completed_attempt_failed", result["reasons"])
        self.assertTrue(result["alert_required"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))

    def test_old_failure_before_success_is_not_a_current_failure(self):
        failed = snapshot(name="cloud-soc-p2-old-failed", state="FAILED", start=NOW - timedelta(hours=4), end=NOW - timedelta(hours=3))
        self.assertEqual(self.health(client(snapshot(), failed))["status"], "metadata_ok")

    def test_stale_recovery_point_is_based_on_start_not_completion(self):
        row = snapshot(start=NOW - timedelta(hours=25), end=NOW - timedelta(hours=1))
        result = self.health(client(row))
        self.assertIn("recovery_point_older_than_24_hours", result["reasons"])

    def test_no_success_partial_and_unknown_repository_are_not_healthy(self):
        for rows in ([], [snapshot(state="PARTIAL")], [snapshot(state="FAILED")]):
            result = self.health(client(*rows))
            self.assertEqual(result["status"], "attention")
            self.assertIn("no_verified_success_in_recent_snapshots", result["reasons"])
        es = client()
        es.snapshot.get.side_effect = RuntimeError("PRIVATE_CANARY")
        result = self.health(es)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["alert_required"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))

    def test_identity_corruption_future_partial_shards_and_limits_fail_closed(self):
        mutations = (
            lambda r: r.update(repository="different"),
            lambda r: r.update(snapshot="arbitrary-backup"),
            lambda r: r["metadata"].update(policy="different"),
            lambda r: r["metadata"].update(cloud_soc_profile="different"),
            lambda r: r.update(start_time=(NOW + timedelta(days=1)).isoformat()),
            lambda r: r.update(end_time=(NOW - timedelta(hours=3)).isoformat()),
            lambda r: r["shards"].update(successful=2),
            lambda r: r["shards"].update(failed=True),
            lambda r: r.update(failures=[{"reason": "PRIVATE_CANARY"}]),
            lambda r: r.update(indices=[INDICES[0], INDICES[0]]),
        )
        for mutate in mutations:
            row = snapshot()
            mutate(row)
            result = self.health(client(row))
            self.assertEqual(result["status"], "unknown")
            self.assertNotIn("PRIVATE_CANARY", json.dumps(result))
        self.assertEqual(self.health(client(*[snapshot()] * 11))["status"], "unknown")
        self.assertEqual(self.health(client(snapshot(), snapshot()))["status"], "unknown")

    def test_missing_inventory_and_unexpected_scope_require_attention(self):
        row = snapshot()
        row["indices"].pop()
        self.assertIn("missing_expected_indices", self.health(client(row))["reasons"])
        row = snapshot()
        row["indices"].append("soc-cloud-oci-test")
        self.assertIn("unexpected_snapshot_scope", self.health(client(row))["reasons"])

    def test_running_backup_does_not_replace_previous_success_and_can_stall(self):
        row = snapshot(name="cloud-soc-p2-active", state="IN_PROGRESS", start=NOW - timedelta(hours=5))
        row.pop("end_time")
        result = self.health(client(row, snapshot()))
        self.assertEqual(result["active_snapshots"], 1)
        self.assertIn("snapshot_running_over_4_hours", result["reasons"])
        row["start_time"] = (NOW - timedelta(minutes=10)).isoformat()
        self.assertEqual(self.health(client(row, snapshot()))["status"], "metadata_ok")
        self.assertEqual(self.health(client(row))["status"], "attention")

    def test_bad_input_rejected_before_any_network_call(self):
        for names in ([], ["*"], ["soc-cloud-oci-test"], [True], INDICES + [INDICES[0]]):
            es = client()
            with self.assertRaises(ValueError):
                backup_health(es, repository=REPOSITORY, expected_indices=names, now=NOW)
            es.options.assert_not_called()
        es = client()
        with self.assertRaises(ValueError):
            backup_health(es, repository="*", expected_indices=INDICES, now=NOW)
        es.options.assert_not_called()

    def test_real_sdk_serializes_bounded_get_without_network(self):
        from elasticsearch import Elasticsearch
        from elastic_transport import ApiResponseMeta, HttpHeaders, NodeConfig

        meta = ApiResponseMeta(status=200, http_version="1.1", duration=0,
                               headers=HttpHeaders({"x-elastic-product": "Elasticsearch"}),
                               node=NodeConfig("http", "127.0.0.1", 1))
        with Elasticsearch("http://127.0.0.1:1", max_retries=0) as es:
            with patch.object(es.transport, "perform_request", return_value=(meta, {"snapshots": [snapshot()]})) as request:
                result = self.health(es)
            self.assertEqual(result["status"], "metadata_ok")
            args = request.call_args.args
            self.assertEqual(args[0], "GET")
            self.assertTrue(args[1].startswith("/_snapshot/cloud-soc-p2-backup/cloud-soc-p2-*?"))
            self.assertIn("size=10", args[1])
            self.assertIn("slm_policy_filter=cloud-soc-p2-daily", args[1])
            self.assertEqual(request.call_count, 1)


class CommandTests(unittest.TestCase):
    def test_offline_commands_do_not_connect(self):
        cli = load_cli()
        with patch.object(cli.io, "connect", side_effect=AssertionError("No network")), io.StringIO() as output, patch("sys.stdout", output):
            self.assertEqual(cli.main(["plan"]), 0)
            self.assertFalse(json.loads(output.getvalue())["activation_ready"])
        old, new = samples()
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "first.json", Path(folder) / "second.json"
            first.write_text(json.dumps(old))
            second.write_text(json.dumps(new))
            with patch.object(cli.io, "connect", side_effect=AssertionError("No network")), io.StringIO() as output, patch("sys.stdout", output):
                self.assertEqual(cli.main(["capacity", "--previous", str(first), "--current", str(second)]), 0)
                self.assertEqual(json.loads(output.getvalue())["projected_net_primary_bytes"], 5800)
            with io.StringIO() as output, patch("sys.stdout", output):
                self.assertEqual(cli.main(["next-sample", "--report", str(first)]), 0)

    def test_health_input_before_credentials_and_attention_exit_code(self):
        cli = load_cli()
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / "report.json"
            report.write_text(json.dumps(samples()[1]))
            args = ["health", "--inventory", str(report), "--endpoint", "https://soc.example.test:9200",
                    "--ca-file", "unused-ca", "--api-key-file", "unused-key", "--repository", "*"]
            with patch.object(cli.io, "connect") as connect, self.assertRaises(ValueError):
                cli.main(args)
            connect.assert_not_called()
            args[-1] = REPOSITORY
            connection = Mock()
            connection.__enter__ = Mock(return_value=client())
            connection.__exit__ = Mock(return_value=False)
            with patch.object(cli.io, "connect", return_value=connection), io.StringIO() as output, patch("sys.stdout", output):
                self.assertEqual(cli.main(args), 2)
                self.assertTrue(json.loads(output.getvalue())["alert_required"])

    def test_cli_failure_does_not_export_secret_or_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "invalid.json"
            config.write_text(json.dumps({"type": "unconfigured", "secret": "PRIVATE_CANARY"}))
            result = subprocess.run([sys.executable, str(ROOT / "deploy/server/backup-readiness.py"),
                                     "plan", "--storage-config", str(config)], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b"PRIVATE_CANARY", result.stdout + result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_reader_role_has_only_snapshot_monitoring_and_no_raw_read(self):
        role = json.loads((ROOT / "deploy/server/backup-health-reader-role.json").read_text())
        self.assertEqual(role, {"cluster": ["monitor_snapshot"], "indices": []})
        self.assertEqual(json.loads((ROOT / "deploy/server/backup-storage.example.json").read_text()), {"type": "unconfigured"})


if __name__ == "__main__":
    unittest.main()
