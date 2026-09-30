"""Bounded read-only audits must never claim exact loss or authorize replay."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.portal.loss_audit import AuditError, inspect_window, references


AGENT = "4d01630e-cc19-416f-b5ce-759b2948474b"
SINCE = "2026-09-28T04:45:00Z"
UNTIL = "2026-09-28T05:00:00Z"
REFERENCE = {"channel": "Synthetic", "record_id": 1, "provider": "Test", "event_code": "1", "occurred_at": SINCE}


class Reader:
    def __init__(self, counts=(42, 1, 0, 2)):
        self.counts = iter(counts)
        self.calls = []

    def search(self, **kwargs):
        self.calls.append(kwargs)
        return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
                "hits": {"total": {"relation": "eq", "value": next(self.counts)}}}


class LossAuditTests(unittest.TestCase):
    def test_receipts_are_not_loss_and_references_are_not_content_identity(self):
        client = Reader()
        refs = [{**REFERENCE, "record_id": n} for n in (1, 2, 3)]
        report = inspect_window(client, AGENT, SINCE, UNTIL, refs + refs)
        self.assertEqual(report["stored_documents_in_receipt_window"], 42)
        self.assertEqual(report["reference_count"], 3)
        self.assertEqual(report["reference_matches"], 2)
        self.assertEqual(report["reference_not_found"], 1)
        self.assertEqual(report["multiple_reference_matches"], 1)
        self.assertIsNone(report["historical_loss_count"])
        for flag in ("identity_verified", "complete_loss_count", "recovery_ready", "replay_performed"):
            self.assertFalse(report[flag])
        self.assertNotIn(AGENT, str(report))
        self.assertNotIn("Synthetic", str(report))
        for call in client.calls:
            self.assertEqual(call["index"], "soc-host-raw-windows-*")
            self.assertEqual(call["size"], 0)
            self.assertFalse(call["source"])
            self.assertFalse(call["allow_partial_search_results"])
            self.assertIn({"term": {"agent.id": AGENT}}, call["query"]["bool"]["filter"])
        self.assertIn("event.ingested", str(client.calls[0]))
        self.assertIn("@timestamp", str(client.calls[1]))
        self.assertNotIn("runtime_mappings", client.calls[0])
        runtime=client.calls[1]["runtime_mappings"]
        self.assertEqual(set(runtime), {"soc_loss_channel", "soc_loss_record_id", "soc_loss_provider", "soc_loss_event_code"})
        self.assertTrue(all(item["type"] == "keyword" for item in runtime.values()))
        self.assertTrue(all("params._source" in item["script"]["source"] for item in runtime.values()))
        self.assertNotIn("Synthetic", str(runtime))

    def test_invalid_inputs_never_query(self):
        for agent, start, end, refs in (
            ("not-a-uuid", SINCE, UNTIL, []), (AGENT.upper(), SINCE, UNTIL, []),
            (AGENT, "2026-09-28", UNTIL, []), (AGENT, UNTIL, SINCE, []),
            (AGENT, SINCE, "2026-11-28T05:00:00Z", []),
            (AGENT, SINCE, UNTIL, [REFERENCE] * 201),
            (AGENT, SINCE, UNTIL, [{**REFERENCE, "message": "SECRET"}]),
            (AGENT, SINCE, UNTIL, [{**REFERENCE, "record_id": True}]),
            (AGENT, SINCE, UNTIL, [{**REFERENCE, "occurred_at": "2026-02-30T00:00:00Z"}]),
            (AGENT, SINCE, UNTIL, [{**REFERENCE, "provider": "x\nSECRET"}]),
        ):
            client = Reader()
            with self.assertRaises(AuditError):
                inspect_window(client, agent, start, end, refs)
            self.assertEqual(client.calls, [])

    def test_partial_or_inexact_results_fail_closed(self):
        valid = Reader().search()
        for patch in ({"timed_out": True}, {"_shards": {"total": 2, "successful": 1, "failed": 1}},
                      {"hits": {"total": {"relation": "gte", "value": 10000}}},
                      {"hits": {"total": {"relation": "eq", "value": True}}},
                      {"hits": {"total": {"relation": "eq", "value": -1}}}, {"_shards": {}}):
            class Partial:
                def search(self, **kwargs):
                    return {**copy.deepcopy(valid), **patch}
            with self.assertRaises(AuditError):
                inspect_window(Partial(), AGENT, SINCE, UNTIL)

    def test_empty_indices_and_zero_receipts_never_prove_no_loss(self):
        class Empty:
            def search(self, **kwargs):
                return {"timed_out": False, "_shards": {"total": 0, "successful": 0, "failed": 0},
                        "hits": {"total": {"relation": "eq", "value": 0}}}
        report = inspect_window(Empty(), AGENT, SINCE, UNTIL)
        self.assertFalse(report["indices_present"])
        self.assertFalse(report["complete_loss_count"])
        self.assertIsNone(report["historical_loss_count"])

    def test_reference_whitelist_and_deduplication(self):
        self.assertEqual(references([REFERENCE, REFERENCE]), [REFERENCE])
        for value in (None, {}, [{**REFERENCE, "event_code": "abc"}], [{**REFERENCE, "channel": "x" * 257}],
                      [{**REFERENCE, "record_id": 2**63}], [{**REFERENCE, "record_id": 0}]):
            with self.assertRaises(AuditError):
                references(value)

    def test_global_time_limit_never_returns_partial_success(self):
        client = Reader()
        with patch("cloud_soc.portal.loss_audit.time.monotonic", side_effect=[0, 61]):
            with self.assertRaises(AuditError):
                inspect_window(client, AGENT, SINCE, UNTIL)
        self.assertEqual(client.calls, [])
