"""Exact read-only dashboard aggregation across bounded concrete-index requests."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.portal.operations import Operations, exact_indices, index_batches, INDEX_PATH_BUDGET

START = "2026-09-30T00:00:00Z"
END = "2026-09-30T00:10:00Z"
LATER = "2026-09-30T00:05:00Z"
PATTERN = ["soc-host-raw-*"]


def response(count=1, *, stamp=START, statuses=None):
    aggs = {"trend": {"buckets": [{"key_as_string": stamp, "doc_count": count}]}}
    if statuses is not None:
        aggs["status"] = {"buckets": [{"key": key, "doc_count": value} for key, value in statuses.items()],
                          "sum_other_doc_count": 0, "doc_count_error_upper_bound": 0}
    return {"timed_out": False, "_shards": {"failed": 0},
            "hits": {"total": {"relation": "eq", "value": count}, "hits": []}, "aggregations": aggs}


def client_for(names):
    client = Mock()
    client.options.return_value = client
    client.indices.resolve_index.return_value = {"indices": [{"name": name} for name in names]}
    client.field_caps.return_value = {"fields": {"event.ingested": {"date": {}, "date_nanos": {}},
                                               "@timestamp": {"date": {}}}}
    client.search.return_value = response()
    return client


class OperationsBatchTests(unittest.TestCase):
    def test_encoded_paths_bounded_and_exact_names_retained(self):
        names = ["soc-host-raw-" + "\ud55c" * 20 + str(i) for i in range(233)]
        batches = index_batches(names)
        self.assertGreater(len(batches), 1)
        self.assertEqual([name for batch in batches for name in batch], names)
        for batch in batches:
            self.assertLessEqual(len(quote(",".join(batch), safe="")), INDEX_PATH_BUDGET)

    def test_233_indices_merge_counts_chronological_buckets_and_requests(self):
        names = ["soc-host-raw-" + "x" * 70 + str(i) for i in range(233)]
        client = client_for(names)
        def search(**kwargs):
            return response(len(kwargs["index"]), stamp=LATER if names[0] in kwargs["index"] else START)
        client.search.side_effect = search
        result = Operations(client).series(PATTERN, "event.ingested", START, END, "5m")
        self.assertEqual((result["state"], result["count"]), ("ok", 233))
        self.assertEqual(sum(row["count"] for row in result["buckets"]), 233)
        self.assertEqual([row["time"] for row in result["buckets"]],
                         [START, LATER])
        self.assertGreater(client.search.call_count, 1)
        caps_names = [call.kwargs["index"] for call in client.field_caps.call_args_list]
        search_names = [call.kwargs["index"] for call in client.search.call_args_list]
        self.assertEqual(caps_names, search_names)
        self.assertEqual([name for batch in search_names for name in batch], names)
        for call in client.search.call_args_list:
            self.assertFalse(call.kwargs["allow_partial_search_results"])
            self.assertFalse(call.kwargs["source"])
            self.assertEqual(call.kwargs["query"], {"range": {"event.ingested": {"gte": START, "lt": END}}})

    def test_duplicate_resolution_not_double_counted_and_aliases_rejected(self):
        client = client_for(["soc-host-raw-one"] * 2)
        self.assertEqual(exact_indices(client, PATTERN), ["soc-host-raw-one"])
        for change in ({"aliases": [{"name": "soc-host-raw-alias"}]}, {"data_streams": [{}]},
                       {"indices": [{"name": ".security"}]}):
            client.indices.resolve_index.return_value = change
            with self.assertRaises(ValueError):
                Operations(client).series(PATTERN, "event.ingested", START, END, "5m")
        client.search.assert_not_called()

    def test_missing_index_and_successful_zero_distinct(self):
        client = client_for([])
        self.assertEqual(Operations(client).series(PATTERN, "event.ingested", START, END, "5m")["state"], "no_index")
        client.search.assert_not_called()
        client = client_for(["soc-host-raw-one"])
        client.search.return_value = response(0)
        result = Operations(client).series(PATTERN, "event.ingested", START, END, "5m")
        self.assertEqual((result["state"], result["count"]), ("ok", 0))

    def test_failure_in_later_batch_never_returns_partial_or_zero(self):
        names = ["soc-host-raw-" + str(i) for i in range(3)]
        for failed in ({"timed_out": True}, {"_shards": {"failed": 1}}, RuntimeError("PRIVATE_CANARY"),
                       response(-1), response(True)):
            client = client_for(names)
            client.search.side_effect = [response(8), failed]
            with patch("cloud_soc.portal.operations.INDEX_PATH_BUDGET", 20):
                summary = json.loads(Operations(client).summary([("start", START), ("end", END)]))
            self.assertEqual(summary["sections"]["intake"], {"state": "unavailable"})
            self.assertNotIn("PRIVATE_CANARY", json.dumps(summary))

    def test_later_mapping_failure_rejects_whole_series(self):
        client = client_for(["soc-host-raw-one", "soc-host-raw-two"])
        for caps in ({"unmapped": {}}, {"keyword": {}}, {"date": {"aggregatable": False}}, {}):
            client.field_caps.side_effect = [
                {"fields": {"event.ingested": {"date": {}}}}, {"fields": {"event.ingested": caps}}]
            with patch("cloud_soc.portal.operations.INDEX_PATH_BUDGET", 20), self.assertRaises(ValueError):
                Operations(client).series(PATTERN, "event.ingested", START, END, "5m")

    def test_statuses_merged_without_losing_unknown_categories(self):
        client = client_for(["soc-host-raw-one", "soc-host-raw-two"])
        client.search.side_effect = [response(3, statuses={"normalized": 2, "legacy": 1}),
                                    response(4, statuses={"normalized": 1, "unsupported": 1, "other": 2})]
        with patch("cloud_soc.portal.operations.INDEX_PATH_BUDGET", 20):
            result = Operations(client).series(PATTERN, "event.ingested", START, END, "5m", records=True)
        self.assertEqual(result["count"], 7)
        self.assertEqual({row["key"]: row["doc_count"] for row in result["statuses"]},
                         {"normalized": 3, "unsupported": 1, "unknown": 3})

    def test_inexact_or_incomplete_aggregations_rejected(self):
        for mutate in (lambda r: r["hits"]["total"].update(relation="gte"),
                       lambda r: r["aggregations"]["trend"].update(buckets=[]),
                       lambda r: r["aggregations"]["status"].update(sum_other_doc_count=1),
                       lambda r: r["aggregations"]["status"].update(doc_count_error_upper_bound=1)):
            value = response(1, statuses={"normalized": 1})
            mutate(value)
            client = client_for(["soc-host-raw-one"])
            client.search.return_value = value
            with self.assertRaises(ValueError):
                Operations(client).series(PATTERN, "event.ingested", START, END, "5m", records=True)

    def test_deadline_and_scope_budget_do_not_return_success(self):
        client = client_for(["soc-host-raw-one", "soc-host-raw-two"])
        with patch("cloud_soc.portal.operations.monotonic", side_effect=[0, 0, 0, 13]):
            with self.assertRaisesRegex(RuntimeError, "budget exhausted"):
                Operations(client).series(PATTERN, "event.ingested", START, END, "5m")
        with patch("cloud_soc.portal.operations.MAX_INDEX_BATCHES", 1), patch("cloud_soc.portal.operations.INDEX_PATH_BUDGET", 20):
            with self.assertRaisesRegex(ValueError, "scope too large"):
                Operations(client).series(PATTERN, "event.ingested", START, END, "5m")
        self.assertEqual(client.search.call_count, 1)

    def test_unsafe_concrete_names_rejected(self):
        for name in ("soc-host-raw-*", "soc-host-raw-a,b", "soc-host-raw-a/b", "soc-host-raw-" + "x" * 256):
            with self.assertRaises(ValueError):
                index_batches([name])

    def test_alert_projection_and_latest_order_preserved(self):
        client = client_for(["security-alerts"])
        value = response(2)
        value["hits"]["hits"] = [{"_id": str(i), "_source": {"@timestamp": stamp, "message": "PRIVATE_CANARY"}}
                                  for i, stamp in enumerate((LATER, START))]
        client.search.return_value = value
        result = Operations(client).series(["security-alerts"], "@timestamp", START, END, "5m", alerts=True)
        self.assertEqual([row["timestamp"] for row in result["rows"]], [LATER, START])
        self.assertEqual(client.search.call_args.kwargs["size"], 50)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
