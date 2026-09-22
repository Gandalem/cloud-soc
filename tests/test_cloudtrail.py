from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cloud_soc.aws.cloudtrail import project_event, timestamp
from cloud_soc.aws.collector import CollectionError, Settings, State, run_cycle, poll_region
from cloud_soc.aws.__main__ import main, endpoint
from cloud_soc.portal.log_contract import project_hit, parse_filters
from cloud_soc.portal.security_detail import security_detail

EVENTS = json.loads((ROOT / "tests/fixtures/cloudtrail_management.json").read_text(encoding="utf-8"))["events"]
NOW = datetime(2026, 9, 22, 2, tzinfo=timezone.utc)
CONFIG = {"account_id": "123456789012", "organization": "fixture", "regions": ["us-east-1"], "lookback_hours": 1}


def envelope(event):
    return {"EventId": event["eventID"], "EventTime": timestamp(event["eventTime"]),
            "EventName": event["eventName"], "EventSource": event["eventSource"], "CloudTrailEvent": json.dumps(event)}


def projected(event):
    return project_event(envelope(event), account=CONFIG["account_id"], region=event["awsRegion"], organization="fixture")


class ProjectionTests(unittest.TestCase):
    def test_console_iam_sg_metadata_without_raw_or_host(self):
        original = deepcopy(EVENTS)
        for event in EVENTS:
            index, identifier, document = projected(event)
            self.assertTrue(index.startswith("soc-cloud-aws-"))
            self.assertEqual(len(identifier), 64)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(document))
            for key in ("host", "message", "event.original", "requestParameters", "responseElements"):
                self.assertNotIn(key, document)
            self.assertNotIn("ingested", document["event"])
            self.assertEqual(document["cloud"]["account"]["id"], "123456789012")
            row = project_hit({"_index": index, "_id": identifier, "_source": document})
            self.assertEqual(row["stream"], "cloud")
            self.assertEqual(row["os"], "cloud")
            self.assertIsNone(row["host_name"])
            detail = security_detail(document)
            self.assertEqual(detail["fields"]["api"], event["eventName"])
            self.assertIn("management_events_not_object_access", detail["limitations"])
        self.assertEqual(EVENTS, original)
        self.assertEqual(projected(EVENTS[0])[2]["event"]["outcome"], "failure")
        self.assertEqual(projected(EVENTS[1])[2]["aws"]["cloudtrail"]["target_user"], "target-fixture")
        sg = projected(EVENTS[2])[2]
        self.assertEqual(sg["event"]["outcome"], "failure")
        self.assertNotIn("ip", sg["source"])
        self.assertEqual(sg["aws"]["cloudtrail"]["target_group_id"], "sg-0123456789abcdef0")

    def test_outcome_basis_missing_console_and_no_error_reported(self):
        event = deepcopy(EVENTS[0])
        event["responseElements"] = None
        self.assertEqual(projected(event)[2]["event"]["outcome"], "unknown")
        event["responseElements"] = {"ConsoleLogin": "Success"}
        self.assertEqual(projected(event)[2]["event"]["outcome"], "success")
        self.assertEqual(projected(EVENTS[1])[2]["aws"]["cloudtrail"]["outcome_basis"], "no_error_reported")

    def test_scope_type_version_and_envelope_conflicts_fail_closed(self):
        for key, value in (("recipientAccountId", "999999999999"), ("awsRegion", "eu-west-1"),
                           ("eventCategory", "Data"), ("managementEvent", False), ("eventVersion", "2.0"), ("eventID", "bad")):
            event = {**EVENTS[0], key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                project_event(envelope(event), account=CONFIG["account_id"], region="us-east-1", organization="fixture")
        for key, value in (("EventId", "different"), ("EventName", "different"), ("EventTime", NOW),
                           ("CloudTrailEvent", "{"), ("CloudTrailEvent", "x" * (1024 * 1024 + 1)),
                           ("CloudTrailEvent", '{"duplicate":1,"duplicate":2}')):
            with self.assertRaises(ValueError):
                project_event({**envelope(EVENTS[0]), key: value}, account=CONFIG["account_id"], region="us-east-1", organization="fixture")

    def test_selected_strings_are_masked_and_resources_bounded(self):
        event = deepcopy(EVENTS[1])
        event["userIdentity"]["arn"] = "password=PRIVATE_CANARY"
        event["resources"] *= 30
        doc = projected(event)[2]
        self.assertNotIn("PRIVATE_CANARY", json.dumps(doc))
        self.assertEqual(len(doc["aws"]["cloudtrail"]["resources"]), 20)
        self.assertTrue(doc["aws"]["cloudtrail"]["resources_truncated"])

    def test_event_identity_and_date_index_are_replay_stable(self):
        first = projected(EVENTS[0])
        self.assertEqual(first, projected(deepcopy(EVENTS[0])))
        self.assertEqual(first[0], "soc-cloud-aws-2026.09.22")
        changed = deepcopy(EVENTS[0])
        changed["recipientAccountId"] = "999999999999"
        other = project_event(envelope(changed), account="999999999999", region="us-east-1", organization="fixture")
        self.assertNotEqual(first[1], other[1])
        self.assertEqual(parse_filters([("collector", "cloudtrail"), ("os", "cloud")]).os, "cloud")


class MemorySink:
    def __init__(self):
        self.docs = {}

    def create(self, index, identifier, document):
        key = (index, identifier)
        if key in self.docs:
            return False
        self.docs[key] = deepcopy(document)
        return True


class CollectorTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "checkpoint.sqlite"
        self.settings = Settings.parse(CONFIG)
        self.state = State(self.path, self.settings, now=NOW)
        self.addCleanup(self.state.close)
        self.sink, self.aws, self.sts = MemorySink(), Mock(), Mock()
        self.sts.get_caller_identity.return_value = {"Account": CONFIG["account_id"], "Arn": "arn:aws:iam::123456789012:role/fixture"}

    def cycle(self, **kwargs):
        return run_cycle(self.settings, self.state, self.sts, {"us-east-1": self.aws}, self.sink, now=NOW, sleep=lambda _: None, **kwargs)

    def test_pagination_fixed_window_and_checkpoint_after_delivery(self):
        self.aws.lookup_events.side_effect = [{"Events": [envelope(EVENTS[1])], "NextToken": "fixture-token"}, {"Events": [envelope(EVENTS[0])]}]
        result = self.cycle()[0]
        self.assertEqual(result["created"], 2)
        self.assertEqual(result["watermark"], "2026-09-22T01:55:00Z")
        calls = self.aws.lookup_events.call_args_list
        self.assertEqual(calls[0].kwargs["StartTime"], calls[1].kwargs["StartTime"])
        self.assertEqual(calls[0].kwargs["EndTime"], calls[1].kwargs["EndTime"])
        self.assertEqual(calls[1].kwargs["NextToken"], "fixture-token")
        self.assertNotIn("EventCategory", calls[0].kwargs)
        self.assertEqual(self.state.status()[0]["last_success"], "2026-09-22T02:00:00Z")

    def test_partial_failure_restarts_window_without_duplicate_documents(self):
        self.aws.lookup_events.side_effect = [{"Events": [envelope(EVENTS[1])], "NextToken": "token"}, RuntimeError("PRIVATE_CANARY")]
        first = self.cycle()
        self.assertEqual(first[0]["status"], "error")
        self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")
        self.assertNotIn("PRIVATE_CANARY", json.dumps(self.state.status()))
        second_state = State(self.path, self.settings, now=NOW + timedelta(hours=1))
        try:
            self.assertEqual(second_state.status()[0]["watermark"], "2026-09-22T01:00:00Z")
            self.aws.lookup_events.side_effect = [{"Events": [envelope(EVENTS[1]), envelope(EVENTS[0])]}]
            result = run_cycle(self.settings, second_state, self.sts, {"us-east-1": self.aws}, self.sink, now=NOW, sleep=lambda _: None)
            self.assertEqual(result[0]["duplicates"], 1)
            self.assertEqual(len(self.sink.docs), 2)
        finally:
            second_state.close()

    def test_sink_failure_never_advances_watermark(self):
        self.aws.lookup_events.return_value = {"Events": [envelope(EVENTS[0])]}
        self.sink.create = Mock(side_effect=RuntimeError("PRIVATE_CANARY"))
        result = self.cycle()
        self.assertEqual(result[0]["code"], "collection_failed")
        self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")

    def test_scope_mismatch_and_credentials_failure_contact_no_cloudtrail(self):
        self.sts.get_caller_identity.return_value["Account"] = "999999999999"
        with self.assertRaisesRegex(CollectionError, "aws_account_mismatch"):
            self.cycle()
        self.aws.lookup_events.assert_not_called()
        self.sts.get_caller_identity.side_effect = RuntimeError("PRIVATE_CANARY")
        with self.assertRaisesRegex(CollectionError, "aws_identity_unavailable"):
            self.cycle()
        self.assertNotIn("PRIVATE_CANARY", json.dumps(self.state.status()))

    def test_invalid_event_and_repeated_token_do_not_skip_data(self):
        for pages in ([{"Events": [{}]}], [{"Events": [], "NextToken": "repeat"}, {"Events": [], "NextToken": "repeat"}]):
            self.aws.lookup_events.side_effect = pages
            self.assertEqual(self.cycle()[0]["status"], "error")
            self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")

    def test_page_budget_and_history_gap_stop_without_advancing(self):
        self.aws.lookup_events.return_value = {"Events": [], "NextToken": "more"}
        with self.assertRaisesRegex(CollectionError, "page_limit"):
            poll_region(self.settings, self.state, "us-east-1", self.aws, self.sink, now=NOW, sleep=lambda _: None, max_pages=1)
        with self.assertRaisesRegex(CollectionError, "history_gap"):
            poll_region(self.settings, self.state, "us-east-1", self.aws, self.sink, now=NOW + timedelta(days=91), sleep=lambda _: None)
        self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")

    def test_overlap_picks_up_delayed_events_and_preserves_first_copy(self):
        self.aws.lookup_events.return_value = {"Events": []}
        self.cycle()
        delayed = {**EVENTS[0], "eventTime": "2026-09-22T01:50:00Z"}
        self.aws.lookup_events.return_value = {"Events": [envelope(delayed)]}
        self.assertEqual(self.cycle()[0]["created"], 1)
        self.assertEqual(self.cycle()[0]["duplicates"], 1)
        self.assertEqual(self.aws.lookup_events.call_args.kwargs["StartTime"], timestamp("2026-09-22T01:40:00Z"))

    def test_concurrent_writer_and_changed_configuration_are_rejected(self):
        other = sqlite3.connect(self.path, isolation_level=None)
        try:
            other.execute("BEGIN IMMEDIATE")
            self.assertEqual(self.cycle()[0]["status"], "error")
            self.aws.lookup_events.assert_not_called()
        finally:
            other.close()
        changed = Settings.parse({**CONFIG, "organization": "other"})
        with self.assertRaisesRegex(CollectionError, "state_scope_mismatch"):
            State(self.path, changed, now=NOW)

    def test_offline_validation_never_builds_sdk_clients(self):
        config = self.path.parent / "config.json"
        config.write_text(json.dumps(CONFIG), encoding="utf-8")
        fake_sdk = Mock()
        with patch.dict(sys.modules, {"boto3": fake_sdk}), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(config)]), 0)
            fake_sdk.Session.assert_not_called()
            self.assertIn('"aws_contacted": false', output.getvalue())
        with redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(config), "--run", "--es-url", "http://invalid"]), 1)
            self.assertNotIn("Traceback", output.getvalue())

    def test_config_rejects_secrets_duplicate_regions_and_scope_errors(self):
        for change in ({"account_id": 123456789012}, {"account_id": "bad"}, {"regions": ["us-east-1", "us-east-1"]},
                       {"regions": ["cn-north-1"]}, {"regions": []}, {"organization": "password=bad"},
                       {"lookback_hours": True}, {"lookback_hours": 3000}, {"aws_secret_access_key": "CANARY"}):
            with self.assertRaises(CollectionError):
                Settings.parse({**CONFIG, **change})
        for value in (None, "http://example.test", "https://user:pass@example.test", "https://example.test/?key=secret"):
            with self.assertRaises(CollectionError):
                endpoint(value)


@unittest.skipUnless(importlib.util.find_spec("boto3"), "Install optional deploy/aws/requirements.txt for SDK contract tests")
class SDKTests(unittest.TestCase):
    def test_official_sdk_request_schema_and_throttling(self):
        import boto3
        from botocore.stub import Stubber
        from botocore.config import Config
        aws = boto3.client("cloudtrail", region_name="us-east-1", aws_access_key_id="synthetic", aws_secret_access_key="synthetic", config=Config(ignore_configured_endpoint_urls=True))
        request = {"StartTime": NOW - timedelta(hours=1), "EndTime": NOW - timedelta(minutes=5), "MaxResults": 50}
        settings = Settings.parse(CONFIG)
        with tempfile.TemporaryDirectory() as folder:
            state = State(Path(folder) / "state.sqlite", settings, now=NOW)
            try:
                with Stubber(aws) as stub:
                    stub.add_client_error("lookup_events", service_error_code="ThrottlingException", service_message="PRIVATE_CANARY", expected_params=request)
                    with self.assertRaisesRegex(CollectionError, "aws_throttled"):
                        poll_region(settings, state, "us-east-1", aws, MemorySink(), now=NOW, sleep=lambda _: None)
                    self.assertEqual(state.status()[0]["watermark"], "2026-09-22T01:00:00Z")
                    stub.add_response("lookup_events", {"Events": [envelope(EVENTS[0])]}, request)
                    result = poll_region(settings, state, "us-east-1", aws, MemorySink(), now=NOW, sleep=lambda _: None)
                    self.assertEqual(result["created"], 1)
                    stub.assert_no_pending_responses()
            finally:
                state.close()


if __name__ == "__main__":
    unittest.main()
