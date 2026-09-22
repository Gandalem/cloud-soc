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
from cloud_soc.oci.audit import project_event
from cloud_soc.oci.collector import CollectionError, Settings, State, poll_scope, run_cycle
from cloud_soc.oci.__main__ import AuditPages, build_clients, main
from cloud_soc.portal.log_contract import project_hit, parse_filters
from cloud_soc.portal.security_detail import security_detail

FIXTURE = json.loads((ROOT / "tests/fixtures/oci_audit.json").read_text(encoding="utf-8"))
EVENTS = FIXTURE["events"]
TENANCY, REGION, COMPARTMENT = (FIXTURE[key] for key in ("tenancy", "region", "compartment"))
CONFIG = {"tenancy_id": TENANCY, "organization": "fixture", "regions": [REGION], "compartments": [COMPARTMENT], "lookback_hours": 1}
NOW = datetime(2026, 9, 22, 2, 0, 37, tzinfo=timezone.utc)


def projected(event):
    return project_event(event, tenancy=TENANCY, region=REGION, compartment=COMPARTMENT, organization="fixture")


class MemorySink:
    def __init__(self):
        self.docs = {}

    def create(self, index, identifier, document):
        key = (index, identifier)
        if key in self.docs:
            return False
        self.docs[key] = deepcopy(document)
        return True


class ProjectionTests(unittest.TestCase):
    def test_selected_metadata_round_trip_and_no_payload(self):
        original = deepcopy(EVENTS)
        for event, expected in zip(EVENTS, ("success", "failure", "success")):
            index, identifier, doc = projected(event)
            self.assertTrue(index.startswith("soc-cloud-oci-"))
            self.assertEqual(len(identifier), 64)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(doc))
            self.assertNotIn("host", doc)
            self.assertNotIn("ingested", doc["event"])
            self.assertEqual(doc["event"]["outcome"], expected)
            row = project_hit({"_index": index, "_id": identifier, "_source": doc})
            self.assertEqual((row["cloud_provider"], row["os"], row["collector"]), ("oci", "cloud", "oci-audit"))
            self.assertIsNone(row["host_name"])
            detail = security_detail(doc)
            self.assertEqual(detail["adapter"], "oci_audit_metadata_v1")
            self.assertEqual(detail["fields"]["resource_id"], event["data"]["resource_id"])
            self.assertIn("oci_audit_not_object_or_identity_domain_access", detail["limitations"])
        self.assertEqual(EVENTS, original)
        self.assertEqual(parse_filters([("collector", "oci-audit"), ("os", "cloud")]).collector, "oci-audit")

    def test_missing_status_actor_and_api_do_not_become_success(self):
        event = deepcopy(EVENTS[0])
        for value in (None, "302", "bad", [], True, 200):
            event["data"]["response"]["status"] = value
            self.assertEqual(projected(event)[2]["event"]["outcome"], "unknown")
        event["data"].update(identity=None, event_name=None)
        detail = security_detail(projected(event)[2])
        self.assertEqual(detail["status"], "partial")
        self.assertIn("actor", detail["missing"])

    def test_scope_schema_and_time_fail_closed(self):
        for key, value in (("event_id", "bad"), ("cloud_events_version", "1.0"), ("event_type_version", "3.0"),
                           ("event_type", "other"), ("event_time", "2026-09-22T01:00:00"), ("data", {})):
            with self.assertRaises(ValueError):
                projected({**EVENTS[0], key: value})
        event = deepcopy(EVENTS[0])
        event["data"]["compartment_id"] = TENANCY
        with self.assertRaises(ValueError):
            projected(event)

    def test_selected_secret_redaction_and_stable_identity(self):
        event = deepcopy(EVENTS[0])
        event["data"]["resource_name"] = "password=PRIVATE_CANARY"
        event["data"]["identity"]["principal_name"] = "x" * 513
        doc = projected(event)[2]
        self.assertNotIn("PRIVATE_CANARY", json.dumps(doc))
        self.assertEqual(doc["user"]["name"], "[REDACTED]")
        self.assertEqual(projected(event)[:2], projected(EVENTS[0])[:2])
        changed = project_event(event, tenancy=TENANCY, compartment=COMPARTMENT, region=REGION, organization="other")
        self.assertNotEqual(projected(event)[1], changed[1])


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "checkpoint.sqlite"
        self.settings = Settings.parse(CONFIG)
        self.state = State(self.path, self.settings, now=NOW)
        self.client, self.sink = Mock(), MemorySink()

    def tearDown(self):
        self.state.close()
        self.folder.cleanup()

    def cycle(self, now=NOW):
        return run_cycle(self.settings, self.state, {REGION: self.client}, self.sink, now=now, sleep=lambda _: None)

    def test_fixed_minute_boundaries_and_pages(self):
        self.client.page.side_effect = [([EVENTS[0]], "page-two"), ([EVENTS[1]], None)]
        result = self.cycle()[0]
        self.assertEqual(result["created"], 2)
        self.assertEqual(result["watermark"], "2026-09-22T01:50:00Z")
        first, second = [call.args for call in self.client.page.call_args_list]
        self.assertEqual(first[:3], second[:3])
        self.assertEqual(first[1].second, 0)
        self.assertEqual(first[2].microsecond, 0)
        self.assertEqual((first[3], second[3]), (None, "page-two"))

    def test_failure_reopen_replay_deduplicates(self):
        self.client.page.side_effect = [([EVENTS[0]], "next"), RuntimeError("PRIVATE_CANARY")]
        self.assertEqual(self.cycle()[0]["code"], "oci_lookup_failed")
        self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")
        self.state.close()
        self.state = State(self.path, self.settings, now=NOW + timedelta(days=1))
        self.client.page.side_effect = None
        self.client.page.return_value = (EVENTS, None)
        result = self.cycle()[0]
        self.assertEqual((result["created"], result["duplicates"]), (2, 1))
        self.assertNotIn("PRIVATE_CANARY", json.dumps(self.state.status()))

    def test_sink_failure_and_invalid_event_do_not_advance(self):
        self.client.page.return_value = ([EVENTS[0]], None)
        with patch.object(self.sink, "create", side_effect=CollectionError("elasticsearch_write_failed")):
            self.assertEqual(self.cycle()[0]["code"], "elasticsearch_write_failed")
        self.client.page.return_value = ([{"bad": "PRIVATE_CANARY"}], None)
        self.assertEqual(self.cycle()[0]["code"], "invalid_oci_event")
        self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")

    def test_bad_page_tokens_and_budget(self):
        self.client.page.return_value = ([], "repeat")
        self.assertEqual(self.cycle()[0]["code"], "invalid_pagination")
        self.client.page.return_value = ([], "next")
        with self.assertRaisesRegex(CollectionError, "page_limit_reached"):
            poll_scope(self.settings, self.state, REGION, COMPARTMENT, self.client, self.sink, now=NOW, max_pages=1, sleep=lambda _: None)
        self.client.page.return_value = ({}, None)
        self.assertEqual(self.cycle()[0]["code"], "invalid_oci_page")

    def test_delayed_event_occurrence_is_not_query_processing_time(self):
        event = {**EVENTS[0], "event_time": "2026-09-21T22:00:00Z"}
        self.client.page.return_value = ([event], None)
        self.assertEqual(self.cycle()[0]["created"], 1)
        self.assertEqual(self.cycle()[0]["duplicates"], 1)
        self.assertEqual(self.client.page.call_args.args[1].isoformat(), "2026-09-22T01:35:00+00:00")

    def test_history_gap_future_clock_and_concurrent_writer(self):
        self.assertEqual(self.cycle(NOW + timedelta(days=366))[0]["code"], "history_gap_requires_review")
        self.assertEqual(self.cycle(NOW - timedelta(hours=2))[0]["status"], "waiting")
        lock = sqlite3.connect(self.path, isolation_level=None)
        try:
            lock.execute("BEGIN IMMEDIATE")
            self.assertEqual(self.cycle()[0]["status"], "error")
            self.client.page.assert_not_called()
        finally:
            lock.close()

    def test_scope_change_refused_and_independent_compartments(self):
        changed = Settings.parse({**CONFIG, "compartments": [COMPARTMENT, TENANCY]})
        with self.assertRaisesRegex(CollectionError, "state_scope_mismatch"):
            State(self.path, changed, now=NOW)
        state = State(self.path.parent / "other.sqlite", changed, now=NOW)
        try:
            self.client.page.side_effect = [RuntimeError("PRIVATE_CANARY"), ([], None)]
            result = run_cycle(changed, state, {REGION: self.client}, self.sink, now=NOW, sleep=lambda _: None)
            self.assertEqual([item["status"] for item in result], ["error", "ok"])
        finally:
            state.close()

    def test_settings_reject_secret_scope_duplicates_and_limits(self):
        for change in ({"tenancy_id": "ocid1.tenancy.oc2..notallowed"}, {"regions": ["https://evil.test"]},
                       {"regions": [REGION, REGION]}, {"compartments": []}, {"compartments": [COMPARTMENT, COMPARTMENT]},
                       {"compartments": ["ocid1.tenancy.oc1..differenttenancy"]}, {"lookback_hours": True},
                       {"lookback_hours": 8760}, {"private_key": "PRIVATE_CANARY"}):
            with self.assertRaises(CollectionError):
                Settings.parse({**CONFIG, **change})

    def test_service_errors_remain_static_and_keep_checkpoint(self):
        for status, code in ((401, "oci_authentication_failed"), (403, "oci_access_denied"), (404, "oci_scope_unavailable"), (429, "oci_throttled"), (500, "oci_lookup_failed")):
            error = RuntimeError("PRIVATE_CANARY")
            error.status = status
            self.client.page.side_effect = error
            self.assertEqual(self.cycle()[0]["code"], code)
            self.assertEqual(self.state.status()[0]["watermark"], "2026-09-22T01:00:00Z")
            self.assertNotIn("PRIVATE_CANARY", json.dumps(self.state.status()))

    def test_cli_offline_no_auth_or_network_and_safe_failure(self):
        config = self.path.parent / "config.json"
        config.write_text(json.dumps(CONFIG), encoding="utf-8")
        with patch("cloud_soc.oci.__main__.build_clients") as build, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(config)]), 0)
            self.assertIn('"oci_contacted": false', output.getvalue())
            build.assert_not_called()
        with redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(config), "--run", "--es-url", "http://invalid"]), 1)
            self.assertNotIn("Traceback", output.getvalue())
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(config), "--state", str(self.path), "--status"]), 0)
            self.assertIn("not_collected", output.getvalue())


@unittest.skipUnless(importlib.util.find_spec("oci"), "Install optional deploy/oci/requirements.txt for SDK tests")
class SDKTests(unittest.TestCase):
    def test_standard_api_key_profile_builds_clients_without_network(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import oci
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with tempfile.TemporaryDirectory() as folder:
            key_path, config_path = Path(folder) / "synthetic.pem", Path(folder) / "config"
            key_path.write_bytes(private_key)
            config_path.write_text(f"[DEFAULT]\ntenancy={TENANCY}\nuser=ocid1.user.oc1..syntheticuser000\nfingerprint={':'.join(['00'] * 16)}\nkey_file={key_path}\nregion={REGION}\nservice_endpoint=https://not-approved.test\nlog_requests=true\n", encoding="utf-8")
            with patch.object(oci._vendor.requests.sessions.Session, "request", side_effect=AssertionError("No network allowed")):
                clients = build_clients(Settings.parse(CONFIG), "config", str(config_path), "DEFAULT")
                try:
                    self.assertEqual(clients[REGION].client.base_client.endpoint, f"https://audit.{REGION}.oraclecloud.com/20190901")
                    self.assertFalse(clients[REGION].client.base_client.config.get("log_requests", False))
                finally:
                    for wrapper in clients.values():
                        wrapper.client.base_client.session.close()

    def test_real_sdk_deserialization_and_pagination_without_network(self):
        import oci
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from oci._vendor.requests import Response
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        signer = oci.signer.Signer(TENANCY, "ocid1.user.oc1..syntheticuser000", "00:11", None, private_key_content=key)
        config = {"region": REGION, "tenancy": TENANCY, "user": "ocid1.user.oc1..syntheticuser000", "fingerprint": ":".join(["00"] * 16), "key_content": key}
        client = oci.audit.AuditClient(config, signer=signer, service_endpoint=f"https://audit.{REGION}.oraclecloud.com", retry_strategy=oci.retry.NoneRetryStrategy())
        raw = {"eventType": EVENTS[0]["event_type"], "cloudEventsVersion": "0.1", "eventTypeVersion": "2.0", "source": "ComputeApi",
               "eventId": EVENTS[0]["event_id"], "eventTime": EVENTS[0]["event_time"], "contentType": "application/json",
               "data": {"eventName": "LaunchInstance", "compartmentId": COMPARTMENT, "response": {"status": "202"}, "identity": {"principalName": "fixture"}}}
        response = Response()
        response.status_code, response._content = 200, json.dumps([raw]).encode()
        response.headers.update({"content-type": "application/json", "opc-next-page": "next-fixture"})
        try:
            with patch.object(client.base_client.session, "request", return_value=response) as request:
                events, token = AuditPages(oci, client).page(COMPARTMENT, NOW.replace(second=0) - timedelta(hours=1), NOW.replace(second=0), None)
                self.assertEqual(token, "next-fixture")
                self.assertEqual(projected(events[0])[2]["event"]["outcome"], "success")
                self.assertEqual(request.call_count, 1)
                self.assertIn("compartmentId", str(request.call_args))
        finally:
            client.base_client.session.close()

    def test_auth_scope_and_endpoint_pinning(self):
        import oci
        settings = Settings.parse(CONFIG)
        with patch.object(oci.config, "from_file", return_value={"tenancy": "different"}), patch.object(oci.signer, "Signer") as signer:
            with self.assertRaisesRegex(CollectionError, "oci_tenancy_mismatch"):
                build_clients(settings, "config", "unused", "DEFAULT")
            signer.assert_not_called()
        with patch.object(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", return_value=Mock(tenancy_id="different")):
            with self.assertRaisesRegex(CollectionError, "oci_tenancy_mismatch"):
                build_clients(settings, "instance-principal", "unused", "DEFAULT")
        with patch.dict("os.environ", {"OCI_METADATA_BASE_URL": "http://not-approved"}):
            with self.assertRaisesRegex(CollectionError, "metadata_override_not_allowed"):
                build_clients(settings, "instance-principal", "unused", "DEFAULT")
        with patch.object(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", return_value=Mock(tenancy_id=TENANCY)), patch.object(oci.audit, "AuditClient") as client:
            build_clients(settings, "instance-principal", "unused", "DEFAULT")
            self.assertEqual(client.call_args.kwargs["service_endpoint"], f"https://audit.{REGION}.oraclecloud.com")
            self.assertEqual(client.call_args.kwargs["timeout"], (5, 20))


if __name__ == "__main__":
    unittest.main()
