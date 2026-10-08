"""Privacy, source identity, outcome and immutable migration regression."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.parsers.linux_operational import parse_linux_operational
from cloud_soc.processing.contract import normalize

NOW = "2026-10-05T04:00:00Z"


def hit(message, app="sudo", kind="linux_journald"):
    return {"_index": "soc-host-raw-test", "_id": "synthetic", "_source": {
        "@timestamp": NOW, "event": {"ingested": NOW}, "organization": {"id": "fixture"},
        "labels": {"log_source": kind}, "process": {"name": app}, "message": message}}


class LinuxOperationalTests(unittest.TestCase):
    def test_sudo_metadata_has_no_command_arguments_or_success_claim(self):
        sample = hit("fixture : TTY=pts/0 ; PWD=/PRIVATE_CANARY ; USER=root ; COMMAND=/bin/sh -c 'password=PRIVATE_CANARY'")
        original = copy.deepcopy(sample)
        key, record, event = normalize(sample, NOW)
        self.assertEqual(sample, original)
        self.assertEqual(record["status"], "normalized")
        self.assertEqual(event["event"]["outcome"], "unknown")
        self.assertEqual(event["event"]["action"], "sudo_command_logged")
        self.assertEqual(event["user"]["name"], "fixture")
        self.assertEqual(event["cloud_soc"]["detail"]["fields"]["target_user"], "root")
        self.assertNotIn("PRIVATE_CANARY", json.dumps([record, event]))
        self.assertEqual(event["cloud_soc"]["normalizer_version"], "linux-operational-v1")
        old = hit("unsupported", "unrelated")
        self.assertNotEqual(key, normalize(old, NOW)[0])
        self.assertEqual(key, normalize(sample, "2026-10-05T05:00:00Z")[0])

    def test_file_prefix_requires_timezone_and_preserves_source_timestamp(self):
        sample = hit("Oct  5 04:00:00 fixture sudo[12]: fixture : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/true", kind="linux_file")
        self.assertEqual(normalize(sample, NOW)[1]["reason"], "linux_timezone_missing")
        sample["_source"]["event"]["timezone"] = "UTC"
        event = normalize(sample, NOW)[2]
        self.assertEqual(event["@timestamp"], NOW)
        sample["_source"]["event"]["timezone"] = "invalid"
        self.assertEqual(normalize(sample, NOW)[1]["reason"], "linux_time_invalid")

    def test_systemd_failure_and_lifecycle_do_not_retain_description(self):
        for message, action, outcome in (
            ("Failed to start PRIVATE_CANARY.", "service_start_failed", "failure"),
            ("Started PRIVATE_CANARY.", "service_started", "unknown"),
            ("Starting PRIVATE_CANARY...", "service_start_requested", "unknown"),
        ):
            event = normalize(hit(message, "systemd"), NOW)[2]
            self.assertEqual(event["event"]["action"], action)
            self.assertEqual(event["event"]["outcome"], outcome)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(event))

    def test_docker_json_and_logfmt_extract_only_level(self):
        for message in ('{"level":"error","msg":"password=PRIVATE_CANARY"}',
                        'time="2026-10-05T04:00:00Z" level=info msg="PRIVATE_CANARY" module=runtime'):
            event = normalize(hit(message, "dockerd"), NOW)[2]
            self.assertEqual(event["event"]["outcome"], "unknown")
            self.assertNotIn("PRIVATE_CANARY", json.dumps(event))

    def test_unknown_malformed_and_wrong_provider_are_not_supported(self):
        for sample in (hit("Started example.", "unrelated"),
                       hit('time="x" level=unknown msg="x"', "dockerd"),
                       hit("Started x.\nforged", "systemd"), hit("x" * 8193)):
            self.assertIsNone(parse_linux_operational(sample["_source"]))
        sample = hit("Started example.", "systemd")
        sample["_index"] = "soc-cloud-aws-test"
        self.assertEqual(normalize(sample, NOW)[1]["reason"], "source_scope_mismatch")

    def test_desktop_kernel_and_network_metadata_are_not_authentication(self):
        for app in ("gnome-shell", "kernel", "NetworkManager", "avahi-daemon", "systemd-udevd"):
            event = normalize(hit("PRIVATE_CANARY arbitrary message", app), NOW)[2]
            self.assertNotIn("authentication", event["event"]["category"])
            self.assertEqual(event["event"]["outcome"], "unknown")
            self.assertNotIn("PRIVATE_CANARY", json.dumps(event))

    def test_pam_sudo_session_and_auth_failure(self):
        for body, action, outcome in (
            ("pam_unix(sudo:session): session opened for user root by fixture", "sudo_session_opened", "unknown"),
            ("pam_unix(sudo:session): session closed for user root", "sudo_session_closed", "unknown"),
            ("pam_unix(sudo:auth): authentication failure; logname=PRIVATE_CANARY", "sudo_authentication_failed", "failure"),
        ):
            event = normalize(hit(body), NOW)[2]
            self.assertEqual(event["event"]["action"], action)
            self.assertEqual(event["event"]["outcome"], outcome)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(event))

    def test_access_log_explicit_offset_and_no_url_or_headers(self):
        sample = hit('192.0.2.1 - - [05/Oct/2026:13:00:00 +0900] "GET /?token=PRIVATE_CANARY HTTP/1.1" 401 12 "PRIVATE_CANARY" "PRIVATE_CANARY"', kind="linux_file")
        sample["_source"]["log"] = {"file": {"path": "/var/log/nginx/access_log"}}
        event = normalize(sample, NOW)[2]
        self.assertEqual(event["@timestamp"], NOW)
        self.assertEqual(event["event"]["category"], ["web"])
        self.assertEqual(event["event"]["outcome"], "failure")
        self.assertNotIn("PRIVATE_CANARY", json.dumps(event))
        sample["_source"]["message"] = sample["_source"]["message"].replace("05/Oct", "32/Oct")
        self.assertEqual(normalize(sample, NOW)[1]["reason"], "linux_time_invalid")

    def test_remaining_known_providers_are_observed_without_semantic_guessing(self):
        for app in ("sudo", "dbus-daemon", "chrome"):
            event = normalize(hit("PRIVATE_CANARY unknown payload", app), NOW)[2]
            self.assertEqual(event["event"]["outcome"], "unknown")
            self.assertNotIn("authentication", event["event"]["category"])
            self.assertNotIn("PRIVATE_CANARY", json.dumps(event))

    def test_unidentified_messages_are_partial_metadata_not_authentication(self):
        sample = hit("PRIVATE_CANARY unidentified payload")
        del sample["_source"]["process"]
        key, record, event = normalize(sample, NOW)
        self.assertEqual(record["adapter"], "linux_unclassified_v1")
        self.assertEqual(event["event"]["category"], [])
        self.assertEqual(event["event"]["outcome"], "unknown")
        self.assertEqual(event["cloud_soc"]["parse_status"], "partial")
        self.assertFalse(event["cloud_soc"]["provenance"]["time"]["source_event_time_known"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps([record, event]))
        sample["_source"]["labels"]["log_source"] = "linux_file"
        self.assertIsNone(normalize(sample, NOW)[2])
        sample["_source"]["log"] = {"file": {"path": "/var/log/syslog"}}
        self.assertEqual(normalize(sample, NOW)[1]["adapter"], "linux_unclassified_v1")

    def test_hostname_access_with_two_uninterpreted_fields(self):
        sample = hit('localhost - - [05/Oct/2026:13:00:00 +0900] "POST /PRIVATE_CANARY HTTP/1.1" 200 12 Print-Job successful-ok', kind="linux_file")
        sample["_source"]["log"] = {"file": {"path": "/var/log/cups/access_log"}}
        event = normalize(sample, NOW)[2]
        self.assertEqual(event["cloud_soc"]["parse_status"], "partial")
        self.assertEqual(event["event"]["category"], ["web"])
        self.assertNotIn("source", event)
        for value in ("PRIVATE_CANARY", "localhost", "Print-Job", "successful-ok"):
            self.assertNotIn(value, json.dumps(event))
        self.assertIn("trailing_fields_uninterpreted", event["cloud_soc"]["detail"]["limitations"])
        sample["_source"]["message"] += " unexpected-third-field"
        self.assertIsNone(normalize(sample, NOW)[2])
