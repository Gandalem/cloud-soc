"""Regression tests for explicitly allowlisted unsupported host audit metadata."""
import copy
import json
import unittest

from cloud_soc.parsers.unsupported_metadata import selected_host_audit
from cloud_soc.processing.contract import normalize

STAMP = "2026-11-12T01:30:00Z"


def hit(source, identifier="test-raw"):
    base = {"@timestamp": STAMP, "event": {"ingested": STAMP},
            "organization": {"id": "lab"}, "host": {"id": "host-test"},
            "agent": {"type": "filebeat"}}
    base.update(source)
    return {"_index": "soc-host-raw-test", "_id": identifier, "_source": base}


def linux(name, transport="audit"):
    return hit({"labels": {"log_source": "linux_journald"},
                "systemd": {"transport": transport},
                "journald": {"custom": {"audit_type_name": name,
                                        "audit_field_unit": "unit-fixture.service"}},
                "message": "PRIVATE_CANARY password=PRIVATE_CANARY"})


def windows(channel, provider, code, data=None):
    return hit({"labels": {"log_source": "windows_event"},
                "winlog": {"channel": channel, "provider_name": provider,
                           "event_id": code, "event_data": data or {}},
                "event": {"ingested": STAMP, "code": code},
                "message": "PRIVATE_CANARY script and secret"})


class HostAuditTests(unittest.TestCase):
    def test_selected_linux_audit_types_only(self):
        kinds = {
            "SERVICE_START": "audit_service_started",
            "SERVICE_STOP": "audit_service_stopped",
            "AVC": "selinux_avc_observed",
            "USER_AVC": "selinux_user_avc_observed",
            "SECCOMP": "seccomp_audit_observed",
            "BPF": "bpf_audit_observed",
        }
        for name, action in kinds.items():
            with self.subTest(name=name):
                item = linux(name)
                original = copy.deepcopy(item)
                key, rec, event = normalize(item, STAMP)
                self.assertEqual(item, original)
                self.assertEqual(rec["status"], "normalized")
                self.assertEqual(rec["version"], "selected-host-audit-v1")
                self.assertEqual(event["event"]["action"], action)
                self.assertEqual(event["event"]["outcome"], "unknown")
                self.assertEqual(event["cloud_soc"]["detail"]["adapter"], "linux_audit_metadata_v1")
                self.assertNotIn("PRIVATE_CANARY", json.dumps([rec, event]))
                self.assertEqual(key, normalize(item, STAMP)[0])

    def test_linux_non_audit_or_unselected_types_not_promoted(self):
        for name, transport in (("OTHER", "audit"), ("AVC", "stdout"),
                                ("SYSCALL", "audit"), ("MAC_TASK_CONTEXTS", "audit")):
            with self.subTest(name=name, transport=transport):
                self.assertIsNone(selected_host_audit(linux(name, transport)["_source"]))

    def test_windows_security_credential_read_not_successful_theft(self):
        event = windows("Security", "Microsoft-Windows-Security-Auditing",
                        "5379", {"SubjectUserName": "analyst", "TargetName": "PRIVATE_CANARY"})
        _, record, normalized = normalize(event, STAMP)
        self.assertEqual(record["status"], "normalized")
        self.assertEqual(normalized["event"]["action"], "credential_manager_read_audit")
        self.assertEqual(normalized["event"]["outcome"], "unknown")
        self.assertEqual(normalized["user"]["name"], "analyst")
        self.assertNotIn("PRIVATE_CANARY", json.dumps([record, normalized]))

    def test_windows_credential_missing_actor_remains_partial(self):
        event = windows("Security", "Microsoft-Windows-Security-Auditing", "5379")
        _, rec, out = normalize(event, STAMP)
        self.assertEqual(rec["status"], "normalized")
        self.assertEqual(out["cloud_soc"]["parse_status"], "partial")
        self.assertEqual(out["cloud_soc"]["detail"]["missing"], ["actor"])

    def test_windows_powershell_defender_system_metadata_only(self):
        cases = [
            ("Microsoft-Windows-PowerShell/Operational",
             "Microsoft-Windows-PowerShell", "4104", "powershell_script_block_logged"),
            ("Microsoft-Windows-Windows Defender/Operational",
             "Microsoft-Windows-Windows Defender", "5007", "defender_configuration_changed"),
            ("System", "Service Control Manager", "7036", "windows_service_state_observed"),
        ]
        for channel, provider, code, action in cases:
            with self.subTest(code=code):
                event = windows(channel, provider, code, {"ScriptBlockText": "PRIVATE_CANARY",
                                                           "New Value": "PRIVATE_CANARY"})
                _, rec, out = normalize(event, STAMP)
                self.assertEqual(rec["status"], "normalized")
                self.assertEqual(out["event"]["action"], action)
                self.assertEqual(out["event"]["outcome"], "unknown")
                self.assertNotIn("PRIVATE_CANARY", json.dumps([rec, out]))

    def test_windows_wrong_provider_code_and_source_scope_rejected(self):
        base = windows("Security", "Microsoft-Windows-Security-Auditing", "5379",
                       {"SubjectUserName": "fixture"})
        for key, bad in (("provider_name", "Someone Else"), ("event_id", "4625"),
                         ("channel", "Application")):
            item = copy.deepcopy(base)
            item["_source"]["winlog"][key] = bad
            self.assertIsNone(selected_host_audit(item["_source"]))
        item = copy.deepcopy(base)
        item["_source"]["agent"]["type"] = "not-filebeat"
        self.assertIsNone(selected_host_audit(item["_source"]))
        item = copy.deepcopy(base)
        item["_index"] = "soc-network-test"
        _, rec, out = normalize(item, STAMP)
        self.assertEqual(rec["reason"], "source_scope_mismatch")
        self.assertIsNone(out)

    def test_cron_and_ssm_operational_logs_not_promoted(self):
        for source in (
            {"labels": {"log_source": "linux_journald"},
             "systemd": {"transport": "syslog"}, "process": {"name": "CRON"}},
            {"labels": {"log_source": "linux_journald"},
             "systemd": {"transport": "stdout", "unit": "amazon-ssm-agent.service"}},
            {"labels": {"log_source": "linux_file"},
             "log": {"file": {"path": "/var/log/auth.log"}}},
        ):
            self.assertIsNone(selected_host_audit(hit(source)["_source"]))


if __name__ == "__main__":
    unittest.main()
