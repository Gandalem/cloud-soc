"""List interpretation is allowlisted metadata, never a guessed generic-channel parser."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.portal.log_contract import project_hit
from cloud_soc.portal.log_query import project_list_hit


def hit(code=4625, channel="Security", provider="Microsoft-Windows-Security-Auditing"):
    return {"_index": "soc-host-raw-test", "_id": "synthetic", "_source": {
        "labels": {"log_source": "windows_event"},
        "event": {"code": str(code), "action": "None"},
        "winlog": {"channel": channel, "provider_name": provider, "event_id": code,
                   "event_data": {"TargetUserName": "fixture-user", "LogonType": "10", "IpAddress": "192.0.2.10"}}}}


class ListInterpretationTests(unittest.TestCase):
    def test_none_opcode_not_an_action_and_identifiers_are_preserved(self):
        for placeholder in ("None", "none", " null ", "-"):
            event = hit(21, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                        "Microsoft-Windows-TerminalServices-LocalSessionManager")
            event["_source"]["event"]["action"] = placeholder
            event["_source"]["winlog"]["user"] = {"identifier": "S-1-5-18"}
            original = deepcopy(event)
            row = project_list_hit(event)
            self.assertIsNone(row["action"])
            self.assertEqual(row["event_code"], "21")
            self.assertEqual(row["provider"], event["_source"]["winlog"]["provider_name"])
            self.assertEqual(row["actor_id"], "S-1-5-18")
            self.assertEqual(row["parse_status"], "unsupported")
            self.assertEqual(row["interpretation"]["fields"], {})
            self.assertIsNone(row["source_ip"])
            self.assertEqual(row["outcome"], "unknown")
            self.assertEqual(event, original)

    def test_provider_opcode_preserved_without_success_guess(self):
        event = hit(3077, "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-CodeIntegrity")
        event["_source"]["event"]["action"] = "CreateSection"
        row = project_list_hit(event)
        self.assertEqual(row["action"], "CreateSection")
        self.assertEqual(row["outcome"], "unknown")
        self.assertEqual(row["parse_status"], "unsupported")

    def test_supported_login_summary_uses_existing_adapter_not_raw_mutation(self):
        event = hit()
        row = project_list_hit(event)
        self.assertEqual(row["parse_status"], "recognized")
        fields = row["interpretation"]["fields"]
        self.assertEqual(fields["action"], "login")
        self.assertEqual(fields["outcome"], "failure")
        self.assertEqual(fields["target_user"], "fixture-user")
        self.assertEqual(fields["source_ip"], "192.0.2.10")
        self.assertEqual(row["outcome"], "unknown")
        self.assertIsNone(row["user"])
        self.assertEqual(project_hit(event)["parse_status"], "not_evaluated")

    def test_partial_wrong_provider_conflict_and_unknown_source(self):
        event = hit()
        del event["_source"]["winlog"]["event_data"]["LogonType"]
        self.assertEqual(project_list_hit(event)["parse_status"], "partial")
        for change in (lambda s: s["winlog"].update(provider_name="Other"),
                       lambda s: s["event"].update(code="4624"),
                       lambda s: s["labels"].update(log_source="network_packetbeat"),
                       lambda s: s["labels"].update(log_source="windows_file")):
            event = hit()
            change(event["_source"])
            row = project_list_hit(event)
            self.assertEqual(row["parse_status"], "unsupported")
            self.assertEqual(row["interpretation"]["fields"], {})

    def test_identifiers_fallback_and_malformed_sid_not_forwarded(self):
        event = hit()
        del event["_source"]["event"]["code"]
        self.assertEqual(project_list_hit(event)["event_code"], "4625")
        event["_source"]["winlog"].update(event_id=65536, user={"identifier": "not-a-sid"})
        row = project_list_hit(event)
        self.assertIsNone(row["event_code"])
        self.assertIsNone(row["actor_id"])

    def test_summary_does_not_forward_secret_raw_or_process_fields(self):
        event = hit()
        event["_source"].update(message="BODY_CANARY", api_key="KEY_CANARY", process={"command_line": "CMD_CANARY"})
        event["_source"]["winlog"]["event_data"].update(Password="PASSWORD_CANARY", NewProcessName="PATH_CANARY")
        encoded = json.dumps(project_list_hit(event))
        for marker in ("BODY_CANARY", "KEY_CANARY", "CMD_CANARY", "PASSWORD_CANARY", "PATH_CANARY"):
            self.assertNotIn(marker, encoded)

    def test_cloud_event_id_and_original_api_not_guessed_from_windows_fields(self):
        event = hit()
        event["_index"] = "soc-cloud-aws-test"
        event["_source"]["labels"]["log_source"] = "aws_cloudtrail"
        event["_source"]["event"] = {"id": "synthetic-cloud-event", "action": "ConsoleLogin"}
        row = project_list_hit(event)
        self.assertEqual(row["event_code"], "synthetic-cloud-event")
        self.assertEqual(row["action"], "ConsoleLogin")
        self.assertEqual(row["interpretation"]["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
