from copy import deepcopy
import json
import unittest

from cloud_soc.portal.security_detail import DETAIL_FIELDS, security_detail, number, guid
from cloud_soc.portal.log_query import LogReader
from test_log_query import client, FIXTURE


def windows(code="4625", *, sysmon=False, **data):
    return {"event": {"code": code}, "organization": {"id": "fixture"}, "host": {"id": "host-fixture"},
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational" if sysmon else "Security",
                       "provider_name": "Microsoft-Windows-Sysmon" if sysmon else "Microsoft-Windows-Security-Auditing",
                       "event_id": code, "event_data": data}}


class SecurityDetailTests(unittest.TestCase):
    def test_login_subject_and_target_are_distinct(self):
        for code, outcome in (("4624", "success"), ("4625", "failure")):
            result = security_detail(windows(code, SubjectUserName="actor", TargetUserName="target", LogonType="10", IpAddress="2001:db8::1", IpPort="50000"))
            self.assertEqual(result["status"], "recognized")
            self.assertEqual(result["fields"]["outcome"], outcome)
            self.assertEqual(result["fields"]["actor"], "actor")
            self.assertEqual(result["fields"]["target_user"], "target")
            self.assertEqual(result["fields"]["source_port"], 50000)
            self.assertEqual(result["audit_configuration"], "not_checked")

    def test_provider_channel_and_code_must_all_agree(self):
        for path, value in (("channel", "Application"), ("channel", []), ("provider_name", "other"), ("event_id", "4624"), ("event_id", [4625])):
            source = windows()
            source["winlog"][path] = value
            self.assertEqual(security_detail(source)["status"], "unsupported")
        self.assertEqual(security_detail({"event": {"code": "4625"}})["status"], "unsupported")

    def test_unknown_and_missing_do_not_claim_successful_parsing(self):
        for source in (None, [], {}, windows("9999")):
            self.assertEqual(security_detail(source)["status"], "unsupported")
        result = security_detail(windows())
        self.assertEqual(result["status"], "partial")
        self.assertIn("target_user", result["missing"])

    def test_account_and_group_changes(self):
        for code in ("4720", "4726"):
            self.assertEqual(security_detail(windows(code, TargetUserName="target"))["fields"]["category"], "account")
        for code in ("4732", "4733"):
            result = security_detail(windows(code, SubjectUserName="actor", TargetUserName="Administrators", MemberSid="S-1-5-21-1001"))
            self.assertEqual(result["fields"]["group"], "Administrators")
            self.assertEqual(result["status"], "recognized")

    def test_privilege_assignment_is_not_privilege_use(self):
        result = security_detail(windows("4672", SubjectUserName="actor", PrivilegeList="SeDebugPrivilege"))
        self.assertIn("privilege_assignment_not_use", result["limitations"])

    def test_process_creation_pid_is_not_entity_identity(self):
        result = security_detail(windows("4688", SubjectUserName="creator", TargetUserName="execution-user", NewProcessId="0x12", NewProcessName="C:\\fixture.exe", ProcessId="0x10", ParentProcessName="C:\\parent.exe", CommandLine="password=CANARY"))
        self.assertEqual(result["fields"]["actor"], "creator")
        self.assertEqual(result["fields"]["execution_user"], "execution-user")
        self.assertEqual(result["fields"]["process_pid"], 18)
        self.assertEqual(result["fields"]["parent_pid"], 16)
        self.assertEqual(result["process_link"], "not_established")
        self.assertNotIn("CANARY", json.dumps(result))

    def test_file_rights_distinguish_object_type_and_do_not_prove_read_content(self):
        result = security_detail(windows("4663", SubjectUserName="actor", ObjectType="File", ObjectName="C:\\approved\\test.txt", AccessMask="0x10003"))
        self.assertEqual(result["fields"]["access_rights"], ["read_data_or_list_directory", "write_data_or_add_file", "delete_right"])
        self.assertIn("access_right_not_exfiltration_or_completed_delete", result["limitations"])
        registry = security_detail(windows("4663", ObjectType="Key", AccessMask="0x1"))
        self.assertEqual(registry["fields"]["category"], "object")
        self.assertNotIn("access_rights", registry["fields"])
        self.assertEqual(security_detail(windows("4656"))["status"], "unsupported")

    def test_sysmon_guid_hash_parent_and_file_change(self):
        source = windows("1", sysmon=True, User="fixture", Image="C:\\fixture.exe", ProcessId="42",
                         ProcessGuid="{11111111-2222-3333-4444-555555555555}",
                         ParentProcessGuid="{11111111-2222-3333-4444-666666666666}",
                         Hashes="MD5=" + "b" * 32 + ",SHA256=" + "A" * 64)
        result = security_detail(source)
        self.assertEqual(result["fields"]["sha256"], "a" * 64)
        self.assertEqual(result["process_link"], "guid_in_same_host_event")
        del source["host"]
        self.assertEqual(security_detail(source)["process_link"], "not_established")
        for code in ("11", "26"):
            self.assertIn("not_file_read_audit", security_detail(windows(code, sysmon=True))["limitations"])
        self.assertEqual(security_detail(windows("23", sysmon=True))["status"], "unsupported")

    def test_sysmon_network_connection_has_explicit_process_only(self):
        result = security_detail(windows("3", sysmon=True, SourceIp="192.0.2.1", DestinationIp="198.51.100.1", DestinationPort="443"))
        self.assertEqual(result["fields"]["destination_port"], 443)
        self.assertEqual(result["process_link"], "not_established")

    def test_configuration_metadata_never_includes_task_commands(self):
        for code in ("4697", "4698", "4702", "4719", "4670"):
            result = security_detail(windows(code, SubjectUserName="actor", TaskName="fixture-task", ServiceName="fixture-service", TaskContent="PRIVATE_CANARY", CommandLine="PRIVATE_CANARY"))
            self.assertEqual(result["fields"]["category"], "configuration")
            self.assertNotIn("CANARY", json.dumps(result))

    def test_selected_metadata_redaction_and_no_mutation(self):
        source = windows("4625", TargetUserName="password=PRIVATE_CANARY", LogonType="10")
        source.update(message="PRIVATE_CANARY", process={"command_line": "PRIVATE_CANARY"})
        before = deepcopy(source)
        result = security_detail(source)
        self.assertEqual(result["fields"]["target_user"], "[REDACTED]")
        self.assertIn("target_user", result["missing"])
        self.assertNotIn("CANARY", json.dumps(result))
        self.assertEqual(source, before)

    def test_numeric_and_guid_validation(self):
        for item in (True, -1, "-1", "1.5", "0x", {}, 2**63):
            self.assertIsNone(number(item))
        for item in ("not-guid", "00000000-0000-0000-0000-000000000000", {}, 123):
            self.assertIsNone(guid(item))

    def test_packetbeat_metadata_never_attributes_process_or_sums_flows(self):
        result = security_detail({"agent": {"type": "packetbeat"}, "labels": {"log_source": "network_packetbeat"},
                                  "source": {"ip": "192.0.2.1", "port": 40000}, "destination": {"ip": "198.51.100.1", "port": 443},
                                  "network": {"bytes": 2048}, "flow": {"final": False},
                                  "dns": {"question": {"name": "fixture.example.test"}},
                                  "tls": {"version": "1.3", "client": {"server_name": "fixture.example.test"}},
                                  "process": {"pid": 42}})
        self.assertEqual(result["fields"]["bytes"], 2048)
        self.assertFalse(result["fields"]["flow_final"])
        self.assertNotIn("process_pid", result["fields"])
        self.assertIn("no_process_or_file_attribution", result["limitations"])

    def test_detail_api_allowlist_and_reference_are_preserved(self):
        es = client()
        es.get.return_value = {**FIXTURE, "_source": windows("4625", TargetUserName="target", LogonType="10")}
        reader = LogReader(es, secret="fixture", principal="fixture")
        response = json.loads(reader.detail([("index", FIXTURE["_index"]), ("id", FIXTURE["_id"])]))
        self.assertEqual(response["security"]["fields"]["target_user"], "target")
        self.assertEqual(response["row"]["reference"]["id"], FIXTURE["_id"])
        fields = es.get.call_args.kwargs["source_includes"]
        for forbidden in ("message", "winlog.event_data", "event.original", "process.command_line", "winlog.event_data.CommandLine", "winlog.event_data.TaskContent"):
            self.assertNotIn(forbidden, fields)
        self.assertTrue(all("*" not in item for item in DETAIL_FIELDS))


if __name__ == "__main__":
    unittest.main()
