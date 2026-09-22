from copy import deepcopy
import json
import unittest

from cloud_soc.parsers.linux_security import parse_linux_ssh, parse_linux_audit


def records(syscall="59", arch="c000003e", success="yes"):
    lines = [f'type=SYSCALL msg=audit(1790000000.123:123): arch={arch} syscall={syscall} success={success} items=1 auid=1000 uid=1000 euid=0 pid=42 ppid=40 exe="/usr/bin/fixture"',
             'type=PATH msg=audit(1790000000.123:123): item=0 name="/srv/approved/fixture.txt" nametype=NORMAL',
             'type=EXECVE msg=audit(1790000000.123:123): argc=2 a0="fixture" a1="password=PRIVATE_CANARY"',
             'type=PROCTITLE msg=audit(1790000000.123:123): proctitle=PRIVATE_CANARY']
    return [{"organization": "fixture", "host_id": "host-fixture", "line": line} for line in lines]


class LinuxSecurityTests(unittest.TestCase):
    def test_ssh_success_failure_and_time_uncertainty(self):
        for message, outcome in (("Accepted publickey for fixture", "success"), ("Failed password for invalid user fixture", "failure")):
            result = parse_linux_ssh("Sep 22 01:02:00 host sshd[42]: " + message + " from 198.51.100.1 port 55000 ssh2")
            self.assertEqual(result["outcome"], outcome)
            self.assertEqual(result["time_basis"], "year_timezone_required")
            self.assertNotIn("message", result)
            self.assertEqual(result["target_user"], "fixture")

    def test_ssh_unsupported_invalid_and_oversized(self):
        for line in (None, [], "x" * 8193, "useradd: new user", "Sep 22 01:02:00 host sshd[42]: Failed password for fixture from 198.51.100.1 port 99999 ssh2"):
            self.assertIsNone(parse_linux_ssh(line))
        self.assertIsNone(parse_linux_ssh("Sep 22 01:02:00 host sshd[" + "1" * 5000 + "]: Failed password for fixture from 198.51.100.1 port 22 ssh2"))

    def test_audit_execution_and_actor_ids_no_arguments(self):
        source = records()
        before = deepcopy(source)
        result = parse_linux_audit(source)
        self.assertEqual(result["status"], "recognized")
        self.assertEqual(result["login_uid"], 1000)
        self.assertEqual(result["effective_uid"], 0)
        self.assertEqual(result["process_path"], "/usr/bin/fixture")
        self.assertIsNone(result["process_identity"])
        self.assertNotIn("CANARY", json.dumps(result))
        self.assertEqual(source, before)

    def test_open_is_not_read_and_failure_is_preserved(self):
        result = parse_linux_audit(records(syscall="257", success="no"))
        self.assertEqual(result["action"], "open_attempt")
        self.assertEqual(result["outcome"], "failure")
        self.assertFalse(result["file_read_proven"])

    def test_unknown_arch_and_syscall_not_guessed(self):
        for source in (records(arch="c00000b7"), records(syscall="999")):
            result = parse_linux_audit(source)
            self.assertEqual(result["action"], "unsupported_syscall")
            self.assertEqual(result["status"], "partial")

    def test_mixed_host_organization_or_audit_id_rejected(self):
        for key, value in (("host_id", "other"), ("organization", "other"), ("line", records()[1]["line"].replace(":123)", ":124)"))):
            source = records()
            source[1][key] = value
            self.assertIsNone(parse_linux_audit(source))

    def test_missing_paths_duplicate_records_and_limits(self):
        self.assertEqual(parse_linux_audit(records()[:1])["status"], "partial")
        for source in (records() + [records()[0]], records() + [records()[1]], [], records() * 17,
                       [{"organization": "fixture", "host_id": "fixture", "line": "x" * 8193}]):
            self.assertIsNone(parse_linux_audit(source))

    def test_unset_auid_hex_paths_and_malformed_fields(self):
        source = records()
        source[0]["line"] = source[0]["line"].replace("auid=1000", "auid=4294967295")
        source[1]["line"] = source[1]["line"].replace('"/srv/approved/fixture.txt"', "2F746D702F66696C65")
        result = parse_linux_audit(source)
        self.assertIsNone(result["login_uid"])
        self.assertIsNone(result["paths"][0]["path"])
        self.assertEqual(result["status"], "partial")
        source[0]["line"] += " pid=99"
        self.assertIsNone(parse_linux_audit(source))

    def test_selected_metadata_is_filtered_and_missing_execution_data_is_partial(self):
        source = records()
        source[0]["line"] = source[0]["line"].replace('/usr/bin/fixture', '/srv/password=PRIVATE_CANARY')
        result = parse_linux_audit(source)
        self.assertEqual(result["process_path"], "[REDACTED]")
        self.assertEqual(result["status"], "partial")
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
