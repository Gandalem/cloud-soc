"""Installer protocol/state tests; no real service, credential or capture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'deploy/agents/enrollment-linux.py'
module_spec = importlib.util.spec_from_file_location('linux_enrollment', PATH)
installer = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(installer)


class LinuxEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.spec = {'os': 'ubuntu', 'network': False, 'organization': 'school',
                     'endpoint': 'https://receiver.invalid:9200', 'enrollment_protocol': 1}
        self.token = 'a' * 32 + '.' + 'b' * 43

    def reply(self):
        return {'id': self.token[:32], 'endpoint': self.spec['endpoint'], 'organization': 'school',
                'receipt_verified': False, 'probe': 'c' * 64, 'keys': [{'scope': 'host', 'key': 'synthetic:host'}]}

    def test_role_and_recovery_binding_reject_extra_missing_or_swapped_keys(self):
        self.assertEqual(installer.validate_reply(self.reply(), self.spec, self.token), {'host': 'synthetic:host'})
        for change in ('extra', 'missing', 'server', 'receipt', 'recovery'):
            reply = self.reply()
            if change == 'extra': reply['keys'].append({'scope': 'network', 'key': 'synthetic:network'})
            if change == 'missing': reply['keys'] = []
            if change == 'server': reply['endpoint'] = 'https://other.invalid'
            if change == 'receipt': reply['receipt_verified'] = True
            if change == 'recovery': reply['recovery_probe'] = 'd' * 64
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                installer.validate_reply(reply, self.spec, self.token)

    def bundle(self):
        names = ['package.json','ca.crt','enrollment-linux.py','install-ubuntu.sh','discover-linux.sh','privacy.js']
        for name in names:
            (self.root / name).write_bytes(name.encode())
        (self.root / 'SHA256SUMS').write_text(''.join(hashlib.sha256(name.encode()).hexdigest() + '  ' + name + '\n' for name in names))

    def test_integrity_rejects_tampered_duplicate_traversal_and_missing_network(self):
        self.bundle()
        installer.verify_source(self.root)
        with self.assertRaises(RuntimeError): installer.verify_source(self.root, True)
        sums = self.root / 'SHA256SUMS'
        original = sums.read_text()
        sums.write_text(original + original.splitlines()[0] + '\n')
        with self.assertRaises(RuntimeError): installer.verify_source(self.root)
        sums.write_text('0' * 64 + '  ../outside\n')
        with self.assertRaises(RuntimeError): installer.verify_source(self.root)
        sums.write_text(original)
        (self.root / 'privacy.js').write_text('changed')
        with self.assertRaises(RuntimeError): installer.verify_source(self.root)

    def test_fresh_dry_run_does_not_create_state_or_prompt_or_use_network(self):
        self.bundle()
        roots = {'host': self.root / 'missing-host', 'network': self.root / 'missing-network'}
        state = self.root / 'missing-state'
        with patch.object(installer, 'STATE', state), patch.object(installer, 'ROOTS', roots), \
             patch.object(installer, 'UNIT_ROOT', self.root / 'missing-units'), \
             patch.object(installer.os, 'geteuid', return_value=0, create=True), \
             patch.object(installer, 'tls_context') as tls, patch.object(installer.getpass, 'getpass') as prompt:
            installer.execute(self.root, self.spec, '0' * 64, None, False, True)
            tls.assert_not_called()
            prompt.assert_not_called()
            self.assertFalse(state.exists())
            roots['host'].mkdir()
            with self.assertRaises(RuntimeError):
                installer.execute(self.root, self.spec, '0' * 64, None, False, True)

    def test_failed_scope_and_hashes_cannot_adopt_completed_or_modified_state(self):
        ca = self.root / 'ca.crt'
        ca.write_text('public synthetic CA')
        receipt = {'schema': 1, 'state': 'failed', 'owner': 'a' * 32, 'probe': 'b' * 64,
                   'spec': self.spec, 'ca_sha256': installer.sha(ca), 'files': {'synthetic': 'same'}}
        with patch.object(installer, 'stable', return_value={'synthetic': 'different'}):
            with self.assertRaises(RuntimeError): installer.validate_failed(self.root, self.spec, receipt)
        receipt['state'] = 'complete'
        with self.assertRaises(RuntimeError): installer.validate_failed(self.root, self.spec, receipt)


if __name__ == '__main__':
    unittest.main()
