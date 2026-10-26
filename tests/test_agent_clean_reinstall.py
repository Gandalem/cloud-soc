"""Actual disposable files and simulated OS commands; never installs a host collector."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_install_device_tools import load


class LinuxCleanReinstallTests(unittest.TestCase):
    temp_parent = None

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=self.temp_parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.manager = load('deploy/agents/agent-manager.py')
        self.enrollment = load('deploy/agents/enrollment-linux.py')
        self.root_private = self.enrollment.private
        self.state = self.root / 'state'
        self.state.mkdir()
        self.archive = self.state / 'retired-test'
        self.archive.mkdir()
        self.units = self.root / 'units'
        self.units.mkdir()
        self.source = self.root / 'bundle'
        self.source.mkdir()
        self.roots = {'host': self.root / 'cloud-soc-agent', 'network': self.root / 'cloud-soc-network'}
        self.spec = {'package_id': 'a' * 32, 'managed_device_id': 'b' * 32, 'network': False}
        self.session = 'c' * 32
        self.completed = self.state / ('complete-' + self.session + '.json')
        self.operation = {'state': 'removed', 'device_id': self.spec['managed_device_id'], 'session': self.session,
                          'data_preserved': False, 'remote_revocation': 'not_confirmed'}
        self.row = {'state': 'complete', 'spec': self.spec, 'session': self.session, 'files': {}}
        self.write(self.completed, self.row)
        self.write(self.archive / 'operation.json', self.operation)
        if not hasattr(os, 'O_NOFOLLOW'):
            flag = patch.object(os, 'O_NOFOLLOW', 0, create=True)
            flag.start()
            self.addCleanup(flag.stop)
        for name, value in [('STATE', self.state), ('ROOTS', self.roots), ('UNIT_ROOT', self.units), ('private', self.private)]:
            p = patch.object(self.enrollment, name, value)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value), encoding='utf8')

    def private(self, path, directory=False):
        # Filesystem boundary double, not an assertion of actual root ownership/Unix modes.
        path = Path(path)
        if path.is_symlink() or not path.resolve().is_relative_to(self.root) or not path.exists():
            raise RuntimeError('Untrusted trial path')
        if directory and not path.is_dir():
            raise RuntimeError('Directory required')

    def test_deleted_receipt_is_archived_byte_for_byte_then_new_install_is_not_blocked(self):
        before = self.completed.read_bytes()
        self.enrollment.retire_removed_receipts()
        self.assertFalse(self.completed.exists())
        self.assertEqual((self.archive / self.completed.name).read_bytes(), before)
        self.enrollment.retire_removed_receipts()
        self.assertEqual(list(self.state.glob('complete-*.json')), [])

    def test_preserved_or_partial_removal_cannot_be_used_for_fresh_install(self):
        for state, preserved in [('removed', True), ('removing', False), ('purging', True)]:
            with self.subTest(state=state, preserved=preserved):
                self.write(self.archive / 'operation.json', {**self.operation, 'state': state, 'data_preserved': preserved})
                with self.assertRaises(RuntimeError):
                    self.enrollment.retire_removed_receipts()
                self.assertTrue(self.completed.exists())

    def test_remaining_collector_unit_or_retained_tree_blocks_archival(self):
        for path in [self.roots['host'], self.units / 'cloud-soc-discovery.timer', self.archive / self.roots['host'].name]:
            with self.subTest(path=path.name):
                path.write_bytes(b'keep')
                with self.assertRaises(RuntimeError):
                    self.enrollment.retire_removed_receipts()
                self.assertEqual(path.read_bytes(), b'keep')
                path.unlink()

    def test_other_device_or_session_and_existing_history_are_not_overwritten(self):
        for change in [{'spec': {**self.spec, 'managed_device_id': 'd' * 32}}, {'session': 'e' * 32}, {'state': 'failed'}]:
            with self.subTest(change=change):
                self.write(self.completed, {**self.row, **change})
                with self.assertRaises(RuntimeError):
                    self.enrollment.retire_removed_receipts()
                self.assertTrue(self.completed.exists())
        self.write(self.completed, self.row)
        target = self.archive / self.completed.name
        target.write_bytes(b'previous-history')
        with self.assertRaises(RuntimeError):
            self.enrollment.retire_removed_receipts()
        self.assertEqual(target.read_bytes(), b'previous-history')

    def test_archive_rename_failure_preserves_the_original_receipt(self):
        with patch.object(Path, 'rename', side_effect=OSError('trial rename failure')):
            with self.assertRaises(OSError):
                self.enrollment.retire_removed_receipts()
        self.assertTrue(self.completed.exists())
        self.assertFalse((self.archive / self.completed.name).exists())

    def test_new_bundle_enters_existing_enrollment_with_new_registration_and_no_recovery(self):
        new_spec = {**self.spec, 'package_id': 'd' * 32, 'managed_device_id': 'e' * 32}
        registration = {'enrollment_id': 'f' * 32, 'package_sha256': '0' * 64, 'token': 'synthetic-one-time-value'}
        self.write(self.source / 'package.json', new_spec)
        self.write(self.source / 'registration.json', registration)
        locks = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=Mock())
        local_os = SimpleNamespace(name='posix', geteuid=lambda: 0, open=os.open, close=os.close,
                                   O_RDWR=os.O_RDWR, O_CREAT=os.O_CREAT, O_NOFOLLOW=os.O_NOFOLLOW)
        with (patch.object(self.manager, '__file__', str(self.source / 'agent-manager.py')),
              patch.object(self.manager, 'enrollment', return_value=self.enrollment),
              patch.object(self.manager, 'os', local_os),
              patch.dict(sys.modules, {'fcntl': locks}),
              patch.object(self.enrollment, 'execute') as execute,
              patch('sys.argv', ['agent-manager', 'install']), patch('sys.stdout', new=io.StringIO())):
            self.assertEqual(self.manager.main(), 0)
        self.assertEqual(execute.call_args.args[:6], (self.source, new_spec, '0' * 64, None, False, False))
        self.assertEqual(execute.call_args.kwargs['registration'], registration)
        self.assertEqual(len(execute.call_args.kwargs['attempt']), 43)
        self.assertTrue((self.archive / self.completed.name).exists())
        self.assertFalse((self.source / 'registration.json').exists())

    def retained(self):
        self.operation['data_preserved'] = True
        self.target = self.archive / self.roots['host'].name
        self.target.mkdir()
        config = self.target / 'filebeat.yml'
        config.write_bytes(b'synthetic-protected-config')
        (self.target / 'queue').write_bytes(b'synthetic-unsent-data')
        self.row['files'] = {str(self.roots['host'] / 'filebeat.yml'): hashlib.sha256(config.read_bytes()).hexdigest()}
        self.write(self.completed, self.row)
        self.write(self.archive / 'operation.json', self.operation)
        self.write(self.source / 'managed-local.json', {'state': 'removed', 'device_id': self.spec['managed_device_id']})
        command = Mock(side_effect=lambda args, **kwargs: SimpleNamespace(returncode=3 if args[0] == 'systemctl' else 1))
        self.commands = command
        return SimpleNamespace(STATE=self.state, ROOTS=self.roots, UNIT_ROOT=self.units, private=self.private, re=re,
                               roles=self.enrollment.roles, units=self.enrollment.units, sha=self.enrollment.sha,
                               save=self.enrollment.save, subprocess=SimpleNamespace(run=command, DEVNULL=subprocess.DEVNULL))

    def test_explicit_retained_data_deletion_then_archive_preserves_history(self):
        module = self.retained()
        with patch('sys.stdout', new=io.StringIO()):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads((self.archive / 'operation.json').read_text())['data_preserved'], False)
        self.assertTrue(self.completed.exists())
        self.enrollment.retire_removed_receipts()
        self.assertTrue((self.archive / self.completed.name).exists())

    def test_cancel_and_tampered_config_never_delete_retained_queue(self):
        module = self.retained()
        with patch('sys.stdout', new=io.StringIO()):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'no')
        self.assertEqual((self.target / 'queue').read_bytes(), b'synthetic-unsent-data')
        (self.target / 'filebeat.yml').write_bytes(b'tampered')
        with self.assertRaises(RuntimeError):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertTrue((self.target / 'queue').exists())

    def test_active_process_and_unknown_file_scope_block_purge(self):
        module = self.retained()
        self.commands.side_effect = lambda args, **kwargs: SimpleNamespace(returncode=0)
        with self.assertRaises(RuntimeError):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.commands.side_effect = lambda args, **kwargs: SimpleNamespace(returncode=3 if args[0] == 'systemctl' else 1)
        self.row['files'][str(self.root / 'unrelated')] = '0' * 64
        self.write(self.completed, self.row)
        with self.assertRaises(RuntimeError):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertTrue((self.target / 'queue').exists())

    def test_failed_delete_retains_purging_state_and_retry_finishes_same_operation(self):
        module = self.retained()
        with patch.object(self.manager.shutil, 'rmtree', side_effect=OSError('trial disk failure')):
            with patch('sys.stdout', new=io.StringIO()), self.assertRaises(OSError):
                self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertEqual(json.loads((self.archive / 'operation.json').read_text())['state'], 'purging')
        self.assertTrue(self.target.exists())
        with patch('sys.stdout', new=io.StringIO()):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads((self.archive / 'operation.json').read_text())['state'], 'removed')

    def test_local_state_save_failure_does_not_hide_remote_revocation_or_erase_history(self):
        module = self.retained()
        real_save = module.save
        def save(path, value):
            if path.name == 'managed-local.json':
                raise OSError('trial local state failure')
            real_save(path, value)
        module.save = save
        with patch('sys.stdout', new=io.StringIO()), self.assertRaises(OSError):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertEqual(json.loads((self.archive / 'operation.json').read_text())['remote_revocation'], 'not_confirmed')
        module.save = real_save
        with patch('sys.stdout', new=io.StringIO()):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertTrue(self.completed.exists())


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'isolated Linux root filesystem required')
class LinuxRootCleanReinstallTests(LinuxCleanReinstallTests):
    """Same cases with real Unix ownership checks; intended for a disposable container."""
    temp_parent = '/root'

    def private(self, path, directory=False):
        if not Path(path).is_relative_to(self.root):
            raise RuntimeError('Outside trial root')
        self.root_private(path, directory=directory)

    def test_actual_symlink_and_hardlink_are_rejected_before_deleting_data(self):
        module = self.retained()
        outside = self.root / 'keep-outside'
        outside.write_bytes(b'unrelated-original')
        config = self.target / 'filebeat.yml'
        config.unlink()
        config.symlink_to(outside)
        with self.assertRaises(RuntimeError):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertEqual(outside.read_bytes(), b'unrelated-original')
        config.unlink()
        os.link(outside, config)
        with self.assertRaises(RuntimeError):
            self.manager.purge_removed(module, self.spec, self.source, confirm=lambda _: 'DELETE')
        self.assertEqual(outside.read_bytes(), b'unrelated-original')


if __name__ == '__main__':
    unittest.main()
