"""Disposable root-owned Linux paths only; no Beat, systemd or host installation."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from test_install_device_tools import load


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'isolated Linux root path fixture')
class BootstrapLinuxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cloud-soc-bootstrap-test-', dir='/root')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tool = load('deploy/agents/bootstrap-linux.py')
        self.tool.BASE = self.root / 'bundles'
        self.tool.BASE.mkdir(mode=0o700)

    def test_status_and_uninstall_work_without_original_download_or_registration(self):
        target = self.tool.BASE / ('a'*32)
        target.mkdir(mode=0o700)
        (target / 'package.json').write_text('{}')
        (target / 'agent-manager.py').write_text('# synthetic placeholder, never executed\n')
        for action in ('status', 'uninstall', 'install'):
            with (patch('sys.argv', ['bootstrap', action]),
                  patch.object(self.tool, 'prepare', side_effect=AssertionError('must not need a token')),
                  patch.object(self.tool.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as command):
                self.assertEqual(self.tool.main(), 0)
                self.assertEqual(command.call_args.args[0][1:], [str(target / 'agent-manager.py'), action])

    def test_linked_installed_manager_is_rejected_before_execution(self):
        outside = self.root / 'outside'
        outside.mkdir(mode=0o700)
        (outside / 'package.json').write_text('{}')
        (outside / 'agent-manager.py').write_text('# never executed')
        (self.tool.BASE / ('a'*32)).symlink_to(outside, target_is_directory=True)
        with patch('sys.argv', ['bootstrap', 'uninstall']), patch.object(self.tool.subprocess, 'run') as command:
            with self.assertRaises(RuntimeError):
                self.tool.main()
            command.assert_not_called()

    def test_archive_traversal_and_parent_members_never_escape_target(self):
        source = self.root / 'source'
        source.mkdir(mode=0o700)
        (source / 'package.json').write_text(json.dumps({'managed_device_id': 'a'*32}))
        for name in ('../escape.py', '..', '.', '/tmp/escape.py'):
            data = io.BytesIO()
            with zipfile.ZipFile(data, 'w') as archive:
                archive.writestr(name, b'never execute')
            (source / 'runtime.zip').write_bytes(data.getvalue())
            (source / 'registration.json').write_text(json.dumps({'device_id': 'a'*32,
                'runtime_sha256': hashlib.sha256(data.getvalue()).hexdigest()}))
            with self.subTest(member=name), self.assertRaises(RuntimeError):
                self.tool.prepare(source)
        self.assertFalse((self.tool.BASE / 'escape.py').exists())
        self.assertEqual(list((self.tool.BASE / ('a'*32)).iterdir()), [])
