"""Fixed error codes preserve actionable failures without exporting secrets."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from elasticsearch import ApiError
from cloud_soc.processing.errors import error_code


class WorkerErrorTests(unittest.TestCase):
    def test_api_status_is_projected_without_response_body(self):
        for status, expected in ((401, 'authentication_failed_or_key_expired'),
                                 (403, 'authorization_denied'), (429, 'elasticsearch_overloaded')):
            error = ApiError('PRIVATE_CANARY', meta=Mock(status=status), body={'reason': 'PRIVATE_CANARY'})
            self.assertEqual(error_code(error), expected)
        self.assertEqual(error_code(RuntimeError('PRIVATE_CANARY')), 'processing_failed')
        self.assertEqual(error_code(ValueError({'secret': 'PRIVATE_CANARY'})), 'processing_failed')
        self.assertEqual(error_code(ValueError('rule_or_scope_changed_requires_new_state')),
                         'rule_or_scope_changed_requires_new_state')

    def test_sqlite_lock_is_reported_without_path(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'state.sqlite'
            with sqlite3.connect(path) as first, sqlite3.connect(path, timeout=0) as second:
                first.execute('CREATE TABLE sample(id INTEGER)'); first.commit()
                first.execute('BEGIN IMMEDIATE')
                try:
                    second.execute('BEGIN IMMEDIATE')
                except sqlite3.OperationalError as error:
                    self.assertEqual(error_code(error), 'checkpoint_locked')
                else:
                    self.fail('Expected lock conflict')
