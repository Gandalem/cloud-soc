"""Synthetic canaries only; never read personal files or production events."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cloud_soc.portal.privacy import display
from cloud_soc.portal.log_contract import project_hit, parse_filters, document_reference
from cloud_soc.portal.agent_status import encode_cursor


class PrivacyTests(unittest.TestCase):
    def test_metadata_strings_are_checked_before_truncation(self):
        for text in ('password=CANARY', 'Bearer CANARY', 'https://host/?other=CANARY',
                     'https://user:CANARY@host/', 'x' * 600 + ' token=CANARY'):
            hit = {'_index': 'soc-host-raw-test', '_id': '1', '_source': {
                'host': {'name': text}, 'user': {'name': text}, 'message': 'RAW_CANARY',
                'log': {'file': {'path': text}}, 'event': {'original': 'RAW_CANARY'}}}
            rendered = json.dumps(project_hit(hit))
            self.assertNotIn('CANARY', rendered)
            self.assertIn('[REDACTED]', rendered)
        self.assertEqual(display('ordinary-host'), 'ordinary-host')

    def test_cursor_and_reference_do_not_encode_detected_secrets(self):
        with self.assertRaises(ValueError):
            parse_filters([('host', 'password=CANARY')])
        with self.assertRaises(ValueError):
            document_reference('soc-host-raw-test', 'token=CANARY')
        with self.assertRaises(ValueError):
            encode_cursor({'agent_id': 'password=CANARY'})
