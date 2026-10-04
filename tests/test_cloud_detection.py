from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_cloudtrail import EVENTS, projected
from test_intake_detection import client_for
from cloud_soc.aws.network_risk import public_management_ingress
from cloud_soc.oci.audit import project_event as oci_project
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.detection.worker import approved_rules, run_once
from cloud_soc.detection.engine import detect_events, condition_matches
from cloud_soc.detection.rule_loader import validate_rule
from cloud_soc.detection.incremental import run_incremental, utc
from cloud_soc.main import make_alert_id

ROOT = Path(__file__).resolve().parents[1]


def event(action, provider='iam.amazonaws.com', request=None, failure=False, number=1):
    value = deepcopy(EVENTS[1])
    value.update(eventName=action, eventSource=provider, requestParameters=request or {},
                 eventID=f'11111111-2222-3333-4444-{number:012d}')
    value.pop('errorCode', None)
    if failure: value['errorCode'] = 'AccessDenied'
    index, identifier, source = projected(value)
    source['event']['ingested'] = value['eventTime']
    key, record, result = normalize({'_index': index, '_id': identifier, '_source': source}, value['eventTime'])
    assert record['status'] == 'normalized'
    result['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    return result


def ingress(port=22, cidr='0.0.0.0/0', protocol='tcp', upper=None):
    key, name = ('ipv6Ranges', 'cidrIpv6') if ':' in cidr else ('ipRanges', 'cidrIp')
    return {'ipPermissions': {'items': [{'ipProtocol': protocol, 'fromPort': port,
            'toPort': port if upper is None else upper, key: {'items': [{name: cidr}]}}]}}


class CloudDetectionTests(unittest.TestCase):
    def detections(self, values):
        return detect_events(values, approved_rules(include_cloud=True))

    def test_high_privilege_attachment(self):
        for action in ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy'):
            result = self.detections([event(action, request={'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'})])
            self.assertEqual([r['rule_id'] for r in result], ['AWS-IAM-001'])
            self.assertEqual(result[0]['event_count'], 1)
            self.assertEqual(len(result[0]['evidence']), 1)
            self.assertTrue(result[0]['evidence'][0]['complete'])

    def test_read_only_and_missing_policy_are_not_privilege_alerts(self):
        for request in ({}, {'policyArn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}):
            self.assertEqual(self.detections([event('AttachUserPolicy', request=request)]), [])

    def test_failed_and_wrong_provider_do_not_alert(self):
        self.assertEqual(self.detections([event('StopLogging', 'cloudtrail.amazonaws.com', failure=True)]), [])
        self.assertEqual(self.detections([event('StopLogging', 'iam.amazonaws.com')]), [])

    def test_audit_stop_and_delete(self):
        for action in ('StopLogging', 'DeleteTrail'):
            row = event(action, 'cloudtrail.amazonaws.com', {'name': 'fixture-trail'})
            self.assertEqual(row['cloud_soc']['detail']['fields']['target_trail'], 'fixture-trail')
            self.assertEqual(self.detections([row])[0]['rule_id'], 'AWS-AUDIT-001')

    def test_public_ipv4_ipv6_ranges_and_all_protocols(self):
        requests = [ingress(), ingress(3389, '::/0'), ingress(20, upper=30), ingress(protocol='-1')]
        for request in requests:
            self.assertTrue(public_management_ingress(request))
            self.assertEqual(self.detections([event('AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', request)])[0]['rule_id'], 'AWS-NETWORK-001')

    def test_private_web_and_missing_permissions_do_not_alert(self):
        for request in (ingress(cidr='10.0.0.0/8'), ingress(port=443), ingress(protocol='udp'), {}):
            self.assertEqual(self.detections([event('AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', request)]), [])
        self.assertIsNone(public_management_ingress({}))

    def test_no_cross_permission_port_cidr_join(self):
        first = ingress(cidr='10.0.0.0/8')['ipPermissions']['items'][0]
        second = ingress(port=443)['ipPermissions']['items'][0]
        self.assertFalse(public_management_ingress({'ipPermissions': {'items': [first, second]}}))

    def test_two_same_timestamp_single_events_are_independent(self):
        rows = [event('StopLogging', 'cloudtrail.amazonaws.com', number=n) for n in (1, 2)]
        matches = self.detections(rows)
        self.assertEqual(len(matches), 2)
        self.assertNotEqual(make_alert_id(matches[0]), make_alert_id(matches[1]))
        self.assertEqual({make_alert_id(d) for d in self.detections(list(reversed(rows)))}, {make_alert_id(d) for d in matches})

    def test_oci_policy_change_and_failed_result(self):
        fixture = json.loads((ROOT / 'tests/fixtures/oci_audit.json').read_text())
        for status, expected in [('200', 1), ('403', 0)]:
            value = deepcopy(fixture['events'][2])
            value['data']['response']['status'] = status
            index, key, source = oci_project(value, tenancy=fixture['tenancy'], compartment=fixture['compartment'], region=fixture['region'], organization='fixture')
            source['event']['ingested'] = value['event_time']
            identifier, record, row = normalize({'_index': index, '_id': key, '_source': source}, value['event_time'])
            row['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': identifier}
            matches = self.detections([row])
            self.assertEqual(len(matches), expected)
            if expected: self.assertEqual(matches[0]['rule_id'], 'OCI-IAM-001')

    def test_sensitive_request_content_is_not_retained(self):
        request = ingress()
        request.update(password='PRIVATE_CANARY', userData='PRIVATE_CANARY')
        row = event('AuthorizeSecurityGroupIngress', 'ec2.amazonaws.com', request)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(row))

    def test_default_profile_preserves_ssh_only(self):
        self.assertEqual([r['id'] for r in approved_rules()], ['AUTH-001'])
        self.assertEqual(len(approved_rules(include_cloud=True)), 5)

    def test_missing_negative_condition_and_exists(self):
        self.assertFalse(condition_matches({}, {'field': 'missing', 'operator': 'not_equals', 'value': 'normal'}))
        self.assertFalse(condition_matches({}, {'field': 'missing', 'operator': 'exists', 'value': True}))
        self.assertTrue(condition_matches({'flag': False}, {'field': 'flag', 'operator': 'exists', 'value': True}))

    def test_single_rule_cannot_suppress_other_events(self):
        rule = deepcopy(approved_rules(include_cloud=True)[1])
        rule['cooldown'] = {'seconds': 300}
        with self.assertRaises(ValueError): validate_rule(rule)

    def test_incremental_cloud_profile_and_replay(self):
        row = event('StopLogging', 'cloudtrail.amazonaws.com')
        base = utc(row['@timestamp'])
        row['cloud_soc']['normalized_at'] = (base + timedelta(seconds=10)).isoformat()
        hit = {'_index': NORMALIZED, '_id': row.pop('_cloud_soc_meta')['document_id'], '_source': row}
        client = client_for([])
        client.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {}}}}
        client.count.return_value = {'count': 0}
        with tempfile.TemporaryDirectory() as folder:
            args = dict(state_path=Path(folder)/'state.sqlite', start=base, lateness_seconds=60,
                        include_cloud=True, scanner=lambda *a, **kw: [hit])
            self.assertEqual(run_incremental(client, now=base+timedelta(seconds=140), **args)['created'], 1)
            self.assertEqual(run_incremental(client, now=base+timedelta(seconds=210), **args)['created'], 0)
            self.assertIn('AWS-AUDIT-001', client.index.call_args.kwargs['document']['detection'])
            with self.assertRaises(ValueError):
                run_incremental(client, now=base+timedelta(seconds=280), **{**args, 'include_cloud': False})


if __name__ == '__main__': unittest.main()
