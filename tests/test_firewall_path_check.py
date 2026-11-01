"""Offline mutation/rollback boundary checks; never contact AWS."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('firewall_path', Path(__file__).parents[1] /
                                              'deploy/aws/firewall-path-check.py')
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


class Fake:
    def __init__(self):
        self.calls = []
        self.data = [
            {'RouteTableId': fw.MAIN, 'VpcId': fw.VPC, 'Routes': [{'DestinationCidrBlock': '10.250.0.0/16',
             'GatewayId': 'local', 'State': 'active'}], 'Associations': [{'Main': True}]},
            {'RouteTableId': fw.MALL, 'VpcId': fw.VPC, 'Routes': [{'DestinationCidrBlock': '0.0.0.0/0',
             'GatewayId': fw.IGW, 'State': 'active'}], 'Associations': [{'SubnetId': fw.SUBNET}]},
        ]
        self.before = copy.deepcopy(self.data)
        self.state = {'schema': fw.OWNER, 'account': fw.ACCOUNT, 'vpc': fw.VPC,
                      'change_id': 'a' * 32, 'before': self.before, 'replace_attempted': True}

    def __call__(self, *args):
        self.calls.append(args)
        op = args[1]
        if op == 'get-caller-identity':
            return {'Account': fw.ACCOUNT}
        if op == 'describe-route-tables':
            return {'RouteTables': copy.deepcopy(self.data)}
        if op == 'replace-route':
            self.data[1]['Routes'][0] = {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': fw.IGW, 'State': 'active'}
        elif op == 'disassociate-route-table':
            for table in self.data:
                table['Associations'] = [a for a in table['Associations']
                                         if a.get('RouteTableAssociationId') != args[-1]]
        elif op == 'delete-route-table':
            self.data = [t for t in self.data if t['RouteTableId'] != args[-1]]
        else:
            raise AssertionError(args)
        return {}

    def owned(self, role, association):
        table = {'RouteTableId': 'rtb-test-' + role, 'VpcId': fw.VPC, 'Routes': [],
                 'Tags': [{'Key': fw.OWNER_KEY, 'Value': self.state['change_id']},
                          {'Key': 'cloud-soc:purpose', 'Value': fw.OWNER},
                          {'Key': 'cloud-soc:role', 'Value': role}], 'Associations': [association]}
        self.data.append(table)
        return table


def test_default_plan_never_contacts_aws(monkeypatch, capsys):
    monkeypatch.setattr(fw, 'aws', lambda *a: pytest.fail('AWS contacted'))
    assert fw.main([]) == 0
    assert json.loads(capsys.readouterr().out)['approval_required'] is True


def test_preflight_account_mismatch_stops_before_any_write():
    calls = []
    def call(*args):
        calls.append(args)
        return {'Account': '000000000000'}
    with pytest.raises(fw.Stop, match='account_mismatch'):
        fw.preflight(call)
    assert len(calls) == 1


def test_preflight_changed_inventory_stops_before_any_write():
    fake = Fake()
    fake.data.append({'RouteTableId': 'rtb-teammate'})
    with pytest.raises(fw.Stop, match='inventory_changed'):
        fw.preflight(fake)
    assert all(c[1] in ('get-caller-identity', 'describe-route-tables') for c in fake.calls)


def approved_responses():
    fake = Fake()
    for table in fake.data:
        table['Routes'] = [{'DestinationCidrBlock': '10.250.0.0/16', 'GatewayId': 'local', 'State': 'active'},
                           {'DestinationCidrBlock': '169.254.170.248/29', 'GatewayId': 'GuardDuty', 'State': 'active'},
                           {'DestinationIpv6CidrBlock': 'fd00:ec2:6d00::/64', 'GatewayId': 'GuardDuty', 'State': 'active'}]
    fake.data[1]['Routes'].append({'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': fw.IGW, 'State': 'active'})
    group_arn = f'arn:aws:network-firewall:{fw.REGION}:{fw.ACCOUNT}:stateful-rulegroup/cloud-soc-stateful-test'
    return {
        'get-caller-identity': {'Account': fw.ACCOUNT},
        'describe-route-tables': {'RouteTables': fake.data},
        'describe-subnets': {'Subnets': [{'SubnetId': subnet, 'VpcId': fw.VPC, 'AvailabilityZone': 'ap-northeast-3b',
                                        'CidrBlock': cidr} for subnet, cidr in
                                       ((fw.SUBNET, '10.250.10.0/24'), (fw.FW_SUBNET, '10.250.4.0/28'))]},
        'describe-network-interfaces': {'NetworkInterfaces': [{'NetworkInterfaceId': identifier} for identifier in
                                      ('eni-09f0031d9334bb978', 'eni-090fb707c7cdcee4e', 'eni-008b63de03827e412')]},
        'describe-instances': {'Reservations': [{'Instances': [{'State': {'Name': 'running'}, 'SubnetId': fw.SUBNET,
                                'PrivateIpAddress': '10.250.10.156', 'PublicIpAddress': '198.51.100.1'}]}]},
        'describe-internet-gateways': {'InternetGateways': [{'Attachments': [{'State': 'available', 'VpcId': fw.VPC}]}]},
        'describe-firewall': {'Firewall': {'VpcId': fw.VPC, 'SubnetMappings': [{'SubnetId': fw.FW_SUBNET,
                                'IPAddressType': 'IPV4'}], 'FirewallPolicyArn':
                                f'arn:aws:network-firewall:{fw.REGION}:{fw.ACCOUNT}:firewall-policy/cloud-soc-firewall-policy'},
                              'FirewallStatus': {'Status': 'READY', 'SyncStates': {'ap-northeast-3b': {
                                  'Attachment': {'EndpointId': fw.ENDPOINT, 'Status': 'READY'},
                                  'Config': {group_arn: {'SyncStatus': 'IN_SYNC'}}}}}},
        'describe-firewall-policy': {'FirewallPolicy': {
            'StatelessDefaultActions': ['aws:forward_to_sfe'], 'StatelessFragmentDefaultActions': ['aws:forward_to_sfe'],
            'StatefulDefaultActions': ['aws:alert_established_app_layer_to_server'],
            'StatefulEngineOptions': {'RuleOrder': 'STRICT_ORDER', 'StreamExceptionPolicy': 'REJECT'},
            'StatefulRuleGroupReferences': [{'ResourceArn': group_arn, 'Priority': 1}]}},
        'describe-rule-group': {'RuleGroup': {'RulesSource': {'RulesString': 'alert tcp $HOME_NET any -> any 443 '
            '(msg:"CLOUD_SOC_TEST_HTTPS"; flow:to_server,established; sid:1000001; rev:1;)'},
            'StatefulRuleOptions': {'RuleOrder': 'STRICT_ORDER'},
            'RuleVariables': {'IPSets': {'HOME_NET': {'Definition': ['10.250.0.0/16']}}},
            'ReferenceSets': None}},
        'describe-logging-configuration': {'LoggingConfiguration': {'LogDestinationConfigs': [
            {'LogType': kind, 'LogDestinationType': 'CloudWatchLogs',
             'LogDestination': {'logGroup': '/cloud-soc/aws/network-firewall-' + kind.lower()}}
            for kind in ('ALERT', 'FLOW')]}},
        'describe-network-acls': {'NetworkAcls': [{'Associations': [{'SubnetId': fw.SUBNET}, {'SubnetId': fw.FW_SUBNET}],
            'Entries': [{'Egress': egress, 'RuleNumber': number, 'RuleAction': action, 'Protocol': '-1',
                         'CidrBlock': '0.0.0.0/0'} for egress in (False, True)
                        for number, action in ((100, 'allow'), (32767, 'deny'))]}]},
    }


@pytest.mark.parametrize('change', [None, 'default_route', 'extra_rule', 'logging',
                                   'home_net_changed', 'home_net_missing', 'extra_variable', 'reference'])
def test_preflight_rechecks_approved_topology_and_never_mutates(change):
    responses = approved_responses()
    if change == 'default_route':
        responses['describe-route-tables']['RouteTables'][1]['Routes'][-1]['GatewayId'] = 'igw-changed'
    elif change == 'extra_rule':
        responses['describe-rule-group']['RuleGroup']['RulesSource']['RulesString'] += '\npass ip any any -> any any;'
    elif change == 'logging':
        responses['describe-logging-configuration']['LoggingConfiguration']['LogDestinationConfigs'].pop()
    elif change == 'home_net_changed':
        responses['describe-rule-group']['RuleGroup']['RuleVariables']['IPSets']['HOME_NET']['Definition'] = ['0.0.0.0/0']
    elif change == 'home_net_missing':
        responses['describe-rule-group']['RuleGroup'].pop('RuleVariables')
    elif change == 'extra_variable':
        responses['describe-rule-group']['RuleGroup']['RuleVariables']['PortSets'] = {'HTTPS_PORTS': {'Definition': ['443']}}
    elif change == 'reference':
        responses['describe-rule-group']['RuleGroup']['ReferenceSets'] = {'IPSetReferences': {'EXTERNAL': {'ReferenceArn': 'other'}}}
    def call(*args):
        assert args[1] in responses, 'Unexpected mutation/API'
        return responses[args[1]]
    if change:
        with pytest.raises(fw.Stop):
            fw.preflight(call)
    else:
        assert len(fw.preflight(call)) == 2


def test_restore_outbound_then_ingress_then_firewall_and_only_owned_tables():
    fake = Fake()
    fake.data[1]['Routes'][0] = {'DestinationCidrBlock': '0.0.0.0/0', 'VpcEndpointId': fw.ENDPOINT, 'State': 'active'}
    fake.owned('firewall-subnet', {'SubnetId': fw.FW_SUBNET, 'RouteTableAssociationId': 'firewall-assoc'})
    fake.owned('internet-ingress', {'GatewayId': fw.IGW, 'RouteTableAssociationId': 'ingress-assoc'})
    fake.data.append({'RouteTableId': 'rtb-unrelated', 'VpcId': fw.VPC, 'Associations': []})
    assert fw.restore(fake.state, fake)['restored'] is True
    writes = [c for c in fake.calls if c[1] not in ('get-caller-identity', 'describe-route-tables')]
    assert writes[0][1] == 'replace-route' and writes[0][-1] == fw.IGW
    assert [c[-1] for c in writes if c[1] == 'disassociate-route-table'] == ['ingress-assoc', 'firewall-assoc']
    assert all(c[-1].startswith('rtb-test-') for c in writes if c[1] == 'delete-route-table')
    assert fake.data[-1]['RouteTableId'] == 'rtb-unrelated'
    # Repeated recovery reads but does not rewrite a restored path.
    fake.calls.clear()
    fw.restore(fake.state, fake)
    assert all(c[1] in ('get-caller-identity', 'describe-route-tables') for c in fake.calls)


@pytest.mark.parametrize('retained_before_call', [True, False])
def test_restore_ignores_retained_disassociated_gateway_record(retained_before_call):
    fake = Fake()
    ingress = fake.owned('internet-ingress', {'GatewayId': fw.IGW,
        'RouteTableAssociationId': 'ended-ingress', 'AssociationState': {
            'State': 'disassociated' if retained_before_call else 'associated'}})
    firewall = fake.owned('firewall-subnet', {})
    firewall['Associations'] = []
    original = fake.__call__
    def call(*args):
        if args[1] == 'disassociate-route-table':
            assert not retained_before_call
            fake.calls.append(args)
            ingress['Associations'][0]['AssociationState']['State'] = 'disassociated'
            return {}
        return original(*args)
    assert fw.restore(fake.state, call)['restored'] is True
    assert fake.data == fake.before
    assert [c[1] for c in fake.calls].count('disassociate-route-table') == (0 if retained_before_call else 1)
    assert not any(c[1] == 'replace-route' for c in fake.calls)


@pytest.mark.parametrize('status', ['associating', 'failed', 'unknown'])
def test_pending_or_unknown_association_is_never_treated_as_detached(status):
    fake = Fake()
    fake.owned('internet-ingress', {'GatewayId': fw.IGW, 'RouteTableAssociationId': 'pending',
                                   'AssociationState': {'State': status}})
    with pytest.raises(fw.Stop, match='association_transition'):
        fw.restore(fake.state, fake)
    assert not any(c[1] in ('delete-route-table', 'disassociate-route-table') for c in fake.calls)


@pytest.mark.parametrize('kind', ['changed_target', 'foreign_association', 'unowned_path'])
def test_restore_does_not_overwrite_external_changes(kind):
    fake = Fake()
    if kind == 'changed_target':
        fake.data[1]['Routes'][0]['GatewayId'] = 'igw-other'
    elif kind == 'foreign_association':
        fake.owned('firewall-subnet', {'SubnetId': 'subnet-teammate', 'RouteTableAssociationId': 'other'})
    else:
        fake.data[1]['Routes'][0]['GatewayId'] = fw.ENDPOINT
        fake.state.pop('replace_attempted')
    with pytest.raises(fw.Stop):
        fw.restore(fake.state, fake)
    assert all(c[1] in ('get-caller-identity', 'describe-route-tables') for c in fake.calls)


@pytest.mark.parametrize('failure', ['create-route-table', 'replace-route', 'during_window'])
def test_apply_error_or_lost_response_always_attempts_owned_rollback(tmp_path, monkeypatch, failure):
    fake = Fake()
    monkeypatch.setattr(fw, 'preflight', lambda call: copy.deepcopy(fake.before))
    original = fake.__call__
    def call(*args):
        if args[1] == 'create-route-table':
            tags = json.loads(args[-1])[0]['Tags']
            fake.state['change_id'] = tags[0]['Value']
            table = fake.owned(tags[-1]['Value'], {})
            table['Associations'] = []
            if failure == 'create-route-table':
                raise fw.Stop('lost_response_after_create')
            return {'RouteTable': table}
        if args[1] == 'create-route':
            return {}
        if args[1] == 'associate-route-table':
            table = next(t for t in fake.data if t['RouteTableId'] == args[3])
            table['Associations'] = [{'RouteTableAssociationId': args[-1],
                                      'SubnetId' if args[-2] == '--subnet-id' else 'GatewayId': args[-1]}]
            return {}
        if args[1] == 'replace-route' and args[-2] == '--vpc-endpoint-id':
            fake.data[1]['Routes'][0]['GatewayId'] = fw.ENDPOINT
            if failure == 'replace-route':
                raise fw.Stop('lost_response_after_replace')
            return {}
        return original(*args)
    def sleep(seconds):
        assert seconds == 120
        raise KeyboardInterrupt()
    path = tmp_path / 'manifest.json'
    with pytest.raises((fw.Stop, KeyboardInterrupt)):
        fw.apply(path, call, sleep)
    assert json.loads(path.read_text())['restored'] is True
    assert fake.data == fake.before
