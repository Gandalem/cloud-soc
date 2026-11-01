"""Two-minute, explicitly approved lab route test. Default mode only prints a plan.

Run in independent AWS CloudShell, never on the EC2 whose path is being changed.
No credentials or traffic bodies are stored. See docs/aws_firewall_path_check_plan.md.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

ACCOUNT = '897722691159'
REGION = 'ap-northeast-3'
VPC = 'vpc-0e4bb99234215e866'
MAIN = 'rtb-0f881f16bf456eb55'
MALL = 'rtb-0451cd3c7d6a78b05'
SUBNET = 'subnet-01a1c4d0b3cb9f88a'
FW_SUBNET = 'subnet-0aa993e5f60986ee8'
IGW = 'igw-07e3020d17e2a282f'
ENDPOINT = 'vpce-0d3de19f10e3a1e23'
FIREWALL = 'cloud-soc-network-firewall'
INSTANCE = 'i-0e94f1225ca4df1e9'
OWNER = 'cloud-soc-gyumin-firewall-path-v1'
OWNER_KEY = 'cloud-soc:temporary-path'


class Stop(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Stop(code)


def aws(service, operation, *args):
    try:
        result = subprocess.run(['aws', service, operation, *args, '--region', REGION,
                                 '--output', 'json', '--no-cli-pager', '--cli-connect-timeout', '5',
                                 '--cli-read-timeout', '15'], capture_output=True, text=True, timeout=25)
        require(result.returncode == 0, 'aws_operation_failed_' + operation)
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        raise Stop('aws_operation_unavailable_' + operation) from None


def tables(call=aws):
    return call('ec2', 'describe-route-tables', '--filters', 'Name=vpc-id,Values=' + VPC)['RouteTables']


def default_target(table):
    routes = [r for r in table['Routes'] if r.get('DestinationCidrBlock') == '0.0.0.0/0']
    require(len(routes) == 1 and routes[0].get('State') == 'active', 'default_route_changed')
    return routes[0].get('GatewayId') or routes[0].get('VpcEndpointId')


def preflight(call=aws):
    require(call('sts', 'get-caller-identity').get('Account') == ACCOUNT, 'account_mismatch')
    current = tables(call)
    require({t['RouteTableId'] for t in current} == {MAIN, MALL}, 'route_table_inventory_changed')
    main = next(t for t in current if t['RouteTableId'] == MAIN)
    mall = next(t for t in current if t['RouteTableId'] == MALL)
    require(default_target(mall) == IGW, 'mall_default_changed')
    require(len(main['Associations']) == 1 and main['Associations'][0].get('Main') is True,
            'main_association_changed')
    require(len(mall['Associations']) == 1 and mall['Associations'][0].get('SubnetId') == SUBNET
            and not mall['Associations'][0].get('Main'), 'mall_association_changed')
    # Fail closed on other routes; retain the exact GuardDuty-managed entries in place.
    for table in current:
        expected = {('10.250.0.0/16', 'local'), ('169.254.170.248/29', 'GuardDuty'),
                    ('fd00:ec2:6d00::/64', 'GuardDuty')}
        if table['RouteTableId'] == MALL:
            expected.add(('0.0.0.0/0', IGW))
        require({(r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock'), r.get('GatewayId'))
                 for r in table['Routes']} == expected and all(r.get('State') == 'active' for r in table['Routes']),
                'routes_changed')
    subnets = call('ec2', 'describe-subnets', '--subnet-ids', SUBNET, FW_SUBNET)['Subnets']
    require({(s['SubnetId'], s['VpcId'], s['AvailabilityZone'], s['CidrBlock']) for s in subnets}
            == {(SUBNET, VPC, 'ap-northeast-3b', '10.250.10.0/24'),
                (FW_SUBNET, VPC, 'ap-northeast-3b', '10.250.4.0/28')}, 'subnets_changed')
    interfaces = call('ec2', 'describe-network-interfaces', '--filters', 'Name=vpc-id,Values=' + VPC)
    require({e['NetworkInterfaceId'] for e in interfaces['NetworkInterfaces']}
            == {'eni-09f0031d9334bb978', 'eni-090fb707c7cdcee4e', 'eni-008b63de03827e412'},
            'interface_inventory_changed')
    instance = call('ec2', 'describe-instances', '--instance-ids', INSTANCE)['Reservations'][0]['Instances'][0]
    require(instance['State']['Name'] == 'running' and instance['SubnetId'] == SUBNET
            and instance['PrivateIpAddress'] == '10.250.10.156' and instance.get('PublicIpAddress'),
            'test_instance_changed')
    gateway = call('ec2', 'describe-internet-gateways', '--internet-gateway-ids', IGW)['InternetGateways']
    require(len(gateway) == 1 and gateway[0]['Attachments'] == [{'State': 'available', 'VpcId': VPC}],
            'gateway_attachment_changed')
    fw = call('network-firewall', 'describe-firewall', '--firewall-name', FIREWALL)
    require(fw['Firewall']['VpcId'] == VPC and fw['FirewallStatus']['Status'] == 'READY'
            and fw['Firewall']['SubnetMappings'] == [{'SubnetId': FW_SUBNET, 'IPAddressType': 'IPV4'}],
            'firewall_changed')
    sync = fw['FirewallStatus']['SyncStates']
    require(set(sync) == {'ap-northeast-3b'} and sync['ap-northeast-3b']['Attachment']['EndpointId'] == ENDPOINT
            and sync['ap-northeast-3b']['Attachment']['Status'] == 'READY'
            and all(c['SyncStatus'] == 'IN_SYNC' for c in sync['ap-northeast-3b']['Config'].values()),
            'endpoint_not_ready')
    policy = call('network-firewall', 'describe-firewall-policy', '--firewall-policy-name',
                  'cloud-soc-firewall-policy')['FirewallPolicy']
    expected_policy = 'arn:aws:network-firewall:' + REGION + ':' + ACCOUNT + ':firewall-policy/cloud-soc-firewall-policy'
    require(fw['Firewall']['FirewallPolicyArn'] == expected_policy
            and policy['StatelessDefaultActions'] == ['aws:forward_to_sfe']
            and policy['StatelessFragmentDefaultActions'] == ['aws:forward_to_sfe']
            and policy.get('StatelessCustomActions', []) == []
            and policy['StatefulDefaultActions'] == ['aws:alert_established_app_layer_to_server']
            and policy['StatefulEngineOptions'] == {'RuleOrder': 'STRICT_ORDER', 'StreamExceptionPolicy': 'REJECT'}
            and policy['StatefulRuleGroupReferences'] == [{'ResourceArn':
                'arn:aws:network-firewall:' + REGION + ':' + ACCOUNT + ':stateful-rulegroup/cloud-soc-stateful-test',
                'Priority': 1}], 'policy_changed')
    rules = call('network-firewall', 'describe-rule-group', '--rule-group-name',
                 'cloud-soc-stateful-test', '--type', 'STATEFUL')['RuleGroup']
    require(rules['RulesSource'] == {'RulesString': 'alert tcp $HOME_NET any -> any 443 '
            '(msg:"CLOUD_SOC_TEST_HTTPS"; flow:to_server,established; sid:1000001; rev:1;)'}
            and rules['StatefulRuleOptions'] == {'RuleOrder': 'STRICT_ORDER'}
            and rules.get('RuleVariables') == {'IPSets': {'HOME_NET': {'Definition': ['10.250.0.0/16']}}}
            and not rules.get('ReferenceSets'), 'rules_changed')
    configs = call('network-firewall', 'describe-logging-configuration', '--firewall-name', FIREWALL)
    require(sorted(configs['LoggingConfiguration']['LogDestinationConfigs'], key=lambda c: c['LogType']) == [
        {'LogType': 'ALERT', 'LogDestinationType': 'CloudWatchLogs',
         'LogDestination': {'logGroup': '/cloud-soc/aws/network-firewall-alert'}},
        {'LogType': 'FLOW', 'LogDestinationType': 'CloudWatchLogs',
         'LogDestination': {'logGroup': '/cloud-soc/aws/network-firewall-flow'}}], 'logging_changed')
    acls = call('ec2', 'describe-network-acls', '--filters', 'Name=vpc-id,Values=' + VPC)['NetworkAcls']
    for subnet in (SUBNET, FW_SUBNET):
        selected = [a for a in acls if any(s['SubnetId'] == subnet for s in a['Associations'])]
        require(len(selected) == 1, 'acl_association_changed')
        entries = selected[0]['Entries']
        require(len(entries) == 4 and {(e['Egress'], e['RuleNumber'], e['RuleAction'], e['Protocol'],
                                      e.get('CidrBlock')) for e in entries} ==
                {(egress, number, action, '-1', '0.0.0.0/0') for egress in (True, False)
                 for number, action in ((100, 'allow'), (32767, 'deny'))}, 'acl_rules_changed')
    return current


def save(path, state):
    # A durable private manifest exists before the first AWS write; no credentials are saved.
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(state, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def owned_tables(state, current):
    owned = []
    for table in current:
        tags = {t['Key']: t['Value'] for t in table.get('Tags', [])}
        if tags.get(OWNER_KEY) == state['change_id'] and tags.get('cloud-soc:purpose') == OWNER:
            require(table['VpcId'] == VPC and table['RouteTableId'] not in (MAIN, MALL), 'ownership_mismatch')
            owned.append(table)
    require(len(owned) <= 2, 'owned_inventory_unexpected')
    return owned


def live_associations(table):
    # DescribeRouteTables may retain a terminal gateway association record.
    # Only this explicit terminal state is safe to ignore, never a pending state.
    return [a for a in table.get('Associations', [])
            if a.get('AssociationState', {}).get('State') != 'disassociated']


def restore(state, call=aws):
    require(state.get('schema') == OWNER and state.get('account') == ACCOUNT
            and state.get('vpc') == VPC and len(state.get('change_id', '')) == 32, 'invalid_manifest')
    require(call('sts', 'get-caller-identity').get('Account') == ACCOUNT, 'account_mismatch')
    current = tables(call)
    mall = next(t for t in current if t['RouteTableId'] == MALL)
    target = default_target(mall)
    require(target in (IGW, ENDPOINT), 'mall_route_changed_by_other_actor')
    owned = owned_tables(state, current)
    # Do not dismantle a pre-existing/third-party endpoint path based solely on its target.
    require(target != ENDPOINT or state.get('replace_attempted') is True, 'unowned_endpoint_path')
    for table in owned:
        role = {t['Key']: t['Value'] for t in table['Tags']}.get('cloud-soc:role')
        require(role in ('firewall-subnet', 'internet-ingress'), 'unknown_owned_role')
        for assoc in live_associations(table):
            require(not assoc.get('Main') and ((role == 'firewall-subnet' and assoc.get('SubnetId') == FW_SUBNET
                    and not assoc.get('GatewayId')) or (role == 'internet-ingress'
                    and assoc.get('GatewayId') == IGW and not assoc.get('SubnetId'))),
                    'foreign_association_do_not_detach')
    if target == ENDPOINT:
        call('ec2', 'replace-route', '--route-table-id', MALL, '--destination-cidr-block', '0.0.0.0/0',
             '--gateway-id', IGW)
    require(default_target(next(t for t in tables(call) if t['RouteTableId'] == MALL)) == IGW,
            'mall_restore_unverified')
    # Restore return path next, then firewall subnet's implicit main association.
    for table in sorted(owned, key=lambda t: 0 if any(a.get('GatewayId') == IGW
                                                    for a in live_associations(t)) else 1):
        for assoc in live_associations(table):
            status = assoc.get('AssociationState', {}).get('State')
            require(status in (None, 'associated', 'disassociating'), 'association_transition_retry_restore')
            if status != 'disassociating':
                call('ec2', 'disassociate-route-table', '--association-id', assoc['RouteTableAssociationId'])
    for table in owned:
        for attempt in range(20):
            fresh = next(t for t in tables(call) if t['RouteTableId'] == table['RouteTableId'])
            require(owned_tables(state, [fresh]), 'delete_ownership_changed')
            if not live_associations(fresh):
                break
            require(all(a.get('RouteTableAssociationId') in
                        {original['RouteTableAssociationId'] for original in table.get('Associations', [])}
                        for a in live_associations(fresh)), 'delete_association_changed')
            time.sleep(1)
        require(not live_associations(fresh), 'association_removal_pending_retry_restore')
        call('ec2', 'delete-route-table', '--route-table-id', fresh['RouteTableId'])
    final = tables(call)
    require(not owned_tables(state, final), 'owned_tables_remain')
    # Compare all original routes/associations, including GuardDuty; ignore tags and response ordering.
    for original in state['before']:
        fresh = next(t for t in final if t['RouteTableId'] == original['RouteTableId'])
        for key in ('Routes', 'Associations'):
            require(sorted(map(lambda x: json.dumps(x, sort_keys=True), fresh[key])) ==
                    sorted(map(lambda x: json.dumps(x, sort_keys=True), original[key])),
                    'original_' + key.lower() + '_changed')
    state['restored'] = True
    return state


def apply(path, call=aws, sleep=time.sleep):
    before = preflight(call)
    state = {'schema': OWNER, 'account': ACCOUNT, 'vpc': VPC, 'change_id': uuid.uuid4().hex,
             'before': before, 'started_at': datetime.now(timezone.utc).isoformat(), 'restored': False}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    save(path, state)
    try:
        print('preflight_ok; recovery_manifest=' + str(path), flush=True)
        created = {}
        # Atomic creation tags allow recovery even if the create response is lost.
        for role in ('internet-ingress', 'firewall-subnet'):
            tags = [{'Key': OWNER_KEY, 'Value': state['change_id']},
                    {'Key': 'cloud-soc:purpose', 'Value': OWNER}, {'Key': 'cloud-soc:role', 'Value': role}]
            table = call('ec2', 'create-route-table', '--vpc-id', VPC, '--tag-specifications',
                         json.dumps([{'ResourceType': 'route-table', 'Tags': tags}]))['RouteTable']['RouteTableId']
            created[role] = table
            state['created'] = created
            save(path, state)
            if role == 'internet-ingress':
                call('ec2', 'create-route', '--route-table-id', table, '--destination-cidr-block',
                     '10.250.10.0/24', '--vpc-endpoint-id', ENDPOINT)
            else:
                call('ec2', 'create-route', '--route-table-id', table, '--destination-cidr-block',
                     '0.0.0.0/0', '--gateway-id', IGW)
        # Ensure the EC2 remains direct before the two-sided path is installed.
        require(default_target(next(t for t in tables(call) if t['RouteTableId'] == MALL)) == IGW,
                'mall_changed_during_setup')
        call('ec2', 'associate-route-table', '--route-table-id', created['firewall-subnet'],
             '--subnet-id', FW_SUBNET)
        call('ec2', 'associate-route-table', '--route-table-id', created['internet-ingress'], '--gateway-id', IGW)
        state['replace_attempted'] = True
        save(path, state)
        call('ec2', 'replace-route', '--route-table-id', MALL, '--destination-cidr-block', '0.0.0.0/0',
             '--vpc-endpoint-id', ENDPOINT)
        require(default_target(next(t for t in tables(call) if t['RouteTableId'] == MALL)) == ENDPOINT,
                'endpoint_route_unverified')
        print('FIREWALL_WINDOW_BEGIN: run a fresh EC2 HTTPS request now; restore in 120 seconds', flush=True)
        state['window_started_at'] = datetime.now(timezone.utc).isoformat()
        save(path, state)
        sleep(120)
    finally:
        try:
            restore(state, call)
            save(path, state)
            print('FIREWALL_ROUTES_RESTORED: original route/association comparison passed', flush=True)
        except Exception:
            print('RESTORE_NEEDS_ATTENTION: retain CloudShell; run --restore ' + str(path), flush=True)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--restore', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.restore:
            path = args.restore.resolve()
            state = json.loads(path.read_text(encoding='utf-8'))
            restore(state)
            save(path, state)
            print('FIREWALL_ROUTES_RESTORED')
        elif args.apply:
            def interrupted(signum, frame):
                raise Stop('interrupted_restore_requested')
            previous = {}
            try:
                for name in ('SIGTERM', 'SIGHUP'):
                    if hasattr(signal, name):
                        signum = getattr(signal, name)
                        previous[signum] = signal.signal(signum, interrupted)
                apply(Path.home() / ('cloud-soc-firewall-path-' + uuid.uuid4().hex + '.json'))
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
        else:
            print(json.dumps({'mode': 'offline_plan', 'account': ACCOUNT, 'region': REGION, 'seconds': 120,
                              'new_route_tables': 2, 'mall_default': [IGW, ENDPOINT, IGW],
                              'preserve': ['main', 'GuardDuty routes', 'SG/NACL', 'RDS', 'firewall rules'],
                              'approval_required': True}))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'stopped', 'code': str(error) if isinstance(error, Stop)
                          else 'unexpected_failure_check_manifest'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
