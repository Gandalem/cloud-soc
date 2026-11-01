"""Allowlisted ECS audit projection. Raw credential-bearing payloads are not indexed."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json

from cloud_soc.privacy import display

PROVIDERS = ('aws', 'azure', 'naver')


def utc(value):
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value / 1000, timezone.utc)
    elif isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError('Timezone-aware event time required')
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def text(value):
    return display(str(value))[:512] if value is not None else ''


def normalize(provider, raw, scope):
    account, organization = str(scope['account']), scope['organization']
    if provider == 'aws':
        if str(raw.get('recipientAccountId')) != account:
            raise ValueError('AWS account mismatch')
        identity = raw.get('userIdentity') or {}
        identifier, when = raw.get('eventID'), raw.get('eventTime')
        action, service = raw.get('eventName'), raw.get('eventSource')
        region, actor, address = raw.get('awsRegion'), identity.get('arn') or identity.get('principalId'), raw.get('sourceIPAddress')
        result = 'failure' if raw.get('errorCode') or (raw.get('responseElements') or {}).get('ConsoleLogin') == 'Failure' else 'success'
        resource = (raw.get('resources') or [{}])[0].get('ARN', '')
        dataset = 'aws.cloudtrail'
    elif provider == 'azure':
        resource = raw.get('resourceId') or ''
        # Azure diagnostics subscriptions are checked against the trusted source configuration.
        subscription = raw.get('subscriptionId')
        if not subscription and resource.lower().startswith('/subscriptions/'):
            subscription = resource.split('/')[2]
        if not subscription or subscription.lower() != account.lower():
            raise ValueError('Azure subscription missing or mismatched')
        props = raw.get('properties') or {}
        identifier = raw.get('eventDataId')
        when = raw.get('time') or raw.get('eventTimestamp') or raw.get('timeGenerated')
        action, service = raw.get('operationName'), raw.get('category') or 'ActivityLog'
        if isinstance(action, dict):
            action = action.get('value')
        region = raw.get('location') or ''
        claims = (raw.get('identity') or {}).get('claim') or {}
        actor = raw.get('caller') or claims.get('oid') or claims.get('http://schemas.microsoft.com/identity/claims/objectidentifier')
        address = raw.get('callerIpAddress') or props.get('ipAddress')
        status = raw.get('resultType') or raw.get('status') or ''
        if isinstance(status, dict):
            status = status.get('value', '')
        result = {'success': 'success', 'succeeded': 'success', 'failure': 'failure', 'failed': 'failure'}.get(str(status).lower(), 'unknown')
        dataset = 'azure.activitylogs'
    elif provider == 'naver':
        identifier, when = raw.get('historyId'), raw.get('eventTime')
        resource = raw.get('nrn') or ''
        # NRN's account field is the fifth colon-delimited component.
        parts = resource.split(':')
        if len(parts) < 6 or parts[4] != account:
            raise ValueError('Naver account missing or mismatched')
        action, service = raw.get('actionDisplayName'), raw.get('productName')
        region = raw.get('regionCode') or ''
        actor = raw.get('actionIdNo') or raw.get('actionSubAccountNo') or raw.get('actionUserType')
        address = raw.get('sourceIp')
        result = {'SUCCESS': 'success', 'FAIL': 'failure'}.get(raw.get('actionResultType'), 'unknown')
        dataset = 'naver.cloudactivitytracer'
    else:
        raise ValueError('Unsupported provider')
    occurred = utc(when)
    if not action:
        raise ValueError('Missing audit action')
    if not identifier:
        identifier = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    event_id = hashlib.sha256(json.dumps([organization, provider, account, dataset, str(identifier)], separators=(',', ':')).encode()).hexdigest()
    category = 'authentication' if any(s in str(action).lower() for s in ('login', 'signin', 'logon')) else 'configuration'
    document = {
        '@timestamp': occurred, 'ecs': {'version': '8.17.0'},
        'organization': {'id': organization},
        'cloud': {'provider': provider, 'account': {'id': account}, 'region': text(region)},
        'event': {'id': event_id, 'dataset': dataset, 'kind': 'event', 'category': [category],
                  'type': ['info'], 'action': text(action), 'outcome': result, 'provider': text(service),
                  'ingested': utc(datetime.now(timezone.utc))},
        'user': {'id': text(actor)}, 'resource': {'id': text(resource)},
        'soc': {'schema_version': 1, 'collector_id': scope['id']},
    }
    try:
        document['source'] = {'ip': str(ipaddress.ip_address(address))}
    except (ValueError, TypeError):
        pass
    return 'soc-multicloud-' + occurred[:10].replace('-', '.'), event_id, document
