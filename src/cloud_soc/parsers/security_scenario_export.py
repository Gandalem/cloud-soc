"""Explicit stdin-to-NDJSON metadata collector for configured audit exporters.

This module never generates security events or starts services. Native audit
exporters must emit the documented timestamp/security_scenario input envelope.
"""
import argparse
import json
import sys

from cloud_soc.parsers.security_scenarios import VERSION, parse
from cloud_soc.portal.agent_status import parse_time, iso
from cloud_soc.portal.privacy import display, REDACTED


def identity(value):
    if (not isinstance(value, str) or not 0 < len(value) <= 128
            or value.strip() != value or value == REDACTED or display(value) != value
            or any(ord(c) < 32 for c in value)):
        raise ValueError('collector_identity_invalid')
    return value


def project(document, *, organization, host, service=None):
    """Only explicit envelope identity and parser-approved metadata are emitted."""
    if not isinstance(document, dict):
        raise ValueError('export_document_invalid')
    occurred = parse_time(document.get('timestamp'))
    if occurred is None:
        raise ValueError('export_timestamp_invalid')
    source = {'@timestamp': iso(occurred), 'organization': {'id': identity(organization)},
              'host': {'id': identity(host)}, 'labels': {'log_source': 'security_scenario'},
              'security_scenario': document.get('security_scenario')}
    if service is not None:
        source['service'] = {'name': identity(service)}
    values = parse(source)
    source['security_scenario'] = {
        'schema': VERSION, 'kind': values['scenario_kind'],
        **{key: value for key, value in values.items()
           if key not in ('category', 'scenario_kind', 'dns_name_length')}}
    source['event'] = {'action': values['action'], 'outcome': values['outcome']}
    if values.get('actor'):
        source['user'] = {'name': values['actor']}
    for endpoint in ('source', 'destination'):
        if values.get(endpoint + '_ip'):
            source[endpoint] = {'ip': values[endpoint + '_ip']}
    return source


def main(argv=None):
    parser = argparse.ArgumentParser(description='Collect structured audit metadata from stdin; emit NDJSON')
    parser.add_argument('--organization', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--service', help='Required for application audit feeds')
    args = parser.parse_args(argv)
    # Configuration is interpreted only when the user explicitly runs this module.
    try:
        identity(args.organization)
        identity(args.host)
        if args.service is not None:
            identity(args.service)
    except ValueError:
        print('collector_configuration_rejected', file=sys.stderr)
        return 2
    rejected = 0
    while True:
        raw = sys.stdin.buffer.readline(65537)
        if not raw:
            break
        if len(raw) > 65536:
            while raw and not raw.endswith(b'\n'):
                raw = sys.stdin.buffer.readline(65537)
            rejected += 1
            print('audit_record_rejected: oversized', file=sys.stderr)
            continue
        try:
            document = json.loads(raw)
            output = project(document, organization=args.organization, host=args.host, service=args.service)
        except (ValueError, TypeError, OverflowError):
            rejected += 1
            print('audit_record_rejected: invalid_metadata', file=sys.stderr)
            continue
        print(json.dumps(output, ensure_ascii=True, separators=(',', ':')), flush=True)
    return 1 if rejected else 0


if __name__ == '__main__':
    raise SystemExit(main())
