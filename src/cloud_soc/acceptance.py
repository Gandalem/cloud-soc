"""Read-only evidence acceptance for an explicitly selected, newly received alert.

No generated events, index creation, rule activation, notifications or services.
The report covers stored pipeline evidence; browser and Slack require separate
human acceptance and are deliberately never inferred from ES documents.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from elasticsearch import Elasticsearch

from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.detection.engine import rule_revision, rule_engine_version
from cloud_soc.detection.profiles import catalog, APPLICATION_IDS
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.portal.log_contract import document_reference, field
from cloud_soc.portal.operations import Operations, ALERT, identifier
from cloud_soc.processing.contract import NORMALIZED, RECORDS, normalize
from cloud_soc.web.scope import NORMALIZER_VERSION as SITE_VERSION, LEGACY_VERSION

DETECTORS = ('detector', 'detector-priority', 'detector-additional')


def inspect(client, *, alert_id, organization, rule_id, since, raw_indices, now=None):
    now = now or datetime.now(timezone.utc)
    since = parse_time(since)
    if (since is None or since > now or not isinstance(organization, str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', organization)
            or not raw_indices or len(raw_indices) > 32 or len(set(raw_indices)) != len(raw_indices)):
        raise ValueError('invalid_acceptance_scope')
    identifier(alert_id)
    for name in raw_indices:
        document_reference(name, 'acceptance')
    rules = {r['id']: r for r in catalog(include_applications=rule_id in APPLICATION_IDS)}
    if rule_id not in rules:
        raise ValueError('unknown_acceptance_rule')
    reader = Operations(client, organizations=(organization,))
    global_reader = Operations(client)
    checks = []

    def check(name, passed):
        checks.append({'name': name, 'passed': bool(passed)})
        return bool(passed)

    report = {'schema_version': 1, 'read_only': True, 'checked_at': now.isoformat(),
              'since': since.isoformat(), 'scope': 'stored_pipeline_evidence', 'checks': checks,
              'pipeline_evidence': 'incomplete', 'full_acceptance': 'unverified',
              'browser': 'unverified', 'slack_channel_receipt': 'unverified',
              'raw_integrity': 'not_hashed_at_detection'}
    source = reader.get(ALERT, alert_id, None)
    if not check('selected_alert_visible', source is not None):
        return report
    rule = rules[rule_id]
    revision = rule_revision(rule)
    provenance = field(source, 'cloud_soc.provenance') or {}
    check('expected_rule_and_revision', field(source, 'rule.id') == rule_id and
          provenance.get('rule_version') == revision and provenance.get('rule_snapshot') == rule and
          provenance.get('engine_version') == rule_engine_version(rule))
    refs = provenance.get('evidence')
    if not check('bounded_nonempty_evidence', isinstance(refs, list) and 1 <= len(refs) <= 1000):
        return report
    # Validate the entire explicit allowlist before reading any referenced document.
    if not check('evidence_within_selected_intake', all(isinstance(ref, dict) and
                 isinstance(ref.get('raw'), dict) and ref['raw'].get('index') in raw_indices and
                 isinstance(ref.get('normalized'), dict) and ref['normalized'].get('index') == NORMALIZED
                 for ref in refs)):
        return report
    evidence_ok, records_ok, reproduced, fresh, received_times = True, True, True, True, []
    normalized_refs = set()
    for ref in refs:
        result = reader.evidence(ref, organization=organization)
        evidence_ok &= result.get('state') == 'exact_reference' and result.get('integrity') == 'normalized_hash_verified'
        # Operations validates IDs, exact concrete indices, tenant and event hash.
        if result.get('state') != 'exact_reference':
            records_ok = reproduced = fresh = False
            continue
        norm_ref, raw_ref = result['normalized'], result['raw']
        normalized_refs.add((norm_ref['index'], norm_ref['id']))
        norm = reader.get(norm_ref['index'], norm_ref['id'], None)
        raw = reader.get(raw_ref['index'], raw_ref['id'], None)
        record = global_reader.get(RECORDS, norm_ref['id'], None)
        records_ok &= bool(record and record.get('status') == 'normalized' and
                           record.get('raw') == raw_ref and record.get('normalized') == norm_ref)
        stamps = [parse_time(field(norm, 'cloud_soc.normalized_at')),
                  parse_time(field(raw, 'event.ingested')), parse_time(field(raw, '@timestamp'))]
        fresh &= all(stamp is not None and since <= stamp <= now for stamp in stamps)
        if raw is None or stamps[0] is None:
            reproduced = False
        else:
            version = field(norm, 'cloud_soc.normalizer_version')
            norm_id, _, event = normalize({'_index': raw_ref['index'], '_id': raw_ref['id'], '_source': raw},
                                          field(norm, 'cloud_soc.normalized_at'),
                                          web_version=LEGACY_VERSION if version == LEGACY_VERSION else SITE_VERSION)
            reproduced &= norm_id == norm_ref['id'] and event == norm
        if stamps[0] is not None:
            received_times.append(stamps[0])
    check('all_raw_and_normalized_evidence_verified', evidence_ok)
    check('all_normalization_records_match', records_ok)
    check('raw_reproduces_stored_normalization', reproduced)
    check('new_input_since_acceptance_start', fresh)
    check('distinct_evidence_and_count', len(normalized_refs) == len(refs) == field(source, 'cloud_soc.event_count'))
    latest_input = max(received_times) if received_times else None
    workers = [global_reader.worker_status(name) for name in DETECTORS]
    check('current_continuous_worker_revision_and_checkpoint', any(
        worker.get('state') in ('running', 'success', 'waiting') and
        worker.get('runtime', {}).get('mode') == 'continuous' and latest_input is not None and
        parse_time(worker.get('last_success')) is not None and
        latest_input <= parse_time(worker['last_success']) <= now and
        parse_time(worker.get('checkpoint')) is not None and latest_input <= parse_time(worker['checkpoint']) <= now and
        any(r['id'] == rule_id and r['revision'] == revision for r in worker.get('runtime', {}).get('rules', []))
        for worker in workers))
    report['rule'] = {'id': rule_id, 'revision': revision}
    report['evidence_count'] = len(refs)
    if all(row['passed'] for row in checks):
        report['pipeline_evidence'] = 'passed'
    return report


def write_report(path, report):
    # Exclusive private output; never overwrite another acceptance or follow a symlink.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('es-url', 'ca-file', 'api-key-file', 'alert-id', 'organization', 'rule-id', 'since', 'report'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--raw-index', action='append', required=True, help='Exact approved intake index; repeat as needed')
    args = parser.parse_args(argv)
    try:
        target = Path(args.report)
        if target.exists() or target.is_symlink() or not Path(args.ca_file).is_file():
            raise ValueError('invalid_output_or_ca')
        with Elasticsearch(endpoint(args.es_url), api_key=protected_key(args.api_key_file),
                           ca_certs=args.ca_file, request_timeout=10, max_retries=0) as client:
            report = inspect(client, alert_id=args.alert_id, organization=args.organization,
                             rule_id=args.rule_id, since=args.since, raw_indices=args.raw_index)
        write_report(target, report)
        print(json.dumps({'read_only': True, 'pipeline_evidence': report['pipeline_evidence'],
                          'full_acceptance': 'unverified'}))
        return 0 if report['pipeline_evidence'] == 'passed' else 2
    except Exception:
        print('acceptance_failed; verify scope, TLS, read privileges and output; credentials and payloads omitted')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
