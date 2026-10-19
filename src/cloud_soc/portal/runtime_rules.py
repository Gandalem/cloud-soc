"""Public rule inventory: checkout, observed worker selection and freshness differ."""
import re

from cloud_soc.detection.engine import rule_revision, rule_engine_version
from cloud_soc.detection.profiles import catalog


def public_manifest(value):
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1
            or value.get('mode') not in ('continuous', 'snapshot', 'retrospective')
            or not isinstance(value.get('rules'), list) or not 1 <= len(value['rules']) <= 64):
        return None
    result, seen = [], set()
    for row in value['rules']:
        if not isinstance(row, dict):
            return None
        identifier, revision, engine = (row.get(k) for k in ('id', 'revision', 'engine_version'))
        if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Z0-9-]{1,64}', identifier)
                or identifier in seen or not isinstance(revision, str)
                or not re.fullmatch(r'[0-9a-f]{64}', revision)
                or not isinstance(engine, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', engine)):
            return None
        seen.add(identifier)
        result.append({'id': identifier, 'revision': revision, 'engine_version': engine})
    return {'schema_version': 1, 'mode': value['mode'], 'rules': result}


def inventory(workers):
    """Global metadata only; caller must exclude organization-scoped principals.

    'running' means a fresh continuous worker selected this revision. It says
    nothing about input coverage, deployment acceptance or notification delivery.
    """
    result = []
    incomplete = any(worker.get('state') == 'unavailable' or
                     worker.get('state') != 'not_started' and not worker.get('runtime')
                     for worker in workers.values())
    # Optional app files cannot prevent independent SOC health inspection.
    try:
        rules = catalog()
    except (OSError, ValueError):
        rules = catalog(include_applications=False)
    for rule in rules:
        revision = rule_revision(rule)
        observations = []
        for name, worker in workers.items():
            manifest = worker.get('runtime')
            if not manifest:
                continue
            for reported in manifest['rules']:
                if reported['id'] != rule['id']:
                    continue
                state = ('revision_mismatch' if reported['revision'] != revision or
                         reported['engine_version'] != rule_engine_version(rule) else
                         'stale' if worker['state'] == 'stale' else
                         'failed' if worker['state'] == 'failed' else
                         'running' if manifest['mode'] == 'continuous' and
                         worker['state'] in ('running', 'success', 'waiting') else 'reported')
                observations.append({'worker': name, 'state': state, 'mode': manifest['mode'],
                                     **reported, 'last_success': worker.get('last_success'),
                                     'checkpoint': worker.get('checkpoint')})
        result.append({'id': rule['id'], 'catalog_revision': revision,
                       'scope': 'application_audit' if rule['id'] in ('WEB-ACCESS-01', 'WEB-AUTH-01') else
                                'application_waf' if rule['id'] == 'WEB-WAF-01' else 'general',
                       'state': 'observed' if observations else 'unknown' if incomplete else 'not_observed',
                       'observations': observations})
    known = {row['id'] for row in result}
    for name, worker in workers.items():
        manifest = worker.get('runtime') or {}
        for reported in manifest.get('rules', []):
            if reported['id'] in known:
                continue
            existing = next((row for row in result if row['id'] == reported['id']), None)
            if existing is None:
                existing = {'id': reported['id'], 'catalog_revision': None, 'scope': 'unknown',
                            'state': 'catalog_unavailable', 'observations': []}
                result.append(existing)
            existing['observations'].append({'worker': name, 'state': 'catalog_unavailable',
                'mode': manifest.get('mode'), **reported, 'last_success': worker.get('last_success'),
                'checkpoint': worker.get('checkpoint')})
    return result
