#!/usr/bin/env python3
"""Read-only deployment planning diagnostics. Never applies or restarts services."""
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

REPO = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/outputs/cloud-soc')
STATE = Path('/home/lyn/cloud-soc/state/server')
sys.path.insert(0, str(REPO / 'src'))
from cloud_soc.deployment.host import Docker, snapshot, summary

if os.geteuid() != 0:
    raise SystemExit('Run this diagnostic with sudo python3.')
if (STATE / 'runtime/pending.json').exists():
    print('stage=interrupted_apply; pending recovery record exists; no new plan or apply attempted')
    raise SystemExit(2)

PREFLIGHT_PROBE = r'''import json, sys, traceback
from pathlib import Path
from cloud_soc.deployment.preflight import main
reasons = {
    'Existing key invalid; renewal must be explicit': 'worker_key_invalid',
    'Unbounded key requires explicit adoption': 'worker_key_unbounded',
    'Unexpected notification key or privileges': 'notification_key_invalid',
    'Unexpected notification role scope': 'notification_role_scope_invalid',
    'Unexpected notification role authority': 'notification_role_authority_invalid',
    'Unexpected notification index scope': 'notification_index_scope_invalid',
    'Unexpected notification index privileges': 'notification_index_privileges_invalid',
    'State integrity failed': 'state_integrity_failed',
    'Normalizer initial start changed': 'normalizer_start_changed',
    'SSH adapter floor changed': 'ssh_adapter_floor_changed',
    'State identity mismatch; database was not reset': 'state_identity_mismatch',
    'Concrete index expected, no alias adoption': 'index_alias_not_allowed',
    'Existing mapping requires explicit migration': 'mapping_contract_mismatch',
    'Restricted index scope cannot be expanded automatically': 'restricted_role_scope',
    'Invalid protected API key; no replacement issued': 'protected_key_format_invalid',
    'Rule revision has no release validation; live activation refused': 'rule_revision_mismatch',
}
try:
    main()
except Exception as error:
    message = error.args[0] if error.args and isinstance(error.args[0], str) else ''
    allowed_scopes = {'normalizer', 'normalizer-priority', 'detector', 'detector-priority',
                      'detector-additional', 'detector-retrospective', 'soc-normalized-v1',
                      'soc-processing-v1', 'soc-pipeline-status', 'soc-detection-runs-v1',
                      'soc-detection-exclusions-v1', 'soc-alert-notices-v1', 'security-alerts',
                      'cloud_soc_agent_monitor', 'cloud_soc_normalizer'}
    scopes = []
    for frame, _ in traceback.walk_tb(error.__traceback__):
        scope = frame.f_locals.get('name')
        if isinstance(scope, str) and scope in allowed_scopes:
            scopes.append(scope)
    result = {'exception': type(error).__name__, 'reason': reasons.get(message, 'unclassified_preflight_failure'),
              'http_status': getattr(getattr(error, 'meta', None), 'status', None),
              'sqlite_error': getattr(error, 'sqlite_errorname', None), 'scope': scopes[-1] if scopes else None,
              'frames': [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                         for frame in traceback.extract_tb(error.__traceback__) if '/cloud_soc/' in frame.filename]}
    print('SAFE_PREFLIGHT_DIAGNOSTIC=' + json.dumps(result), file=sys.stderr)
    raise SystemExit(1) from None
'''

class DiagnosticDocker(Docker):
    def run(self, args, *, input=None, env=None, timeout=180):
        if args[-2:] == ['-m', 'cloud_soc.deployment.preflight']:
            args = [*args[:-2], '-c', PREFLIGHT_PROBE]
        family = args[0]
        if family == 'compose':
            family += '_' + next((part for part in args if part in ('config', 'up', 'stop', 'ps')), 'query')
        print('docker_stage=' + family, flush=True)
        result = subprocess.run(self.prefix + args, input=input, text=True, capture_output=True,
                                env={**self.env, **(env or {})}, timeout=timeout)
        if result.returncode:
            # Inspect stderr only for fixed classifications; never print its contents.
            message = (result.stderr or '').lower()
            signatures = {
                'permission denied': 'permission_denied',
                'no such file or directory': 'file_missing',
                'is not set': 'compose_variable_missing',
                'required variable': 'compose_variable_required',
                'no space left': 'disk_full',
                'connection refused': 'connection_refused',
                'cannot connect': 'docker_connection_failed',
                'network not found': 'network_missing',
                'assertionerror': 'candidate_source_or_rule_assertion',
                'modulenotfounderror': 'candidate_dependency_missing',
                'unauthorized': 'authentication_failed',
                'forbidden': 'authorization_denied',
                'address already in use': 'port_conflict',
            }
            for line in (result.stderr or '').splitlines():
                if line.startswith('SAFE_PREFLIGHT_DIAGNOSTIC='):
                    print(line, flush=True)
            codes = [code for signature, code in signatures.items() if signature in message]
            print(json.dumps({'docker_stage': family, 'exit_code': result.returncode,
                              'diagnostics': codes or ['unclassified_docker_failure']}), flush=True)
            # A private local record is retained for an administrator, never echoed.
            folder = STATE / 'runtime'
            import tempfile
            descriptor, filename = tempfile.mkstemp(prefix='receipt-diagnostic-', suffix='.txt', dir=folder)
            with os.fdopen(descriptor, 'w') as output:
                output.write(result.stderr or '')
            print('private_diagnostic_file=' + filename)
            raise RuntimeError('docker_diagnostic_failed')
        return result.stdout

try:
    value = snapshot(DiagnosticDocker(), REPO, STATE, 'cloud-soc-runtime:ssh-96d2ab8')
    print(json.dumps(summary(value)))
    print('Planning succeeded; no apply performed.')
except Exception as error:
    frames = [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
              for frame in traceback.extract_tb(error.__traceback__) if '/cloud_soc/' in frame.filename]
    safe_reasons = {
        'Active Compose file escapes approved state/workspace roots': 'active_compose_scope_refused',
        'State path escapes the approved root': 'protected_path_scope_refused',
        'Cannot identify the exact active Compose command; provide its protected receipt': 'active_compose_receipt_mismatch',
        'Deployment changed after planning; no mutation performed': 'plan_stale',
        'Reviewed plan was modified; no mutation performed': 'plan_changed',
        'Interrupted upgrade retained; run manage.py recover before making a new plan': 'interrupted_upgrade',
    }
    message = error.args[0] if error.args and isinstance(error.args[0], str) else ''
    print(json.dumps({'failure_class': type(error).__name__,
                      'reason': safe_reasons.get(message, 'unclassified_deployment_failure'), 'frames': frames}))
    raise SystemExit(1) from None
