"""Linux root acceptance with real Compose and disposable idle service fixtures.

Use an already-present image with /bin/sh and sleep; no pulls or product data.
This checks configuration adoption/recovery, not Portal login or log ingestion.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from cloud_soc.deployment import compose_review as review
from cloud_soc.deployment.contract import SERVICES
from cloud_soc.deployment.host import Docker, _restore_execution, containers, save_previous_site
from cloud_soc.deployment.migrations import atomic_json


def exercise(image):
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run as root on the disposable Linux Docker test host')
    engine = Docker()
    image_id = engine.json(['image', 'inspect', image])[0]['Id']
    project = 'soc-review-check-' + uuid.uuid4().hex[:12]
    alias = project + ':fixture'
    engine.run(['image', 'tag', image_id, alias])
    checks = []
    with tempfile.TemporaryDirectory(prefix=project + '-') as temp:
        root = Path(temp)
        state = root / 'state/server'
        runtime = state / 'runtime'
        runtime.mkdir(mode=0o700, parents=True)
        state.chmod(0o700)
        base = root / 'deploy/compose.json'
        base.parent.mkdir()
        outside = root / 'outside'
        outside.mkdir()
        sentinel = root / 'data'
        sentinel.mkdir()
        (sentinel / 'preserve.txt').write_text('configuration recovery fixture')
        files = [base, runtime / 'site.json', outside / 'portal.json', outside / 'entry.json']
        rows = {n: {'image': alias, 'command': ['sh', '-c', 'exec sleep 300'], 'stop_grace_period': '1s',
                    'environment': {'SOC_AGENT_ENDPOINT': 'https://192.0.2.30:9200'}} for n in SERVICES}
        rows['portal']['volumes'] = [{'type': 'bind', 'source': '../data', 'target': '/fixture-data', 'read_only': True}]
        atomic_json(base, {'services': rows})
        atomic_json(files[1], {'services': {}})
        atomic_json(files[2], {'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://portal.example'}},
                                           'gateway': {'environment': {'SOC_PORTAL_LAN_ORIGIN': 'https://portal.example'}}}})
        atomic_json(files[3], {'services': {'portal': {'image': alias}}})
        (state / 'compose.env').write_text('SOC_REVIEW_TEST=1\n')
        (state / 'compose.env').chmod(0o600)
        directory = str(base.parent)
        full = review.command(state, list(map(str, files)), directory, project)
        original = review.command(state, list(map(str, files[:2])), directory, project)
        atomic_json(runtime / 'compose.active.json', ['docker', 'compose', *original])
        try:
            for count, names in ((2, [n for n in SERVICES if n not in ('portal', 'gateway')]),
                                 (3, ['gateway']), (4, ['portal'])):
                args = review.command(state, list(map(str, files[:count])), directory, project)
                engine.run(['compose', *args, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', *names])
            before = containers(engine, project)
            receipt_before = (runtime / 'compose.active.json').read_bytes()
            result = review.create(engine, state, files, before, project)
            path = Path(result['review'])
            frozen, fingerprints = review.load(engine, state, path, before, project)
            after_review = containers(engine, project)
            assert {n: o['Id'] for n, o in before.items()} == {n: o['Id'] for n, o in after_review.items()}
            assert (runtime / 'compose.active.json').read_bytes() == receipt_before
            assert set(result['config_file_counts'].values()) == {2, 3, 4}
            checks.append('actual_compose_2_3_4_file_adoption_without_service_or_receipt_change')
            model = review.render(engine, frozen)
            assert all(model['services'][n]['image'] == image_id for n in SERVICES)
            assert model['services']['portal']['volumes'][0]['source'] == str(sentinel)
            checks.append('resolved_relative_bind_and_image_id_pinning')
            prior = files[2].read_bytes()
            atomic_json(files[2], {'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://changed.example'}}}})
            try:
                review.load(engine, state, path, before, project)
                raise AssertionError('Changed original accepted')
            except review.ComposeReviewError:
                pass
            files[2].write_bytes(prior)
            path.chmod(0o644)
            try:
                review.load(engine, state, path, before, project)
                raise AssertionError('Weak receipt permissions accepted')
            except review.ComposeReviewError:
                pass
            path.chmod(0o600)
            checks.append('source_mutation_and_weak_receipt_permissions_refused')
            review.load(engine, state, path, before, project)
            run = runtime / 'trial'
            run.mkdir(mode=0o700)
            old_site = save_previous_site(runtime, run)
            atomic_json(files[1], {'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://bad.example'}}}})
            # The recovery file is already resolved and pinned; it needs no old tag.
            engine.run(['image', 'rm', alias])
            saved = {'previous_compose': frozen, 'canonical': ['compose', '--project-name', project],
                     'old_names': list(SERVICES), 'old_site': old_site, 'old_contract': None, 'old_current': None,
                     'reviewed_compose_files': fingerprints, 'previous_images': [image_id]}
            _restore_execution(engine, runtime, run, saved)
            recovered = containers(engine, project)
            assert set(recovered) == set(SERVICES)
            for n in SERVICES:
                assert recovered[n]['State']['Running'] and recovered[n]['Image'] == image_id
                assert recovered[n]['Config']['Cmd'] == before[n]['Config']['Cmd']
                # Docker/Compose may reorder environment entries during recreation.
                environment = lambda o: dict(v.split('=', 1) for v in o['Config']['Env'])
                assert environment(recovered[n]) == environment(before[n])
            assert (sentinel / 'preserve.txt').read_text() == 'configuration recovery fixture'
            assert json.loads(files[1].read_text()) == {'services': {}}
            assert json.loads((runtime / 'compose.active.json').read_text()) == ['docker', 'compose', *frozen]
            checks.append('actual_restore_execution_with_deleted_tag_preserves_settings_and_bind_data')
        finally:
            engine.run(['compose', *full, 'down', '--remove-orphans'])
            if engine.run(['image', 'ls', '--filter', 'reference=' + alias, '--format', '{{.ID}}']).strip():
                engine.run(['image', 'rm', alias])
        assert not engine.run(['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]).strip()
        assert not engine.run(['network', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project]).strip()
        checks.append('trial_containers_network_and_tag_removed')
    return {'completed': True, 'checks': checks,
            'scope': 'real Docker Compose idle fixtures; not product Portal deployment or live agent ingestion'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Existing local image only; never pulled')
    args = parser.parse_args()
    print(json.dumps(exercise(args.image)))
