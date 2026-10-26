"""User-click lab: loopback Portal, disposable TLS ES and actual Filebeat.

No UI action is simulated. The user must apply the extension in their browser.
The sender and read-only observer remain active until stop.json or lease expiry.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import secrets
import shutil
import threading
import time

from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server

import device_os_live as common
from cloud_soc.portal.app import create_app


common.HOST = '127.0.0.1'
WEB = 'http://127.0.0.1:18780'
BEAT_IMAGE = 'docker.elastic.co/beats/filebeat:9.5.2'


class ClickLab(common.Lab):
    def __init__(self, docker, root):
        super().__init__(docker, root, None)
        self.network = self.label+'-net'
        self.report.update(scope='user-operated loopback UI, synthetic device and actual container Filebeat',
                           native_wsl='not_run', native_windows='not_run', browser_clicks='awaiting_user')

    def emit(self, **extra):
        row = {'@timestamp': datetime.now(timezone.utc).isoformat(),
               'message': '합성 클릭 시험 로그 '+secrets.token_hex(5),
               'labels': {'log_source': 'key_extension_lab'}, 'event': {'action': 'synthetic_log'}, **extra}
        with self.events.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, ensure_ascii=False)+'\n')

    def prepare(self):
        self.start()
        self.dk('network', 'create', '--label', 'cloud-soc.lab='+self.label, self.network)
        self.dk('network', 'connect', '--alias', 'elasticsearch', self.network, self.containers[0])
        # The device is seeded through the real HTTPS management/enrollment API.
        device, _ = self.device('ubuntu', '/var/log/cloud-soc-click')
        self.device_id = device['id']
        with self.app.extensions['packages'].connect() as db:
            db.execute('UPDATE managed_devices SET label=? WHERE id=?', ('키 연장 클릭 시험 장치', self.device_id))
        # Recover only our just-created encrypted handoff in-process; never log it.
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(self.call('/api/managed-devices/'+self.device_id+'/download'))) as archive:
            registration = json.loads(archive.read('registration.json'))
        attempt = secrets.token_urlsafe(32)
        reply = self.app.extensions['enrollments'].exchange(registration['token'], {
            'attempt': attempt, 'package_id': device['package_id'], 'package_sha256': registration['package_sha256']})
        self.key_id = reply['keys'][0]['id']
        self.secret_values.extend([reply['keys'][0]['key'], attempt])
        config = self.log_dir/'beat-config'
        logs = self.log_dir/'synthetic-logs'
        config.mkdir()
        logs.mkdir()
        self.events = logs/'events.jsonl'
        self.events.touch()
        shutil.copyfile(self.tls/'ca.pem', config/'ca.pem')
        (config/'filebeat.yml').write_text('''filebeat.inputs:
  - type: filestream
    id: synthetic-click-lab
    paths: ["/logs/events.jsonl"]
    prospector.scanner.fingerprint.length: 64
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  api_key: "${CLICK_LAB_KEY}"
  ssl.certificate_authorities: ["/config/ca.pem"]
  index: "soc-host-raw-linux-click-lab"
setup.ilm.enabled: false
setup.template.enabled: false
logging.level: error
''', encoding='utf-8')
        config_volume, data_volume = self.label+'-beat-config', self.label+'-beat-data'
        for volume in (config_volume, data_volume):
            self.dk('volume', 'create', '--label', 'cloud-soc.lab='+self.label, volume)
            self.volumes.append(volume)
        self.dk('run', '--rm', '--name', self.label+'-beat-config-init', '--network', 'none', '--user', '0',
                '--entrypoint', 'sh', '--mount', f'type=bind,src={config},dst=/source,readonly',
                '--mount', f'type=volume,src={config_volume},dst=/config', BEAT_IMAGE, '-c',
                'cp /source/* /config/ && chown 0:0 /config/* && chmod 640 /config/*')
        base = ['run', '--rm', '--network', 'none', '--user', '0', '--entrypoint', 'filebeat',
                '--mount', f'type=volume,src={config_volume},dst=/config,readonly',
                '--mount', f'type=volume,src={data_volume},dst=/usr/share/filebeat/data', BEAT_IMAGE]
        self.dk(*base, 'keystore', 'create', '--force', '-c', '/config/filebeat.yml')
        self.dk(*base[:1], '--interactive', *base[1:], 'keystore', 'add', 'CLICK_LAB_KEY', '--stdin', '--force',
                '-c', '/config/filebeat.yml', data=(reply['keys'][0]['key']+'\n').encode())
        beat = self.label+'-filebeat'
        self.containers.append(beat)
        self.dk('run', '-d', '--name', beat, '--label', 'cloud-soc.lab='+self.label, '--network', self.network,
                '--user', '0', '--memory', '512m', '--mount', f'type=volume,src={config_volume},dst=/config,readonly',
                '--mount', f'type=volume,src={data_volume},dst=/usr/share/filebeat/data',
                '--mount', f'type=bind,src={logs},dst=/logs,readonly',
                BEAT_IMAGE, 'filebeat', '-e', '-c', '/config/filebeat.yml')
        self.beat = beat
        self.emit(labels={'installation_probe': reply['probe'], 'log_source': 'key_extension_lab'},
                  event={'action': 'installation_probe'})
        def receipt():
            self.client.indices.refresh(index='soc-host-raw-*', ignore_unavailable=True)
            if not self.dk('exec', beat, 'cat', '/usr/share/filebeat/data/meta.json', check=False):
                return False
            agent = json.loads(self.dk('exec', beat, 'cat', '/usr/share/filebeat/data/meta.json'))['uuid']
            return self.app.extensions['enrollments'].receipt(registration['token'],
                {'attempt': attempt, 'agents': {'host': agent}})['verified']
        common.wait(receipt, 100)
        self.emit()
        common.wait(lambda: any(h['_source'].get('event', {}).get('action') == 'synthetic_log'
                               for h in self.raw(self.device_id)), 80)
        self.baseline = self.client.security.get_api_key(id=self.key_id, with_limited_by=True)['api_keys'][0]
        self.before_identity = self.identity()
        # Only the browser frontend listens on HTTP loopback. Engine data and
        # enrollment transport remain TLS; no CA trust or production setting changes.
        self.ui_user = 'trial-admin'
        self.ui_password = 'Trial-'+secrets.token_hex(5)
        self.secret_values.append(self.ui_password)
        users = self.log_dir/'portal'/'click-users.json'
        users.write_text(json.dumps({self.ui_user: {'role': 'admin', 'password_hash': generate_password_hash(self.ui_password)}}))
        users.chmod(0o600)
        ui = create_app({'STATE_DIR': self.log_dir/'portal', 'AGENT_SOURCE': common.PROJECT/'deploy/agents',
            'CA_BYTES': (self.tls/'ca.pem').read_bytes(), 'ENDPOINT': self.endpoint, 'PUBLIC_URL': WEB,
            'ENROLLMENT_ENABLED': True, 'ADMIN_USER': self.ui_user, 'ADMIN_HASH': generate_password_hash(self.ui_password),
            'USERS_FILE': users}, issuer=self.app.extensions['issuer'], monitor=self.app.extensions['monitor'])
        server = make_server('127.0.0.1', 18780, ui, threaded=True, request_handler=common.Quiet)
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.report.update(browser_clicks='awaiting_user', portal_url=WEB+'/devices.html', device_label='키 연장 클릭 시험 장치',
                           before_expiration=self.baseline['expiration'])
        self.record('loopback_session_portal_real_filebeat_and_unextended_device_ready')

    def identity(self):
        return {'started': self.dk('inspect', self.beat, '--format', '{{.State.StartedAt}}'),
                'agent': json.loads(self.dk('exec', self.beat, 'cat', '/usr/share/filebeat/data/meta.json'))['uuid'],
                'keystore_sha256': self.dk('exec', self.beat, 'sha256sum', '/usr/share/filebeat/data/filebeat.keystore').split()[0]}

    def observe(self):
        remote = self.app.extensions['issuer'].security.get_api_key(id=self.key_id, owner=True, with_limited_by=True)['api_keys'][0]
        self.report['current_expiration'] = remote['expiration']
        if remote['expiration'] != self.baseline['expiration']:
            detail = self.app.extensions['managed_devices'].detail(self.device_id)
            complete = next((o for o in detail['key_extensions'] if o['state'] == 'complete'
                             and o.get('expiration') == remote['expiration']), None)
            self.report.update(remote_extension_seen=True, local_confirmation=bool(complete),
                same_sender_identity=self.identity() == self.before_identity,
                roles_unchanged=remote['role_descriptors'] == self.baseline['role_descriptors'],
                limits_unchanged=remote['limited_by'] == self.baseline['limited_by'])
            hits = self.raw(self.device_id)
            if complete:
                confirmed = datetime.fromisoformat(next(o['updated'] for o in detail['operations'] if o['id'] == complete['id']))
                after = [h for h in hits if h['_source'].get('event', {}).get('action') == 'synthetic_log'
                         and datetime.fromisoformat(h['_source']['event']['ingested'].replace('Z', '+00:00')) > confirmed]
                self.report['post_extension_log_count'] = len(after)
                if after:
                    self.report['post_extension_raw'] = {'index': after[-1]['_index'], 'id': after[-1]['_id']}
        self.save()

    def close(self):
        try:
            super().close()
        finally:
            self.dk('network', 'rm', self.network, check=False)
            for path in (self.tls, self.log_dir/'portal'):
                assert path.resolve().is_relative_to(self.root.resolve()) and not path.is_symlink()
                if path.exists():
                    shutil.rmtree(path)
            self.report['private_state_removed'] = True
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    root = args.state.resolve()
    if root.exists() or not root.is_relative_to((common.PROJECT/'state').resolve()):
        raise ValueError('Fresh task-owned root required')
    root.mkdir(parents=True, mode=0o700)
    lab = ClickLab(args.docker, root)
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    try:
        lab.prepare()
        ends = datetime.now(timezone.utc)+timedelta(minutes=60)
        lab.report['auto_stop_kst'] = ends.astimezone(timezone(timedelta(hours=9))).isoformat()
        lab.save()
        # Intentional one-time credential handoff, never written to status/log files.
        print(json.dumps({'ready': True, 'url': WEB+'/devices.html', 'username': lab.ui_user,
                          'password': lab.ui_password, 'auto_stop_kst': lab.report['auto_stop_kst']}, ensure_ascii=False), flush=True)
        while datetime.now(timezone.utc) < ends and not (root/'stop.json').exists():
            lab.emit()
            try:
                lab.observe()
            except Exception as error:
                lab.report['observer_error_type'] = type(error).__name__
                lab.save()
            time.sleep(10)
    except Exception as error:
        import traceback
        lab.report.update(failure_type=type(error).__name__, failure_location=[
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        lab.save()
        print('Click lab failed: '+type(error).__name__, flush=True)
        return 1
    finally:
        lab.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
