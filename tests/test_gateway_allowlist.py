"""Opt-in exact Caddy adapter plus isolated loopback matcher integration."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CADDY = os.environ.get('SOC_TEST_CADDY')


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def fixture_handlers(value):
    if isinstance(value, dict):
        if value.get('handler') == 'reverse_proxy':
            return {'handler': 'static_response', 'status_code': 204}
        return {key: fixture_handlers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [fixture_handlers(item) for item in value]
    return value


@unittest.skipUnless(CADDY, 'Set SOC_TEST_CADDY to a verified Caddy binary for gateway integration')
class GatewayTests(unittest.TestCase):
    def adapt(self, allowed):
        env = {**os.environ, 'SOC_PUBLIC_HOST': 'soc.invalid'}
        if allowed is None:
            env.pop('SOC_ADMIN_ALLOWED_CIDRS', None)
        else:
            env['SOC_ADMIN_ALLOWED_CIDRS'] = allowed
        result = subprocess.run([CADDY, 'adapt', '--adapter', 'caddyfile', '--config', str(ROOT / 'deploy/server/Caddyfile')],
            env=env, capture_output=True, text=True, timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def exercise(self, allowed, expected):
        config = deepcopy(self.adapt(allowed))
        # Preserve production routes/matchers; substitute only TLS/listeners and
        # upstreams so no production certificate, port or server is touched.
        config['apps'].pop('tls', None)
        config['admin'] = {'disabled': True, 'config': {'persist': False}}
        ports = []
        for server in config['apps']['http']['servers'].values():
            chosen = port(); ports.append(chosen)
            server['listen'] = [f'127.0.0.1:{chosen}']
            server.pop('tls_connection_policies', None)
            server['automatic_https'] = {'disable': True}
            server['routes'] = fixture_handlers(server['routes'])
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / 'gateway.json'
            filename.write_text(json.dumps(config), encoding='utf-8')
            env = {**os.environ, 'LOCALAPPDATA': directory, 'APPDATA': directory,
                   'XDG_CONFIG_HOME': directory, 'XDG_DATA_HOME': directory}
            validation = subprocess.run([CADDY, 'validate', '--config', str(filename)], env=env,
                capture_output=True, text=True, timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.assertEqual(validation.returncode, 0, validation.stderr)
            process = subprocess.Popen([CADDY, 'run', '--config', str(filename)], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            try:
                deadline = time.monotonic() + 8
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', ports[0]), timeout=.2):
                            break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail('Isolated gateway did not start')
                        time.sleep(.05)
                for number in ports:
                    for path in ('/', '/api/keys', '/api/enrollment/exchange'):
                        with self.subTest(port=number, path=path, allowed=allowed):
                            req = Request(f'http://127.0.0.1:{number}{path}', headers={
                                'Host': 'soc.invalid', 'X-Forwarded-For': '192.0.2.35', 'Forwarded': 'for=192.0.2.35'})
                            try:
                                with urlopen(req, timeout=2) as response:
                                    status = response.status
                            except HTTPError as error:
                                status = error.code
                                error.close()
                            except URLError:
                                self.fail('Isolated gateway request failed')
                            self.assertEqual(status, expected)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)

    def test_default_preserves_current_access_on_both_listeners(self):
        self.exercise(None, 204)

    def test_approved_multi_cidr_peer_is_allowed_on_both_listeners(self):
        self.exercise('127.0.0.1/32 ::1/128', 204)

    def test_other_peer_is_denied_despite_spoofed_forwarded_headers(self):
        self.exercise('192.0.2.0/24', 403)

    def test_compose_passes_allowlist_without_changing_receiver_ports(self):
        import yaml
        compose = yaml.safe_load((ROOT / 'deploy/server/compose.yaml').read_text(encoding='utf-8'))
        self.assertEqual(compose['services']['gateway']['environment']['SOC_ADMIN_ALLOWED_CIDRS'],
                         '${SOC_ADMIN_ALLOWED_CIDRS:-0.0.0.0/0 ::/0}')
        self.assertEqual(compose['services']['elasticsearch']['ports'], ['${SOC_BIND_IP:-127.0.0.1}:9200:9200'])
