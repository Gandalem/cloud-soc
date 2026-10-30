"""Bounded startup acceptance for the exact images restored by the coordinator."""
import json
import time
from urllib.parse import urlsplit

from cloud_soc.deployment.image_safety import DeploymentSafetyError

# Run in the restored Portal image using only stdlib: older images need not contain
# this new module. No credentials, redirects, proxy environment or response bodies.
HTTP_PROBE = '''
import http.client, ipaddress, json, os, socket, ssl, sys, time
try:
    p = json.load(sys.stdin)
    deadline = time.monotonic() + p['seconds']
    def budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError()
        return min(2, remaining)
    c = http.client.HTTPConnection('127.0.0.1', p['portal_port'], timeout=budget())
    try:
        c.request('GET', '/login', headers={'Host': p['portal_host']})
        if c.getresponse().status != 200: raise ValueError()
    finally:
        c.close()
    if p.get('gateway'):
        context = ssl.create_default_context(cafile=os.environ.get('SOC_CA_FILE', '/run/certs/ca.crt'))
        networks = [ipaddress.ip_network(n, strict=False) for n in p['allowed'].split()]
        if not networks: raise ValueError()
        for port in p['gateway_ports']:
            raw = socket.create_connection((p['gateway'], port), timeout=budget())
            c = http.client.HTTPSConnection(p['gateway_host'], port, context=context, timeout=budget())
            try:
                c.sock = context.wrap_socket(raw, server_hostname=p['gateway_host'])
                peer = ipaddress.ip_address(c.sock.getsockname()[0])
                allowed = any(peer in n for n in networks)
                authority = p['gateway_host'] + (':' + str(port) if port != 443 else '')
                c.request('GET', '/login', headers={'Host': authority})
                status = c.getresponse().status
                if status not in ((200, 302) if allowed else (403,)): raise ValueError()
            finally:
                c.close()
                raw.close()
    print('recovery_http_ready')
except Exception:
    raise SystemExit(1) from None
'''


def public_environment(obj):
    allowed = {'SOC_PUBLIC_URL', 'SOC_PUBLIC_HOST', 'SOC_ADMIN_ALLOWED_CIDRS'}
    return {key: value for item in (obj.get('Config') or {}).get('Env', []) or []
            for key, sep, value in [item.partition('=')] if sep and key in allowed}


def probe_http(engine, project, objects, seconds):
    if not {'portal', 'gateway'}.intersection(objects):
        return True
    if 'portal' not in objects:
        return False  # No verified Python container from which to probe the gateway.
    portal = public_environment(objects['portal'])
    origin = urlsplit(portal.get('SOC_PUBLIC_URL', ''))
    if (origin.scheme not in ('http', 'https') or not origin.hostname
            or origin.username or origin.password or any(c.isspace() for c in origin.netloc)):
        return False
    payload = {'portal_host': origin.netloc, 'portal_port': 8000, 'seconds': seconds}
    if 'gateway' in objects:
        gateway = public_environment(objects['gateway'])
        authority = gateway.get('SOC_PUBLIC_HOST', '')
        parsed = urlsplit('https://' + authority)
        if (not authority or parsed.netloc != authority or not parsed.hostname or parsed.username or parsed.password
                or parsed.port is not None or any(c.isspace() for c in authority)):
            return False
        payload.update(gateway=project + '-gateway-1', gateway_host=parsed.hostname,
                       gateway_ports=[443, 5601] if 'kibana' in objects else [443],
                       allowed=gateway.get('SOC_ADMIN_ALLOWED_CIDRS', '0.0.0.0/0 ::/0'))
    try:
        result = engine.run(['exec', '-i', project + '-portal-1', 'python', '-c', HTTP_PROBE],
                            input=json.dumps(payload), timeout=seconds)
        return result.strip() == 'recovery_http_ready'
    except (RuntimeError, OSError, ValueError):
        return False


def wait_for_recovery(engine, project, pins, *, timeout=180, interval=2,
                      clock=None, sleep=None, probe=None):
    """One deadline for all services, inspect calls and application probes."""
    if not pins:
        return
    if not 0 < timeout <= 180 or not 0 < interval <= 10:
        raise ValueError('Invalid recovery readiness deadline')
    clock, sleep, probe = clock or time.monotonic, sleep or time.sleep, probe or probe_http
    deadline = clock() + timeout
    names = {project + '-' + name + '-1': name for name in pins}
    while clock() < deadline:
        remaining = deadline - clock()
        if remaining <= 0:
            break
        try:
            rows = engine.json(['inspect', *names], timeout=min(10, remaining))
        except (RuntimeError, OSError, ValueError):
            rows = []
        if isinstance(rows, list):
            objects = {names[row['Name'].lstrip('/')]: row for row in rows
                       if isinstance(row, dict) and isinstance(row.get('Name'), str)
                       and row['Name'].lstrip('/') in names}
            if len(objects) == len(rows) and set(objects) == set(pins):
                ready = True
                for name, obj in objects.items():
                    if obj.get('Image') != pins[name]:
                        raise DeploymentSafetyError('복구 이미지가 기록과 다릅니다. 복구 필요 상태를 보존했습니다')
                    state = obj.get('State') or {}
                    if not state.get('Running') or state.get('Paused') or state.get('Restarting'):
                        ready = False
                    health = state.get('Health')
                    test = ((obj.get('Config') or {}).get('Healthcheck') or {}).get('Test') or []
                    if name in ('elasticsearch', 'kibana') or health is not None or test and test[0] != 'NONE':
                        if not isinstance(health, dict) or health.get('Status') != 'healthy':
                            ready = False
                remaining = deadline - clock()
                if ready and remaining > 0 and probe(engine, project, objects, min(8, remaining)):
                    if clock() < deadline:
                        return
        remaining = deadline - clock()
        if remaining > 0:
            sleep(min(interval, remaining))
    raise DeploymentSafetyError('복구 서비스의 준비 상태 확인 시간이 초과됐습니다. pending과 복구 기록을 보존했습니다')
