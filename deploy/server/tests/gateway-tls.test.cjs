const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const tls = require('node:tls');
const { setTimeout: delay } = require('node:timers/promises');

const root = path.resolve(__dirname, '../../..');
const source = fs.readFileSync(path.join(root, 'deploy/server/Caddyfile'), 'utf8');
const image = 'caddy:2.11.4-alpine';
const dockerHost = process.platform === 'win32' ? 'npipe:////./pipe/docker_engine' : 'unix:///var/run/docker.sock';

test('gateway supplies the configured host for no-SNI clients without disabling TLS', () => {
  assert.match(source, /^\s*default_sni \{\$SOC_PUBLIC_HOST\}\s*$/m);
  assert.match(source, /^\s*admin off\s*$/m);
  assert.equal((source.match(/^https:\/\/\{\$SOC_PUBLIC_HOST\}(?::5601)? \{/gm) || []).length, 2);
  assert.equal((source.match(/tls \/certs\/server\.crt \/certs\/server\.key/g) || []).length, 2);
  assert.doesNotMatch(source, /tls_insecure_skip_verify|http:\/\//);
});

function command(program, args) {
  const result = spawnSync(program, args, { encoding: 'utf8', timeout: 30000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${program}: ${result.stderr}`);
  return result.stdout.trim();
}

function docker(...args) {
  return command('docker', ['--host', dockerHost, ...args]);
}

function connect(port, options = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: '127.0.0.1', port, servername: '', ...options });
    socket.setTimeout(3000, () => socket.destroy(new Error('TLS connection timed out')));
    socket.once('secureConnect', () => { socket.destroy(); resolve(); });
    socket.once('error', reject);
  });
}

async function waitForPort(port) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const ready = await new Promise(resolve => {
      const socket = net.connect({ host: '127.0.0.1', port });
      socket.setTimeout(200, () => socket.destroy());
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => resolve(false));
      socket.once('close', () => resolve(false));
    });
    if (ready) return;
    await delay(100);
  }
  throw new Error('Test gateway did not start');
}

test('real Caddy TLS: NAT IP without SNI, DNS SNI, CA and hostname validation', {
  skip: process.env.SOC_TEST_DOCKER_TLS !== '1', timeout: 120000,
}, async t => {
  // Opt-in only: local daemon, pre-pulled image, synthetic keys, loopback ports.
  docker('image', 'inspect', image);
  const parent = path.join(root, 'state');
  fs.mkdirSync(parent, { recursive: true });
  const base = fs.mkdtempSync(path.join(parent, 'cloud-soc-gateway-test-'));
  const realBase = fs.realpathSync(base);
  const openssl = process.env.OPENSSL_EXE || 'openssl';
  const caFile = path.join(base, 'ca.crt');
  const keyFile = path.join(base, 'server.key');
  const certFile = path.join(base, 'server.crt');
  let container;
  try {
    command(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
      '-subj', '/CN=Cloud SOC synthetic test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
      '-keyout', path.join(base, 'ca.key'), '-out', caFile]);
    command(openssl, ['req', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=192.0.2.10',
      '-keyout', keyFile, '-out', path.join(base, 'server.csr')]);
    fs.writeFileSync(path.join(base, 'server.ext'), [
      'subjectAltName=IP:192.0.2.10,DNS:soc.example.test,DNS:localhost,IP:127.0.0.1',
      'basicConstraints=critical,CA:FALSE', 'extendedKeyUsage=serverAuth', '',
    ].join('\n'));
    command(openssl, ['x509', '-req', '-in', path.join(base, 'server.csr'), '-CA', caFile,
      '-CAkey', path.join(base, 'ca.key'), '-CAcreateserial', '-out', certFile, '-days', '1',
      '-sha256', '-extfile', path.join(base, 'server.ext')]);
    const ca = fs.readFileSync(caFile);

    for (const [host, legacy] of [['192.0.2.10', true], ['192.0.2.10', false], ['soc.example.test', false]]) {
      const template = legacy ? source.replace(/^[ \t]*default_sni[^\n]*\n/m, '') : source;
      const config = template.replace(/\{\$SOC_PUBLIC_HOST\}/g, host);
      fs.writeFileSync(path.join(base, 'Caddyfile'), config);
      container = docker('create', '--pull', 'never', '--label', 'cloud-soc.test=gateway-tls',
        '--read-only', '--tmpfs', '/data', '--tmpfs', '/config', '--cap-drop', 'ALL',
        '--cap-add', 'NET_BIND_SERVICE', '--security-opt', 'no-new-privileges',
        '--publish', '127.0.0.1::443', '--publish', '127.0.0.1::5601',
        '--mount', `type=bind,src=${path.join(base, 'Caddyfile')},dst=/etc/caddy/Caddyfile,readonly`,
        '--mount', `type=bind,src=${certFile},dst=/certs/server.crt,readonly`,
        '--mount', `type=bind,src=${keyFile},dst=/certs/server.key,readonly`, image);
      docker('start', container);
      const details = JSON.parse(docker('inspect', container))[0];
      const bindings = details.NetworkSettings.Ports;
      for (const internalPort of ['443/tcp', '5601/tcp']) {
        assert.equal(bindings[internalPort][0].HostIp, '127.0.0.1');
        const port = Number(bindings[internalPort][0].HostPort);
        await waitForPort(port);
        const verify = (_hostname, cert) => tls.checkServerIdentity(host, cert);
        const servername = net.isIP(host) ? '' : host;
        // With explicit SNI the old configuration worked even behind Docker NAT.
        await connect(port, { ca, servername: 'localhost', checkServerIdentity: verify });
        t.diagnostic(`${host} ${internalPort}: explicit SNI control passed`);
        if (legacy) {
          await assert.rejects(connect(port, { ca, servername, checkServerIdentity: verify }),
            { code: 'ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR' });
          t.diagnostic(`${host} ${internalPort}: old no-SNI failure reproduced`);
          continue;
        }
        await connect(port, { ca, servername, checkServerIdentity: verify });
        await assert.rejects(connect(port, { servername, checkServerIdentity: verify }),
          /self.signed|unable to verify|unable to get local issuer/i);
        await assert.rejects(connect(port, { ca, servername,
          checkServerIdentity: (_hostname, cert) => tls.checkServerIdentity('wrong.example.test', cert),
        }), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
        t.diagnostic(`${host} ${internalPort}: TLS and negative verification checks passed`);
      }
      docker('rm', '--force', container);
      container = undefined;
    }
  } finally {
    if (container) {
      t.diagnostic(docker('logs', '--tail', '25', container));
      docker('rm', '--force', container);
    }
    assert.equal(fs.realpathSync(base), realBase);
    assert.equal(path.dirname(realBase), fs.realpathSync(parent));
    assert.ok(path.basename(realBase).startsWith('cloud-soc-gateway-test-'));
    fs.rmSync(realBase, { recursive: true, force: true });
  }
});
