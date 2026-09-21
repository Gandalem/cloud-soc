// Optional native smoke test: reads a generated PCAP, never a live NIC, writes only locally.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { syntheticPcap, secret } = require('./synthetic-network.cjs');
const root = path.resolve(__dirname, '..');
const exe = process.argv[2] && path.resolve(process.argv[2]);
assert.ok(exe && fs.existsSync(exe), 'Usage: node validate-packetbeat.cjs PATH_TO_VERIFIED_PACKETBEAT');
function run(command, args, timeout = 30000) {
  const r = spawnSync(command, args, { encoding: 'utf8', cwd: root, timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
  assert.ifError(r.error);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  return r;
}
if (process.platform === 'win32') {
  // Avoid the upstream bundled driver's absent-Npcap auto-install path entirely.
  run(process.env.POWERSHELL_EXE || 'pwsh', ['-NoProfile', '-NonInteractive', '-File', 'tests/network-windows-functions.ps1', '-VerifyInstalledNpcap']);
}
const state = path.resolve(root, '../../state');
fs.mkdirSync(state, { recursive: true });
const dir = fs.mkdtempSync(path.join(state, 'packetbeat-smoke-'));
const config = JSON.parse(fs.readFileSync(path.join(root, 'packetbeat.base.json'), 'utf8'));
config['packetbeat.interfaces'].device = 'NEVER_OPEN_LIVE_INTERFACE';
config['packetbeat.interfaces'].type = 'pcap';
delete config['output.elasticsearch'];
config['output.console'] = { pretty: false };
config['logging.to_files'] = false;
config['logging.to_stderr'] = true;
config['logging.metrics.enabled'] = false;
// Upstream's offline replay test hook lets asynchronous publishers drain at EOF.
config['packetbeat.publish_timeout'] = '3s';
// Do not collect local machine metadata in a synthetic test.
config.processors[0] = { add_fields: { target: 'host', fields: { name: 'network-offline-fixture' } } };
config.processors[1].add_fields.fields.id = 'offline-test';
config.processors[2].add_fields.fields.sensor_platform = process.platform === 'win32' ? 'windows' : 'linux';
const pcap = path.join(dir, 'synthetic.pcap');
const configuration = path.join(dir, 'packetbeat.yml');
fs.writeFileSync(pcap, syntheticPcap(), { mode: 0o600 });
fs.writeFileSync(configuration, JSON.stringify(config), { mode: 0o600 });
const args = ['--path.home', path.dirname(exe), '--path.config', dir, '--path.data', path.join(dir, 'data'), '--path.logs', path.join(dir, 'logs'), '-c', configuration];
// The run subcommand validates configuration and accepts -I; test config does not.
const result = run(exe, [...args, 'run', '-I', pcap, '-t', '-l', '1', '-e'], 60000);
fs.writeFileSync(path.join(dir, 'events.ndjson'), result.stdout, { mode: 0o600 });
fs.writeFileSync(path.join(dir, 'diagnostics.log'), result.stderr, { mode: 0o600 });
const events = result.stdout.split(/\r?\n/).filter(line => line.startsWith('{')).map(line => JSON.parse(line)).filter(event => event['@timestamp'] && !event['log.level']);
assert.ok(events.length > 0, 'No decoded synthetic events');
assert.doesNotMatch(result.stdout, new RegExp(secret));
assert.doesNotMatch(result.stdout, /"(http|request|response|answers|message|original|certificate_chain)"\s*:/);
assert.ok(events.some(e => e.dns?.question?.name?.replace(/\.$/, '') === 'cloud-soc.example.test'), 'Missing DNS event');
assert.ok(events.some(e => e.dns?.resolved_ip?.includes('203.0.113.5')), 'Missing resolved address');
assert.ok(events.some(e => e.tls?.client?.server_name === 'cloud-soc.example.test'), 'Missing TLS metadata');
const flows = events.filter(e => e.flow?.final === true);
assert.ok(flows.length >= 5, 'Missing final flows (including non-decoded protocols)');
assert.ok(flows.some(e => e.source?.port === 54000 || e.destination?.port === 54000), 'SSH port flow not collected');
assert.ok(flows.some(e => e.source?.port === 53000 || e.destination?.port === 53000), 'HTTP flow not collected');
for (const event of events) {
  assert.equal(event.organization.id, 'offline-test');
  assert.equal(event.labels.collection_mode, 'metadata_only');
  for (const ip of [event.source?.ip, event.destination?.ip].filter(Boolean)) assert.ok(['192.0.2.10', '198.51.100.20'].includes(ip), `Non-synthetic IP: ${ip}`);
}
console.log(`Packetbeat offline validation passed: ${events.length} events, ${flows.length} final flows; DNS/TLS metadata present, payload canary absent.`);
console.log(`Synthetic-only artifacts: ${dir}`);
console.log(`PCAP SHA256: ${createHash('sha256').update(fs.readFileSync(pcap)).digest('hex')}`);
