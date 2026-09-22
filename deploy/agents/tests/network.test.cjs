const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync, existsSync } = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const windows = process.platform === 'win32';
const bash = process.env.BASH_EXE || (windows ? 'C:/Program Files/Git/bin/bash.exe' : 'bash');
const pwsh = process.env.POWERSHELL_EXE || 'pwsh';
const guid = '11111111-2222-3333-4444-555555555555';
const installRoot = windows ? path.join(process.env.ProgramFiles, 'Cloud-SOC-Network') : '/opt/cloud-soc-network';
const existed = existsSync(installRoot);
const linuxArgs = ['--endpoint', 'https://soc.example.invalid:9200', '--ca', '/tmp/ca.crt', '--organization', 'school', '--interface', 'eth0'];
const winArgs = ['-Endpoint', 'https://soc.example.invalid:9200', '-CaPath', 'C:\\certs\\ca.crt', '-Organization', 'school', '-InterfaceGuid', guid];
function run(exe, args, env = {}) {
  const result = spawnSync(exe, args, { cwd: root, encoding: 'utf8', timeout: 30000, windowsHide: true, env: { ...process.env, ...env } });
  assert.ifError(result.error);
  return result;
}
function linux(extra = []) { return run(bash, ['install-network-ubuntu.sh', ...linuxArgs, ...extra, '--dry-run']); }
function win(extra = []) { return run(pwsh, ['-NoProfile', '-NonInteractive', '-File', 'install-network-windows.ps1', ...winArgs, ...extra, '-DryRun']); }
function config(result) {
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /DRY RUN/);
  assert.doesNotMatch(result.stdout, /__[A-Z_]+__/);
  return JSON.parse(result.stdout);
}
function assertSafe(c, platform) {
  assert.equal(c['output.elasticsearch'].index, `soc-network-${platform}-9.5.2-%{+yyyy.MM.dd}`);
  assert.deepEqual(c['output.elasticsearch'].hosts, ['https://soc.example.invalid:9200']);
  assert.equal(c['output.elasticsearch'].api_key, '${CLOUD_SOC_NETWORK_API_KEY}');
  assert.equal(c['output.elasticsearch']['ssl.verification_mode'], 'full');
  assert.equal(c['setup.template.enabled'], false);
  assert.equal(c['setup.ilm.enabled'], false);
  assert.equal(c['queue.disk'].max_size, '1GB');
  assert.equal(c['packetbeat.interfaces'].auto_promisc_mode, false);
  assert.equal(c['packetbeat.interfaces'].bpf_filter, undefined);
  assert.equal(c['packetbeat.npcap.never_install'], true);
  assert.equal(c['packetbeat.flows'].enabled, true);
  assert.equal(c['packetbeat.flows'].enable_delta_flow_reports, false);
  assert.deepEqual(c['packetbeat.protocols'].map(p => p.type), ['dns', 'tls']);
  for (const protocol of c['packetbeat.protocols']) {
    assert.equal(protocol.send_request, false);
    assert.equal(protocol.send_response, false);
  }
  assert.equal(c['packetbeat.protocols'][1].include_raw_certificates, false);
  const fields = c.processors.find(p => p.include_fields).include_fields.fields;
  assert.equal(c.processors.at(-2).script.file, 'privacy.js');
  assert.equal(c.processors.at(-1).drop_event.when.contains.tags, '_privacy_error');
  for (const required of ['source.ip', 'destination.ip', 'flow.final', 'dns.question.name', 'tls.client.server_name', 'organization.id']) assert.ok(fields.includes(required));
  assert.ok(!fields.some(f => /^(message|http|url|request|response|event.original|dns.answers|tls.detailed)(\.|$)/.test(f)));
}
test('Linux network syntax and metadata-only dry run', () => {
  assert.equal(run(bash, ['-n', 'install-network-ubuntu.sh']).status, 0);
  const c = config(linux()); assertSafe(c, 'linux');
  assert.equal(c['packetbeat.interfaces'].device, 'eth0');
  assert.equal(c['packetbeat.interfaces'].type, 'af_packet');
  assert.equal(config(linux(['--interface', 'any']))['packetbeat.interfaces'].device, 'any');
});
test('Linux rejects capture scope/config injection and plaintext key options', () => {
  for (const extra of [['--interface', '0'], ['--interface', '../eth0'], ['--interface', '${SECRET}'], ['--interface', 'eth0|x'], ['--interface', 'eth0"'], ['--ca', '/tmp/a&b'], ['--organization', '${SECRET}'], ['--api-key', 'secret'], ['--interface']]) {
    assert.notEqual(linux(extra).status, 0, JSON.stringify(extra));
  }
});
test('Linux dry-run cannot call the installer or open an interface', () => {
  const result = run(bash, ['-c', 'source ./install-network-ubuntu.sh; install_agent() { fail "MUST NOT INSTALL"; }; main "$@"', 'test', ...linuxArgs, '--dry-run']);
  assertSafe(config(result), 'linux');
});
test('Linux checksum guards fail closed and existing Filebeat is allowed', () => {
  assert.equal(run(bash, ['-c', 'source ./install-network-ubuntu.sh; h=$(sha512sum packetbeat.base.json); verify_archive packetbeat.base.json "${h%% *}"']).status, 0);
  assert.notEqual(run(bash, ['-c', 'source ./install-network-ubuntu.sh; verify_archive packetbeat.base.json "$(printf "%0128d" 0)"']).status, 0);
  const result = run(bash, ['-c', 'source ./install-network-ubuntu.sh; systemctl() { [[ "$2" == cloud-soc-filebeat.service ]] && printf loaded || printf not-found; }; pgrep() { return 1; }; check_existing']);
  assert.equal(result.status, 0, result.stderr);
  assert.notEqual(run(bash, ['-c', 'source ./install-network-ubuntu.sh; systemctl() { printf loaded; }; check_existing']).status, 0);
});
for (const endpoint of ['http://localhost:9200', 'https://user:secret@host', 'https://host/path', 'https://host?x=1', 'https://host#f', 'https://host:0', 'https://host:65536', 'https://host\n', 'https://${SECRET}']) {
  test(`Network installers reject endpoint ${JSON.stringify(endpoint)}`, () => {
    const l = run(bash, ['-c', 'source ./install-network-ubuntu.sh; main --endpoint "$TEST_ENDPOINT" --ca /tmp/ca --organization school --interface eth0 --dry-run'], { TEST_ENDPOINT: endpoint });
    assert.notEqual(l.status, 0); assert.match(l.stderr, /HTTPS|port/);
    if (windows) {
      const w = run(pwsh, ['-NoProfile', '-NonInteractive', '-Command', `& ./install-network-windows.ps1 -Endpoint $env:TEST_ENDPOINT -CaPath C:\\certs\\ca.crt -Organization school -InterfaceGuid ${guid} -DryRun`], { TEST_ENDPOINT: endpoint });
      assert.notEqual(w.status, 0); assert.match(w.stderr, /HTTPS|port/);
    }
  });
}
test('Windows uses a stable Npcap device GUID and the same privacy configuration', { skip: !windows }, () => {
  const c = config(win()); assertSafe(c, 'windows');
  assert.equal(c['packetbeat.interfaces'].device, `\\Device\\NPF_{${guid}}`);
  const l = config(linux());
  assert.deepEqual(c['packetbeat.protocols'], l['packetbeat.protocols']);
  assert.deepEqual(c.processors.at(-1), l.processors.at(-1));
});
test('Windows rejects wildcard/index/empty/injected interface identifiers', { skip: !windows }, () => {
  for (const value of ['any', '0', '00000000-0000-0000-0000-000000000000', '${SECRET}', guid + '\n']) {
    const args = winArgs.map((arg, i) => winArgs[i - 1] === '-InterfaceGuid' ? value : arg);
    assert.notEqual(run(pwsh, ['-NoProfile', '-NonInteractive', '-File', 'install-network-windows.ps1', ...args, '-DryRun']).status, 0);
  }
});
test('Windows helper behavior and PowerShell 5.1 syntax', { skip: !windows }, () => {
  const result = run(pwsh, ['-NoProfile', '-NonInteractive', '-File', 'tests/network-windows-functions.ps1']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const syntax = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$t=$null; $e=$null; [Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) 'install-network-windows.ps1'), [ref]$t, [ref]$e) | Out-Null; if ($e.Count) { $e; exit 1 }"]);
  assert.equal(syntax.status, 0, syntax.stderr);
});
test('Network publisher and mapped metadata do not expand host-log permissions', () => {
  const read = name => JSON.parse(readFileSync(path.join(root, name), 'utf8'));
  const role = read('network-publisher-role.json');
  assert.deepEqual(role.cluster, ['monitor']);
  assert.deepEqual(role.indices, [{ names: ['soc-network-*'], privileges: ['auto_configure', 'create_doc'] }]);
  assert.deepEqual(read('publisher-role.json').indices[0].names, ['soc-host-raw-*', 'soc-agent-health-*']);
  const template = read('network-index-template.json');
  assert.deepEqual(template.index_patterns, ['soc-network-*']);
  const props = template.template.mappings.properties;
  assert.equal(template.template.mappings.dynamic, false);
  for (const field of read('packetbeat.base.json').processors.find(p => p.include_fields).include_fields.fields) {
    let entry = { properties: props };
    for (const part of field.split('.')) entry = entry?.properties?.[part];
    assert.ok(entry, `Unmapped allowed field: ${field}`);
  }
  assert.equal(props.source.properties.ip.type, 'ip');
  assert.equal(props.flow.properties.final.type, 'boolean');
});
test('Installers retain pinned downloads, key isolation and no PCAP dump option', () => {
  for (const name of ['install-network-ubuntu.sh', 'install-network-windows.ps1']) {
    const code = readFileSync(path.join(root, name), 'utf8');
    assert.match(code, /[a-f0-9]{128}/);
    assert.match(code, /CLOUD_SOC_NETWORK_API_KEY/);
    assert.doesNotMatch(code, /--dump|ExecutionPolicy.*Bypass|ssl.verification_mode.*none/);
  }
  const win = readFileSync(path.join(root, 'install-network-windows.ps1'), 'utf8');
  assert.match(win, /-DependsOn npcap/);
  assert.match(win, /Assert-Npcap\s+& \$Exe/);
  assert.match(readFileSync(path.join(root, 'install-network-ubuntu.sh'), 'utf8'), /CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN/);
  assert.equal(existsSync(installRoot), existed);
});
