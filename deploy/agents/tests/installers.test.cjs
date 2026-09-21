const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const windows = process.platform === 'win32';
const bash = process.env.BASH_EXE || (windows ? 'C:/Program Files/Git/bin/bash.exe' : 'bash');
const powershell = process.env.POWERSHELL_EXE || 'pwsh';
const installRoot = windows ? path.join(process.env.ProgramFiles, 'Cloud-SOC-Agent') : '';
const installedBefore = windows && existsSync(installRoot);
const linuxArgs = ['--endpoint', 'https://soc.example.invalid:9200', '--ca', '/tmp/ca.crt', '--organization', 'school'];
const winArgs = ['-Endpoint', 'https://soc.example.invalid:9200', '-CaPath', 'C:\\certs\\ca.crt', '-Organization', 'school'];

function run(executable, args, env = {}) {
  const result = spawnSync(executable, args, { cwd: root, encoding: 'utf8', timeout: 30000, env: { ...process.env, ...env } });
  assert.ifError(result.error);
  return result;
}

function linux(extra = [], base = linuxArgs) {
  return run(bash, ['install-ubuntu.sh', ...base, ...extra, '--dry-run']);
}

function win(extra = [], base = winArgs) {
  return run(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', 'install-windows.ps1', ...base, ...extra, '-DryRun']);
}

function config(result) {
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stderr, /DRY RUN/);
  return JSON.parse(result.stdout);
}

function assertOutput(conf, platform) {
  const output = conf['output.elasticsearch'];
  assert.deepEqual(output.hosts, ['https://soc.example.invalid:9200']);
  assert.equal(output.api_key, '${CLOUD_SOC_API_KEY}');
  assert.equal(output['ssl.verification_mode'], 'full');
  assert.equal(output['ssl.certificate_authorities'].length, 1);
  assert.equal(output.index, `soc-host-raw-${platform}-9.5.2-%{+yyyy.MM.dd}`);
  assert.equal(conf['setup.template.enabled'], false);
  assert.equal(conf['setup.ilm.enabled'], false);
  assert.equal(conf['queue.disk'].max_size, '1GB');
}

test('Bash syntax and baseline dry-run configuration', () => {
  const syntax = run(bash, ['-n', 'install-ubuntu.sh']);
  assert.equal(syntax.status, 0, syntax.stderr);
  const conf = config(linux());
  assertOutput(conf, 'linux');
  assert.deepEqual(conf['filebeat.inputs'].map(input => input.fields.labels.log_source), ['linux_auth', 'linux_syslog']);
});

test('Linux additional paths have stable IDs independent of ordering', () => {
  const a = config(linux(['--log-file', '/var/log/app.log', '--log-file', '/var/log/nginx/access.log']));
  const b = config(linux(['--log-file', '/var/log/nginx/access.log', '--log-file', '/var/log/app.log']));
  assert.equal(a['filebeat.inputs'][2].id, b['filebeat.inputs'][3].id);
  assert.equal(new Set(a['filebeat.inputs'].map(input => input.id)).size, 4);
  assert.equal(a['filebeat.inputs'][2].fields.labels.log_source, 'linux_file');
});

for (const endpoint of ['http://localhost:9200', 'https://user:secret@host', 'https://host/path', 'https://host?x=1', 'https://host#f', 'https://host:0', 'https://host:65536', 'https://host\n', 'https://${SECRET}']) {
  test(`Linux rejects unsafe endpoint ${JSON.stringify(endpoint)}`, () => {
    const result = run(bash, ['-c', 'source ./install-ubuntu.sh; main --endpoint "$INSTALLER_TEST_ENDPOINT" --ca /tmp/ca.crt --organization school --dry-run'], { INSTALLER_TEST_ENDPOINT: endpoint });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /HTTPS|port/);
  });
}

test('Linux rejects malformed options, duplicate paths and config interpolation', () => {
  for (const extra of [
    ['--log-file', '/var/log/auth.log'], ['--log-file', '/etc/shadow'],
    ['--log-file', '/var/log/../secret'], ['--log-file', '/var/log/*.log'],
    ['--organization', '${SECRET}'],
    ['--api-key', 'should-not-accept-plaintext-cli-key'], ['--unknown'], ['--ca'],
  ]) assert.notEqual(linux(extra).status, 0, JSON.stringify(extra));
  const newline = run(bash, ['-c', 'source ./install-ubuntu.sh; main --endpoint https://host --ca /tmp/a --organization "$INSTALLER_TEST_ORG" --dry-run'], { INSTALLER_TEST_ORG: 'school\n' });
  assert.notEqual(newline.status, 0);
});

test('Linux dry-run cannot reach installer actions, even with hostile VERSION env', () => {
  const result = run(bash, ['-c', 'source ./install-ubuntu.sh; VERSION=22.04; install_agent() { fail "INSTALL MUST NOT RUN"; }; main "$@"', 'test', ...linuxArgs, '--dry-run']);
  assertOutput(config(result), 'linux');
});

test('Linux checksum and existing-service guards are exercised without installation', () => {
  const good = run(bash, ['-c', 'source ./install-ubuntu.sh; h=$(sha512sum install-ubuntu.sh); verify_archive install-ubuntu.sh "${h%% *}"']);
  assert.equal(good.status, 0, good.stderr);
  const bad = run(bash, ['-c', 'source ./install-ubuntu.sh; verify_archive install-ubuntu.sh "$(printf "%0128d" 0)"']);
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /SHA-512 mismatch/);
  const existing = run(bash, ['-c', 'source ./install-ubuntu.sh; systemctl() { printf "loaded\\n"; }; check_existing']);
  assert.notEqual(existing.status, 0);
  assert.match(existing.stderr, /Existing (service|installation)/);
});

test('Windows baseline dry-run and extra event channel', { skip: !windows }, () => {
  const conf = config(win(['-AdditionalChannel', 'Microsoft-Windows-PowerShell/Operational']));
  assertOutput(conf, 'windows');
  assert.deepEqual(conf['winlogbeat.event_logs'].map(log => log.name), ['Application', 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational']);
  assert.ok(conf['winlogbeat.event_logs'].every(log => log.include_xml && !log.ignore_missing_channel));
});

for (const endpoint of ['http://localhost:9200', 'https://user:secret@host', 'https://host/path', 'https://host?x=1', 'https://host#f', 'https://host:0', 'https://host:65536', 'https://host\n', 'https://${SECRET}']) {
  test(`Windows rejects unsafe endpoint ${JSON.stringify(endpoint)}`, { skip: !windows }, () => {
    const result = run(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '& ./install-windows.ps1 -Endpoint $env:INSTALLER_TEST_ENDPOINT -CaPath C:\\certs\\ca.crt -Organization school -DryRun'], { INSTALLER_TEST_ENDPOINT: endpoint });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /HTTPS|port/);
  });
}

test('Windows duplicate channels are rejected case-insensitively', { skip: !windows }, () => {
  const result = win(['-AdditionalChannel', 'security']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Duplicate/);
});

test('PowerShell isolated helper tests', { skip: !windows }, () => {
  const result = run(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', 'tests/windows-functions.ps1']);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.match(result.stdout, /tests passed/);
});

test('PowerShell 5.1 syntax compatibility without executing the installer', { skip: !windows }, () => {
  const result = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$t=$null; $e=$null; [Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) 'install-windows.ps1'), [ref]$t, [ref]$e) | Out-Null; if ($e.Count) { $e; exit 1 }"]);
  assert.equal(result.status, 0, result.stderr + result.stdout);
});

test('Central index template and publisher role are limited to the isolated intake', () => {
  const template = JSON.parse(readFileSync(path.join(root, 'index-template.json'), 'utf8'));
  assert.deepEqual(template.index_patterns, ['soc-host-raw-*']);
  assert.equal(template.template.mappings.properties['@timestamp'].type, 'date');
  const role = JSON.parse(readFileSync(path.join(root, 'publisher-role.json'), 'utf8'));
  assert.deepEqual(role.cluster, ['monitor']);
  assert.deepEqual(role.indices[0].names, ['soc-host-raw-*']);
  assert.deepEqual(role.indices[0].privileges, ['auto_configure', 'create_doc']);
});

test('Dry-run tests leave Windows installation-root existence unchanged', { skip: !windows }, () => {
  assert.equal(existsSync(installRoot), installedBefore);
});
