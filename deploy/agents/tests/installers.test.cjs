const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { existsSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } = require('node:fs');
const { tmpdir } = require('node:os');
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
  assert.deepEqual(conf['filebeat.inputs'].map(input => input.fields.labels.log_source), ['linux_journald']);
  assert.equal(conf['filebeat.inputs'][0].seek, 'head');
  assert.equal(conf['filebeat.inputs'][0].id, 'cloud-soc-journal-v2');
  assert.equal(conf['filebeat.config.inputs']['reload.enabled'], true);
  assert.equal(conf['logging.to_syslog'], false);
});

test('Linux accepts additional log roots without limiting journal collection', () => {
  const result = linux(['--log-root', '/srv/app/logs']);
  const conf = config(result);
  assert.match(result.stderr, /\/var\/log \/srv\/app\/logs/);
  assert.equal(conf['filebeat.inputs'][0].include_matches, undefined);
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
    ['--log-root', '/var/log'], ['--log-root', '/'], ['--log-root', '/etc'],
    ['--log-root', '/home/user'], ['--log-root', '/opt/cloud-soc-agent/logs'],
    ['--log-file', '/etc/shadow'],
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

test('Windows baseline dry-run uses Filebeat reload, not a fixed three-channel list', { skip: !windows }, () => {
  const conf = config(win(['-AdditionalChannel', 'Microsoft-Windows-PowerShell/Operational']));
  assertOutput(conf, 'windows');
  assert.equal(conf['winlogbeat.event_logs'], undefined);
  assert.equal(conf['filebeat.config.inputs']['reload.enabled'], true);
  assert.equal(conf['logging.to_eventlog'], false);
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
  const helper = run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "$t=$null; $e=$null; [Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) 'discover-windows.ps1'), [ref]$t, [ref]$e) | Out-Null; if ($e.Count) { $e; exit 1 }"]);
  assert.equal(helper.status, 0, helper.stderr + helper.stdout);
});

function fixture(action) {
  const dir = mkdtempSync(path.join(tmpdir(), 'cloud-soc-discovery-'));
  try { return action(dir); }
  finally {
    const target = realpathSync(dir);
    assert.equal(path.dirname(target), realpathSync(tmpdir()));
    assert.match(path.basename(target), /^cloud-soc-discovery-/);
    rmSync(target, { recursive: true, force: true });
  }
}

test('Linux discovers nested logs and rotations, rejects binaries, and reports exclusions', () => fixture(dir => {
  const nested = path.join(dir, ...Array(12).fill('deep'));
  mkdirSync(nested, { recursive: true });
  writeFileSync(path.join(dir, 'auth.log'), 'Sep 3 sshd: login test\n');
  writeFileSync(path.join(dir, 'app.log.1'), 'rotated text record\n');
  writeFileSync(path.join(nested, 'service output.log'), 'deep service record\n');
  writeFileSync(path.join(dir, 'archive.gz'), 'not processed even if text\n');
  writeFileSync(path.join(dir, 'key.pem'), 'excluded secret\n');
  writeFileSync(path.join(dir, 'server.CRT'), 'excluded certificate\n');
  writeFileSync(path.join(dir, '.env'), 'excluded credentials\n');
  writeFileSync(path.join(dir, 'opaque'), Buffer.from([0, 1, 0, 255]));
  writeFileSync(path.join(dir, 'empty'), '');
  writeFileSync(path.join(dir, '$bad.log'), 'unsupported variable-like path\n');
  writeFileSync(path.join(dir, '[bad].log'), 'unsupported glob-like path\n');
  const script = 'source ./discover-linux.sh; r=$TEST_ROOT; command -v cygpath >/dev/null && r=$(cygpath -u "$r"); discover_linux_logs "$r" "$r"; render_discovered_inputs; render_discovery_report';
  const result = run(bash, ['-c', script], { TEST_ROOT: dir });
  assert.equal(result.status, 0, result.stderr);
  const [inputs, report] = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(inputs.length, 1);
  assert.equal(inputs[0].id, 'cloud-soc-linux-discovered-v2');
  assert.equal(inputs[0].paths.length, 3);
  assert.ok(inputs[0].paths.some(p => p.endsWith('service output.log')));
  assert.ok(inputs[0].paths.some(p => p.endsWith('app.log.1')));
  assert.ok(report.entries.some(e => e.status === 'unsupported_encoding_or_binary'));
  assert.ok(report.entries.some(e => e.status === 'empty_pending'));
  assert.equal(report.selected_files, 3);
  assert.equal(report.entries.filter(e => e.status === 'unsafe_path').length, 2);
  writeFileSync(path.join(dir, 'new.log'), 'appeared after initial discovery\n');
  const refreshed = run(bash, ['-c', script], { TEST_ROOT: dir });
  assert.equal(refreshed.status, 0, refreshed.stderr);
  const [newInputs] = refreshed.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line));
  assert.equal(newInputs[0].id, inputs[0].id);
  assert.equal(newInputs[0].paths.length, 4);
}));

test('Linux inventory escapes control characters without JSON injection', () => {
  const result = run(bash, ['-c', 'source ./discover-linux.sh; json_string $\'log\\001\\n"value\'']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout), 'log\x01\n"value');
});

test('Linux failed enumeration does not silently publish a partial inventory', () => {
  const result = run(bash, ['-c', 'source ./discover-linux.sh; realpath() { printf "%s\\n" "$3"; }; find() { return 1; }; discover_linux_logs /tmp']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Discovery failed/);
});

test('Windows discovery isolates disabled/direct channels and finds file logs', { skip: !windows }, () => {
  const result = run(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', 'tests/windows-discovery.ps1']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /discovery tests passed/);
});

test('Auto-discovery preserves minimum permissions, pinned packages and existing-install guards', () => {
  const linuxSource = readFileSync(path.join(root, 'install-ubuntu.sh'), 'utf8');
  const winSource = readFileSync(path.join(root, 'install-windows.ps1'), 'utf8');
  assert.match(linuxSource, /OnUnitActiveSec=1min/);
  assert.match(winSource, /New-TimeSpan -Minutes 1/);
  assert.doesNotMatch(winSource, /ExecutionPolicy\s+Bypass|Set-ExecutionPolicy/);
  assert.match(winSource, /cdb07ad1e39e7c65cefcd7c71e1dfcfa/);
  assert.match(winSource, /cloud-soc-winlogbeat/);
  assert.doesNotMatch(linuxSource + winSource, /auditpol|wevtutil\s+sl|journalctl\s+--vacuum/);
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
