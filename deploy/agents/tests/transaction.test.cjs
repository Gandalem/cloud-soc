const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');

for (const shell of ['powershell.exe', 'pwsh']) test(`SYSTEM probe and scratch cleanup use isolated mocks: ${shell}`, { skip: process.platform !== 'win32' }, () => {
  const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'transaction-windows.ps1')], { encoding: 'utf8', timeout: 30000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('host SYSTEM discovery runs before downloads and service creation', () => {
  const source = readFileSync(path.join(root, 'install-windows.ps1'), 'utf8').split('\ntry {')[1];
  const probe = source.indexOf('Invoke-SocDiscoveryProbe -Root');
  assert.ok(probe > 0 && probe < source.indexOf('Receive-CloudSocArchive'));
  assert.ok(source.indexOf('Test-DiscoveryTask') < source.indexOf('New-Service'));
  assert.ok(source.indexOf("@('test', 'output')") < source.indexOf('[IO.Directory]::Move'));
  assert.match(source, /-WorkingDirectory \$Root/);
});

test('both installers validate staged config before promotion and never delete post-start queues', () => {
  for (const name of ['install-windows.ps1', 'install-network-windows.ps1']) {
    const source = readFileSync(path.join(root, name), 'utf8').split('\ntry {')[1];
    assert.ok(source.indexOf('New-SocStage') < source.indexOf('Receive-CloudSocArchive'));
    assert.ok(source.indexOf("@('test', 'output')") < source.indexOf('[IO.Directory]::Move'));
    assert.ok(source.indexOf('[IO.Directory]::Move') < source.indexOf('New-Service'));
    assert.match(source, /-not \$ServiceStarted/);
    assert.match(source, /Remove-SocOwnedDirectory/);
    assert.doesNotMatch(source, /Remove-Item .*\$FinalRoot/);
  }
});
