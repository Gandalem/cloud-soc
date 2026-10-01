const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
for (const shell of ['powershell.exe', 'pwsh']) {
  test(`prepared receipt/file identity and promotion: ${shell}`, { skip: process.platform !== 'win32' }, () => {
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'bundle-receipt-windows.ps1')],
      { encoding: 'utf8', timeout: 30000, windowsHide: true });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
  test(`combined Windows preparation/failure preservation: ${shell}`, { skip: process.platform !== 'win32' }, () => {
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'bundle-windows.ps1')],
      { encoding: 'utf8', timeout: 60000, windowsHide: true });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
  test(`combined stopped-pair recovery, isolated OS mocks: ${shell}`, { skip: process.platform !== 'win32' }, () => {
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'bundle-repair-windows.ps1')],
      { encoding: 'utf8', timeout: 120000, windowsHide: true });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
test('both preparation modes hand off before promotion; independent installs remain supported', () => {
  for (const name of ['install-windows.ps1', 'install-network-windows.ps1']) {
    const source = readFileSync(path.join(__dirname, '..', name), 'utf8');
    assert.ok(source.indexOf('Write-SocPreparedReceipt') < source.indexOf('[IO.Directory]::Move'));
    assert.ok(source.indexOf("@('test', 'output')") < source.indexOf('Write-SocPreparedReceipt'));
    assert.match(source, /Assert-SocReceiptDestination \$PreparedReceipt/);
  }
  const source = readFileSync(path.join(__dirname, '../bundle-windows.ps1'), 'utf8');
  assert.match(source, /Read-SocPreparedReceipt \$Member.Receipt \$Member.Kind/);
  assert.match(source, /Get-FileHash.*SHA256/);
  assert.match(source, /FileMode\]::CreateNew/);
  assert.match(source, /if \(-not \$state.Started -and \$state.CleanupSafe\)/);
  assert.doesNotMatch(source, /ExecutionPolicy|Bypass|Remove-Item.*\$Member.Root/);
});

test('combined repair is explicit, keeps keys/queues and packages the helper', () => {
  const source = readFileSync(path.join(__dirname, '../bundle-repair-windows.ps1'), 'utf8');
  assert.doesNotMatch(source, /ExecutionPolicy|Bypass|keystore.*(?:create|add)|Remove-SocOwnedDirectory|Receive-CloudSocArchive/);
  assert.match(source, /Central document receipt is NOT yet verified/);
  assert.match(source, /Cloud-SOC-Filebeat-Recovery/);
  assert.match(source, /Restore-SocRepairFiles/);
  const packages = readFileSync(path.join(__dirname, '../../../src/cloud_soc/portal/packages.py'), 'utf8');
  assert.match(packages, /"bundle-repair-windows.ps1"/);
});

test('bundle recovery uses the same pinned distributions as fresh installers', () => {
  const bundle = readFileSync(path.join(__dirname, '../bundle-windows.ps1'), 'utf8');
  for (const name of ['install-windows.ps1', 'install-network-windows.ps1']) {
    const installer = readFileSync(path.join(__dirname, '..', name), 'utf8');
    const hash = installer.match(/\$Hash = '([a-f0-9]{128})'/)?.[1];
    assert.ok(hash);
    assert.ok(bundle.includes(`Hash='${hash}'`));
  }
});

test('resume is explicit and does not stop collectors or rewind queues', () => {
  const source = readFileSync(path.join(__dirname, '../bundle-resume-windows.ps1'), 'utf8');
  assert.doesNotMatch(source, /ExecutionPolicy|Bypass|Start-Service|Stop-Service|Restore-SocRepairFiles|Remove-SocOwnedDirectory/);
  assert.match(source, /Assert-SocRepairBackup/);
  assert.match(source, /Ambiguous\/missing service registration/);
  assert.match(source, /File\]::Replace/);
  const packages = readFileSync(path.join(__dirname, '../../../src/cloud_soc/portal/packages.py'), 'utf8');
  assert.match(packages, /"bundle-resume-windows.ps1"/);
  assert.match(packages, /Use -Repair -ResumeRepair together/);
  assert.match(packages, /ResumeRepair requires the complete Windows two-collector bundle/);
});
