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
