const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
for (const shell of ['powershell.exe', 'pwsh']) {
  test(`stopped Filebeat recovery, isolated OS mocks: ${shell}`, { skip: process.platform !== 'win32' }, () => {
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'repair-windows.ps1')], {
      encoding: 'utf8', timeout: 60000, windowsHide: true,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
test('existing installation is offered recovery before the new-install rejection', () => {
  const text = readFileSync(path.join(__dirname, '../install-windows.ps1'), 'utf8').split('\ntry {')[1];
  assert.ok(text.indexOf('Invoke-SocFilebeatRepair') < text.indexOf('Assert-NoInstallation'));
  assert.ok(text.indexOf('if ($DryRun)') < text.indexOf('Invoke-SocFilebeatRepair'));
  const repair = readFileSync(path.join(__dirname, '../repair-windows.ps1'), 'utf8');
  assert.doesNotMatch(repair, /ExecutionPolicy|--insecure|--ssl-no-revoke|keystore.*create|Remove-Service/);
  assert.match(repair, /Server ingestion is NOT yet verified/);
});
