const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
for (const shell of ['powershell.exe', 'pwsh']) {
  test(`running Discovery update and rollback with isolated OS mocks: ${shell}`, {skip: process.platform !== 'win32'}, () => {
    const run = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'update-discovery.ps1')], {
      encoding: 'utf8', windowsHide: true, timeout: 60000,
    });
    assert.ifError(run.error);
    assert.equal(run.status, 0, run.stdout + run.stderr);
  });
}
test('Discovery updater never changes services, execution policy, keys or queue', () => {
  const text = fs.readFileSync(path.join(__dirname, '../update-discovery-windows.ps1'), 'utf8');
  assert.doesNotMatch(text, /(?:Stop|Start|Set|Remove)-Service|Set-ExecutionPolicy|ExecutionPolicy\s+(?:Bypass|RemoteSigned)|Invoke-Expression|keystore\s+create/);
  assert.match(text, /FileShare\]::None/);
  assert.match(text, /Server ingestion of new metrics is NOT yet verified/);
  assert.match(text, /discovery-update-pending.json/);
});
