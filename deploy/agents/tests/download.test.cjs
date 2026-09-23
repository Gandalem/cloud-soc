const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const windows = process.platform === 'win32';

for (const shell of windows ? ['powershell.exe', 'pwsh'] : ['pwsh']) {
  test(`bounded native downloader behavior: ${shell}`, () => {
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'download-windows.test.ps1')],
      { encoding: 'utf8', timeout: 30000, windowsHide: true });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /tests passed/);
  });
}

test('both installers use the shared downloader and verify hash before extracting', () => {
  for (const name of ['install-windows.ps1', 'install-network-windows.ps1']) {
    const source = readFileSync(path.join(root, name), 'utf8');
    assert.match(source, /Join-Path \$PSScriptRoot 'download-windows.ps1'/);
    assert.doesNotMatch(source, /Invoke-WebRequest/);
    assert.ok(source.indexOf('$null = Get-SystemCurl') < source.indexOf('$Stage = New-SocStage'));
    const download = source.indexOf('Receive-CloudSocArchive -Uri');
    const hash = source.indexOf('Assert-ArchiveHash $archive $Hash');
    assert.ok(download > 0 && hash > download && source.indexOf('Expand-Archive') > hash);
  }
});
