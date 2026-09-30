const {test} = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const path = require('node:path');
for (const shell of ['powershell.exe', 'pwsh']) {
  test(`loss audit coverage and privacy: ${shell}`, {skip:process.platform !== 'win32'}, () => {
    const env = {...process.env};
    for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key];
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'audit-loss.ps1')],
      {encoding:'utf8', windowsHide:true, timeout:30000, env});
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /no replay passed/);
  });
}
