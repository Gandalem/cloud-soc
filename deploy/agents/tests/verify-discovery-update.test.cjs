const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const verifier = path.join(__dirname, '../verify-discovery-update-windows.ps1');
const fixture = path.join(__dirname, 'verify-discovery-update.ps1');

test('P2C-07 verifier is read-only against protected Windows state', () => {
  const text = fs.readFileSync(verifier, 'utf8');
  assert.doesNotMatch(text, /\b(?:Start|Stop|Restart|Set|Remove|New)-Service\b/i);
  assert.doesNotMatch(text, /\b(?:Register|Unregister|Enable|Disable|Start|Stop|Set)-ScheduledTask\b/i);
  assert.doesNotMatch(text, /\bSet-ExecutionPolicy\b/i);
  assert.doesNotMatch(text, /\bSet-Acl\b|\bicacls(?:\.exe)?\b|\btakeown(?:\.exe)?\b/i);
  assert.doesNotMatch(text, /\bStart-Process\b/i);
  assert.doesNotMatch(text, /\b(?:Set|New|Remove)-ItemProperty\b/i);
  assert.doesNotMatch(text, /\b(?:Copy|Move|Remove|Rename|New)-Item\b/i);
  assert.doesNotMatch(text, /\b(?:Set|Add|Clear|Out)-Content\b/i);
  assert.doesNotMatch(text, /\[IO\.File\]::(?:Write|WriteAllText|Open|Create)/i);
  assert.doesNotMatch(text, /\bsc(?:\.exe)?\b|\breg(?:\.exe)?\b/i);
  assert.match(text, /raw_logs_read\s*=\s*\$false/);
  assert.match(text, /pre_update_guard_matches_current/);
  assert.match(text, /no_pending_or_probe_traces/);
  assert.match(text, /execution_policy_unchanged/);
});

for (const shell of ['powershell.exe', 'pwsh']) {
  test(`P2C-07 verifier synthetic pass/fail matrix: ${shell}`, { skip: process.platform !== 'win32' }, () => {
    const env = { ...process.env };
    // Let Windows PowerShell use its own modules rather than inherited PS7 modules.
    if (shell === 'powershell.exe') {
      for (const key of Object.keys(env)) {
        if (key.toLowerCase() === 'psmodulepath') delete env[key];
      }
    }
    const run = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-File', fixture], {
      encoding: 'utf8', windowsHide: true, timeout: 60000, env,
    });
    assert.ifError(run.error);
    assert.equal(run.status, 0, run.stdout + run.stderr);
  });
}
