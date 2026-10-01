const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const path = require('node:path');
for (const shell of ['powershell.exe','pwsh']) test(`single-token Windows install isolated mocks: ${shell}`, {skip: process.platform !== 'win32'}, () => {
  const result = spawnSync(shell, ['-NoProfile','-NonInteractive','-File',path.join(__dirname,'enrollment-windows.ps1')], {encoding:'utf8',timeout:30000,windowsHide:true});
  assert.ifError(result.error);
  assert.equal(result.status,0,result.stdout + result.stderr);
});
test('enrollment HTTP refuses redirects and keeps TLS/size protections without global trust changes', () => {
  const source = readFileSync(path.join(__dirname,'../enrollment-http.cs'),'utf8');
  assert.match(source,/AllowAutoRedirect = false/);
  assert.match(source,/X509RevocationMode.Online/);
  assert.match(source,/errors & ~SslPolicyErrors.RemoteCertificateChainErrors/);
  assert.match(source,/return AcceptChain/);
  assert.match(source,/pinned && allowUnavailable/);
  assert.match(source,/status.Status & ~permitted/);
  assert.match(source,/output.Length \+ count > 32768/);
  assert.doesNotMatch(source,/ServicePointManager|X509Store|NoCheck|Process.Start/);
  const client = readFileSync(path.join(__dirname,'../enrollment-windows.ps1'),'utf8');
  assert.match(client,/Read-Host[^\n]*-AsSecureString/);
  assert.match(client,/RandomNumberGenerator/);
  assert.match(client,/'x' \* 1100/);
  assert.doesNotMatch(client,/Set-ExecutionPolicy|Authorization.*curl|SetEnvironmentVariable/);
});
