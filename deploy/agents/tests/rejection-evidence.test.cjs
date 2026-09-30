const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

test('rejection evidence parser and bounded store (synthetic, not administrator ACL)', {skip:process.platform !== 'win32'}, () => {
  const parent = path.resolve(__dirname,'../../../state');
  fs.mkdirSync(parent,{recursive:true});
  const temp = fs.mkdtempSync(path.join(parent,'evidence-test-'));
  try {
    const framework = path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319');
    const exe = path.join(temp,'evidence-tests.exe');
    const build = spawnSync(path.join(framework,'csc.exe'), ['/noconfig','/nologo','/target:exe','/platform:x64','/main:EvidenceTests',
      ...['System.dll','System.Core.dll','System.Web.Extensions.dll'].map(n=>`/reference:${path.join(framework,n)}`),`/out:${exe}`,
      path.join(__dirname,'../discovery-native.cs'),path.join(__dirname,'rejection-evidence-tests.cs')],{encoding:'utf8',windowsHide:true,timeout:30000});
    assert.ifError(build.error); assert.equal(build.status,0,build.stdout+build.stderr);
    const run = spawnSync(exe,[temp],{encoding:'utf8',windowsHide:true,timeout:60000});
    assert.ifError(run.error); assert.equal(run.status,0,run.stdout+run.stderr);
    assert.match(run.stdout,/no replay passed/);
  } finally {
    assert.equal(path.dirname(path.resolve(temp)),parent);
    assert.match(path.basename(temp),/^evidence-test-/);
    fs.rmSync(temp,{recursive:true,force:true});
  }
});

test('evidence stays opt-in, local and isolated from collector success', () => {
  const source=fs.readFileSync(path.join(__dirname,'../discovery-native.cs'),'utf8');
  assert.match(source,/summary\["rejection_evidence"\] = RejectionEvidence.Run/);
  assert.match(source,/if \(!Directory.Exists\(store\)\) return Discovery.Map\("state", "disabled"\)/);
  assert.match(source,/catch \{ return Discovery.Map\("state", "error"/);
  assert.doesNotMatch(source,/Process\.Start|HttpClient|WebClient|powershell\.exe|System\.Management\.Automation/);
  const enable=fs.readFileSync(path.join(__dirname,'../enable-rejection-evidence.ps1'),'utf8');
  assert.match(enable,/\[switch\]\$ApproveRetention/);
  assert.match(enable,/\[IO.Directory\]::Move\(\$stage, \$target\)/);
  assert.doesNotMatch(enable,/Set-ExecutionPolicy|Remove-Item|Restart-Service|Start-Service|api_key/);
});
