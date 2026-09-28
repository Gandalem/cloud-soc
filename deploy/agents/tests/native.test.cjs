const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

test('independent .NET worker synthetic contract', {skip:process.platform !== 'win32'}, () => {
  fs.mkdirSync(path.resolve(__dirname,'../../../state'), {recursive:true});
  const temp = fs.mkdtempSync(path.resolve(__dirname, '../../../state/soc-native-build-'));
  try {
    const exe = path.join(temp, 'native-tests.exe');
    const framework = path.join(process.env.WINDIR, 'Microsoft.NET', 'Framework64', 'v4.0.30319');
    const build = spawnSync(path.join(framework,'csc.exe'), ['/noconfig','/nologo','/target:exe','/platform:x64','/main:DiscoveryTests',
      ...['System.dll','System.Core.dll','System.Web.Extensions.dll'].map(n=>`/reference:${path.join(framework,n)}`), `/out:${exe}`,
      path.join(__dirname,'../discovery-native.cs'),path.join(__dirname,'discovery-native-tests.cs')], {encoding:'utf8',windowsHide:true,timeout:30000});
    assert.ifError(build.error); assert.equal(build.status,0,build.stdout+build.stderr);
    const run=spawnSync(exe,[temp],{encoding:'utf8',windowsHide:true,timeout:30000});
    assert.ifError(run.error); assert.equal(run.status,0,run.stdout+run.stderr);
  } finally {
    assert.equal(path.dirname(path.resolve(temp)), path.resolve(__dirname,'../../../state'));
    assert.ok(path.basename(temp).startsWith('soc-native-build-'));
    fs.rmSync(temp,{recursive:true,force:true});
  }
});
test('worker is not a PowerShell wrapper and installation never changes execution policies',()=>{
  const worker=fs.readFileSync(path.join(__dirname,'../discovery-native.cs'),'utf8');
  assert.doesNotMatch(worker,/System\.Management\.Automation|Process\.Start|powershell\.exe|HttpClient|WebClient/);
  for(const name of ['native-windows.ps1','transaction-windows.ps1','repair-windows.ps1','install-windows.ps1']) {
    const source=fs.readFileSync(path.join(__dirname,'..',name),'utf8');
    assert.doesNotMatch(source,/Set-ExecutionPolicy|ExecutionPolicy\s+(Bypass|RemoteSigned)|EncodedCommand|Invoke-Expression/);
  }
  const helper=fs.readFileSync(path.join(__dirname,'../native-windows.ps1'),'utf8');
  assert.match(helper,/Get-AuthenticodeSignature/);
  assert.match(helper,/Assert-SocNativeDiscovery/);
});
for (const shell of ['powershell.exe','pwsh']) test(`native build/integrity without admin: ${shell}`, {skip:process.platform !== 'win32'}, () => {
  fs.mkdirSync(path.resolve(__dirname,'../../../state'), {recursive:true});
  const result=spawnSync(shell,['-NoProfile','-NonInteractive','-File',path.join(__dirname,'native-build.ps1')],{encoding:'utf8',windowsHide:true,timeout:60000});
  assert.ifError(result.error); assert.equal(result.status,0,result.stdout+result.stderr);
});
for (const shell of ['powershell.exe','pwsh']) test(`read-only loss audit: ${shell}`, {skip:process.platform !== 'win32'}, () => {
  const result=spawnSync(shell,['-NoProfile','-NonInteractive','-File',path.join(__dirname,'audit-loss.ps1')],{encoding:'utf8',windowsHide:true,timeout:30000});
  assert.ifError(result.error); assert.equal(result.status,0,result.stdout+result.stderr);
});
