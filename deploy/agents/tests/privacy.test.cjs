const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../privacy.js'), 'utf8'), context);

function run(source, fail = false) {
  const event = {source: structuredClone(source), cancelled: false,
    Get() { return this.source; },
    Put(key, value) {
      if (fail) throw Error('CANARY');
      const parts = key.split('.'); let cursor = this.source;
      for (const part of parts.slice(0, -1)) cursor = cursor[part] ||= {};
      cursor[parts.at(-1)] = value;
    },
    Delete(key) {
      const parts = key.split('.'); let cursor = this.source;
      for (const part of parts.slice(0, -1)) cursor = cursor[part];
      delete cursor[parts.at(-1)]; return true;
    },
    Cancel() { this.cancelled = true; }
  };
  context.process(event);
  return event;
}

test('privacy removes duplicate raw, arguments and structured credentials', () => {
  const event = run({event: {code: '4625', original: 'CANARY'}, process: {args: ['CANARY'], command_line: 'CANARY'},
    winlog: {event_data: {Password: 'CANARY', clientSecret: 'CANARY', User: 'alice'}}, message: 'authentication failed'});
  assert.equal(event.cancelled, false);
  assert.ok(!JSON.stringify(event.source).includes('CANARY'));
  assert.equal(event.source.event.code, '4625');
  assert.equal(event.source.message, undefined);
  assert.equal(event.source.labels.privacy_policy, 'v2');
});

test('whole suspicious strings and oversized fields are withheld before queueing', () => {
  for (const message of ['password=CANARY', 'Bearer CANARY', 'https://user:CANARY@host/',
    'https://host/path?unknown=CANARY', '-----BEGIN PRIVATE KEY-----\nCANARY', 'x'.repeat(8193)]) {
    assert.equal(run({message}).source.message, '[REDACTED]');
  }
});

test('processor exceptions and oversized object graphs fail closed', () => {
  assert.equal(run({message: 'safe'}, true).cancelled, true);
  assert.equal(run({message: Array(4100).fill('safe')}).cancelled, true);
  let nested = {}; for (let n = 0; n < 15; n++) nested = {nested};
  assert.equal(run(nested).cancelled, true);
  context.test();
});

test('P3 audit metadata survives privacy while task content and command lines do not', () => {
  const event = run({ message: 'Rendered arguments PRIVATE_CANARY', winlog: {provider_name: 'Microsoft-Windows-Sysmon', event_id: '1', event_data: {
    ProcessGuid: '{11111111-2222-3333-4444-555555555555}', Image: 'C:\\fixture.exe',
    Hashes: 'SHA256=' + 'a'.repeat(64), TargetFilename: 'C:\\approved\\fixture.txt',
    AccessMask: '0x1', SubjectUserName: 'fixture', CommandLine: 'PRIVATE_CANARY',
    ParentCommandLine: 'PRIVATE_CANARY', TaskContent: '<task>PRIVATE_CANARY</task>',
    NewTaskContent: 'PRIVATE_CANARY', ScriptBlockText: 'PRIVATE_CANARY' }} });
  assert.equal(event.cancelled, false);
  assert.ok(!JSON.stringify(event.source).includes('PRIVATE_CANARY'));
  assert.equal(event.source.winlog.event_data.Image, 'C:\\fixture.exe');
  assert.equal(event.source.winlog.event_data.AccessMask, '0x1');
  assert.equal(event.source.winlog.event_data.Hashes, 'SHA256=' + 'a'.repeat(64));
});

test('native Linux audit argument records are withheld, not decoded and published', () => {
  for (const type of ['EXECVE', 'PROCTITLE', 'USER_CMD']) {
    assert.equal(run({labels: {log_source: 'linux_file'}, message: `type=${type} msg=audit(1790000000.1:1): proctitle=43414e415259`}).cancelled, true);
  }
  assert.equal(run({labels: {log_source: 'linux_file'}, message: 'type=SYSCALL msg=audit(1790000000.1:1): syscall=59'}).cancelled, false);
});
