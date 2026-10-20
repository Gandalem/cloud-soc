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
test('generic file, journal and Docker mirrors cannot ship ModSecurity audit payloads',()=>{
  const audit=JSON.stringify({transaction:{producer:{modsecurity:'fixture'},request:{uri:'/private-customer-path'},messages:[]}});
  for(const message of [audit,JSON.stringify({log:audit})]) {
    assert.equal(run({labels:{log_source:'linux_journald'},message}).cancelled,true);
  }
  assert.equal(run({labels:{log_source:'linux_file'},message:'native request body',log:{file:{path:'/var/log/modsecurity/audit.log'}}}).cancelled,true);
});

test('P5 SSH and PAM sudo metadata survive unchanged while sudo command logs stay masked', () => {
  const bodies = [
    'Oct  1 00:00:00 host sshd[100]: Failed password for fixture from 192.0.2.10 port 12345 ssh2',
    'Oct  1 00:00:10 host sshd[100]: Accepted password for fixture from 192.0.2.10 port 12345 ssh2',
    'Oct  1 00:01:00 host sudo[200]: pam_unix(sudo:session): session opened for user root(uid=0) by fixture(uid=1000)'
  ];
  for (const message of bodies) {
    const event = run({labels:{log_source:'linux_file'},message});
    assert.equal(event.cancelled, false);
    assert.equal(event.source.message,message);
  }
  const command=run({labels:{log_source:'linux_file'},message:'fixture : TTY=pts/0 ; PWD=/PRIVATE_CANARY ; USER=root ; COMMAND=/bin/echo PRIVATE_CANARY'});
  assert.equal(command.source.message,'[REDACTED]');
  assert.ok(!JSON.stringify(command.source).includes('PRIVATE_CANARY'));
});

test('privacy removes duplicate raw, arguments and structured credentials', () => {
  const event = run({event: {code: '4625', original: 'CANARY'}, process: {args: ['CANARY'], command_line: 'CANARY'},
    winlog: {event_data: {Password: 'CANARY', clientSecret: 'CANARY', User: 'alice'}}, message: 'authentication failed'});
  assert.equal(event.cancelled, false);
  assert.ok(!JSON.stringify(event.source).includes('CANARY'));
  assert.equal(event.source.event.code, '4625');
  assert.equal(event.source.message, undefined);
  assert.equal(event.source.labels.privacy_policy, 'v3');
});

test('generic discovery and journal cannot bypass optional protected web collection', () => {
  const access='192.0.2.1 - PRIVATE_CANARY [14/Oct/2026:09:00:00 +0900] "GET /?unknown=PRIVATE_CANARY HTTP/1.1" 200 22';
  for(const kind of ['linux_file','linux_journald','windows_file']) {
    assert.equal(run({labels:{log_source:kind},message:access}).cancelled,true);
    assert.equal(run({labels:{log_source:kind},message:JSON.stringify({log:access})}).cancelled,true);
  }
  const protectedEvent=run({labels:{log_source:'generic_web_access'},web:{schema:'web-access-agent-v1'},http:{request:{method:'GET'},response:{status_code:200}}});
  assert.equal(protectedEvent.cancelled,false);
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

test('v3 also withholds secret options, non-HTTP URI credentials and hidden separators', () => {
  for (const message of ['--password PRIVATE_CANARY', '/token PRIVATE_CANARY',
    'postgres://user:PRIVATE_CANARY@host/db', 'ssh://host/path?unknown=PRIVATE_CANARY', 'abc\u200bPRIVATE_CANARY']) {
    const event=run({message});
    assert.equal(event.source.message,'[REDACTED]');
    assert.equal(event.source.labels.privacy_policy,'v3');
    assert.ok(!JSON.stringify(event.source).includes('PRIVATE_CANARY'));
  }
});
