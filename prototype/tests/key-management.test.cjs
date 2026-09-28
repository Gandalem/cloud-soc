const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { rows, markup } = require('../agents.js');
const script = fs.readFileSync(path.join(__dirname, '../agents.js'), 'utf8');
const key = { id: 'host-id', package_id: 'pkg', package_name: 'lab-install', package_os: 'windows',
  organization: 'school', target_label: 'VMware lab 01', scope: 'host', status: 'unverified',
  expiration: 1900000000000, created_at: '2026-09-28T01:00:00Z' };
const portal = { packages: [{ id: 'pkg', name: 'lab', filename: 'lab-setup.zip', organization: 'school',
  os: 'windows', endpoint: 'https://soc.example.test:9200', created_at: key.created_at }], elasticsearch: 'connected' };
const ok = json => () => ({ ok: true, json: async () => json });
const fail = error => () => ({ ok: false, status: 503, json: async () => ({ error }) });
const settle = () => new Promise(resolve => setImmediate(resolve));

function browser(responses, initialHash = '') {
  const elements = new Map(), calls = [];
  const get = selector => {
    if (!elements.has(selector)) elements.set(selector, { textContent: '', innerHTML: '', hidden: false, open: false,
      value: selector === '#history-filter' ? 'all' : '', dataset: {}, listeners: {}, disabled: false,
      addEventListener(name, fn) { this.listeners[name] = fn; }, replaceChildren() { this.innerHTML = ''; }, querySelector() { return { focus() {} }; },
      showModal() { this.open = true; }, close() { this.open = false; this.listeners.close?.(); } });
    return elements.get(selector);
  };
  const listeners = {}, location = { pathname: '/agents.html', search: '' };
  let hash = initialHash;
  Object.defineProperty(location, 'hash', {get: () => hash, set: value => {
    hash = value ? '#' + value.replace(/^#/, '') : ''; listeners.hashchange?.();
  }});
  const context = { document: { querySelector: get, querySelectorAll: () => [], getElementById: id => get('#' + id) },
    window: { location, addEventListener(name, fn) { listeners[name] = fn; }, dispatchEvent(event) { listeners[event.type]?.(); },
      history: {replaceState(_a, _b, url) { hash = new URL(url, 'https://example.test').hash; }} }, Event, Intl, Date, setTimeout: () => 1, clearTimeout() {},
    fetch: async (url, options) => { calls.push({ url, options }); return responses.shift()(); } };
  vm.runInNewContext(script, context);
  function action(name, id = 'host-id', label = 'VMware lab 01') {
    const card = { dataset: { key: id }, querySelector: () => ({ value: label }) };
    const button = { dataset: { keyAction: name }, closest: () => card };
    return get('#history-content').listeners.click({ target: { closest: () => button } });
  }
  return { get, calls, action, context };
}

test('key purpose, label and package search; revoked filter is explicit', () => {
  const keys = [key, { ...key, id: 'network-id', scope: 'network', status: 'revoked' }];
  for (const query of ['VMWARE', 'lab-install', 'school', 'windows', 'Filebeat', 'host-id']) assert.equal(rows(keys, query, 'not_revoked').length, 1);
  assert.equal(rows(keys, 'Packetbeat', 'revoked')[0].id, 'network-id');
  assert.equal(rows(keys, 'not-found', 'all').length, 0);
});

test('key menu deep link opens once, closing restores package route, hash navigation reopens', async () => {
  const ui = browser([ok(portal), ok({keys:[key]}), ok({keys:[]})], '#keys');
  await settle();
  assert.equal(ui.get('#history-dialog').open, true);
  assert.equal(ui.calls.filter(call => call.url === '/api/keys').length, 1);
  ui.get('#history-dialog').close();
  assert.equal(ui.context.window.location.hash, '');
  ui.context.window.location.hash = 'keys';
  await settle();
  assert.equal(ui.get('#history-dialog').open, true);
  assert.match(ui.get('#history-content').innerHTML, /표시할 발급 이력이 없습니다/);
  ui.context.window.location.hash = '';
  assert.equal(ui.get('#history-dialog').open, false);
});

test('metadata is escaped, unknown values stay unknown, revoked action disabled', () => {
  const html = markup({ ...key, id: '"><img src=x>', target_label: '"><script>alert(1)</script>', package_name: '<svg/onload=x>', scope: '__proto__', status: '__proto__', created_at: 'invalid' });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script'));
  assert.ok(!html.includes('<svg'));
  assert.match(html, /용도 미확인/);
  assert.match(html, /기록 없음/);
  assert.match(markup({ ...key, status: 'revoked', revoked_at: key.created_at }), /data-key-action="revoke"[^>]*disabled/);
  assert.match(markup(key, true), /data-key-action="check"[^>]*disabled/);
});

test('revocation confirmation persists in refreshed history and no secret is fetched', async () => {
  const revoked = { ...key, status: 'revoked', revoked_at: key.created_at };
  const ui = browser([ok(portal), ok({ keys: [key] }), ok({ revoked: true, key: revoked }), ok({ keys: [revoked] })]);
  await settle(); await ui.get('#key-history').listeners.click(); await settle();
  assert.match(ui.get('#history-content').innerHTML, /Filebeat/);
  await ui.action('revoke');
  await ui.action('confirm-revoke');
  assert.match(ui.get('#history-message').textContent, /폐기를 확인/);
  assert.match(ui.get('#history-content').innerHTML, /폐기 완료/);
  await ui.get('#history-refresh').listeners.click();
  assert.match(ui.get('#history-content').innerHTML, /data-key-action="revoke"[^>]*disabled/);
  assert.equal(ui.calls[2].options.method, 'POST');
  assert.equal(ui.calls[2].options.headers['X-Cloud-SOC'], 'portal');
});

test('failed revoke stays retryable and error is inside the open dialog', async () => {
  const ui = browser([ok(portal), ok({ keys: [key] }), fail('폐기 연결 실패')]);
  await settle(); await ui.get('#key-history').listeners.click(); await settle(); await ui.action('revoke'); await ui.action('confirm-revoke');
  assert.equal(ui.get('#history-dialog').open, true);
  assert.match(ui.get('#history-message').textContent, /Filebeat.*폐기 연결 실패/);
  assert.doesNotMatch(ui.get('#history-content').innerHTML, /data-key-action="revoke"[^>]*disabled/);
});

test('cancel sends no revocation, confirmation identifies target and purpose', async () => {
  const ui = browser([ok(portal), ok({ keys: [key] })]);
  await settle(); await ui.get('#key-history').listeners.click(); await settle();
  await ui.action('revoke');
  assert.match(ui.get('#history-content').innerHTML, /VMware lab 01/);
  assert.match(ui.get('#history-content').innerHTML, /확인 후 키 폐기/);
  await ui.action('cancel-revoke'); assert.equal(ui.calls.length, 2);
  assert.doesNotMatch(ui.get('#history-content').innerHTML, /확인 후 키 폐기/);
});

test('failed server check clears previously active indicator', async () => {
  const ui = browser([ok(portal), ok({ keys: [{ ...key, status: 'active' }] }), fail('서버 확인 실패')]);
  await settle(); await ui.get('#key-history').listeners.click(); await settle(); await ui.action('check');
  assert.match(ui.get('#history-content').innerHTML, /서버 확인 실패/);
  assert.doesNotMatch(ui.get('#history-content').innerHTML, /유효 \(마지막/);
});

test('alias failures preserve draft across rendering and search', async () => {
  const ui = browser([ok(portal), ok({ keys: [key] }), fail('저장 실패')]);
  await settle(); await ui.get('#key-history').listeners.click(); await settle();
  ui.get('#history-content').listeners.input({ target: { matches: () => true, closest: () => ({ dataset: { key: 'host-id' } }), value: 'edited lab' } });
  await ui.action('label', 'host-id', 'edited lab');
  assert.match(ui.get('#history-content').innerHTML, /edited lab/);
  assert.equal(JSON.parse(ui.calls[2].options.body).target_label, 'edited lab');
});

test('package delete failure keeps dialog and explains remaining retry', async () => {
  const ui = browser([ok(portal), fail('삭제 권한 확인'), ok(portal), ok({ deleted: true }), ok({ ...portal, packages: [] })]);
  await settle();
  ui.get('#package-rows').listeners.click({ target: { closest: () => ({ dataset: { delete: 'pkg' } }) } });
  await ui.get('#confirm-delete').listeners.click();
  assert.equal(ui.get('#delete-dialog').open, true);
  assert.equal(ui.get('#delete-error').hidden, false);
  assert.match(ui.get('#delete-error').textContent, /남은 1개/);
  await ui.get('#confirm-delete').listeners.click();
  assert.equal(ui.get('#delete-dialog').open, false);
  assert.equal(ui.calls.filter(call => call.options.method === 'DELETE').length, 2);
});

test('old history response cannot overwrite reopened dialog', async () => {
  let release;
  const ui = browser([ok(portal), () => new Promise(resolve => { release = () => resolve({ ok: true, json: async () => ({ keys: [key] }) }); }), ok({ keys: [] })]);
  await settle(); const old = ui.get('#key-history').listeners.click(); await settle();
  ui.get('#history-dialog').close(); await ui.get('#key-history').listeners.click(); await settle();
  release(); await old;
  assert.match(ui.get('#history-content').innerHTML, /표시할 발급 이력이 없습니다/);
});
