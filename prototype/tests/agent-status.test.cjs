const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { rowsFor, rowMarkup, status } = require('../agent-status.js');
const script = fs.readFileSync(path.join(__dirname, '../agent-status.js'), 'utf8');
const row = { host_name: 'test-PC', host_ips: ['192.0.2.1'], os: 'Windows', organization: 'school',
  agent_id: 'one', agent_type: 'filebeat', version: '9.5.2', last_received: '2026-09-21T06:00:00Z',
  last_event: null, documents: 10, status: 'recent' };
const result = { agents: [row], checked_at: row.last_received, basis: 'server_ingestion', next_cursor: null, unidentified_documents: 0 };

test('current-page search and filters include collector, organization and IP', () => {
  for (const query of ['TEST-pc', '192.0.2.1', 'school', 'filebeat']) assert.equal(rowsFor([row], query, 'all').length, 1);
  assert.equal(rowsFor([row], '', 'delayed').length, 0);
  assert.equal(rowsFor([row], '', 'recent').length, 1);
});

test('all server metadata is escaped and unknown status cannot inject classes', () => {
  const injection = '<img src=x onerror="alert(1)">';
  const html = rowMarkup({ ...row, host_name: injection, host_ips: [injection], os: injection,
    organization: injection, agent_id: injection, agent_type: injection, version: injection, status: injection });
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(html.includes('activity-badge unknown'));
  assert.equal(status('__proto__'), 'unknown');
  assert.ok(rowMarkup({ ...row, last_received: 'invalid', documents: injection }).includes('<time>없음</time>'));
});

function browser(responses) {
  const elements = new Map();
  const get = selector => {
    if (!elements.has(selector)) elements.set(selector, { textContent: '', innerHTML: '', hidden: false,
      value: selector === '#agent-filter' ? 'all' : '', checked: true, disabled: false, listeners: {},
      addEventListener(event, fn) { this.listeners[event] = fn; }, setAttribute() {} });
    return elements.get(selector);
  };
  const calls = [];
  let interval;
  const context = { document: { querySelector: get, hidden: false, addEventListener() {} },
    window: { addEventListener() {} }, AbortController, Intl, Date,
    setTimeout: () => 1, clearTimeout() {}, setInterval: fn => { interval = fn; },
    fetch: async (url, options) => { calls.push({ url, options }); return responses.shift()(); } };
  vm.runInNewContext(script, context);
  return { get, calls, tick: () => interval(), context };
}
const ok = data => () => ({ ok: true, json: async () => data });
const settle = () => new Promise(resolve => setImmediate(resolve));

test('failed refresh clears old rows and counters rather than retaining healthy status', async () => {
  const ui = browser([ok(result), () => { throw new TypeError('Failed to fetch'); }]);
  await settle();
  assert.equal(ui.get('#count-recent').textContent, 1);
  assert.ok(ui.get('#agent-rows').innerHTML.includes('test-PC'));
  await ui.get('#status-refresh').listeners.click();
  assert.equal(ui.get('#agent-rows').innerHTML, '');
  assert.equal(ui.get('#count-recent').textContent, '-');
  assert.equal(ui.get('#status-error').hidden, false);
  assert.match(ui.get('#status-error').textContent, /중앙 서버에 연결하지 못했습니다/);
  assert.match(ui.get('#query-state').textContent, /판단 불가/);
  assert.equal(ui.get('#status-next').disabled, true);
});

test('next page sends opaque cursor and previous page restores the query', async () => {
  const ui = browser([ok({ ...result, next_cursor: 'opaque/+=' }), ok({ ...result, agents: [] }), ok(result)]);
  await settle();
  ui.get('#status-next').listeners.click();
  await settle();
  assert.equal(ui.calls[1].url, '/api/agents/status?cursor=opaque%2F%2B%3D');
  assert.equal(ui.get('#status-page').textContent, '2 페이지');
  ui.get('#status-previous').listeners.click();
  await settle();
  assert.equal(ui.calls[2].url, '/api/agents/status');
  assert.equal(ui.get('#status-page').textContent, '1 페이지');
  assert.equal(ui.calls[0].options.cache, 'no-store');
});

test('refresh does not overlap and stops when hidden or disabled', async () => {
  let resolve;
  const ui = browser([() => new Promise(done => { resolve = done; }), ok(result)]);
  ui.tick();
  assert.equal(ui.calls.length, 1);
  resolve({ ok: true, json: async () => result });
  await settle();
  ui.context.document.hidden = true;
  ui.tick();
  ui.context.document.hidden = false;
  ui.get('#auto-refresh').checked = false;
  ui.tick();
  assert.equal(ui.calls.length, 1);
  ui.get('#auto-refresh').checked = true;
  ui.tick();
  await settle();
  assert.equal(ui.calls.length, 2);
});

test('missing monitor returns its setup error without displaying an empty healthy list', async () => {
  const ui = browser([() => ({ ok: false, status: 503, json: async () => ({ error: 'setup required' }) })]);
  await settle();
  assert.equal(ui.get('#status-error').textContent, 'setup required');
  assert.equal(ui.get('#count-all').textContent, '-');
});
