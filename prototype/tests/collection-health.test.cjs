const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const script = fs.readFileSync(path.join(__dirname, '../collection-health.js'), 'utf8');
const item = {host: '<img src=x>', organization: 'synthetic', report_state: 'recent', generated_at: '2026-09-22T00:00:00Z',
  received_at: '2026-09-22T00:01:00Z', delay_seconds: 60, selected: 1, excluded: 0, errors: 0,
  policy_version: 1, sources: [{id: 'a'.repeat(64), status: 'selected'}], omitted_sources: 0};
const page = {rows: [item], next_cursor: null};
const ok = data => () => ({ok: true, json: async () => data});
const settle = () => new Promise(resolve => setImmediate(resolve));
function browser(responses) {
  const elements = new Map(), calls = [];
  function element() { return {textContent: '', children: [], listeners: {}, disabled: false,
    addEventListener(name, fn) { this.listeners[name] = fn; },
    replaceChildren() { this.children = []; }, append(...nodes) { this.children.push(...nodes); }}; }
  const get = key => { if (!elements.has(key)) elements.set(key, element()); return elements.get(key); };
  vm.runInNewContext(script, {document: {querySelector: get, createElement: element}, AbortController, Date,
    setTimeout: () => 1, clearTimeout() {}, fetch: async (url, options) => { calls.push({url, options}); return responses.shift()(); }});
  return {get, calls};
}
test('health renders text nodes and uses the authenticated report endpoint', async () => {
  const ui = browser([ok(page)]); await settle();
  assert.equal(ui.get('#health-rows').children[0].children[0].textContent, '<img src=x> / synthetic');
  assert.match(ui.get('#query-state').textContent, /미측정/);
  assert.equal(ui.calls[0].url, '/api/agents/health');
  assert.equal(ui.calls[0].options.credentials, 'same-origin');
});
test('failed refresh clears all stale data without leaking exception payload', async () => {
  const ui = browser([ok(page), () => { throw Error('PRIVATE_CANARY'); }]); await settle();
  ui.get('#refresh').listeners.click(); await settle();
  assert.equal(ui.get('#health-rows').children.length, 0);
  assert.match(ui.get('#query-state').textContent, /조회 실패/);
  assert.ok(!ui.get('#query-state').textContent.includes('CANARY'));
});
test('cursor navigation and refresh do not permit stale requests to win', async () => {
  let release;
  const ui = browser([ok({...page, next_cursor: 'opaque/='}), () => new Promise(resolve => {release = resolve;}), ok({rows: []})]);
  await settle(); ui.get('#next').listeners.click(); await settle();
  ui.get('#refresh').listeners.click(); await settle();
  release({ok: true, json: async () => page}); await settle();
  assert.equal(ui.get('#health-rows').children.length, 0);
  assert.equal(ui.calls[1].options.signal.aborted, true);
  assert.ok(ui.calls[1].url.endsWith('opaque%2F%3D'));
});
test('authentication failure and empty data are distinct', async () => {
  const denied = browser([() => ({ok: false, status: 401})]); await settle();
  assert.match(denied.get('#query-state').textContent, /로그인/);
  const empty = browser([ok({rows: []})]); await settle();
  assert.match(empty.get('#query-state').textContent, /보고가 없습니다/);
});
