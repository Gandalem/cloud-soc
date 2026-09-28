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
const textOf = node => typeof node === 'string' ? node : node.textContent + node.children.map(textOf).join(' ');
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

test('numeric samples show backlog and failures without treating absent counters as zero', async () => {
  const metrics = {state:'recent', queue_state:'high', queue_pct:.9, queue_bytes:900, queue_events:10,
    sampled_at:'2026-09-22T00:00:00Z', interval_seconds:30, output_total:20, output_acked:18,
    output_failed:2, output_dropped:null, scan_partial:true, transport_state:'error_observed'};
  const ui = browser([ok({rows:[{...item,collector_metrics:metrics}]})]); await settle();
  const text = textOf(ui.get('#health-rows'));
  assert.match(text,/90\.0% · 적체 주의/);
  assert.match(text,/재시도 실패 2 \/ 포기 미보고/);
  assert.match(text,/읽기 범위 제한/);
  assert.match(text,/누적 유실량\/전체 정상 판정 아님/);
});

test('stale, clock-invalid, absent and malformed samples remain visibly uncertain', async () => {
  for (const [state,label] of [['stale','오래된 표본'],['clock_warning','시계 확인'],['unavailable','미측정'],['invalid','보고 형식 확인']]) {
    const ui=browser([ok({rows:[{...item,collector_metrics:{state,sampled_at:item.generated_at}}]})]); await settle();
    assert.match(textOf(ui.get('#health-rows')),new RegExp(label));
    assert.doesNotMatch(textOf(ui.get('#health-rows')),/포기 0|정상입니다/);
  }
});
