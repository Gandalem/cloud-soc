const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const code = fs.readFileSync(path.join(__dirname, '../reprocessing-history.js'), 'utf8');
function element() {
  return {value: '', children: [], listeners: {}, hidden: false, open: false, showModal() {this.open = true;}, close() {this.open = false;},
    scrollIntoView() {this.scrolled = true;},
    append(...items) {this.children.push(...items);},
    replaceChildren() {this.children = [];},
    addEventListener(name, fn) {this.listeners[name] = fn;}};
}
async function boot(response) {
  const nodes = Object.fromEntries(['detail-close','refresh','summary','error','detail-panel','detail','rows','status','search','previous','next','page-state'].map(id => [id, element()]));
  vm.runInNewContext(code, {document: {getElementById: id => nodes[id], createElement: element},
    Intl, Date, fetch: async () => response});
  await new Promise(resolve => setImmediate(resolve));
  return nodes;
}
test('history counts, pagination, partial filtering and details use text nodes', async () => {
  const row = {id: 'a', timestamp: '2026-10-05T04:00:00Z', host: '<script>canary</script>', action: 'http_access',
    parse_status: 'recognized', timezone_corrected: false, raw: {index: 'raw', id: 'original'}};
  const rows = Array.from({length: 51}, (_, i) => ({...row, id: String(i), parse_status: i === 50 ? 'partial' : 'recognized'}));
  const nodes = await boot({ok: true, json: async () => ({total: 51, recognized: 50, partial: 1, timezone_corrected: 0, rows})});
  assert.equal(nodes.rows.children.length, 50);
  assert.match(nodes.summary.textContent, /전체 51건/);
  assert.equal(nodes.rows.children[0].children[2].textContent, row.host);
  nodes.next.listeners.click();
  assert.equal(nodes.rows.children.length, 1);
  nodes.status.value = 'partial'; nodes.status.listeners.input();
  assert.equal(nodes.rows.children.length, 1);
  nodes.rows.children[0].children[6].children[0].listeners.click();
  assert.equal(nodes['detail-panel'].open, true);
  nodes['detail-close'].listeners.click();
  assert.equal(nodes['detail-panel'].open, false);
  assert.ok(nodes.detail.children.some(node => node.textContent === 'original'));
});
test('permission failure displays an error without stale or synthetic rows', async () => {
  const nodes = await boot({ok: false, json: async () => ({error: '권한 없음'})});
  assert.equal(nodes.error.textContent, '권한 없음');
  assert.equal(nodes.error.hidden, false);
  assert.equal(nodes.rows.children.length, 0);
  assert.equal(nodes.refresh.disabled, false);
});
test('redacted collection produces a clear schema error without crashing', async () => {
  const nodes = await boot({ok: true, json: async () => ({total: 757, rows: '[REDACTED]'})});
  assert.match(nodes.error.textContent, /응답 형식/);
  assert.equal(nodes.rows.children.length, 0);
});

test('757 rows navigate every page exactly once and return, with filter reset and bounds', async () => {
  const rows = Array.from({length: 757}, (_, i) => ({id: String(i), host: 'vm', action: 'log',
    parse_status: i < 744 ? 'recognized' : 'partial', raw: {index: 'raw', id: String(i)}}));
  const nodes = await boot({ok: true, json: async () => ({total: 757, recognized: 744, partial: 13, timezone_corrected: 385, rows})});
  const seen = [];
  for (let page = 0; page < 16; page++) {
    assert.match(nodes['page-state'].textContent, new RegExp(`${page + 1} / 16페이지`));
    for (const row of nodes.rows.children) seen.push(Number(row.children[0].textContent));
    nodes.next.listeners.click();
  }
  assert.deepEqual(seen, Array.from({length: 757}, (_, i) => i + 1));
  assert.equal(nodes.rows.children.length, 7);
  assert.equal(nodes.next.disabled, true);
  for (let page = 15; page > 0; page--) nodes.previous.listeners.click();
  assert.equal(nodes.rows.children[0].children[0].textContent, 1);
  assert.equal(nodes.previous.disabled, true);
  assert.equal(nodes['page-state'].scrolled, true);
  nodes.status.value = 'partial'; nodes.status.listeners.input();
  assert.equal(nodes.rows.children.length, 13);
  assert.equal(nodes.previous.disabled, true);
  assert.equal(nodes.next.disabled, true);
  nodes.status.value = ''; nodes.status.listeners.input();
  assert.equal(nodes.rows.children.length, 50);
  assert.equal(nodes.next.disabled, false);
});

test('typing sudo, unmatched text, whitespace and clearing searches render correct results', async () => {
  const base = {timestamp: null, host: 'lyn-vm', parse_status: 'recognized', raw: {index: 'raw', id: 'a'}};
  const rows = [{...base, id: 'a', action: 'sudo_session_opened'}, {...base, id: 'b', action: 'desktop_log_observed'}];
  const nodes = await boot({ok: true, json: async () => ({total: 2, recognized: 2, partial: 0, timezone_corrected: 0, rows})});
  nodes.search.value = ' sudo '; nodes.search.listeners.input();
  assert.equal(nodes.rows.children.length, 1);
  assert.equal(nodes.rows.children[0].children[3].textContent, 'sudo_session_opened');
  nodes.search.value = '없는호스트123'; nodes.search.listeners.compositionend();
  assert.equal(nodes.rows.children.length, 0);
  assert.match(nodes['page-state'].textContent, /0건/);
  nodes.search.value = ''; nodes.search.listeners.search();
  assert.equal(nodes.rows.children.length, 2);
});
