const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
function setup() {
  const element = tag => ({tag, nodeType: 1, children: [], textContent: '', append(...items) {this.children.push(...items);}, setAttribute() {}});
  const document = {createElement: element, createTextNode: text => ({textContent: text, children: []})};
  const window = {};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../prototype/dashboard-widgets.js'), 'utf8'), {window, document, URLSearchParams});
  const box = element('div');
  const flatten = n => [n.textContent, ...n.children.map(flatten)].join(' ');
  return {ui: window.CloudSOCWidgets, box, text: () => flatten(box)};
}
test('Mall count widget uses exact server count rather than newest-50 rows', () => {
  const {ui, box, text} = setup();
  ui.render(box, {type: 'security-mall-count', config: {title: 'Mall', limit: 8}}, {enabled: true, source: 'operations', renderer: 'kpi'},
    {body: {sections: {security_mall: {state: 'ok', count: 7}, alerts: {state: 'ok', count: 99, rows: []}}}});
  assert.match(text(), /7/);
  assert.ok(!text().includes('99'));
});
test('existing alert widget shows Mall fields and legacy AUTH-001 with computed risk', () => {
  const {ui, box, text} = setup();
  const rows = [{id: 'a1', rule: 'WEB-AUTH-01', title: 'Mall auth', service: 'security-mall', severity: 'medium', risk_level: 'high', event_count: 6, status: 'stored', timestamp: '2026-10-01T00:00:00Z'},
    {id: 'a2', rule: 'AUTH-001', title: 'SSH', severity: 'high', risk_level: 'high', status: 'stored', event_count: 10}];
  ui.render(box, {type: 'alerts', config: {limit: 8, severity: 'all', chart: 'table'}}, {enabled: true, source: 'operations', renderer: 'alerts'},
    {body: {sections: {alerts: {state: 'ok', count: 2, rows}}}});
  for (const v of ['WEB-AUTH-01', 'AUTH-001', 'security-mall', '계산 위험 등급', '높음', '저장됨', '관측 건수']) assert.ok(text().includes(v), v);
});
