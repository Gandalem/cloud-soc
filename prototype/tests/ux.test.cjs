const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const read = name => fs.readFileSync(path.join(__dirname, '..', name), 'utf8');
const pages = ['index.html', 'dashboard.html', 'operations.html', 'logs.html', 'cases.html', 'workbench.html', 'agents.html',
  'agent-status.html', 'collection-health.html', 'detection-history.html', 'reprocessing-history.html'];

test('all workspaces retain one heading, an accessible main and concise secondary help', () => {
  for (const page of pages) {
    const html = read(page);
    assert.equal((html.match(/<h1\b/g) || []).length, 1, page);
    assert.equal((html.match(/id="main"/g) || []).length, 1, page);
    assert.match(html, /href="#main"/, page);
    assert.doesNotMatch(html, /class="eyebrow"|검토된 설치 스크립트|단일 관리자 인증/, page);
    assert.doesNotMatch(html, /demo-data\.js|logs-data\.js/, page);
  }
});

test('operations shows metrics and alerts before the case queue without duplicate targets', () => {
  const html = read('operations.html');
  assert.ok(html.indexOf('id="ops-metrics"') < html.indexOf('id="case-queue"'));
  assert.ok(html.indexOf('id="ops-alerts"') < html.indexOf('id="case-queue"'));
  for (const id of ['ops-metrics', 'ops-intake-chart', 'ops-alert-chart', 'ops-alert-rows'])
    assert.equal((html.match(new RegExp(`id="${id}"`, 'g')) || []).length, 1);
  assert.match(html, /경보 0건이 안전을 의미하지/);
});

test('short copy retains irreversible actions, missing measurements and privacy limits', () => {
  assert.match(read('agents.html'), /키를 폐기하면.*전송이 중단/);
  assert.match(read('agents.html'), /설치된 에이전트와 키는 유지/);
  assert.match(read('agents.html'), /토큰은 15분.*명령줄·파일·ZIP에 저장하지/);
  assert.match(read('workbench.html'), /저장 후 수정·삭제할 수 없습니다/);
  assert.match(read('collection-health.html'), /미측정 항목은 0건이 아닙니다/);
  assert.match(read('agent-status.html'), /미수신 상태만으로 오프라인/);
  assert.match(read('logs.html'), /조회 사유와 결과가 기록/);
});

test('login uses same-origin public assets and preserves password-manager semantics', () => {
  const html = read('login.html');
  assert.match(html, /href="\/login\/styles.css"/);
  assert.match(html, /href="\/login\/agents.css"/);
  assert.match(html, /autocomplete="username"/);
  assert.match(html, /type="password" autocomplete="current-password"/);
  assert.doesNotMatch(html, /<style|style=|onclick=|https?:\/\//);
});

test('package identifiers use valid HTML unicode-set patterns and preserve server constraints', () => {
  const patterns = [...read('agents.html').matchAll(/pattern="([^"]+)"/g)].map(match => new RegExp('^(?:' + match[1] + ')$', 'v'));
  assert.equal(patterns.length, 2);
  for (const pattern of patterns) {
    for (const value of ['school', 'school-web_01', '1']) assert.ok(pattern.test(value));
    for (const value of ['한글', 'a/b', '-school', 'a'.repeat(65), 'a b']) assert.ok(!pattern.test(value));
  }
});
