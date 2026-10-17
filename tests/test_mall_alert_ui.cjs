// Targeted DOM rendering checks; no browser or Portal server is started.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function setup() {
  const box = {children: [], append(x) {this.children.push(x);}};
  const window = {};
  const document = {createElement(tag) {return {tag, textContent: ''};}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../prototype/mall-alerts.js'), 'utf8'), {window, document});
  return {box, ui: window.CloudSOCMall, text: () => box.children.map(n => n.textContent).join('\n')};
}
test('9-B WAF metadata distinguishes repetition and declaration from blocking', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-WAF-01', severity: 'medium'}, risk: {score: 55, level: 'medium'},
    assessment: {reason: 'scoped_crs_sqli_metadata', request_count: 3, repeat_threshold: 3,
      pattern: 'repeated_suspected_requests', matched_rule_ids: ['942100'], declared_actions: ['block'],
      engine_mode: 'DetectionOnly', blocked: false}});
  for (const value of ['SQLi 의심', 'SQL 실행 또는 침해 성공 확정 아님', '3 / 3', '반복 의심 요청',
    '942100', '선언 동작: block', 'DetectionOnly · 실제 차단 아님', '55 / medium', '분석 결과 또는 검증 가능한 증거 부족']) {
    assert.ok(text().includes(value), value);
  }
  assert.ok(!text().includes('계정 탈취'));
});
test('9-B verified WAF evidence uses existing metadata link without native payload', () => {
  const {box, ui, text} = setup();
  const item = {state: 'exact_reference', integrity: 'normalized_hash_verified',
    normalized_event: {id: 'event-waf'}, normalized: {index: 'norm', id: 'n'}, raw: {index: 'raw', id: 'r'},
    security: {status: 'recognized', adapter: 'security_mall_edge_v1', fields: {
      timestamp: '2026-10-17', request_id: '<img onerror=CANARY>', rules: [{id: '942100'}],
      engine_mode: 'DetectionOnly', blocked: false}}};
  ui.evidence(box, item, 0);
  assert.match(text(), /event-waf/);
  assert.match(text(), /942100/);
  assert.match(text(), /실제 차단 아님/);
  assert.ok(box.children.every(n => !Object.hasOwn(n, 'innerHTML')));
  assert.equal(box.children.at(-1).href, '/api/logs/detail?index=raw&id=r');
  const rejected = setup();
  rejected.ui.evidence(rejected.box, {...item, integrity: 'normalized_hash_mismatch'}, 0);
  assert.equal(rejected.box.children.length, 0);
});
test('access denial is blocked access and separate low severity / risk', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-ACCESS-01', service: 'security-mall', severity: 'low'}, risk: {score: 20, level: 'low'}, rule_snapshot: {conditions: [{field: 'event.action', value: 'order_view'}]}});
  assert.match(text(), /접근 시도 차단/);
  assert.match(text(), /규칙 severity: low/);
  assert.match(text(), /계산 위험 점수 \/ 등급: 20 \/ low/);
  assert.match(text(), /order_view/);
});
test('auth is suspicious, medium rule distinct from high calculated risk', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-AUTH-01', severity: 'medium'}, risk: {score: 60, level: 'high'}, rule_snapshot: {threshold: {count: 5}, time_window: {seconds: 300}, success_window: {seconds: 600}, cooldown: {seconds: 900}}});
  assert.match(text(), /계정 탈취 확정 아님/);
  assert.match(text(), /규칙 severity: medium/);
  assert.match(text(), /60 \/ high/);
  for (const v of ['300', '600', '900']) assert.ok(text().includes(v));
});
test('legacy AUTH-001 uses its existing rendering', () => {
  const {box, ui} = setup();
  ui.summary(box, {alert: {rule: 'AUTH-001'}});
  assert.equal(box.children.length, 0);
});
test('verified evidence displays pseudonym, key, event and exact refs; absent HTTP remains unknown', () => {
  const {box, ui, text} = setup();
  ui.evidence(box, {state: 'exact_reference', integrity: 'normalized_hash_verified',
    security: {adapter: 'security_mall_audit_v1', fields: {event_id: 'fake-uuid', account_id: 'fake-pseudonym', account_key_id: 'key-v1', authorization_reason: 'not_owner', timestamp: '2026-10-01T00:00:00Z', action: 'order_view', outcome: 'failure'}},
    normalized: {index: 'norm-fixture', id: 'n1'}, raw: {index: 'raw-fixture', id: 'r1'}, http_status: null}, 2);
  for (const value of ['이벤트 순서: 3', 'HTTP 상태: 미관측', 'fake-pseudonym', 'key-v1', 'fake-uuid', 'raw-fixture / r1', 'norm-fixture / n1']) assert.ok(text().includes(value), value);
  assert.ok(!text().includes('403'));
  assert.equal(box.children.at(-1).href, '/api/logs/detail?index=raw-fixture&id=r1');
});
test('unverified or foreign evidence renders no identifiers', () => {
  const {box, ui} = setup();
  ui.evidence(box, {state: 'provenance_mismatch', raw: {id: 'FOREIGN'}}, 0);
  assert.equal(box.children.length, 0);
});
test('untrusted display text stays text; no HTML execution path', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-ACCESS-01', reason: '<img onerror=CANARY>'}, condition: {}});
  assert.match(text(), /<img onerror=CANARY>/);
  assert.ok(box.children.every(n => !Object.hasOwn(n, 'innerHTML')));
});

test('7-C limited snapshot shows existing risk separately and never invents missing streams', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-ACCESS-01', severity: 'low'}, risk: {score: 20, level: 'low'},
    investigation: {state: 'available', triage_score: 20, triage_priority: 'low', evidence_confidence: 'limited',
      completeness: 'partial', event_count: 1, evidence_count: 1, bundle_count: 1, independent_request_count: 0,
      streams: {app: 'observed', web: 'unconfirmed', waf: 'unconfirmed'}, unresolved_alert_references: 0,
      range: {start: '2026-10-16', end: '2026-10-17'}, uncertainties: ['delayed_evidence', 'missing_streams'],
      factors: [{code: 'existing_detection_risk', points: 20}]}});
  for (const value of ['조사 우선순위 점수 / 등급: 20 / low', '계산 위험 점수 / 등급: 20 / low',
    '규칙 severity: low', '증거 신뢰도: limited', '웹 연결 증거: 미확인', 'WAF 연결 증거: 미확인',
    '앱 연결 증거: 관측됨', '연결 이벤트 / 증거 / 요청 묶음: 1 / 1 / 1', '실제 전체 요청 수 아님',
    '지연 수신 증거 포함', '실시간 분석 아님']) assert.ok(text().includes(value), value);
});

test('7-C absence or rejected evidence keeps original details usable', () => {
  for (const state of [undefined, 'not_found', 'unavailable', 'evidence_unavailable']) {
    const {box, ui, text} = setup();
    ui.summary(box, {alert: {rule: 'WEB-ACCESS-01', severity: 'low'}, risk: {score: 20, level: 'low'},
      investigation: state ? {state} : undefined});
    assert.match(text(), /미확인 · 분석 결과 또는 검증 가능한 증거 부족/);
    assert.match(text(), /20 \/ low/);
    assert.ok(!text().includes('조사 우선순위 점수'));
  }
});

test('7-C complete stream metadata remains text and does not expose raw links', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-AUTH-01', severity: 'medium'}, risk: {score: 60, level: 'high'},
    investigation: {state: 'available', triage_score: 60, triage_priority: 'high', evidence_confidence: 'corroborated_metadata',
      completeness: 'complete', event_count: 18, evidence_count: 18, bundle_count: 6, independent_request_count: 6,
      streams: {app: 'observed', web: 'observed', waf: 'observed'}, range: {start: '<img onerror=CANARY>', end: 'end'},
      factors: [{code: '<script>CANARY</script>', points: 0}], uncertainties: ['<script>CANARY</script>']}});
  assert.match(text(), /웹 연결 증거: 관측됨/);
  assert.match(text(), /연결 이벤트 \/ 증거 \/ 요청 묶음: 18 \/ 18 \/ 6/);
  assert.match(text(), /규칙 severity: medium/);
  assert.match(text(), /<img onerror=CANARY>/);
  assert.ok(!text().includes('<script>'));
  assert.ok(box.children.every(n => n.tag === 'p' && !Object.hasOwn(n, 'innerHTML')));
});

test('7-C request ID reuse is explicitly uncertain', () => {
  const {box, ui, text} = setup();
  ui.summary(box, {alert: {rule: 'WEB-ACCESS-01'}, investigation: {state: 'available',
    range: {}, uncertainties: ['request_id_reused_multiple_web_events_no_join']}});
  assert.match(text(), /같은 요청 ID의 복수 웹 요청 · 확정 연결하지 않음/);
});
