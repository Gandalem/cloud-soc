const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { rowMarkup, query, validPage, time } = require('../logs.js');
const script = fs.readFileSync(path.join(__dirname, '../logs.js'), 'utf8');
const row = { reference: { index: 'soc-host-raw-test', id: 'fixture-id' }, host_name: 'fixture-host', os: 'windows',
  received_at: '2026-09-22T01:00:03Z', event_at: null, source_kind: 'windows_event', outcome: 'unknown',
  quality: { invalid_fields: [], truncated_fields: [] } };
const result = { contract_version: 1, rows: [row], next_cursor: null, raw_access: 'restricted', total: null,
  filters: { start: '2026-09-22T01:00:00Z', end: '2026-09-22T02:00:00Z', time_basis: 'ingested' } };
const defaults = { period: '60', timeBasis: 'ingested', pageSize: '25', host: '', ip: '', os: '', collector: '' };
const ok = data => () => ({ ok: true, json: async () => data });
const settle = () => new Promise(resolve => setImmediate(resolve));

function browser(responses) {
  const elements = new Map(), windowEvents = {}, calls = [];
  const initial = { '#log-period': '60', '#log-time-basis': 'ingested', '#log-page-size': '25' };
  function element(value = '') {
    return { textContent: '', innerHTML: '', value, hidden: false, disabled: false, open: false, children: [], listeners: {},
      addEventListener(name, fn) { this.listeners[name] = fn; }, setAttribute() {},
      replaceChildren() { this.children = []; }, append(...nodes) { this.children.push(...nodes); },
      close() { this.open = false; }, showModal() { this.open = true; }, reset() {} };
  }
  const get = selector => { if (!elements.has(selector)) elements.set(selector, element(initial[selector] || '')); return elements.get(selector); };
  const context = { document: { querySelector: get, createElement: () => element() },
    window: { addEventListener: (name, fn) => { windowEvents[name] = fn; } }, AbortController, URLSearchParams, Intl, Date, TypeError,
    setTimeout: () => 1, clearTimeout() {},
    fetch: async (url, options) => { calls.push({ url, options }); return responses.shift()(); } };
  vm.runInNewContext(script, context);
  return { get, calls, windowEvents };
}

test('relative and custom windows are UTC while custom inputs mean KST', () => {
  const url = new URL(query({ ...defaults, host: 'a&b' }, Date.parse('2026-09-22T02:00:00Z')), 'https://example.test');
  assert.equal(url.searchParams.get('start'), '2026-09-22T01:00:00.000Z');
  assert.equal(url.searchParams.get('host'), 'a&b');
  const custom = new URL(query({ ...defaults, period: 'custom', start: '2026-09-22T10:00', end: '2026-09-22T11:00' }), 'https://example.test');
  assert.equal(custom.searchParams.get('start'), url.searchParams.get('start'));
  for (const values of [{ period: 'all' }, { period: 'custom', start: '', end: '' },
    { period: 'custom', start: '2026-09-22T12:00', end: '2026-09-22T11:00' }]) assert.throws(() => query({ ...defaults, ...values }));
});

test('untrusted table values cannot introduce HTML and missing fields remain unknown', () => {
  const malicious = '<img src=x onerror="alert(1)">';
  const html = rowMarkup({ ...row, reference: { ...row.reference, id: malicious }, host_name: malicious,
    file_path: malicious, source_ip: malicious, user: malicious, source_kind: '__proto__', outcome: '__proto__' }, 0);
  assert.ok(!html.includes('<img'));
  assert.match(html, /&lt;img/);
  assert.match(html, /미분류/);
  assert.match(html, /미관측/);
  assert.match(html, /미평가/);
  assert.equal(time('not-a-date'), '미관측');
});

test('invalid response shapes are rejected, not used as fake empty success', () => {
  assert.ok(validPage(result));
  for (const data of [null, {}, { ...result, contract_version: 2 }, { ...result, rows: [null] },
    { ...result, rows: Array(51).fill(row) }, { ...result, raw_access: 'full' }, { ...result, next_cursor: 123 }]) assert.ok(!validPage(data));
});

test('next fetches cursor only; previous and visited next use snapshot memory', async () => {
  const ui = browser([ok({ ...result, next_cursor: 'opaque/+=' }), ok({ ...result, rows: [{ ...row, reference: { ...row.reference, id: 'second' } }] })]);
  await settle();
  assert.match(ui.get('#log-rows').innerHTML, /fixture-host/);
  ui.get('#log-next').listeners.click(); await settle();
  assert.equal(new URL(ui.calls[1].url, 'https://example.test').searchParams.get('cursor'), 'opaque/+=');
  assert.equal(ui.get('#log-page-label').textContent, '2 페이지');
  ui.get('#log-prev').listeners.click();
  assert.equal(ui.get('#log-page-label').textContent, '1 페이지');
  ui.get('#log-next').listeners.click();
  assert.equal(ui.calls.length, 2);
  assert.equal(ui.get('#log-next').disabled, true);
  assert.equal(ui.calls[0].options.cache, 'no-store');
});

test('failed refresh clears old results, counters, details and navigation', async () => {
  const ui = browser([ok(result), () => { throw new TypeError('Failed to fetch'); }]);
  await settle();
  await ui.get('#log-refresh').listeners.click();
  assert.equal(ui.get('#log-rows').innerHTML, '');
  assert.equal(ui.get('#log-result').textContent, '-');
  assert.equal(ui.get('#log-empty').hidden, true);
  assert.equal(ui.get('#log-error').hidden, false);
  assert.equal(ui.get('#log-next').disabled, true);
});

test('401, 403, 410, 413 and 503 remain errors without echoing upstream messages', async () => {
  for (const status of [401, 403, 410, 413, 503]) {
    const ui = browser([() => ({ ok: false, status, json: async () => ({ error: 'PRIVATE_CANARY' }) })]);
    await settle();
    assert.equal(ui.get('#log-state-label').textContent, '조회 실패');
    assert.ok(!ui.get('#log-error').textContent.includes('CANARY'));
    assert.equal(ui.get('#log-empty').hidden, true);
  }
});

test('late old requests cannot overwrite a newer refresh', async () => {
  let release;
  const ui = browser([() => new Promise(resolve => { release = resolve; }), ok({ ...result, rows: [] })]);
  await ui.get('#log-refresh').listeners.click();
  release({ ok: true, json: async () => result }); await settle();
  assert.equal(ui.get('#log-empty').hidden, false);
  assert.equal(ui.get('#log-rows').innerHTML, '');
  assert.equal(ui.calls[0].options.signal.aborted, true);
});

test('detail uses encoded reference and text nodes; late details stay closed', async () => {
  let release;
  const dangerous = { ...row, reference: { ...row.reference, id: 'a/b?c&d' }, host_name: '<img src=x>' };
  const ui = browser([ok({ ...result, rows: [dangerous] }), ok({ contract_version: 1, row: dangerous, raw_access: 'restricted' }),
    () => new Promise(resolve => { release = resolve; })]);
  await settle();
  const event = { target: { closest: () => ({ dataset: { row: '0' } }) } };
  ui.get('#log-rows').listeners.click(event); await settle();
  const url = new URL(ui.calls[1].url, 'https://example.test');
  assert.equal(url.searchParams.get('id'), 'a/b?c&d');
  assert.ok(ui.get('#log-detail-fields').children.some(node => node.textContent === '<img src=x>'));
  ui.get('#log-detail-close').listeners.click();
  ui.get('#log-rows').listeners.click(event);
  ui.get('#log-detail-close').listeners.click();
  release({ ok: true, json: async () => ({ contract_version: 1, row: dangerous, raw_access: 'restricted' }) }); await settle();
  assert.equal(ui.get('#log-detail-dialog').open, false);
  assert.equal(ui.get('#log-detail-fields').children.length, 0);
});

test('leaving page clears in-memory metadata and cancels outstanding requests', async () => {
  const ui = browser([ok(result)]); await settle();
  ui.windowEvents.pagehide();
  assert.equal(ui.get('#log-rows').innerHTML, '');
  assert.equal(ui.get('#log-detail-fields').children.length, 0);
});

test('security detail is Korean, text-only and ignores unapproved fields', async () => {
  const security = { version: 1, status: 'recognized', adapter: 'sysmon_v1', process_link: 'not_established',
    fields: { category: 'process', action: 'process_created', process_path: '<img src=x>', command_line: 'PRIVATE_CANARY' },
    missing: ['actor'], limitations: ['not_a_detection', 'pid_not_stable_identity'] };
  const ui = browser([ok(result), ok({ contract_version: 1, row, raw_access: 'restricted', security })]);
  await settle();
  ui.get('#log-rows').listeners.click({ target: { closest: () => ({ dataset: { row: '0' } }) } });
  await settle();
  const text = ui.get('#log-detail-fields').children.map(node => node.textContent).join('\n');
  assert.match(text, /프로세스 생성/);
  assert.match(text, /<img src=x>/);
  assert.match(text, /감사 비활성으로 단정할 수 없음/);
  assert.match(text, /PID만으로/);
  assert.ok(!text.includes('PRIVATE_CANARY'));
  assert.ok(ui.get('#log-detail-fields').children.every(node => !node.innerHTML));
});

test('unsupported and partial security states never look fully parsed', () => {
  const { securityEntries } = require('../logs.js');
  assert.match(JSON.stringify(securityEntries(null)), /미제공/);
  assert.match(JSON.stringify(securityEntries({ version: 1, status: 'unsupported' })), /미지원/);
  assert.match(JSON.stringify(securityEntries({ version: 1, status: 'partial', missing: ['process_guid'] })), /부분 해석/);
  const rendered = JSON.stringify(securityEntries({ version: 1, status: 'recognized', fields: { bytes: 0, flow_final: false }, limitations: ['no_process_or_file_attribution', 'flow_counters_cumulative_do_not_sum_reports'] }));
  assert.match(rendered, /합산하지/);
  assert.match(rendered, /아니요/);
  assert.match(rendered, /프로세스나 유출 파일을 알 수 없습니다/);
});

test('AWS records display account/Region without pretending they are hosts', () => {
  const cloud = { ...row, stream: 'cloud', os: 'cloud', source_kind: 'aws_cloudtrail', collector: 'cloudtrail',
    host_name: null, cloud_account: '123456789012', cloud_region: 'us-east-1', actor_id: 'ROLE:fixture', user: null,
    action: 'ConsoleLogin', outcome: 'failure' };
  const html = rowMarkup(cloud, 0);
  assert.match(html, /AWS 123456789012 \/ us-east-1/);
  assert.match(html, /클라우드 API/);
  assert.match(html, /AWS 관리 이벤트/);
  assert.match(html, /ROLE:fixture/);
  const url = new URL(query({ ...defaults, collector: 'cloudtrail', os: 'cloud' }), 'https://example.test');
  assert.equal(url.searchParams.get('collector'), 'cloudtrail');
  assert.equal(url.searchParams.get('os'), 'cloud');
  const { securityEntries } = require('../logs.js');
  const details = securityEntries({ version: 1, adapter: 'aws_cloudtrail_metadata_v1', status: 'recognized',
    fields: { category: 'cloud', action: 'management_api_call', api: 'AttachUserPolicy', resource_arns: ['<img src=x>'], outcome_basis: 'no_error_reported' },
    limitations: ['management_events_not_object_access'] });
  assert.match(JSON.stringify(details), /데이터 이벤트는 미수집/);
  assert.match(JSON.stringify(details), /AttachUserPolicy/);
  assert.match(JSON.stringify(details), /최종 자원 상태 보장 아님/);
  assert.ok(!JSON.stringify(details).includes('requestParameters'));
});

test('OCI records display tenancy and selected audit fields, not AWS labels', () => {
  const cloud = { ...row, stream: 'cloud', os: 'cloud', cloud_provider: 'oci', source_kind: 'oci_audit', collector: 'oci-audit',
    cloud_account: 'ocid1.tenancy.oc1..fixture', cloud_region: 'ap-seoul-1', user: null, actor_id: 'fixture-principal' };
  const html = rowMarkup(cloud, 0);
  assert.match(html, /OCI ocid1.tenancy/);
  assert.match(html, /OCI 감사 이벤트/);
  assert.ok(!html.includes('AWS'));
  const url = new URL(query({ ...defaults, collector: 'oci-audit', os: 'cloud' }), 'https://example.test');
  assert.equal(url.searchParams.get('collector'), 'oci-audit');
  const { securityEntries } = require('../logs.js');
  const details = JSON.stringify(securityEntries({ version: 1, adapter: 'oci_audit_metadata_v1', status: 'recognized',
    fields: { category: 'cloud', api: 'UpdateSecurityList', http_status: 403, compartment_id: 'fixture', outcome_basis: 'http_status' },
    limitations: ['oci_audit_not_object_or_identity_domain_access', 'region_from_collection_scope'] }));
  assert.match(details, /OCI 구획 OCID/);
  assert.match(details, /HTTP 응답 코드/);
  assert.match(details, /403/);
  assert.match(details, /별도 수집/);
  assert.ok(!details.includes('AWS'));
});
