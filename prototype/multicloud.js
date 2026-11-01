'use strict';
const el = id => document.getElementById(id);
const names = {aws: 'AWS', azure: 'Microsoft Azure', naver: 'Naver Cloud'};
const labels = {success: '성공', failure: '실패', unknown: '확인 불가'};
const date = value => value ? new Date(value).toLocaleString() : '수신 기록 없음';
function node(tag, content, css) { const n = document.createElement(tag); if (content !== undefined) n.textContent = content; if (css) n.className = css; return n; }
let busy = false;
async function load() {
  if (busy) return;
  busy = true; el('refresh').disabled = true; el('status').textContent = '로그를 불러오는 중입니다.';
  try {
    const params = new URLSearchParams({hours: el('hours').value});
    for (const key of ['provider', 'outcome']) if (el(key).value) params.set(key, el(key).value);
    const response = await fetch('/api/multicloud?' + params, {credentials: 'same-origin', headers: {'Accept': 'application/json'}});
    if (response.status === 401) { window.location.assign('/login'); return; }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '로그를 조회하지 못했습니다.');
    el('cards').replaceChildren();
    for (const provider of Object.keys(names)) {
      const bucket = data.metrics.providers?.buckets.find(v => v.key === provider);
      const card = node('article', undefined, 'card');
      card.append(node('h2', names[provider]), node('strong', (bucket?.doc_count || 0).toLocaleString()), node('p', `실패 ${(bucket?.failures.doc_count || 0).toLocaleString()}건`), node('small', `마지막 이벤트: ${date(bucket?.last_event.value_as_string)}`));
      el('cards').append(card);
    }
    el('timeline').replaceChildren();
    const buckets = data.metrics.timeline?.buckets || [];
    const max = Math.max(1, ...buckets.map(b => b.doc_count));
    for (const b of buckets) {
      const bar = node('div', undefined, 'bucket');
      const meter = document.createElement('meter'); meter.min = 0; meter.max = max; meter.value = b.doc_count;
      meter.title = `${date(b.key_as_string)} · ${b.doc_count}건`;
      bar.append(node('small', new Date(b.key).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})), meter, node('span', b.doc_count));
      el('timeline').append(bar);
    }
    el('actions').replaceChildren(...(data.metrics.actions?.buckets || []).map(b => node('span', `${b.key} · ${b.doc_count}건`, 'chip')));
    el('events').replaceChildren();
    for (const e of data.events) {
      const row = node('tr');
      const values = [date(e['@timestamp']), `${names[e.cloud.provider]} / ${e.cloud.account.id}`, e.organization.id, `${e.event.action} / ${e.event.dataset}`, labels[e.event.outcome] || '확인 불가', e.user?.id || '—', e.source?.ip || '—', e.resource?.id || '—'];
      values.forEach((v, i) => row.append(node('td', v, i === 4 ? e.event.outcome : undefined)));
      el('events').append(row);
    }
    el('count').textContent = `총 ${data.total.toLocaleString()}건`;
    el('status').textContent = data.total ? '현재 필터에 해당하는 감사 로그입니다.' : '현재 권한과 조회 조건에 해당하는 로그가 없습니다.';
    el('updated').textContent = `갱신 ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    el('status').textContent = err.message;
    el('updated').textContent = '갱신 실패 · 이전 표시 데이터는 최신 상태가 아닙니다.';
  } finally { busy = false; el('refresh').disabled = false; }
}
for (const key of ['hours','provider','outcome']) el(key).addEventListener('change', load);
el('refresh').addEventListener('click', load);
setInterval(() => { if (!document.hidden) load(); }, 30000);
load();
