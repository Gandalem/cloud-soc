(() => {
  'use strict';
  const labels = { recent: '최근 수신', delayed: '수신 지연', silent: '장기 미수신', unknown: '판단 불가' };
  const escape = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const date = value => value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value)) : '없음';
  const status = value => Object.hasOwn(labels, value) ? value : 'unknown';
  function rowsFor(rows, query, selected) {
    const q = query.trim().toLowerCase();
    return rows.filter(row => (selected === 'all' || status(row.status) === selected) &&
      [row.host_name, ...(row.host_ips || []), row.os, row.organization, row.agent_id, row.agent_type, row.version].join(' ').toLowerCase().includes(q));
  }
  function rowMarkup(row) {
    const state = status(row.status);
    const reason = row.reason === 'future_ingestion_time' ? '서버 시각 확인 필요' : state === 'unknown' ? '수신 시각 기록 없음' : '';
    const show = value => escape(value || '정보 없음');
    return `<tr><td><span class="activity-badge ${state}">${labels[state]}</span><small class="agent-meta">${reason}</small></td><td><strong>${show(row.host_name)}</strong><small class="agent-meta">${(row.host_ips || []).map(escape).join('<br>') || 'IP 정보 없음'}</small></td><td>${show(row.os)}</td><td>${show(row.organization)}</td><td>${show(row.agent_type)} <span class="agent-meta">${show(row.version)}</span><code class="agent-meta agent-id">${show(row.agent_id)}</code></td><td><time>${date(row.last_received)}</time></td><td><time>${date(row.last_event)}</time></td><td>${Number.isSafeInteger(row.documents) && row.documents >= 0 ? row.documents.toLocaleString('ko-KR') : '-'}</td></tr>`;
  }
  // Export pure helpers for offline tests without loading demo data into production.
  if (typeof module !== 'undefined' && module.exports) { module.exports = { rowsFor, rowMarkup, status }; return; }
  const $ = selector => document.querySelector(selector);
  const state = { snapshot: null, cursors: [null], page: 0, busy: false, healthy: false, controller: null };
  function render() {
    const rows = state.healthy ? state.snapshot.agents : [];
    const shown = rowsFor(rows, $('#agent-search').value, $('#agent-filter').value);
    $('#agent-rows').innerHTML = shown.map(rowMarkup).join('');
    $('#count-all').textContent = state.healthy ? rows.length : '-';
    $('#count-recent').textContent = state.healthy ? rows.filter(row => row.status === 'recent').length : '-';
    $('#count-delayed').textContent = state.healthy ? rows.filter(row => row.status === 'delayed').length : '-';
    $('#count-other').textContent = state.healthy ? rows.filter(row => !['recent', 'delayed'].includes(row.status)).length : '-';
    $('#row-count').textContent = state.healthy ? `현재 페이지 ${rows.length}개 · 필터 결과 ${shown.length}개` : '조회 결과 없음';
    $('#status-empty').hidden = state.busy || (state.healthy && shown.length > 0);
    $('#empty-title').textContent = !state.healthy ? '수신 상태를 판단할 수 없습니다.' : rows.length ? '현재 페이지에서 일치하는 수집기가 없습니다.' : state.page ? '이후 수집기가 없습니다.' : '관측된 수집기가 없습니다.';
    $('#empty-description').textContent = !state.healthy ? '오류를 확인한 뒤 새로고침하세요. 조회 실패는 에이전트 오프라인을 의미하지 않습니다.' : rows.length ? '검색어·상태 필터를 바꾸거나 다른 페이지를 확인하세요.' : '설치만 완료해도 표시되는 목록이 아닙니다. 최근 30일 안에 수집 데이터가 도착해야 합니다.';
    $('#status-page').textContent = `${state.page + 1} 페이지`;
    $('#status-previous').disabled = state.busy || state.page === 0;
    $('#status-next').disabled = state.busy || !state.healthy || !state.snapshot.next_cursor;
    const missing = state.healthy ? state.snapshot.unidentified_documents : 0;
    $('#unidentified-note').hidden = !missing;
    $('#unidentified-note').textContent = `조회 범위에 agent.id가 없는 문서 ${Number(missing).toLocaleString('ko-KR')}건이 있어 수집기 목록에서 제외했습니다.`;
  }
  async function load() {
    if (state.busy) return;
    state.busy = true;
    state.healthy = false;
    $('#status-refresh').disabled = true;
    $('#status-panel').setAttribute('aria-busy', 'true');
    $('#status-error').hidden = true;
    $('#query-state').textContent = '조회 중';
    render();
    const controller = new AbortController();
    state.controller = controller;
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const cursor = state.cursors[state.page];
      const response = await fetch(`/api/agents/status${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, {
        credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) throw new Error(data?.error || (response.status === 401 ? '관리자 로그인이 필요합니다.' : '수신 현황 조회에 실패했습니다.'));
      if (!data || !Array.isArray(data.agents) || !data.checked_at || data.basis !== 'server_ingestion') throw new Error('잘못된 조회 응답입니다. 중앙 서버 버전을 확인하세요.');
      state.snapshot = data;
      state.healthy = true;
      // Live data can change the next cursor; invalidate previously visited later pages.
      state.cursors.length = state.page + 1;
      if (data.next_cursor) state.cursors.push(data.next_cursor);
      $('#checked-at').textContent = date(data.checked_at);
      $('#query-state').textContent = '조회 성공 · 수신 기록 기준';
    } catch (error) {
      state.snapshot = null;
      $('#query-state').textContent = '조회 실패 · 상태 판단 불가';
      $('#status-error').hidden = false;
      $('#status-error').textContent = error.name === 'AbortError' ? '조회 시간이 초과됐습니다. 서버 연결을 확인하세요.' :
        error.name === 'TypeError' ? '중앙 서버에 연결하지 못했습니다. 네트워크와 로그인을 확인하세요.' : error.message;
    } finally {
      clearTimeout(timeout);
      state.controller = null;
      state.busy = false;
      $('#status-refresh').disabled = false;
      $('#status-panel').setAttribute('aria-busy', 'false');
      render();
    }
  }
  $('#status-refresh').addEventListener('click', load);
  $('#agent-search').addEventListener('input', render);
  $('#agent-filter').addEventListener('change', render);
  $('#status-previous').addEventListener('click', () => { if (!state.busy && state.page > 0) { state.page--; load(); } });
  $('#status-next').addEventListener('click', () => { if (!state.busy && state.healthy && state.snapshot.next_cursor) { state.page++; load(); } });
  setInterval(() => { if ($('#auto-refresh').checked && !document.hidden) load(); }, 30000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && $('#auto-refresh').checked) load(); });
  window.addEventListener('pagehide', () => state.controller?.abort());
  load();
})();
